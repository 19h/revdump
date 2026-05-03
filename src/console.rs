//! Interactive console for DLL injection mode.
//!
//! When the library is loaded as a DLL into a target process, this module
//! provides a REPL interface for controlling the dump operations.

#[cfg(target_os = "windows")]
use std::io::{self, BufRead, Write};
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::thread::{self, JoinHandle};

#[cfg(target_os = "windows")]
use windows::core::PCSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::HMODULE;
#[cfg(target_os = "windows")]
use windows::Win32::System::Console::{
    AllocConsole, FreeConsole, GetConsoleMode, SetConsoleMode, SetConsoleTitleA, CONSOLE_MODE,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
#[cfg(target_os = "windows")]
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, GetModuleFileNameExA, GetModuleInformation, MODULEINFO,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::GetCurrentProcess;

#[cfg(target_os = "windows")]
use crate::dumper::{DumpConfig, Dumper, ProgressInfo};
#[cfg(target_os = "windows")]
use crate::memory::strip_pointer_tags;
#[cfg(target_os = "windows")]
use crate::progress::{progress_display, progress_percent};
#[cfg(target_os = "windows")]
use crate::stub::EdgeConfidence;

/// Console state and settings.
#[cfg(target_os = "windows")]
pub struct Console {
    /// Console thread handle.
    thread: Option<JoinHandle<()>>,
    /// Flag to signal shutdown.
    should_exit: Arc<AtomicBool>,
    /// Target module name.
    target_module: String,
    /// Output directory path.
    output_path: String,
    /// Max recursive heap scan depth.
    max_depth: usize,
    /// Max bytes to scan per heap object.
    max_region_size: usize,
    /// Skip code section (.text).
    skip_code: bool,
    /// Additional sections to skip.
    skip_sections: Vec<usize>,
    /// Enable devirtualization.
    devirt: bool,
    emit_revdmp: bool,
    parse_rtti: bool,
    max_graph_edges: usize,
    min_edge_confidence: EdgeConfidence,
    detect_containers: bool,
    strong_devirt: bool,
}

#[cfg(target_os = "windows")]
impl Console {
    /// Create a new console instance.
    pub fn new() -> Self {
        // Get temp path for default output
        let output_path = std::env::temp_dir().to_string_lossy().to_string();

        // Get main module name as default target
        let target_module =
            Self::get_main_module_name().unwrap_or_else(|| "unknown.exe".to_string());

        Self {
            thread: None,
            should_exit: Arc::new(AtomicBool::new(false)),
            target_module,
            output_path,
            max_depth: 4,
            max_region_size: 0x1000,
            skip_code: false,
            skip_sections: Vec::new(),
            devirt: true,
            emit_revdmp: true,
            parse_rtti: true,
            max_graph_edges: 100_000,
            min_edge_confidence: EdgeConfidence::Low,
            detect_containers: true,
            strong_devirt: true,
        }
    }

    /// Get the main module name.
    fn get_main_module_name() -> Option<String> {
        unsafe {
            let process = GetCurrentProcess();
            let mut modules = vec![HMODULE::default(); 1];
            let mut needed: u32 = 0;

            if EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                std::mem::size_of::<HMODULE>() as u32,
                &mut needed,
            )
            .is_ok()
            {
                let mut name = [0u8; 260];
                GetModuleFileNameExA(Some(process), Some(modules[0]), &mut name);

                let name_str = std::ffi::CStr::from_bytes_until_nul(&name)
                    .ok()?
                    .to_string_lossy();

                // Extract just the filename
                name_str.rsplit('\\').next().map(|s| s.to_string())
            } else {
                None
            }
        }
    }

    /// Start the console in a new thread.
    pub fn start(&mut self) -> bool {
        if self.thread.is_some() {
            return true;
        }

        // Allocate console and redirect stdio
        unsafe {
            // Try to allocate a new console
            let _ = AllocConsole();

            let _ = SetConsoleTitleA(PCSTR(b"RevDump - PE Heap Dumper\0".as_ptr()));

            // Reopen stdio to the new console
            // This is critical for DLL injection where stdio isn't automatically connected
            use windows::Win32::Storage::FileSystem::{
                CreateFileA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
                FILE_SHARE_WRITE, OPEN_EXISTING,
            };
            use windows::Win32::System::Console::{
                GetStdHandle, SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            };

            // Open CONIN$ and CONOUT$ explicitly
            let conin = CreateFileA(
                PCSTR(b"CONIN$\0".as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                Default::default(),
                None,
            );

            let conout = CreateFileA(
                PCSTR(b"CONOUT$\0".as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                Default::default(),
                None,
            );

            if let (Ok(cin), Ok(cout)) = (conin, conout) {
                // Redirect stdio handles
                let _ = SetStdHandle(STD_INPUT_HANDLE, cin);
                let _ = SetStdHandle(STD_OUTPUT_HANDLE, cout);
                let _ = SetStdHandle(STD_ERROR_HANDLE, cout);
            }

            // Try to enable ANSI escape sequences
            if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
                let mut mode = CONSOLE_MODE::default();
                if GetConsoleMode(handle, &mut mode).is_ok() {
                    let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
            }
        }

        let should_exit = self.should_exit.clone();
        let target_module = self.target_module.clone();
        let output_path = self.output_path.clone();
        let max_depth = self.max_depth;
        let max_region_size = self.max_region_size;
        let skip_code = self.skip_code;
        let skip_sections = self.skip_sections.clone();
        let devirt = self.devirt;
        let emit_revdmp = self.emit_revdmp;
        let parse_rtti = self.parse_rtti;
        let max_graph_edges = self.max_graph_edges;
        let min_edge_confidence = self.min_edge_confidence;
        let detect_containers = self.detect_containers;
        let strong_devirt = self.strong_devirt;

        let handle = thread::spawn(move || {
            let mut state = ConsoleState {
                should_exit,
                target_module,
                output_path,
                max_depth,
                max_region_size,
                skip_code,
                skip_sections,
                devirt,
                emit_revdmp,
                parse_rtti,
                max_graph_edges,
                min_edge_confidence,
                detect_containers,
                strong_devirt,
            };
            state.run();
        });

        self.thread = Some(handle);
        true
    }

    /// Stop the console.
    pub fn stop(&mut self) {
        self.should_exit.store(true, Ordering::SeqCst);

        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }

        unsafe {
            let _ = FreeConsole();
        }
    }
}

#[cfg(target_os = "windows")]
impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
impl Drop for Console {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Internal console state for the worker thread.
#[cfg(target_os = "windows")]
struct ConsoleState {
    should_exit: Arc<AtomicBool>,
    target_module: String,
    output_path: String,
    max_depth: usize,
    max_region_size: usize,
    skip_code: bool,
    skip_sections: Vec<usize>,
    devirt: bool,
    emit_revdmp: bool,
    parse_rtti: bool,
    max_graph_edges: usize,
    min_edge_confidence: EdgeConfidence,
    detect_containers: bool,
    strong_devirt: bool,
}

#[cfg(target_os = "windows")]
impl ConsoleState {
    fn run(&mut self) {
        self.print_banner();
        self.print_status();
        println!("\nType 'help' for available commands.\n");

        let stdin = io::stdin();

        while !self.should_exit.load(Ordering::SeqCst) {
            print!("revdump> ");
            let _ = io::stdout().flush();

            let mut line = String::new();
            match stdin.lock().read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {}
                Err(_) => break,
            }

            let cmd = line.trim().to_lowercase();
            if cmd.is_empty() {
                continue;
            }

            match cmd.as_str() {
                "help" | "h" | "?" => self.print_help(),
                "status" | "s" => self.print_status(),
                "modules" | "m" | "list" => self.print_modules(),
                "module" | "target" | "t" => self.cmd_set_module(),
                "output" | "out" | "o" => self.cmd_set_output(),
                "depth" | "d" => self.cmd_set_depth(),
                "regionsize" | "region" | "r" => self.cmd_set_region_size(),
                "skipcode" | "sc" => self.cmd_toggle_skip_code(),
                "skipsections" | "ss" => self.cmd_set_skip_sections(),
                "devirt" | "dv" => self.cmd_toggle_devirt(),
                "revdmp" => self.cmd_toggle_revdmp(),
                "rtti" => self.cmd_toggle_rtti(),
                "containers" | "ct" => self.cmd_toggle_containers(),
                "strongdevirt" | "sdv" => self.cmd_toggle_strong_devirt(),
                "edges" => self.cmd_set_max_graph_edges(),
                "edgeconf" => self.cmd_set_min_edge_confidence(),
                "dump" | "dumpheap" | "dh" => self.cmd_dump_with_heap(),
                "dumpstd" | "ds" | "standard" => self.cmd_dump_standard(),
                "go" | "run" | "!" => self.cmd_dump_now(),
                "debug" | "dbg" => self.cmd_debug_heap_analysis(),
                "quit" | "exit" | "q" => {
                    println!("Goodbye!");
                    self.should_exit.store(true, Ordering::SeqCst);
                }
                "clear" | "cls" => {
                    print!("\x1B[2J\x1B[H"); // ANSI clear screen
                    let _ = io::stdout().flush();
                    self.print_banner();
                }
                _ => {
                    println!("[ERROR] Unknown command: {}", cmd);
                    println!("Type 'help' for available commands.");
                }
            }
        }
    }

    fn print_banner(&self) {
        println!();
        println!("  ____            ____                        ");
        println!(" |  _ \\ _____   _|  _ \\ _   _ _ __ ___  _ __  ");
        println!(" | |_) / _ \\ \\ / / | | | | | | '_ ` _ \\| '_ \\ ");
        println!(" |  _ <  __/\\ V /| |_| | |_| | | | | | | |_) |");
        println!(" |_| \\_\\___| \\_/ |____/ \\__,_|_| |_| |_| .__/ ");
        println!("                                       |_|    ");
        println!();
        println!(" PE Dumper with Heap Snapshot Embedding (Rust)");
        println!(" Version 0.1.0 | PID: {}", std::process::id());
        println!();
    }

    fn print_help(&self) {
        println!();
        println!("=== Available Commands ===");
        println!();
        println!("  [Configuration]");
        println!("    module, target, t    - Set target module to dump");
        println!("    output, out, o       - Set output file path");
        println!("    depth, d             - Set recursive heap scan depth");
        println!("    regionsize, r        - Set max heap scan size");
        println!("    skipcode, sc         - Toggle skip code section");
        println!("    skipsections, ss     - Set sections to skip");
        println!("    devirt, dv           - Toggle vcall devirtualization");
        println!("    strongdevirt, sdv    - Toggle stronger devirt analysis (default on)");
        println!("    revdmp               - Toggle .revdmp metadata");
        println!("    rtti                 - Toggle RTTI parsing");
        println!("    containers, ct       - Toggle container detection");
        println!("    edges                - Set max graph edges");
        println!("    edgeconf             - Set min edge confidence");
        println!();
        println!("  [Dumping]");
        println!("    dump, dumpheap, dh   - Dump with heap (interactive)");
        println!("    dumpstd, ds          - Standard dump (no heap)");
        println!("    go, run, !           - Quick dump with current settings");
        println!();
        println!("  [Information]");
        println!("    status, s            - Show current settings");
        println!("    modules, m, list     - List loaded modules");
        println!("    debug, dbg           - Debug heap pointer analysis");
        println!("    help, h, ?           - Show this help");
        println!("    clear, cls           - Clear screen");
        println!();
        println!("  [Exit]");
        println!("    quit, exit, q        - Exit console");
        println!();
    }

    fn print_status(&self) {
        println!();
        println!("=== Current Settings ===");
        println!("  Target Module:    {}", self.target_module);
        println!("  Output Path:      {}", self.output_path);
        println!("  Recursive Depth:  {}", self.max_depth);
        println!(
            "  Heap Scan Size:   0x{:X} ({} KB)",
            self.max_region_size,
            self.max_region_size / 1024
        );
        println!(
            "  Skip Code:        {}",
            if self.skip_code { "Yes" } else { "No" }
        );
        println!(
            "  Devirtualize:     {}",
            if self.devirt { "Yes" } else { "No" }
        );
        println!(
            "  Strong Devirt:    {}",
            if self.strong_devirt { "Yes" } else { "No" }
        );
        println!(
            "  .revdmp:          {}",
            if self.emit_revdmp { "Yes" } else { "No" }
        );
        println!(
            "  RTTI Parse:       {}",
            if self.parse_rtti { "Yes" } else { "No" }
        );
        println!(
            "  Containers:       {}",
            if self.detect_containers { "Yes" } else { "No" }
        );
        println!("  Max Graph Edges:  {}", self.max_graph_edges);
        println!("  Min Edge Conf:    {}", self.min_edge_confidence.as_str());

        if !self.skip_sections.is_empty() {
            let sections: Vec<String> = self.skip_sections.iter().map(|s| s.to_string()).collect();
            println!("  Skip Sections:    {}", sections.join(", "));
        }
        println!();
    }

    fn print_modules(&self) {
        println!();
        println!("=== Loaded Modules ===");
        println!();

        unsafe {
            let process = GetCurrentProcess();
            let mut modules = vec![HMODULE::default(); 1024];
            let mut needed: u32 = 0;

            if EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut needed,
            )
            .is_ok()
            {
                let count = needed as usize / std::mem::size_of::<HMODULE>();

                println!("  {:<40} {:<18} {:>10}", "Name", "Base", "Size");
                println!("  {:-<70}", "");

                for (i, &module) in modules.iter().take(count.min(50)).enumerate() {
                    let mut name = [0u8; 260];
                    let mut info = MODULEINFO::default();

                    GetModuleFileNameExA(Some(process), Some(module), &mut name);
                    let _ = GetModuleInformation(
                        process,
                        module,
                        &mut info,
                        std::mem::size_of::<MODULEINFO>() as u32,
                    );

                    let name_str = std::ffi::CStr::from_bytes_until_nul(&name)
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();

                    let short_name = name_str.rsplit('\\').next().unwrap_or(&name_str);
                    let marker = if i == 0 { "*" } else { " " };

                    println!(
                        "{} {:<40} 0x{:016X} {:>7} KB",
                        marker,
                        short_name,
                        module.0 as usize,
                        info.SizeOfImage / 1024
                    );
                }

                if count > 50 {
                    println!("  ... and {} more modules", count - 50);
                }
            }
        }
        println!();
    }

    fn cmd_set_module(&mut self) {
        println!("Current target: {}", self.target_module);
        print!("Enter module name (or press Enter to keep): ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let new_module = input.trim();
            if !new_module.is_empty() {
                // Verify module exists
                let name_cstr = std::ffi::CString::new(new_module).unwrap();
                let result = unsafe { GetModuleHandleA(PCSTR(name_cstr.as_ptr() as *const u8)) };

                match result {
                    Ok(h) if !h.is_invalid() => {
                        self.target_module = new_module.to_string();
                        println!("[OK] Target module set to: {}", self.target_module);
                    }
                    _ => {
                        println!("[ERROR] Module not found: {}", new_module);
                    }
                }
            }
        }
    }

    fn cmd_set_output(&mut self) {
        println!("Current output: {}", self.output_path);
        print!("Enter output path (or press Enter to keep): ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let new_path = input.trim();
            if !new_path.is_empty() {
                self.output_path = new_path.to_string();
                println!("[OK] Output path set to: {}", self.output_path);
            }
        }
    }

    fn cmd_set_depth(&mut self) {
        print!("Recursive heap scan depth [{}]: ", self.max_depth);
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            if let Ok(depth) = input.trim().parse::<usize>() {
                self.max_depth = depth;
            }
        }
        println!("[OK] Max depth set to: {}", self.max_depth);
    }

    fn cmd_set_region_size(&mut self) {
        println!(
            "Current max heap scan size: 0x{:X} ({} KB)",
            self.max_region_size,
            self.max_region_size / 1024
        );
        print!(
            "Max heap scan size in KB [{}]: ",
            self.max_region_size / 1024
        );
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            if let Ok(size_kb) = input.trim().parse::<usize>() {
                self.max_region_size = size_kb * 1024;
            }
        }
        println!(
            "[OK] Max heap scan size set to: 0x{:X} ({} KB)",
            self.max_region_size,
            self.max_region_size / 1024
        );
    }

    fn cmd_toggle_skip_code(&mut self) {
        self.skip_code = !self.skip_code;
        println!(
            "[OK] Skip code section: {}",
            if self.skip_code { "Yes" } else { "No" }
        );
    }

    fn cmd_toggle_devirt(&mut self) {
        self.devirt = !self.devirt;
        println!(
            "[OK] Vcall devirtualization: {}",
            if self.devirt { "Enabled" } else { "Disabled" }
        );
    }

    fn cmd_toggle_revdmp(&mut self) {
        self.emit_revdmp = !self.emit_revdmp;
        println!(
            "[OK] .revdmp metadata: {}",
            if self.emit_revdmp {
                "Enabled"
            } else {
                "Disabled"
            }
        );
    }

    fn cmd_toggle_rtti(&mut self) {
        self.parse_rtti = !self.parse_rtti;
        println!(
            "[OK] RTTI parsing: {}",
            if self.parse_rtti {
                "Enabled"
            } else {
                "Disabled"
            }
        );
    }

    fn cmd_toggle_containers(&mut self) {
        self.detect_containers = !self.detect_containers;
        println!(
            "[OK] Container detection: {}",
            if self.detect_containers {
                "Enabled"
            } else {
                "Disabled"
            }
        );
    }

    fn cmd_toggle_strong_devirt(&mut self) {
        self.strong_devirt = !self.strong_devirt;
        println!(
            "[OK] Strong devirt analysis: {}",
            if self.strong_devirt {
                "Enabled"
            } else {
                "Disabled"
            }
        );
    }

    fn cmd_set_max_graph_edges(&mut self) {
        print!("Max graph edges [{}]: ", self.max_graph_edges);
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            if let Ok(value) = input.trim().parse::<usize>() {
                self.max_graph_edges = value;
            }
        }
        println!("[OK] Max graph edges: {}", self.max_graph_edges);
    }

    fn cmd_set_min_edge_confidence(&mut self) {
        print!(
            "Minimum edge confidence (low/medium/high) [{}]: ",
            self.min_edge_confidence.as_str()
        );
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            match input.trim().to_ascii_lowercase().as_str() {
                "low" => self.min_edge_confidence = EdgeConfidence::Low,
                "medium" | "med" => self.min_edge_confidence = EdgeConfidence::Medium,
                "high" => self.min_edge_confidence = EdgeConfidence::High,
                "" => {}
                other => println!("[ERROR] Invalid confidence: {}", other),
            }
        }
        println!(
            "[OK] Min edge confidence: {}",
            self.min_edge_confidence.as_str()
        );
    }

    fn cmd_set_skip_sections(&mut self) {
        println!("Enter section indices to skip (comma-separated), or 'clear' to clear:");
        print!("Sections: ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let input = input.trim();
            if input == "clear" || input == "none" {
                self.skip_sections.clear();
                println!("[OK] Cleared skip sections list");
                return;
            }

            self.skip_sections.clear();
            for part in input.split(',') {
                if let Ok(idx) = part.trim().parse::<usize>() {
                    self.skip_sections.push(idx);
                }
            }

            if !self.skip_sections.is_empty() {
                let sections: Vec<String> =
                    self.skip_sections.iter().map(|s| s.to_string()).collect();
                println!("[OK] Will skip sections: {}", sections.join(", "));
            }
        }
    }

    fn generate_output_filename(&self, suffix: &str) -> String {
        let timestamp = chrono_lite_timestamp();

        let mut path = self.output_path.clone();
        if !path.ends_with('\\') && !path.ends_with('/') {
            path.push('\\');
        }

        // Remove extension from module name
        let base_name = self
            .target_module
            .rsplit('.')
            .last()
            .unwrap_or(&self.target_module);

        format!("{}{}_{}{}.exe", path, base_name, suffix, timestamp)
    }

    fn cmd_dump_with_heap(&mut self) {
        println!();
        println!("=== Heap Dump Configuration ===");
        println!();

        println!("Target module: {}", self.target_module);
        if !self.confirm("Use this module?") {
            self.cmd_set_module();
        }

        let default_file = self.generate_output_filename("heapdump_");
        print!("Output file [{}]: ", default_file);
        let _ = io::stdout().flush();

        let mut input = String::new();
        let out_file = if io::stdin().read_line(&mut input).is_ok() && !input.trim().is_empty() {
            input.trim().to_string()
        } else {
            default_file
        };

        println!();
        println!("Settings:");
        println!("  Recursive Depth: {}", self.max_depth);
        println!("  Heap Scan Size: 0x{:X}", self.max_region_size);
        println!("  Skip Code: {}", if self.skip_code { "Yes" } else { "No" });
        println!("  Devirtualize: {}", if self.devirt { "Yes" } else { "No" });
        println!(
            "  Strong Devirt: {}",
            if self.strong_devirt { "Yes" } else { "No" }
        );
        println!("  .revdmp: {}", if self.emit_revdmp { "Yes" } else { "No" });
        println!("  RTTI: {}", if self.parse_rtti { "Yes" } else { "No" });
        println!(
            "  Containers: {}",
            if self.detect_containers { "Yes" } else { "No" }
        );

        if !self.confirm("\nProceed with dump?") {
            println!("Cancelled.");
            return;
        }

        self.do_heap_dump(&out_file);
    }

    fn cmd_dump_standard(&mut self) {
        println!();
        println!("=== Standard Dump ===");
        println!();

        let default_file = self.generate_output_filename("dump_");
        println!("Target: {}", self.target_module);
        print!("Output file [{}]: ", default_file);
        let _ = io::stdout().flush();

        let mut input = String::new();
        let out_file = if io::stdin().read_line(&mut input).is_ok() && !input.trim().is_empty() {
            input.trim().to_string()
        } else {
            default_file
        };

        if !self.confirm("Proceed?") {
            println!("Cancelled.");
            return;
        }

        println!();
        println!("*** Dumping... ***");
        println!();

        match Dumper::from_module_name(&self.target_module) {
            Ok(mut dumper) => match dumper.standard_dump(&out_file, &DumpConfig::default()) {
                Ok(()) => {
                    println!();
                    println!("[OK] Dump complete: {}", out_file);
                }
                Err(e) => {
                    println!("[ERROR] Dump failed: {}", e);
                }
            },
            Err(e) => {
                println!("[ERROR] Failed to open module: {}", e);
            }
        }
        println!();
    }

    fn cmd_dump_now(&mut self) {
        let out_file = self.generate_output_filename("heapdump_");

        println!();
        println!("*** Quick dump starting... ***");
        println!("Target: {}", self.target_module);
        println!("Output: {}", out_file);
        println!();

        self.do_heap_dump(&out_file);
    }

    fn do_heap_dump(&mut self, out_file: &str) {
        println!("*** Starting heap dump... ***");
        println!();

        let mut skip_sections = self.skip_sections.clone();
        if self.skip_code && !skip_sections.contains(&0) {
            skip_sections.push(0);
        }

        let config = DumpConfig {
            max_heap_scan_size: self.max_region_size,
            recursive_heap_scan_depth: self.max_depth,
            skip_sections,
            enable_devirt: self.devirt,
            emit_revdmp: self.emit_revdmp,
            parse_rtti: self.parse_rtti,
            max_graph_edges: self.max_graph_edges,
            min_edge_confidence: self.min_edge_confidence,
            detect_containers: self.detect_containers,
            strong_devirt: self.strong_devirt,
            progress_callback: Some(Box::new(|info: &ProgressInfo| {
                print_progress(info);
            })),
            ..Default::default()
        };

        match Dumper::from_module_name(&self.target_module) {
            Ok(mut dumper) => {
                match dumper.dump_with_heap(out_file, &config) {
                    Ok(()) => {
                        // Clear progress line
                        print!("\r\x1B[K");
                        let _ = io::stdout().flush();

                        println!();
                        println!("========================================");
                        println!("[OK] DUMP COMPLETE!");
                        println!("[OK] Output: {}", out_file);
                        println!("========================================");
                    }
                    Err(e) => {
                        println!();
                        println!("[ERROR] DUMP FAILED: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("[ERROR] Failed to open module: {}", e);
            }
        }
        println!();
    }

    fn cmd_debug_heap_analysis(&mut self) {
        use crate::pe::PeParser;
        use crate::stub::{StubConfig, StubDebugProgress, StubGenerator};

        println!();
        println!("=== Debug Heap Analysis ===");
        println!();
        println!("Target: {}", self.target_module);
        println!();

        // Get module info via the module list
        let (base, size) = {
            let mut found = None;
            let process = unsafe { GetCurrentProcess() };
            let mut modules = vec![HMODULE::default(); 1024];
            let mut needed: u32 = 0;

            if unsafe {
                EnumProcessModules(
                    process,
                    modules.as_mut_ptr(),
                    (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                    &mut needed,
                )
            }
            .is_ok()
            {
                let count = needed as usize / std::mem::size_of::<HMODULE>();
                for module in modules.iter().take(count) {
                    let mut name = [0u8; 260];
                    let mut info = MODULEINFO::default();

                    unsafe {
                        let _ = GetModuleFileNameExA(Some(process), Some(*module), &mut name);
                        let _ = GetModuleInformation(
                            process,
                            *module,
                            &mut info,
                            std::mem::size_of::<MODULEINFO>() as u32,
                        );
                    }

                    let name_str = std::ffi::CStr::from_bytes_until_nul(&name)
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();

                    if name_str
                        .to_lowercase()
                        .contains(&self.target_module.to_lowercase())
                    {
                        found = Some((info.lpBaseOfDll as *const u8, info.SizeOfImage as usize));
                        break;
                    }
                }
            }
            match found {
                Some(info) => info,
                None => {
                    println!("[ERROR] Could not find module: {}", self.target_module);
                    return;
                }
            }
        };

        println!("Module base: 0x{:X}", base as u64);
        println!("Module size: 0x{:X}", size);
        println!();

        // Parse PE
        let pe = match unsafe { PeParser::parse(base, size) } {
            Ok(pe) => pe,
            Err(e) => {
                println!("[ERROR] Failed to parse PE: {}", e);
                return;
            }
        };

        println!("Image base: 0x{:X}", pe.image_base);
        println!();

        // Create stub generator
        let stub_config = StubConfig {
            min_ptr_value: 0x10000,
            max_ptr_value: 0x7FFF_FFFF_FFFF,
            max_vfptr_probe: StubConfig::default().max_vfptr_probe,
            max_heap_scan_size: self.max_region_size,
            recursive_heap_scan_depth: self.max_depth,
            max_graph_edges: self.max_graph_edges,
            min_edge_confidence: self.min_edge_confidence,
            detect_containers: self.detect_containers,
        };

        let mut stub_gen = match StubGenerator::new(base, size, stub_config) {
            Ok(sg) => sg,
            Err(e) => {
                println!("[ERROR] Failed to create stub generator: {}", e);
                return;
            }
        };

        // Scan for heap pointers
        println!("Scanning for heap pointers...");
        let scanner_config = stub_gen.scanner_config();
        let mut heap_ptr_locs = Vec::new();
        let scan_started = std::time::Instant::now();
        let scan_total: usize = pe
            .sections
            .iter()
            .filter(|section| section.name != ".text")
            .map(|section| section.virtual_size as usize)
            .sum();
        let mut scanned_bytes = 0usize;

        for section in &pe.sections {
            if section.name == ".text" {
                continue; // Skip code
            }

            println!(
                "  Section {:<8} RVA 0x{:08X} size 0x{:X}",
                section.name, section.virtual_address, section.virtual_size
            );

            let sec_data = unsafe {
                std::slice::from_raw_parts(
                    base.add(section.virtual_address as usize),
                    section.virtual_size as usize,
                )
            };

            // Simple scan for pointers
            for offset in (0..sec_data.len().saturating_sub(8)).step_by(8) {
                if (offset & 0xFFFF) == 0 {
                    print_debug_scan_progress(
                        &section.name,
                        scanned_bytes + offset,
                        scan_total,
                        heap_ptr_locs.len(),
                        scan_started,
                    );
                }

                let ptr = strip_pointer_tags(u64::from_le_bytes(
                    sec_data[offset..offset + 8].try_into().unwrap(),
                ));

                if ptr >= scanner_config.min_ptr
                    && ptr <= scanner_config.max_ptr
                    && (ptr < scanner_config.mod_base || ptr >= scanner_config.mod_end)
                {
                    // Check if it's a valid heap region
                    if stub_gen.cache().is_valid_heap_region(ptr) {
                        let rva = section.virtual_address + offset as u32;
                        heap_ptr_locs.push((rva, ptr));
                    }
                }
            }
            scanned_bytes += sec_data.len();
            print_debug_scan_progress(
                &section.name,
                scanned_bytes,
                scan_total,
                heap_ptr_locs.len(),
                scan_started,
            );
        }

        print!("\r\x1B[K");
        let _ = io::stdout().flush();

        println!(
            "Found {} heap pointers in {:.2}s\n",
            heap_ptr_locs.len(),
            scan_started.elapsed().as_secs_f64()
        );

        if heap_ptr_locs.is_empty() {
            println!("[WARN] No heap pointers found!");
            return;
        }

        // Process with verbose output and progress snapshots.
        let stub_started = std::time::Instant::now();
        stub_gen.process_heap_pointers_verbose_with_progress(&heap_ptr_locs, |progress| {
            print_debug_stub_progress(progress, stub_started);
        });
        print!("\r\x1B[K");
        let _ = io::stdout().flush();

        println!();
        println!(
            "Analysis complete in {:.2}s.",
            scan_started.elapsed().as_secs_f64()
        );
        println!(
            "Created {} stubs, retained {} heap graph edges, detected {} containers.",
            stub_gen.stubs().count(),
            stub_gen.heap_edges().len(),
            stub_gen.containers().len()
        );
        println!();
    }

    fn confirm(&self, prompt: &str) -> bool {
        print!("{} (y/N): ", prompt);
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let c = input.trim().chars().next().unwrap_or('n');
            return c == 'y' || c == 'Y';
        }
        false
    }
}

/// Simple timestamp without chrono dependency.
#[cfg(target_os = "windows")]
fn chrono_lite_timestamp() -> String {
    use windows::Win32::System::SystemInformation::GetLocalTime;

    let st = unsafe { GetLocalTime() };

    format!(
        "{:04}{:02}{:02}_{:02}{:02}{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}

/// Print progress bar.
#[cfg(target_os = "windows")]
fn print_progress(info: &ProgressInfo) {
    let percent = progress_percent(info).clamp(0.0, 100.0);
    let display = progress_display(info);
    let metrics = display.metrics_text();

    // Build progress bar
    const BAR_WIDTH: usize = 28;
    let filled = ((percent / 100.0) * BAR_WIDTH as f64) as usize;

    let bar: String = (0..BAR_WIDTH)
        .map(|i| {
            if i < filled {
                '#'
            } else if i == filled && filled < BAR_WIDTH {
                '>'
            } else {
                '-'
            }
        })
        .collect();

    // Print progress line
    if metrics.is_empty() {
        print!(
            "\r  [{}] {:5.1}% | {:<26} | {:<24} | {}",
            bar, percent, display.stage, display.step, display.progress
        );
    } else {
        print!(
            "\r  [{}] {:5.1}% | {:<26} | {:<24} | {:<18} | {}",
            bar, percent, display.stage, display.step, display.progress, metrics
        );
    }
    let _ = io::stdout().flush();
}

#[cfg(target_os = "windows")]
fn debug_bar(current: usize, total: usize, width: usize) -> (String, f64) {
    let percent = if total > 0 {
        (current as f64 / total as f64 * 100.0).min(100.0)
    } else {
        0.0
    };
    let filled = ((percent / 100.0) * width as f64) as usize;
    let bar = (0..width)
        .map(|i| {
            if i < filled {
                '#'
            } else if i == filled && filled < width {
                '>'
            } else {
                '-'
            }
        })
        .collect();
    (bar, percent)
}

#[cfg(target_os = "windows")]
fn print_debug_scan_progress(
    section_name: &str,
    current_bytes: usize,
    total_bytes: usize,
    heap_ptrs: usize,
    started: std::time::Instant,
) {
    let (bar, percent) = debug_bar(current_bytes, total_bytes, 36);
    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let mb_done = current_bytes as f64 / (1024.0 * 1024.0);
    let mb_total = total_bytes as f64 / (1024.0 * 1024.0);
    let mb_per_sec = mb_done / elapsed;

    print!(
        "\r  DBG scan {:<8} [{}] {:5.1}% {:6.1}/{:6.1} MB {:6.1} MB/s heap_ptrs={}",
        section_name, bar, percent, mb_done, mb_total, mb_per_sec, heap_ptrs
    );
    let _ = io::stdout().flush();
}

#[cfg(target_os = "windows")]
fn print_debug_stub_progress(
    progress: crate::stub::StubDebugProgress,
    started: std::time::Instant,
) {
    if progress.total > 0 && progress.current < progress.total && (progress.current % 32) != 0 {
        return;
    }

    let (bar, percent) = debug_bar(progress.current, progress.total, 36);
    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let per_sec = if progress.current > 0 {
        progress.current as f64 / elapsed
    } else {
        0.0
    };

    if progress.total == 0 {
        print!(
            "\r  DBG {:<20} [recursive scan running] roots={} created={} dup={} invalid={} no_vfptr={} no_module_vtbl={}",
            progress.phase,
            progress.current,
            progress.created,
            progress.already_visited,
            progress.invalid_heap_ptr,
            progress.no_vfptr_found,
            progress.vtable_not_in_module
        );
    } else {
        print!(
            "\r  DBG {:<20} [{}] {:5.1}% {}/{} {:6.1}/s created={} dup={} invalid={} no_vfptr={} no_module_vtbl={} rec={} rva=0x{:X} heap=0x{:X}",
            progress.phase,
            bar,
            percent,
            progress.current,
            progress.total,
            per_sec,
            progress.created,
            progress.already_visited,
            progress.invalid_heap_ptr,
            progress.no_vfptr_found,
            progress.vtable_not_in_module,
            progress.recursive_discovered,
            progress.current_rva,
            progress.current_heap_addr
        );
    }
    let _ = io::stdout().flush();
}

// Global console instance
#[cfg(target_os = "windows")]
static mut G_CONSOLE: Option<Console> = None;

/// Start the global console.
#[cfg(target_os = "windows")]
pub fn start_console() {
    unsafe {
        if G_CONSOLE.is_none() {
            let mut console = Console::new();
            console.start();
            G_CONSOLE = Some(console);
        }
    }
}

/// Stop the global console.
#[cfg(target_os = "windows")]
pub fn stop_console() {
    unsafe {
        if let Some(mut console) = G_CONSOLE.take() {
            console.stop();
        }
    }
}

// Stub implementations for non-Windows
#[cfg(not(target_os = "windows"))]
pub fn start_console() {}

#[cfg(not(target_os = "windows"))]
pub fn stop_console() {}
