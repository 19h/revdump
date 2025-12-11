//! # revdump
//!
//! A PE process dumper that resolves virtual calls through class instances by creating
//! synthetic vtable stubs.
//!
//! ## Overview
//!
//! When analyzing a dumped PE binary, global pointers to heap-allocated C++ class instances
//! appear as undefined data since the heap doesn't exist in the static image. This tool:
//!
//! 1. Scans module sections for pointers to heap memory
//! 2. Dumps the heap regions containing vtable pointers
//! 3. Creates a synthetic `.heap` section with minimal vtable stubs
//! 4. Rewrites global pointers to reference the synthetic section
//!
//! The result is a PE file where decompilers can resolve vcall targets statically.
//!
//! ## Usage as DLL
//!
//! When compiled as a DLL and injected into a target process, the library automatically
//! opens an interactive console for controlling dump operations. Use an injector to load
//! the DLL into the target process.
//!
//! ## Auto-dump mode
//!
//! Set the environment variable `REVDUMP_AUTO=1` to automatically dump on load.
//! The output will be written to `./autodump.exe` in the current directory.

#![warn(clippy::all)]
#![warn(rust_2018_idioms)]
#![allow(clippy::too_many_arguments)]

pub mod error;
pub mod pe;
pub mod memory;
pub mod scanner;
pub mod stub;
pub mod dumper;
pub mod fixup;
pub mod console;
pub mod devirt;

pub use error::{Error, Result};
pub use dumper::{DumpConfig, Dumper, ProgressCallback, ProgressInfo, ProgressStage};
pub use pe::PeParser;
pub use console::{start_console, stop_console};
pub use devirt::{DevirtConfig, DevirtStats};

/// Perform an automatic dump of the main executable.
#[cfg(target_os = "windows")]
pub fn auto_dump() {
    use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;
    use windows::core::PCSTR;

    eprintln!("[revdump] Auto-dump mode enabled");

    // Get the main module (exe)
    let module = unsafe { GetModuleHandleA(PCSTR::null()) };
    let module = match module {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[revdump] Failed to get main module: {:?}", e);
            return;
        }
    };

    let process = unsafe { GetCurrentProcess() };
    let mut info = MODULEINFO::default();

    if unsafe {
        GetModuleInformation(
            process,
            module,
            &mut info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )
    }.is_err() {
        eprintln!("[revdump] Failed to get module info");
        return;
    }

    let base = info.lpBaseOfDll as *const u8;
    let size = info.SizeOfImage as usize;

    eprintln!("[revdump] Module base: 0x{:X}, size: 0x{:X}", base as u64, size);

    // Configure dump with devirt enabled
    let mut config = DumpConfig::default();
    config.enable_devirt = true;

    // Perform dump
    let dumper = Dumper::from_raw(base, size, "autodump");

    let output_path = "autodump.exe";

    // Debug: check if .text is readable
    let text_addr = unsafe { base.add(0x1000) }; // .text typically at RVA 0x1000
    let readable = crate::memory::is_memory_readable(text_addr, 0x100);
    eprintln!("[revdump] .text section readable: {}", readable);

    // Try reading first bytes
    if readable {
        let mut buf = [0u8; 16];
        unsafe { std::ptr::copy_nonoverlapping(text_addr, buf.as_mut_ptr(), 16); }
        eprintln!("[revdump] .text first 16 bytes: {:02x?}", buf);
    }

    let mut dumper = dumper;
    match dumper.dump_with_heap(output_path, &config) {
        Ok(()) => {
            eprintln!("[revdump] Dump complete: {}", output_path);
        }
        Err(e) => {
            eprintln!("[revdump] Dump failed: {:?}", e);
        }
    }

    // Exit after dump
    std::process::exit(0);
}

// DLL entry point for Windows
#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: *mut std::ffi::c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut std::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Check for auto-dump mode
            if std::env::var("REVDUMP_AUTO").is_ok() {
                std::thread::spawn(|| {
                    // Small delay to let the process initialize
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    auto_dump();
                });
            } else {
                // Spawn console in a separate thread to avoid DllMain deadlock
                std::thread::spawn(|| {
                    start_console();
                });
            }
        }
        DLL_PROCESS_DETACH => {
            stop_console();
        }
        _ => {}
    }

    1 // TRUE
}
