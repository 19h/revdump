//! revdump CLI - PE process dumper with vcall resolution.
//!
//! This binary provides a command-line interface for the revdump library.
//! On Windows, it can be injected into a target process to dump PE files
//! with resolved heap pointers.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use revdump::{DumpConfig, Dumper, ProgressInfo, ProgressStage};

#[cfg(target_os = "windows")]
use indicatif::{ProgressBar, ProgressStyle};

/// PE process dumper with vcall resolution via synthetic vtable stubs.
#[derive(Parser)]
#[command(name = "revdump")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Dump a module with heap snapshot
    Dump {
        /// Module name to dump (e.g., "game.exe" or full path)
        #[arg(short, long)]
        module: String,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,

        /// Maximum pointer chain depth
        #[arg(long, default_value = "8")]
        max_depth: usize,

        /// Maximum region size to dump (in bytes)
        #[arg(long, default_value = "65536")]
        max_region_size: usize,

        /// Skip the code section (.text)
        #[arg(long)]
        skip_code: bool,

        /// Section indices to skip (comma-separated)
        #[arg(long, value_delimiter = ',')]
        skip_sections: Vec<usize>,
    },

    /// Dump a module without heap snapshot (standard dump)
    StandardDump {
        /// Module name to dump
        #[arg(short, long)]
        module: String,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// List loaded modules in the current process
    ListModules,
}

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Dump {
            module,
            output,
            max_depth,
            max_region_size,
            skip_code,
            skip_sections,
        } => {
            dump_with_heap(
                &module,
                &output,
                max_depth,
                max_region_size,
                skip_code,
                skip_sections,
            )?;
        }

        Commands::StandardDump { module, output } => {
            standard_dump(&module, &output)?;
        }

        Commands::ListModules => {
            list_modules()?;
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn dump_with_heap(
    module: &str,
    output: &PathBuf,
    max_depth: usize,
    max_region_size: usize,
    skip_code: bool,
    mut skip_sections: Vec<usize>,
) -> anyhow::Result<()> {
    use bytesize::ByteSize;

    println!("Dumping module: {}", module);
    println!("Output: {}", output.display());

    let mut dumper = Dumper::from_module_name(module)?;

    // Configure skip sections
    if skip_code && !skip_sections.contains(&0) {
        skip_sections.push(0);
    }

    // Create progress bar
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% {msg}")?
            .progress_chars("#>-"),
    );

    let pb_clone = pb.clone();
    let config = DumpConfig {
        max_vfptr_probe: max_depth * 8, // Convert depth to probe size
        skip_sections,
        progress_callback: Some(Box::new(move |info: &ProgressInfo| {
            let pct = if info.total > 0 {
                (info.current as f64 / info.total as f64 * 100.0) as u64
            } else {
                0
            };

            let msg = match info.stage {
                ProgressStage::ScanningSection => {
                    let item = info.current_item.as_deref().unwrap_or("");
                    let bytes = ByteSize::b(info.bytes_processed as u64);
                    format!(
                        "{} - {} ({}, {} ptrs)",
                        info.stage.name(),
                        item,
                        bytes,
                        info.pointers_found
                    )
                }
                ProgressStage::CreatingStubs => {
                    format!(
                        "{} - {} stubs",
                        info.stage.name(),
                        info.stubs_created
                    )
                }
                _ => info.stage.name().to_string(),
            };

            pb_clone.set_position(pct);
            pb_clone.set_message(msg);
        })),
        ..Default::default()
    };

    // Suppress unused variable warnings
    let _ = max_region_size;

    dumper.dump_with_heap(output, &config)?;

    pb.finish_with_message("Complete");
    println!("\nDump complete: {}", output.display());

    Ok(())
}

#[cfg(target_os = "windows")]
fn standard_dump(module: &str, output: &PathBuf) -> anyhow::Result<()> {
    println!("Standard dump of module: {}", module);
    println!("Output: {}", output.display());

    let mut dumper = Dumper::from_module_name(module)?;
    dumper.standard_dump(output, &DumpConfig::default())?;

    println!("Dump complete: {}", output.display());
    Ok(())
}

#[cfg(target_os = "windows")]
fn list_modules() -> anyhow::Result<()> {
    use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExA, GetModuleInformation, MODULEINFO};
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::Win32::Foundation::HMODULE;
    use bytesize::ByteSize;

    let process = unsafe { GetCurrentProcess() };
    let mut modules = vec![HMODULE::default(); 1024];
    let mut needed: u32 = 0;

    unsafe {
        EnumProcessModules(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut needed,
        )?;
    }

    let count = needed as usize / std::mem::size_of::<HMODULE>();
    println!("Loaded modules ({}):", count);
    println!("{:<20} {:<16} {:<12} Name", "Base", "Size", "");

    for module in modules.iter().take(count) {
        let mut name = [0u8; 260];
        let mut info = MODULEINFO::default();

        unsafe {
            GetModuleFileNameExA(Some(process), Some(*module), &mut name);
            GetModuleInformation(
                process,
                *module,
                &mut info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )?;
        }

        let name_str = std::ffi::CStr::from_bytes_until_nul(&name)
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        let base = module.0 as usize;
        let size = info.SizeOfImage as usize;

        println!(
            "0x{:016X} {:>12}     {}",
            base,
            ByteSize::b(size as u64),
            name_str
        );
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("revdump is only supported on Windows");
    std::process::exit(1);
}
