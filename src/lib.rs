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

pub use error::{Error, Result};
pub use dumper::{DumpConfig, Dumper, ProgressCallback, ProgressInfo, ProgressStage};
pub use pe::PeParser;
pub use console::{start_console, stop_console};

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
            // Spawn console in a separate thread to avoid DllMain deadlock
            std::thread::spawn(|| {
                start_console();
            });
        }
        DLL_PROCESS_DETACH => {
            stop_console();
        }
        _ => {}
    }

    1 // TRUE
}
