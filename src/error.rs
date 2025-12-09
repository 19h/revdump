//! Error types for revdump.

use thiserror::Error;

/// Result type alias using our error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during PE dumping operations.
#[derive(Error, Debug)]
pub enum Error {
    #[error("module not found: {0}")]
    ModuleNotFound(String),

    #[error("invalid DOS signature at offset 0x{0:X}")]
    InvalidDosSignature(usize),

    #[error("invalid PE signature at offset 0x{0:X}")]
    InvalidPeSignature(usize),

    #[error("unsupported machine type: 0x{0:X}")]
    UnsupportedMachine(u16),

    #[error("failed to read memory at 0x{addr:X} (size: {size})")]
    MemoryReadFailed { addr: u64, size: usize },

    #[error("failed to query memory at 0x{0:X}")]
    MemoryQueryFailed(u64),

    #[error("section '{name}' not found")]
    SectionNotFound { name: String },

    #[error("invalid section index: {0}")]
    InvalidSectionIndex(usize),

    #[error("PE headers too small: expected {expected}, got {actual}")]
    HeadersTooSmall { expected: usize, actual: usize },

    #[error("output file creation failed: {0}")]
    OutputCreationFailed(String),

    #[error("output file write failed: {0}")]
    OutputWriteFailed(String),

    #[error("no heap regions found")]
    NoHeapRegions,

    #[error("fixup target out of bounds: RVA 0x{rva:X}")]
    FixupOutOfBounds { rva: u32 },

    #[cfg(target_os = "windows")]
    #[error("windows API error: {0}")]
    WindowsApi(#[from] windows::core::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
