//! PE format parsing and types.
//!
//! This module provides types for parsing PE headers from memory-mapped images
//! and extracting section information needed for the dump process.

use crate::error::{Error, Result};

// PE format constants
pub const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
pub const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const MACHINE_AMD64: u16 = 0x8664;
pub const MACHINE_I386: u16 = 0x014C;

// Section characteristics
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Default characteristics for the synthetic .heap section.
/// Readable data section (no execute since it's just vtable pointers).
pub const HEAP_SECTION_CHARACTERISTICS: u32 =
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

/// DOS header (64 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct DosHeader {
    pub e_magic: u16,      // Magic number ("MZ")
    pub e_cblp: u16,       // Bytes on last page of file
    pub e_cp: u16,         // Pages in file
    pub e_crlc: u16,       // Relocations
    pub e_cparhdr: u16,    // Size of header in paragraphs
    pub e_minalloc: u16,   // Minimum extra paragraphs needed
    pub e_maxalloc: u16,   // Maximum extra paragraphs needed
    pub e_ss: u16,         // Initial SS value
    pub e_sp: u16,         // Initial SP value
    pub e_csum: u16,       // Checksum
    pub e_ip: u16,         // Initial IP value
    pub e_cs: u16,         // Initial CS value
    pub e_lfarlc: u16,     // File address of relocation table
    pub e_ovno: u16,       // Overlay number
    pub e_res: [u16; 4],   // Reserved words
    pub e_oemid: u16,      // OEM identifier
    pub e_oeminfo: u16,    // OEM information
    pub e_res2: [u16; 10], // Reserved words
    pub e_lfanew: i32,     // File address of new exe header (PE offset)
}

impl DosHeader {
    /// Create a minimal valid DOS header.
    pub fn minimal(pe_offset: u32) -> Self {
        Self {
            e_magic: DOS_MAGIC,
            e_cblp: 0x90,
            e_cp: 0x03,
            e_crlc: 0,
            e_cparhdr: 0x04,
            e_minalloc: 0,
            e_maxalloc: 0xFFFF,
            e_ss: 0,
            e_sp: 0xB8,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0x40,
            e_ovno: 0,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: pe_offset as i32,
        }
    }

    /// Standard DOS stub program.
    pub const DOS_STUB: &'static [u8] = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21This program cannot be run in DOS mode.\r\r\n$";
}

/// COFF file header (20 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Data directory entry.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Optional header (PE32+, 64-bit).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    // Data directories follow (typically 16)
}

/// Optional header (PE32, 32-bit).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct OptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// Section header (40 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    /// Get the section name as a string (trimmed of null bytes).
    pub fn name_str(&self) -> &str {
        // SAFETY: name is always 8 bytes
        let name_slice = &self.name;
        let end = name_slice.iter().position(|&b| b == 0).unwrap_or(8);
        std::str::from_utf8(&name_slice[..end]).unwrap_or("")
    }

    /// Create a new section header with the given name.
    pub fn new(name: &str) -> Self {
        let mut header = Self {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        };
        let name_bytes = name.as_bytes();
        let len = name_bytes.len().min(8);
        header.name[..len].copy_from_slice(&name_bytes[..len]);
        header
    }
}

/// Parsed section information with computed offsets for output.
#[derive(Clone, Debug)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
    /// Computed offset in output file.
    pub new_pointer_to_raw_data: u32,
    /// Computed size in output file (aligned).
    pub new_size_of_raw_data: u32,
}

impl From<&SectionHeader> for SectionInfo {
    fn from(header: &SectionHeader) -> Self {
        Self {
            name: header.name_str().to_string(),
            virtual_size: header.virtual_size,
            virtual_address: header.virtual_address,
            size_of_raw_data: header.size_of_raw_data,
            pointer_to_raw_data: header.pointer_to_raw_data,
            characteristics: header.characteristics,
            new_pointer_to_raw_data: 0,
            new_size_of_raw_data: 0,
        }
    }
}

/// Parsed PE metadata from an in-memory module.
#[derive(Debug)]
pub struct PeParser {
    /// Base address of the module in memory.
    pub base: *const u8,
    /// Size of the module (from MODULEINFO.SizeOfImage).
    pub size: usize,
    /// Offset to PE signature (e_lfanew).
    pub pe_offset: u32,
    /// Machine type.
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Timestamp.
    pub time_date_stamp: u32,
    /// Size of optional header.
    pub size_of_optional_header: u16,
    /// File characteristics.
    pub characteristics: u16,
    /// Image base (runtime).
    pub image_base: u64,
    /// Section alignment.
    pub section_alignment: u32,
    /// File alignment.
    pub file_alignment: u32,
    /// Size of image.
    pub size_of_image: u32,
    /// Size of headers.
    pub size_of_headers: u32,
    /// Is this a 64-bit PE?
    pub is_64bit: bool,
    /// Raw optional header bytes (for copying to output).
    pub optional_header_raw: Vec<u8>,
    /// Parsed section information.
    pub sections: Vec<SectionInfo>,
}

impl PeParser {
    /// Parse PE headers from a memory-mapped module.
    ///
    /// # Safety
    /// The caller must ensure that `base` points to valid memory of at least `size` bytes
    /// containing a valid PE image.
    pub unsafe fn parse(base: *const u8, size: usize) -> Result<Self> {
        if size < std::mem::size_of::<DosHeader>() {
            return Err(Error::HeadersTooSmall {
                expected: std::mem::size_of::<DosHeader>(),
                actual: size,
            });
        }

        // Read DOS header
        let dos_header = &*(base as *const DosHeader);
        if dos_header.e_magic != DOS_MAGIC {
            return Err(Error::InvalidDosSignature(0));
        }

        let pe_offset = dos_header.e_lfanew as u32;
        let pe_header_start = pe_offset as usize;

        // Validate we have enough space for PE signature + file header
        let min_pe_size = pe_header_start + 4 + std::mem::size_of::<FileHeader>();
        if size < min_pe_size {
            return Err(Error::HeadersTooSmall {
                expected: min_pe_size,
                actual: size,
            });
        }

        // Read PE signature
        let pe_sig = *(base.add(pe_header_start) as *const u32);
        if pe_sig != PE_SIGNATURE {
            return Err(Error::InvalidPeSignature(pe_header_start));
        }

        // Read file header
        let file_header = &*(base.add(pe_header_start + 4) as *const FileHeader);
        let machine = file_header.machine;
        let is_64bit = machine == MACHINE_AMD64;

        if machine != MACHINE_AMD64 && machine != MACHINE_I386 {
            return Err(Error::UnsupportedMachine(machine));
        }

        let opt_header_start = pe_header_start + 4 + std::mem::size_of::<FileHeader>();
        let size_of_optional_header = file_header.size_of_optional_header;

        // Parse optional header for key fields
        let (image_base, section_alignment, file_alignment, size_of_image, size_of_headers) =
            if is_64bit {
                let opt = &*(base.add(opt_header_start) as *const OptionalHeader64);
                (
                    opt.image_base,
                    opt.section_alignment,
                    opt.file_alignment,
                    opt.size_of_image,
                    opt.size_of_headers,
                )
            } else {
                let opt = &*(base.add(opt_header_start) as *const OptionalHeader32);
                (
                    opt.image_base as u64,
                    opt.section_alignment,
                    opt.file_alignment,
                    opt.size_of_image,
                    opt.size_of_headers,
                )
            };

        // Copy raw optional header
        let optional_header_raw = std::slice::from_raw_parts(
            base.add(opt_header_start),
            size_of_optional_header as usize,
        )
        .to_vec();

        // Parse section headers
        let section_header_start = opt_header_start + size_of_optional_header as usize;
        let number_of_sections = file_header.number_of_sections;

        let mut sections = Vec::with_capacity(number_of_sections as usize);
        for i in 0..number_of_sections as usize {
            let section_offset = section_header_start + i * std::mem::size_of::<SectionHeader>();
            let section_header = &*(base.add(section_offset) as *const SectionHeader);
            sections.push(SectionInfo::from(section_header));
        }

        Ok(Self {
            base,
            size,
            pe_offset,
            machine,
            number_of_sections,
            time_date_stamp: file_header.time_date_stamp,
            size_of_optional_header,
            characteristics: file_header.characteristics,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            is_64bit,
            optional_header_raw,
            sections,
        })
    }

    /// Align a value up to the given alignment.
    #[inline]
    pub fn align_up(value: usize, alignment: usize) -> usize {
        (value + alignment - 1) & !(alignment - 1)
    }

    /// Get the end address (VA) of the last section for computing new section placement.
    pub fn last_section_end(&self) -> u32 {
        self.sections
            .iter()
            .map(|s| {
                s.virtual_address
                    + s.virtual_size.max(s.size_of_raw_data)
            })
            .max()
            .unwrap_or(self.size_of_headers)
    }

    /// Compute the VA for a new section (aligned to section alignment).
    pub fn next_section_va(&self) -> u32 {
        Self::align_up(self.last_section_end() as usize, self.section_alignment as usize) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_header_size() {
        assert_eq!(std::mem::size_of::<DosHeader>(), 64);
    }

    #[test]
    fn test_file_header_size() {
        assert_eq!(std::mem::size_of::<FileHeader>(), 20);
    }

    #[test]
    fn test_section_header_size() {
        assert_eq!(std::mem::size_of::<SectionHeader>(), 40);
    }

    #[test]
    fn test_section_name() {
        let mut header = SectionHeader::new(".text");
        assert_eq!(header.name_str(), ".text");

        header = SectionHeader::new(".verylongname");
        assert_eq!(header.name_str(), ".verylon"); // Truncated to 8 chars
    }

    #[test]
    fn test_align_up() {
        assert_eq!(PeParser::align_up(0, 4096), 0);
        assert_eq!(PeParser::align_up(1, 4096), 4096);
        assert_eq!(PeParser::align_up(4096, 4096), 4096);
        assert_eq!(PeParser::align_up(4097, 4096), 8192);
    }
}
