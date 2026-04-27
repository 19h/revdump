//! Main PE dumper implementation.
//!
//! This module ties together all components to perform the full dump process:
//! 1. Parse the target module's PE headers
//! 2. Scan sections for heap pointers
//! 3. Create minimal vtable stubs
//! 4. Generate fixups
//! 5. Build and write the output PE

use crate::devirt::{self, DevirtConfig, DevirtStats};
use crate::error::{Error, Result};
use crate::fixup::{apply_fixups, generate_fixups, SectionMapping};
use crate::memory::is_memory_readable;
use crate::pe::{
    FileHeader, OptionalHeader32, OptionalHeader64, PeParser, SectionHeader, SectionInfo,
    HEAP_SECTION_CHARACTERISTICS, PE_SIGNATURE,
};
use crate::scanner::{PointerScanner, ScanResult};
use crate::stub::{StubConfig, StubGenerator, VtableFact};

use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[cfg(target_os = "windows")]
use windows::core::PCSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::HMODULE;
#[cfg(target_os = "windows")]
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
#[cfg(target_os = "windows")]
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::GetCurrentProcess;

/// Progress stage during dump operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressStage {
    Initializing,
    BuildingCache,
    ScanningSection,
    CreatingStubs,
    AssigningRvas,
    BuildingOutput,
    ApplyingFixups,
    Devirtualizing,
    WritingFile,
    Complete,
}

impl ProgressStage {
    /// Get a human-readable name for the stage.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Initializing => "Initializing",
            Self::BuildingCache => "Building memory cache",
            Self::ScanningSection => "Scanning sections",
            Self::CreatingStubs => "Creating vtable stubs",
            Self::AssigningRvas => "Assigning RVAs",
            Self::BuildingOutput => "Building output PE",
            Self::ApplyingFixups => "Applying fixups",
            Self::Devirtualizing => "Devirtualizing vcalls",
            Self::WritingFile => "Writing file",
            Self::Complete => "Complete",
        }
    }
}

/// Progress information during dump.
#[derive(Clone, Debug)]
pub struct ProgressInfo {
    /// Current stage.
    pub stage: ProgressStage,
    /// Current item being processed (e.g., section name).
    pub current_item: Option<String>,
    /// Current progress (item count or bytes).
    pub current: usize,
    /// Total items/bytes.
    pub total: usize,
    /// Stubs created so far.
    pub stubs_created: usize,
    /// Pointers found so far.
    pub pointers_found: usize,
    /// Bytes processed.
    pub bytes_processed: usize,
    /// Total bytes to process.
    pub total_bytes: usize,
}

impl Default for ProgressInfo {
    fn default() -> Self {
        Self {
            stage: ProgressStage::Initializing,
            current_item: None,
            current: 0,
            total: 0,
            stubs_created: 0,
            pointers_found: 0,
            bytes_processed: 0,
            total_bytes: 0,
        }
    }
}

/// Progress callback type.
pub type ProgressCallback = Box<dyn Fn(&ProgressInfo) + Send + Sync>;

/// Build an IDA-friendly metadata section that lists every flattened vtable fact.
pub fn build_revdmp_metadata(facts: &[VtableFact], image_base: u64) -> Vec<u8> {
    let mut text = String::new();
    let _ = writeln!(text, "REVDMP_VTABLE_FACTS v1");
    let _ = writeln!(
        text,
        "source_rva,heap_addr,stub_rva,vfptr_offset,vtable_rva,vtable_va"
    );

    for fact in facts {
        let source = fact
            .source_rva
            .map(|rva| format!("0x{rva:X}"))
            .unwrap_or_else(|| "heap".to_string());
        let _ = writeln!(
            text,
            "{},0x{:X},0x{:X},0x{:X},0x{:X},0x{:X}",
            source,
            fact.heap_addr,
            fact.stub_rva,
            fact.vfptr_offset,
            fact.vtable_rva,
            image_base + fact.vtable_rva as u64,
        );
    }

    text.into_bytes()
}

/// Build a COFF string table for output. If the original table is unavailable in
/// the loaded image, synthesize entries for `/N` long section-name references so
/// PE tooling does not reject the dump as having an empty string table.
fn build_output_coff_string_table(pe: &PeParser) -> Vec<u8> {
    if !pe.coff_symbol_table_raw.is_empty() {
        return pe.coff_symbol_table_raw.clone();
    }

    let slash_names: Vec<(usize, usize)> = pe
        .sections
        .iter()
        .enumerate()
        .filter_map(|(idx, section)| {
            section
                .name
                .strip_prefix('/')
                .and_then(|offset| offset.parse::<usize>().ok())
                .filter(|&offset| offset >= 4)
                .map(|offset| (idx + 1, offset))
        })
        .collect();

    if slash_names.is_empty() {
        return Vec::new();
    }

    let mut table = vec![0u8; 4];
    for (idx, offset) in slash_names {
        if table.len() < offset {
            table.resize(offset, 0);
        }
        let name = format!(".sec{idx:02}\0");
        let bytes = name.as_bytes();
        if table.len() < offset + bytes.len() {
            table.resize(offset + bytes.len(), 0);
        }
        table[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    let size = table.len() as u32;
    table[0..4].copy_from_slice(&size.to_le_bytes());
    table
}

/// Configuration for the dump operation.
pub struct DumpConfig {
    /// Minimum valid pointer value.
    pub min_ptr_value: u64,
    /// Maximum valid pointer value.
    pub max_ptr_value: u64,
    /// Maximum offset to probe for vfptrs (handles multiple inheritance).
    pub max_vfptr_probe: usize,
    /// Section indices to skip during scanning.
    pub skip_sections: Vec<usize>,
    /// Progress callback.
    pub progress_callback: Option<ProgressCallback>,
    /// Enable vcall devirtualization (rewrite indirect calls to direct calls).
    pub enable_devirt: bool,
    /// Devirtualization configuration.
    pub devirt_config: DevirtConfig,
    /// Maximum bytes to scan in each heap allocation for embedded heap pointers.
    pub max_heap_scan_size: usize,
    /// Maximum recursive heap-pointer scan depth.
    pub recursive_heap_scan_depth: usize,
}

impl std::fmt::Debug for DumpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DumpConfig")
            .field("min_ptr_value", &self.min_ptr_value)
            .field("max_ptr_value", &self.max_ptr_value)
            .field("max_vfptr_probe", &self.max_vfptr_probe)
            .field("skip_sections", &self.skip_sections)
            .field("progress_callback", &self.progress_callback.is_some())
            .field("enable_devirt", &self.enable_devirt)
            .field("devirt_config", &self.devirt_config)
            .field("max_heap_scan_size", &self.max_heap_scan_size)
            .field("recursive_heap_scan_depth", &self.recursive_heap_scan_depth)
            .finish()
    }
}

impl Default for DumpConfig {
    fn default() -> Self {
        Self {
            min_ptr_value: 0x10000,
            max_ptr_value: 0x7FFF_FFFF_FFFF,
            max_vfptr_probe: 256,
            skip_sections: Vec::new(),
            progress_callback: None,
            enable_devirt: false,
            devirt_config: DevirtConfig::default(),
            max_heap_scan_size: 0x1000,
            recursive_heap_scan_depth: 2,
        }
    }
}

impl DumpConfig {
    /// Create a config that skips the code section (.text, usually index 0).
    pub fn skip_code() -> Self {
        Self {
            skip_sections: vec![0],
            ..Default::default()
        }
    }

    /// Convert to stub config.
    fn to_stub_config(&self) -> StubConfig {
        StubConfig {
            min_ptr_value: self.min_ptr_value,
            max_ptr_value: self.max_ptr_value,
            max_vfptr_probe: self.max_vfptr_probe,
            max_heap_scan_size: self.max_heap_scan_size,
            recursive_heap_scan_depth: self.recursive_heap_scan_depth,
        }
    }
}

/// Main PE dumper.
pub struct Dumper {
    /// Module base address.
    base: *const u8,
    /// Module size.
    size: usize,
    /// Module name (for logging).
    module_name: String,
    /// Parsed PE.
    pe: Option<PeParser>,
}

impl Dumper {
    /// Create a dumper for a module by name.
    #[cfg(target_os = "windows")]
    pub fn from_module_name(name: &str) -> Result<Self> {
        let name_cstr = std::ffi::CString::new(name).unwrap();
        let hmodule = unsafe { GetModuleHandleA(PCSTR(name_cstr.as_ptr() as *const u8)) }?;

        if hmodule.is_invalid() {
            return Err(Error::ModuleNotFound(name.to_string()));
        }

        Self::from_hmodule(hmodule, name)
    }

    /// Create a dumper from an HMODULE.
    #[cfg(target_os = "windows")]
    pub fn from_hmodule(hmodule: HMODULE, name: &str) -> Result<Self> {
        let base = hmodule.0 as *const u8;
        let mut mod_info = MODULEINFO::default();

        unsafe {
            GetModuleInformation(
                GetCurrentProcess(),
                hmodule,
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )?;
        }

        Ok(Self {
            base,
            size: mod_info.SizeOfImage as usize,
            module_name: name.to_string(),
            pe: None,
        })
    }

    /// Create a dumper from raw address and size.
    pub fn from_raw(base: *const u8, size: usize, name: &str) -> Self {
        Self {
            base,
            size,
            module_name: name.to_string(),
            pe: None,
        }
    }

    /// Parse the PE headers.
    pub fn parse(&mut self) -> Result<&PeParser> {
        if self.pe.is_none() {
            let pe = unsafe { PeParser::parse(self.base, self.size)? };
            self.pe = Some(pe);
        }
        Ok(self.pe.as_ref().unwrap())
    }

    /// Dump the module with vtable stubs.
    pub fn dump_with_heap<P: AsRef<Path>>(
        &mut self,
        output_path: P,
        config: &DumpConfig,
    ) -> Result<()> {
        let mut progress = ProgressInfo::default();
        let report = |p: &ProgressInfo| {
            if let Some(ref cb) = config.progress_callback {
                cb(p);
            }
        };

        // Parse PE
        progress.stage = ProgressStage::Initializing;
        report(&progress);
        self.parse()?;
        let pe = self.pe.as_ref().unwrap();

        // Create stub generator
        progress.stage = ProgressStage::BuildingCache;
        report(&progress);
        let mut stub_generator = StubGenerator::new(self.base, self.size, config.to_stub_config())?;

        // Scan sections for heap pointers
        let heap_ptr_locs =
            self.scan_sections(pe, config, &stub_generator, &mut progress, &report)?;

        if heap_ptr_locs.is_empty() {
            // No heap pointers found, do standard dump
            return self.standard_dump(output_path, config);
        }

        // Create vtable stubs
        progress.stage = ProgressStage::CreatingStubs;
        progress.total = heap_ptr_locs.len();
        progress.current = 0;
        report(&progress);

        stub_generator.process_heap_pointers(&heap_ptr_locs);
        progress.stubs_created = stub_generator.stub_count();

        if stub_generator.stub_count() == 0 {
            return self.standard_dump(output_path, config);
        }

        // Assign RVAs
        progress.stage = ProgressStage::AssigningRvas;
        report(&progress);

        let heap_section_va = pe.next_section_va();
        let heap_section_size = stub_generator.assign_rvas(heap_section_va);
        let vtable_facts = stub_generator.vtable_facts(&heap_ptr_locs);
        let metadata_data = build_revdmp_metadata(&vtable_facts, pe.image_base);
        let metadata_section_va = PeParser::align_up(
            heap_section_va as usize + heap_section_size,
            pe.section_alignment as usize,
        ) as u32;

        // Build output PE
        progress.stage = ProgressStage::BuildingOutput;
        report(&progress);

        let (mut output, section_mappings) = self.build_output_pe(
            pe,
            &stub_generator,
            &heap_ptr_locs,
            heap_section_va,
            heap_section_size,
            metadata_section_va,
            &metadata_data,
        )?;

        // Devirtualize vcalls if enabled
        if config.enable_devirt {
            progress.stage = ProgressStage::Devirtualizing;
            report(&progress);

            let devirt_stats =
                self.apply_devirt(&mut output, pe, &vtable_facts, &section_mappings, config)?;

            eprintln!(
                "Devirt: {} vcalls found, {} resolved, {} patched",
                devirt_stats.vcalls_detected,
                devirt_stats.vcalls_resolved,
                devirt_stats.patches_applied,
            );
        }

        // Write to file
        progress.stage = ProgressStage::WritingFile;
        progress.total = output.len();
        report(&progress);

        self.write_output(output_path, &output)?;

        progress.stage = ProgressStage::Complete;
        progress.current = progress.total;
        report(&progress);

        Ok(())
    }

    /// Scan sections for heap pointers.
    fn scan_sections<F>(
        &self,
        pe: &PeParser,
        config: &DumpConfig,
        stub_generator: &StubGenerator,
        progress: &mut ProgressInfo,
        report: &F,
    ) -> Result<Vec<ScanResult>>
    where
        F: Fn(&ProgressInfo),
    {
        let mut results = Vec::with_capacity(100_000);
        let scanner_config = stub_generator.scanner_config();
        let scanner = PointerScanner::new(scanner_config);
        let cache = stub_generator.cache();

        // Calculate total bytes to scan
        let mut total_bytes = 0usize;
        let mut sections_to_scan = 0usize;

        for (idx, section) in pe.sections.iter().enumerate() {
            if config.skip_sections.contains(&idx) {
                continue;
            }
            total_bytes += section.virtual_size.min(0x2000_0000) as usize;
            sections_to_scan += 1;
        }

        progress.stage = ProgressStage::ScanningSection;
        progress.total = sections_to_scan;
        progress.total_bytes = total_bytes;
        progress.bytes_processed = 0;
        report(progress);

        const CHUNK_SIZE: usize = 0x40_0000; // 4MB chunks

        let mut section_idx = 0;
        for (idx, section) in pe.sections.iter().enumerate() {
            if config.skip_sections.contains(&idx) {
                continue;
            }

            progress.current_item = Some(section.name.clone());
            progress.current = section_idx;
            report(progress);

            let scan_size = (section.virtual_size as usize).min(0x2000_0000);
            let sec_addr = unsafe { self.base.add(section.virtual_address as usize) };

            let mut chunk_off = 0;
            while chunk_off < scan_size {
                let read_size = CHUNK_SIZE.min(scan_size - chunk_off);
                let chunk_ptr = unsafe { sec_addr.add(chunk_off) };

                if is_memory_readable(chunk_ptr, read_size) {
                    let buffer = unsafe { std::slice::from_raw_parts(chunk_ptr, read_size) };
                    let base_rva = section.virtual_address + chunk_off as u32;

                    let chunk_results = scanner.scan_buffer(buffer, base_rva, cache);
                    results.extend(chunk_results);
                }

                progress.bytes_processed += read_size;
                progress.pointers_found = results.len();

                // Report every 16MB
                if progress.bytes_processed % 0x100_0000 < CHUNK_SIZE {
                    report(progress);
                }

                chunk_off += CHUNK_SIZE;
            }

            section_idx += 1;
        }

        progress.current = sections_to_scan;
        progress.pointers_found = results.len();
        report(progress);

        Ok(results)
    }

    /// Build the output PE with heap section.
    /// Returns the output buffer and section mappings for devirt.
    fn build_output_pe(
        &self,
        pe: &PeParser,
        stub_generator: &StubGenerator,
        heap_ptr_locs: &[ScanResult],
        heap_section_va: u32,
        heap_section_size: usize,
        metadata_section_va: u32,
        metadata_data: &[u8],
    ) -> Result<(Vec<u8>, Vec<SectionMapping>)> {
        // Calculate sizes
        let num_sections = pe.sections.len() + 2; // +.heap and .revdmp
        let headers_size = pe.pe_offset as usize
            + 4  // PE signature
            + std::mem::size_of::<FileHeader>()
            + pe.size_of_optional_header as usize
            + num_sections * std::mem::size_of::<SectionHeader>();
        let aligned_headers = PeParser::align_up(headers_size, pe.file_alignment as usize);

        // Dump original sections and compute their new offsets
        let mut section_data: Vec<Vec<u8>> = Vec::with_capacity(pe.sections.len());
        let mut sections_info: Vec<SectionInfo> = pe.sections.clone();
        let mut current_raw_offset = aligned_headers;

        for (i, section) in sections_info.iter_mut().enumerate() {
            let data = self.dump_section(&pe.sections[i]);
            let raw_size = PeParser::align_up(data.len(), pe.file_alignment as usize);

            section.new_pointer_to_raw_data = if data.is_empty() {
                0
            } else {
                current_raw_offset as u32
            };
            section.new_size_of_raw_data = raw_size as u32;

            if !data.is_empty() {
                let mut padded = data;
                padded.resize(raw_size, 0);
                section_data.push(padded);
                current_raw_offset += raw_size;
            } else {
                section_data.push(Vec::new());
            }
        }

        // Build heap section data (minimal stubs)
        let heap_data =
            stub_generator.build_section_data(heap_section_size, pe.file_alignment, pe.image_base);
        let heap_raw_size = PeParser::align_up(heap_data.len(), pe.file_alignment as usize);
        let heap_raw_offset = current_raw_offset as u32;
        current_raw_offset += heap_raw_size;

        // Build metadata section data for IDA/Ghidra sidecar consumers.
        let metadata_raw_size = PeParser::align_up(metadata_data.len(), pe.file_alignment as usize);
        let metadata_raw_offset = current_raw_offset as u32;
        current_raw_offset += metadata_raw_size;

        let coff_symbol_table_raw = build_output_coff_string_table(pe);
        let coff_symbol_table_offset = if coff_symbol_table_raw.is_empty() {
            0
        } else {
            current_raw_offset as u32
        };
        current_raw_offset += coff_symbol_table_raw.len();

        // Calculate total output size
        let total_size = current_raw_offset;
        let mut output = vec![0u8; total_size];

        // Copy entire original DOS header area (includes DOS header, stub, and Rich header)
        // This preserves all metadata up to the PE signature
        let dos_area_size = pe.pe_offset as usize;
        unsafe {
            std::ptr::copy_nonoverlapping(self.base, output.as_mut_ptr(), dos_area_size);
        }

        // Write PE signature
        let mut pos = pe.pe_offset as usize;
        output[pos..pos + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        pos += 4;

        // Write file header
        let file_header = FileHeader {
            machine: pe.machine,
            number_of_sections: num_sections as u16,
            time_date_stamp: pe.time_date_stamp,
            pointer_to_symbol_table: coff_symbol_table_offset,
            number_of_symbols: if coff_symbol_table_raw.is_empty() {
                0
            } else {
                pe.number_of_symbols
            },
            size_of_optional_header: pe.size_of_optional_header,
            characteristics: pe.characteristics,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &file_header as *const _ as *const u8,
                output.as_mut_ptr().add(pos),
                std::mem::size_of::<FileHeader>(),
            );
        }
        pos += std::mem::size_of::<FileHeader>();

        // Write optional header (copy original and update sizes)
        let new_size_of_image = PeParser::align_up(
            (metadata_section_va + metadata_data.len() as u32) as usize,
            pe.section_alignment as usize,
        ) as u32;

        output[pos..pos + pe.optional_header_raw.len()].copy_from_slice(&pe.optional_header_raw);

        // Update SizeOfImage and SizeOfHeaders in optional header
        if pe.is_64bit {
            let opt = unsafe { &mut *(output.as_mut_ptr().add(pos) as *mut OptionalHeader64) };
            opt.size_of_image = new_size_of_image;
            opt.size_of_headers = aligned_headers as u32;
        } else {
            let opt = unsafe { &mut *(output.as_mut_ptr().add(pos) as *mut OptionalHeader32) };
            opt.size_of_image = new_size_of_image;
            opt.size_of_headers = aligned_headers as u32;
        }
        pos += pe.size_of_optional_header as usize;

        // Write section headers
        for section in sections_info.iter() {
            let header = SectionHeader {
                name: {
                    let mut name = [0u8; 8];
                    let bytes = section.name.as_bytes();
                    let len = bytes.len().min(8);
                    name[..len].copy_from_slice(&bytes[..len]);
                    name
                },
                virtual_size: section.virtual_size,
                virtual_address: section.virtual_address,
                size_of_raw_data: section.new_size_of_raw_data,
                pointer_to_raw_data: section.new_pointer_to_raw_data,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: section.characteristics,
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &header as *const _ as *const u8,
                    output.as_mut_ptr().add(pos),
                    std::mem::size_of::<SectionHeader>(),
                );
            }
            pos += std::mem::size_of::<SectionHeader>();
        }

        // Write .heap section header
        let heap_header = SectionHeader {
            name: *b".heap\0\0\0",
            virtual_size: heap_section_size as u32,
            virtual_address: heap_section_va,
            size_of_raw_data: heap_raw_size as u32,
            pointer_to_raw_data: heap_raw_offset,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: HEAP_SECTION_CHARACTERISTICS,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &heap_header as *const _ as *const u8,
                output.as_mut_ptr().add(pos),
                std::mem::size_of::<SectionHeader>(),
            );
        }
        pos += std::mem::size_of::<SectionHeader>();

        // Write .revdmp metadata section header
        let metadata_header = SectionHeader {
            name: *b".revdmp\0",
            virtual_size: metadata_data.len() as u32,
            virtual_address: metadata_section_va,
            size_of_raw_data: metadata_raw_size as u32,
            pointer_to_raw_data: metadata_raw_offset,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: HEAP_SECTION_CHARACTERISTICS,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &metadata_header as *const _ as *const u8,
                output.as_mut_ptr().add(pos),
                std::mem::size_of::<SectionHeader>(),
            );
        }

        // Write section data
        for (i, section) in sections_info.iter().enumerate() {
            if section.new_pointer_to_raw_data > 0 && !section_data[i].is_empty() {
                let offset = section.new_pointer_to_raw_data as usize;
                output[offset..offset + section_data[i].len()].copy_from_slice(&section_data[i]);
            }
        }

        // Write heap section data (vtable stubs)
        {
            let offset = heap_raw_offset as usize;
            let mut padded_heap = heap_data;
            padded_heap.resize(heap_raw_size, 0);
            output[offset..offset + padded_heap.len()].copy_from_slice(&padded_heap);
        }

        // Write metadata section data.
        {
            let offset = metadata_raw_offset as usize;
            let mut padded_metadata = metadata_data.to_vec();
            padded_metadata.resize(metadata_raw_size, 0);
            output[offset..offset + padded_metadata.len()].copy_from_slice(&padded_metadata);
        }

        if !coff_symbol_table_raw.is_empty() {
            let offset = coff_symbol_table_offset as usize;
            output[offset..offset + coff_symbol_table_raw.len()]
                .copy_from_slice(&coff_symbol_table_raw);
        }

        // Generate and apply fixups
        let (fixups, _stats) = generate_fixups(heap_ptr_locs, stub_generator, pe.image_base);

        let section_mappings: Vec<SectionMapping> = sections_info
            .iter()
            .map(|s| {
                SectionMapping::new(
                    s.virtual_address,
                    s.virtual_size,
                    s.new_size_of_raw_data,
                    s.new_pointer_to_raw_data,
                )
            })
            .collect();

        let first_section_rva = sections_info
            .iter()
            .map(|s| s.virtual_address)
            .min()
            .unwrap_or(0);

        let (_applied, _skipped) = apply_fixups(
            &mut output,
            &fixups,
            &section_mappings,
            first_section_rva,
            aligned_headers,
        );

        Ok((output, section_mappings))
    }

    /// Dump a section's data from memory.
    fn dump_section(&self, section: &SectionInfo) -> Vec<u8> {
        let size = section.virtual_size.max(section.size_of_raw_data) as usize;
        if size == 0 {
            return Vec::new();
        }

        let mut result = vec![0u8; size];
        let sec_addr = unsafe { self.base.add(section.virtual_address as usize) };

        // Try to read the entire section at once first
        if is_memory_readable(sec_addr, size) {
            unsafe {
                std::ptr::copy_nonoverlapping(sec_addr, result.as_mut_ptr(), size);
            }
        } else {
            // Fallback: read page by page
            const PAGE_SIZE: usize = 0x1000;
            let mut off = 0;
            while off < size {
                let read_size = PAGE_SIZE.min(size - off);
                let src = unsafe { sec_addr.add(off) };

                if is_memory_readable(src, read_size) {
                    unsafe {
                        std::ptr::copy_nonoverlapping(src, result.as_mut_ptr().add(off), read_size);
                    }
                }
                off += PAGE_SIZE;
            }
        }

        result
    }

    /// Apply devirtualization to the output PE.
    fn apply_devirt(
        &self,
        output: &mut [u8],
        pe: &PeParser,
        vtable_facts: &[VtableFact],
        section_mappings: &[SectionMapping],
        config: &DumpConfig,
    ) -> Result<DevirtStats> {
        // Find .text section (or first code section)
        let text_section = pe
            .sections
            .iter()
            .find(|s| s.name == ".text" || (s.characteristics & 0x20) != 0) // IMAGE_SCN_CNT_CODE
            .ok_or_else(|| Error::SectionNotFound {
                name: ".text".to_string(),
            })?;

        // Calculate headers size for protection
        let num_sections = pe.sections.len() + 2; // +.heap and .revdmp
        let headers_size = pe.pe_offset as usize
            + 4  // PE signature
            + std::mem::size_of::<FileHeader>()
            + pe.size_of_optional_header as usize
            + num_sections * std::mem::size_of::<SectionHeader>();
        let aligned_headers = PeParser::align_up(headers_size, pe.file_alignment as usize);

        // Call devirtualization
        devirt::devirtualize(
            output,
            self.base,
            pe.image_base,
            text_section.virtual_address,
            text_section.virtual_size,
            vtable_facts,
            &section_mappings,
            aligned_headers,
            &config.devirt_config,
        )
    }

    /// Standard dump without heap snapshot.
    pub fn standard_dump<P: AsRef<Path>>(
        &mut self,
        output_path: P,
        _config: &DumpConfig,
    ) -> Result<()> {
        self.parse()?;
        let pe = self.pe.as_ref().unwrap();

        // Calculate sizes
        let headers_size = pe.pe_offset as usize
            + 4
            + std::mem::size_of::<FileHeader>()
            + pe.size_of_optional_header as usize
            + pe.sections.len() * std::mem::size_of::<SectionHeader>();
        let aligned_headers = PeParser::align_up(headers_size, pe.file_alignment as usize);

        // Dump sections
        let mut section_data: Vec<Vec<u8>> = Vec::with_capacity(pe.sections.len());
        let mut sections_info: Vec<SectionInfo> = pe.sections.clone();
        let mut current_raw_offset = aligned_headers;

        for (i, section) in sections_info.iter_mut().enumerate() {
            let data = self.dump_section(&pe.sections[i]);
            let raw_size = PeParser::align_up(data.len(), pe.file_alignment as usize);

            section.new_pointer_to_raw_data = if data.is_empty() {
                0
            } else {
                current_raw_offset as u32
            };
            section.new_size_of_raw_data = raw_size as u32;

            if !data.is_empty() {
                let mut padded = data;
                padded.resize(raw_size, 0);
                section_data.push(padded);
                current_raw_offset += raw_size;
            } else {
                section_data.push(Vec::new());
            }
        }

        let coff_symbol_table_raw = build_output_coff_string_table(pe);
        let coff_symbol_table_offset = if coff_symbol_table_raw.is_empty() {
            0
        } else {
            current_raw_offset as u32
        };
        current_raw_offset += coff_symbol_table_raw.len();

        let total_size = current_raw_offset;
        let mut output = vec![0u8; total_size];

        // Copy entire original DOS header area (includes DOS header, stub, and Rich header)
        let dos_area_size = pe.pe_offset as usize;
        unsafe {
            std::ptr::copy_nonoverlapping(self.base, output.as_mut_ptr(), dos_area_size);
        }

        // PE signature
        let mut pos = pe.pe_offset as usize;
        output[pos..pos + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        pos += 4;

        // File header
        let file_header = FileHeader {
            machine: pe.machine,
            number_of_sections: pe.sections.len() as u16,
            time_date_stamp: pe.time_date_stamp,
            pointer_to_symbol_table: coff_symbol_table_offset,
            number_of_symbols: if coff_symbol_table_raw.is_empty() {
                0
            } else {
                pe.number_of_symbols
            },
            size_of_optional_header: pe.size_of_optional_header,
            characteristics: pe.characteristics,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &file_header as *const _ as *const u8,
                output.as_mut_ptr().add(pos),
                std::mem::size_of::<FileHeader>(),
            );
        }
        pos += std::mem::size_of::<FileHeader>();

        // Optional header
        output[pos..pos + pe.optional_header_raw.len()].copy_from_slice(&pe.optional_header_raw);
        pos += pe.size_of_optional_header as usize;

        // Section headers
        for section in &sections_info {
            let header = SectionHeader {
                name: {
                    let mut name = [0u8; 8];
                    let bytes = section.name.as_bytes();
                    let len = bytes.len().min(8);
                    name[..len].copy_from_slice(&bytes[..len]);
                    name
                },
                virtual_size: section.virtual_size,
                virtual_address: section.virtual_address,
                size_of_raw_data: section.new_size_of_raw_data,
                pointer_to_raw_data: section.new_pointer_to_raw_data,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: section.characteristics,
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &header as *const _ as *const u8,
                    output.as_mut_ptr().add(pos),
                    std::mem::size_of::<SectionHeader>(),
                );
            }
            pos += std::mem::size_of::<SectionHeader>();
        }

        // Section data
        for (i, section) in sections_info.iter().enumerate() {
            if section.new_pointer_to_raw_data > 0 && !section_data[i].is_empty() {
                let offset = section.new_pointer_to_raw_data as usize;
                output[offset..offset + section_data[i].len()].copy_from_slice(&section_data[i]);
            }
        }

        if !coff_symbol_table_raw.is_empty() {
            let offset = coff_symbol_table_offset as usize;
            output[offset..offset + coff_symbol_table_raw.len()]
                .copy_from_slice(&coff_symbol_table_raw);
        }

        self.write_output(output_path, &output)
    }

    /// Write output to file.
    fn write_output<P: AsRef<Path>>(&self, path: P, data: &[u8]) -> Result<()> {
        let mut file =
            File::create(path.as_ref()).map_err(|e| Error::OutputCreationFailed(e.to_string()))?;

        file.write_all(data)
            .map_err(|e| Error::OutputWriteFailed(e.to_string()))?;

        Ok(())
    }

    /// Get module name.
    pub fn module_name(&self) -> &str {
        &self.module_name
    }

    /// Get module base.
    pub fn base(&self) -> *const u8 {
        self.base
    }

    /// Get module size.
    pub fn size(&self) -> usize {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_config_default() {
        let config = DumpConfig::default();
        assert_eq!(config.max_vfptr_probe, 256);
        assert!(config.skip_sections.is_empty());
    }

    #[test]
    fn test_dump_config_skip_code() {
        let config = DumpConfig::skip_code();
        assert_eq!(config.skip_sections, vec![0]);
    }

    #[test]
    fn test_revdmp_metadata_lists_heap_only_and_sourced_facts() {
        let facts = vec![
            VtableFact {
                source_rva: Some(0x2000),
                heap_addr: 0x1000_0000,
                stub_rva: 0x8000,
                vfptr_offset: 0x20,
                vtable_rva: 0x5000,
            },
            VtableFact {
                source_rva: None,
                heap_addr: 0x2000_0000,
                stub_rva: 0x9000,
                vfptr_offset: 0,
                vtable_rva: 0x7000,
            },
        ];

        let metadata = build_revdmp_metadata(&facts, 0x1400_0000);
        let text = String::from_utf8(metadata).unwrap();
        assert!(text.contains("REVDMP_VTABLE_FACTS v1"));
        assert!(text.contains("0x2000,0x10000000,0x8000,0x20,0x5000,0x14005000"));
        assert!(text.contains("heap,0x20000000,0x9000,0x0,0x7000,0x14007000"));
    }

    #[test]
    fn test_synthesizes_coff_string_table_for_slash_section_names() {
        let pe = PeParser {
            base: std::ptr::null(),
            size: 0,
            pe_offset: 0,
            machine: 0x8664,
            number_of_sections: 2,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
            characteristics: 0,
            image_base: 0x1400_0000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: 0,
            size_of_headers: 0,
            is_64bit: true,
            optional_header_raw: Vec::new(),
            coff_symbol_table_raw: Vec::new(),
            sections: vec![
                SectionInfo {
                    name: "/4".to_string(),
                    virtual_size: 0,
                    virtual_address: 0,
                    size_of_raw_data: 0,
                    pointer_to_raw_data: 0,
                    characteristics: 0,
                    new_pointer_to_raw_data: 0,
                    new_size_of_raw_data: 0,
                },
                SectionInfo {
                    name: ".heap".to_string(),
                    virtual_size: 0,
                    virtual_address: 0,
                    size_of_raw_data: 0,
                    pointer_to_raw_data: 0,
                    characteristics: 0,
                    new_pointer_to_raw_data: 0,
                    new_size_of_raw_data: 0,
                },
            ],
        };

        let table = build_output_coff_string_table(&pe);
        assert_eq!(u32::from_le_bytes(table[0..4].try_into().unwrap()) as usize, table.len());
        assert!(table[4..].starts_with(b".sec01\0"));
    }

    #[test]
    fn test_progress_stage_names() {
        assert_eq!(ProgressStage::Initializing.name(), "Initializing");
        assert_eq!(ProgressStage::Complete.name(), "Complete");
    }
}
