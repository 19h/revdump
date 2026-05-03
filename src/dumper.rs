//! Main PE dumper implementation.
//!
//! This module ties together all components to perform the full dump process:
//! 1. Parse the target module's PE headers
//! 2. Scan sections for heap pointers
//! 3. Create minimal vtable stubs
//! 4. Generate fixups
//! 5. Build and write the output PE

use crate::devirt::{self, DevirtConfig, DevirtProgress, DevirtStats, IndirectCallFact, VcallKind};
use crate::error::{Error, Result};
use crate::fixup::{apply_fixups, generate_fixups, SectionMapping};
use crate::memory::{is_memory_readable, strip_pointer_tags};
use crate::pe::{
    FileHeader, OptionalHeader32, OptionalHeader64, PeParser, SectionHeader, SectionInfo,
    HEAP_SECTION_CHARACTERISTICS, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, PE_SIGNATURE,
};
use crate::scanner::{PointerScanner, ScanResult};
use crate::stub::{
    ContainerFact, EdgeConfidence, HeapPointerEdge, StubConfig, StubDebugProgress, StubGenerator,
    VtableFact,
};
use sha2::{Digest, Sha256};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::Write;
use std::ops::Range;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct EnrichedVtableFact {
    pub fact: VtableFact,
    pub type_name: Option<String>,
    msvc_rtti: Option<MsvcRttiFact>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MsvcBaseClassFact {
    type_name: String,
    type_descriptor_rva: u32,
    num_contained_bases: u32,
    mdisp: i32,
    pdisp: i32,
    vdisp: i32,
    attributes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MsvcRttiFact {
    vtable_rva: u32,
    col_rva: u32,
    object_offset: u32,
    constructor_displacement: u32,
    type_descriptor_rva: u32,
    type_name: String,
    hierarchy_rva: Option<u32>,
    hierarchy_attributes: u32,
    base_classes: Vec<MsvcBaseClassFact>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionPointerFact {
    location_rva: u32,
    location_va: u64,
    section_name: String,
    kind: &'static str,
    table_id: Option<String>,
    index: Option<usize>,
    target_rva: u32,
    target_va: u64,
    confidence: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionPointerTableFact {
    id: String,
    start_rva: u32,
    start_va: u64,
    section_name: String,
    entry_count: usize,
    target_rvas: Vec<u32>,
    confidence: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VtableSlotFact {
    vtable_rva: u32,
    type_name: Option<String>,
    slot_index: usize,
    slot_offset: u32,
    entry_rva: u32,
    entry_va: u64,
    normalized_target_rva: u32,
    normalized_target_va: u64,
    slot_kind: &'static str,
    target_kind: &'static str,
    function_symbol: String,
    confidence: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThunkNormalizationFact {
    thunk_rva: u32,
    thunk_va: u64,
    normalized_target_rva: u32,
    normalized_target_va: u64,
    thunk_kind: &'static str,
    instruction_len: usize,
    this_adjustment: Option<i32>,
    confidence: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CfgFunctionFact {
    table_rva: u32,
    entry_index: usize,
    entry_rva: u32,
    raw_entry: u32,
    target_rva: u32,
    target_va: u64,
    suppressed: bool,
    export_suppressed: bool,
    guard_flags: u32,
    confidence: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionFunctionFact {
    entry_rva: u32,
    begin_rva: u32,
    end_rva: u32,
    unwind_info_rva: u32,
    unwind_flags: u8,
    unwind_flag_names: String,
    prolog_size: u8,
    unwind_code_count: u8,
    frame_register: u8,
    frame_offset: u8,
    handler_rva: Option<u32>,
    handler_va: Option<u64>,
    chained_begin_rva: Option<u32>,
    chained_end_rva: Option<u32>,
    chained_unwind_info_rva: Option<u32>,
    confidence: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ThunkAnalysis {
    normalized_target_rva: u32,
    thunk_kind: &'static str,
    instruction_len: usize,
    this_adjustment: Option<i32>,
    reason: &'static str,
}

#[derive(Clone, Debug)]
struct RuntimeObjectFact {
    id: String,
    heap_addr: u64,
    stub_rva: u32,
    stub_va: u64,
    stub_size: usize,
    vfptr_offsets: Vec<u32>,
    vtable_rvas: Vec<u32>,
    type_names: Vec<String>,
    root_rvas: Vec<u32>,
    incoming_edges: usize,
    outgoing_edges: usize,
    container_owner_count: usize,
    container_element_count: usize,
    confidence: &'static str,
    provenance: &'static str,
}

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
    AnalyzingMetadata,
    BuildingMetadata,
    BuildingOutput,
    ProtectingExceptionData,
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
            Self::AnalyzingMetadata => "Analyzing .revdmp metadata",
            Self::BuildingMetadata => "Building .revdmp metadata",
            Self::BuildingOutput => "Building output PE",
            Self::ProtectingExceptionData => "Protecting exception data",
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
    /// Detailed heap-stub progress for heap processing stages.
    pub stub_debug: Option<StubDebugProgress>,
    /// Detailed devirtualization progress for vcall scanning and patching.
    pub devirt_progress: Option<DevirtProgress>,
    /// Detailed progress for exception/unwind protection.
    pub eh_progress: Option<EhProtectionProgress>,
    /// Heap pointer fixups applied so far.
    pub fixups_applied: usize,
    /// Heap pointer fixups skipped so far.
    pub fixups_skipped: usize,
    /// Heap pointer fixups skipped because they overlap protected EH metadata.
    pub protected_fixups_skipped: usize,
}

/// Progress snapshot emitted while building EH protection ranges.
#[derive(Clone, Copy, Debug, Default)]
pub struct EhProtectionProgress {
    pub current: usize,
    pub total: usize,
    pub protected_ranges: usize,
    pub protected_bytes: usize,
    pub unwind_infos: usize,
    pub phase: &'static str,
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
            stub_debug: None,
            devirt_progress: None,
            eh_progress: None,
            fixups_applied: 0,
            fixups_skipped: 0,
            protected_fixups_skipped: 0,
        }
    }
}

/// Progress callback type.
pub type ProgressCallback = Box<dyn Fn(&ProgressInfo) + Send + Sync>;

fn runtime_object_id(stub_rva: u32) -> String {
    format!("obj_{stub_rva:08X}")
}

fn object_id_map(stub_generator: &StubGenerator) -> BTreeMap<u64, String> {
    stub_generator
        .stubs()
        .map(|stub| (stub.original_addr, runtime_object_id(stub.new_rva)))
        .collect()
}

fn should_scan_for_heap_pointers(section: &SectionInfo) -> bool {
    (section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0
}

fn range_overlaps(range: &Range<u32>, other: &Range<u32>) -> bool {
    range.start < other.end && range.end > other.start
}

fn merge_rva_ranges(mut ranges: Vec<Range<u32>>) -> Vec<Range<u32>> {
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<Range<u32>> = Vec::new();
    for range in ranges {
        if range.start >= range.end {
            continue;
        }
        if let Some(last) = merged.last_mut().filter(|last| range.start <= last.end) {
            last.end = last.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}

fn section_rva_end(section: &SectionInfo) -> u32 {
    section
        .virtual_address
        .saturating_add(section.virtual_size.max(section.size_of_raw_data))
}

fn rva_section(sections: &[SectionInfo], rva: u32) -> Option<&SectionInfo> {
    sections
        .iter()
        .find(|section| rva >= section.virtual_address && rva < section_rva_end(section))
}

fn unwind_info_size(pe: &PeParser, unwind_rva: u32) -> Option<u32> {
    let header = read_bytes_at_rva(pe, unwind_rva, 4)?;
    let flags = header[0] >> 3;
    let code_count = header[2] as u32;
    let aligned_code_count = (code_count + 1) & !1;
    let mut size = 4u32.checked_add(aligned_code_count.checked_mul(2)?)?;
    if (flags & 0x3) != 0 {
        size = size.checked_add(4)?;
    } else if (flags & 0x4) != 0 {
        size = size.checked_add(12)?;
    }
    Some(size)
}

fn protected_exception_ranges_with_progress<F>(pe: &PeParser, mut progress: F) -> Vec<Range<u32>>
where
    F: FnMut(EhProtectionProgress),
{
    protected_exception_ranges_inner(pe, Some(&mut progress))
}

fn emit_eh_progress(
    progress: &mut Option<&mut dyn FnMut(EhProtectionProgress)>,
    snapshot: EhProtectionProgress,
) {
    if let Some(progress) = progress.as_mut() {
        (*progress)(snapshot);
    }
}

fn protected_exception_ranges_inner(
    pe: &PeParser,
    mut progress: Option<&mut dyn FnMut(EhProtectionProgress)>,
) -> Vec<Range<u32>> {
    let Some((exception_rva, exception_size)) =
        pe_data_directory(pe, IMAGE_DIRECTORY_ENTRY_EXCEPTION)
    else {
        return Vec::new();
    };
    if exception_size < 12 {
        return std::iter::once(exception_rva..exception_rva.saturating_add(exception_size))
            .collect();
    }

    let mut ranges: Vec<Range<u32>> =
        std::iter::once(exception_rva..exception_rva.saturating_add(exception_size)).collect();
    let entry_count = exception_size / 12;
    let mut unwind_rvas = Vec::new();
    emit_eh_progress(
        &mut progress,
        EhProtectionProgress {
            current: 0,
            total: entry_count as usize,
            protected_ranges: ranges.len(),
            protected_bytes: exception_size as usize,
            unwind_infos: 0,
            phase: "reading .pdata",
        },
    );
    for idx in 0..entry_count {
        let entry_rva = exception_rva.saturating_add(idx.saturating_mul(12));
        if let Some(unwind_rva) = read_u32_at_rva(pe, entry_rva + 8) {
            if rva_in_image(pe, unwind_rva, 4) {
                unwind_rvas.push(unwind_rva);
            }
        }
        if idx % 65_536 == 0 && idx != 0 {
            emit_eh_progress(
                &mut progress,
                EhProtectionProgress {
                    current: idx as usize,
                    total: entry_count as usize,
                    protected_ranges: ranges.len(),
                    protected_bytes: exception_size as usize,
                    unwind_infos: unwind_rvas.len(),
                    phase: "reading .pdata",
                },
            );
        }
    }
    unwind_rvas.sort_unstable();
    unwind_rvas.dedup();
    emit_eh_progress(
        &mut progress,
        EhProtectionProgress {
            current: entry_count as usize,
            total: entry_count as usize,
            protected_ranges: ranges.len(),
            protected_bytes: exception_size as usize,
            unwind_infos: unwind_rvas.len(),
            phase: "reading .pdata",
        },
    );

    for (idx, &unwind_rva) in unwind_rvas.iter().enumerate() {
        let Some(section) = rva_section(&pe.sections, unwind_rva) else {
            continue;
        };
        let min_end = unwind_info_size(pe, unwind_rva)
            .and_then(|size| unwind_rva.checked_add(size))
            .unwrap_or_else(|| unwind_rva.saturating_add(4));
        let next_end = unwind_rvas
            .get(idx + 1)
            .copied()
            .filter(|next| {
                rva_section(&pe.sections, *next).is_some_and(|next_section| {
                    next_section.virtual_address == section.virtual_address
                })
            })
            .filter(|next| next.saturating_sub(unwind_rva) <= 0x400);
        let end = next_end
            .unwrap_or(min_end)
            .max(min_end)
            .min(section_rva_end(section));
        ranges.push(unwind_rva..end);
        if idx % 65_536 == 0 && idx != 0 {
            emit_eh_progress(
                &mut progress,
                EhProtectionProgress {
                    current: idx,
                    total: unwind_rvas.len(),
                    protected_ranges: ranges.len(),
                    protected_bytes: ranges
                        .iter()
                        .map(|range| (range.end - range.start) as usize)
                        .sum(),
                    unwind_infos: unwind_rvas.len(),
                    phase: "protecting unwind info",
                },
            );
        }
    }

    let ranges = merge_rva_ranges(ranges);
    emit_eh_progress(
        &mut progress,
        EhProtectionProgress {
            current: unwind_rvas.len(),
            total: unwind_rvas.len(),
            protected_ranges: ranges.len(),
            protected_bytes: ranges
                .iter()
                .map(|range| (range.end - range.start) as usize)
                .sum(),
            unwind_infos: unwind_rvas.len(),
            phase: "complete",
        },
    );
    ranges
}

fn unprotected_section_ranges(
    section: &SectionInfo,
    protected_ranges: &[Range<u32>],
) -> Vec<Range<u32>> {
    let section_range = section.virtual_address..section_rva_end(section);
    let mut ranges = vec![section_range.clone()];
    for protected in protected_ranges
        .iter()
        .filter(|protected| range_overlaps(&section_range, protected))
    {
        let mut next_ranges = Vec::new();
        for range in ranges {
            if !range_overlaps(&range, protected) {
                next_ranges.push(range);
                continue;
            }
            if range.start < protected.start {
                next_ranges.push(range.start..protected.start);
            }
            if protected.end < range.end {
                next_ranges.push(protected.end..range.end);
            }
        }
        ranges = next_ranges;
    }
    ranges
}

fn output_file_range_for_rva(
    section_mappings: &[SectionMapping],
    rva: u32,
    size: usize,
) -> Option<std::ops::Range<usize>> {
    let end_rva = rva.checked_add(size.try_into().ok()?)?;
    let section = section_mappings.iter().find(|section| {
        let section_end = section
            .virtual_address
            .saturating_add(section.virtual_size.max(section.raw_size));
        rva >= section.virtual_address && end_rva <= section_end
    })?;
    if section.raw_offset == 0 {
        return None;
    }
    let start = section
        .raw_offset
        .checked_add(rva.checked_sub(section.virtual_address)?)? as usize;
    Some(start..start.checked_add(size)?)
}

fn exception_directory_file_range(
    pe: &PeParser,
    section_mappings: &[SectionMapping],
) -> Option<std::ops::Range<usize>> {
    let (rva, size) = pe_data_directory(pe, IMAGE_DIRECTORY_ENTRY_EXCEPTION)?;
    output_file_range_for_rva(section_mappings, rva, size as usize)
}

fn join_hex_u32(values: &[u32]) -> String {
    values
        .iter()
        .map(|value| format!("0x{value:X}"))
        .collect::<Vec<_>>()
        .join(";")
}

fn collect_type_names_by_heap(facts: &[EnrichedVtableFact]) -> BTreeMap<u64, BTreeSet<String>> {
    let mut type_names = BTreeMap::new();
    for enriched in facts {
        if let Some(type_name) = enriched
            .type_name
            .as_deref()
            .filter(|name| !name.is_empty())
        {
            type_names
                .entry(enriched.fact.heap_addr)
                .or_insert_with(BTreeSet::new)
                .insert(type_name.to_string());
        }
    }
    type_names
}

fn join_type_names(type_names: Option<&BTreeSet<String>>) -> String {
    type_names
        .map(|names| names.iter().cloned().collect::<Vec<_>>().join(";"))
        .unwrap_or_default()
}

fn build_runtime_objects(
    facts: &[EnrichedVtableFact],
    heap_ptr_locs: &[(u32, u64)],
    heap_edges: &[HeapPointerEdge],
    containers: &[ContainerFact],
    image_base: u64,
    stub_generator: &StubGenerator,
) -> Vec<RuntimeObjectFact> {
    let type_names_by_heap = collect_type_names_by_heap(facts);
    let mut roots_by_heap: BTreeMap<u64, BTreeSet<u32>> = BTreeMap::new();
    let mut incoming_by_heap: BTreeMap<u64, usize> = BTreeMap::new();
    let mut outgoing_by_heap: BTreeMap<u64, usize> = BTreeMap::new();
    let mut container_owner_by_heap: BTreeMap<u64, usize> = BTreeMap::new();
    let mut container_element_by_heap: BTreeMap<u64, usize> = BTreeMap::new();

    for &(source_rva, heap_addr) in heap_ptr_locs {
        roots_by_heap
            .entry(strip_pointer_tags(heap_addr))
            .or_default()
            .insert(source_rva);
    }

    for edge in heap_edges {
        *outgoing_by_heap.entry(edge.source_heap_addr).or_default() += 1;
        *incoming_by_heap.entry(edge.target_heap_addr).or_default() += 1;
    }

    for container in containers {
        *container_owner_by_heap
            .entry(container.source_heap_addr)
            .or_default() += 1;
        for &target in &container.targets {
            *container_element_by_heap.entry(target).or_default() += 1;
        }
    }

    let mut stubs = stub_generator.stubs().collect::<Vec<_>>();
    stubs.sort_by_key(|stub| (stub.new_rva, stub.original_addr));

    stubs
        .into_iter()
        .map(|stub| {
            let root_rvas = roots_by_heap
                .get(&stub.original_addr)
                .map(|roots| roots.iter().copied().collect::<Vec<_>>())
                .unwrap_or_default();
            let type_names = type_names_by_heap
                .get(&stub.original_addr)
                .map(|names| names.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let vfptr_offsets = stub
                .vtable_refs
                .iter()
                .map(|r| r.offset as u32)
                .collect::<Vec<_>>();
            let vtable_rvas = stub
                .vtable_refs
                .iter()
                .map(|r| r.vtable_rva)
                .collect::<Vec<_>>();
            let confidence = if !type_names.is_empty() {
                "rtti_confirmed"
            } else if !root_rvas.is_empty() {
                "global_rooted"
            } else {
                "heap_reachable"
            };
            let provenance = if !root_rvas.is_empty() {
                "module_pointer_scan"
            } else {
                "recursive_heap_scan"
            };

            RuntimeObjectFact {
                id: runtime_object_id(stub.new_rva),
                heap_addr: stub.original_addr,
                stub_rva: stub.new_rva,
                stub_va: image_base + stub.new_rva as u64,
                stub_size: stub.size,
                vfptr_offsets,
                vtable_rvas,
                type_names,
                root_rvas,
                incoming_edges: incoming_by_heap
                    .get(&stub.original_addr)
                    .copied()
                    .unwrap_or_default(),
                outgoing_edges: outgoing_by_heap
                    .get(&stub.original_addr)
                    .copied()
                    .unwrap_or_default(),
                container_owner_count: container_owner_by_heap
                    .get(&stub.original_addr)
                    .copied()
                    .unwrap_or_default(),
                container_element_count: container_element_by_heap
                    .get(&stub.original_addr)
                    .copied()
                    .unwrap_or_default(),
                confidence,
                provenance,
            }
        })
        .collect()
}

fn executable_ranges(pe: &PeParser) -> Vec<(u32, u32)> {
    pe.sections
        .iter()
        .filter(|section| {
            (section.characteristics & IMAGE_SCN_CNT_CODE) != 0
                || (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
        })
        .map(|section| {
            (
                section.virtual_address,
                section.virtual_size.max(section.size_of_raw_data),
            )
        })
        .collect()
}

fn rva_in_ranges(rva: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|&(start, size)| {
        let end = start.saturating_add(size);
        rva >= start && rva < end
    })
}

fn analyze_function_pointer_tables(
    pe: &PeParser,
) -> (Vec<FunctionPointerFact>, Vec<FunctionPointerTableFact>) {
    let code_ranges = executable_ranges(pe);
    if code_ranges.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut pointers = Vec::new();
    let mut tables = Vec::new();

    for section in &pe.sections {
        if (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            || (section.characteristics & IMAGE_SCN_CNT_CODE) != 0
        {
            continue;
        }
        let scan_size = section.virtual_size.max(section.size_of_raw_data);
        if scan_size < 8 || !rva_in_image(pe, section.virtual_address, scan_size as usize) {
            continue;
        }

        let section_ptr = unsafe { pe.base.add(section.virtual_address as usize) };
        #[cfg(not(test))]
        if !is_memory_readable(section_ptr, scan_size as usize) {
            continue;
        }
        let bytes = unsafe { std::slice::from_raw_parts(section_ptr, scan_size as usize) };
        let mut entries = Vec::new();
        for (idx, chunk) in bytes.chunks_exact(8).enumerate() {
            let raw = u64::from_le_bytes(chunk.try_into().unwrap());
            let Some(target_rva) = ptr_to_rva(pe, raw) else {
                continue;
            };
            if !rva_in_ranges(target_rva, &code_ranges) {
                continue;
            }
            entries.push((section.virtual_address + (idx * 8) as u32, target_rva));
        }

        let mut run_start = 0usize;
        while run_start < entries.len() {
            let mut run_end = run_start + 1;
            while run_end < entries.len() && entries[run_end].0 == entries[run_end - 1].0 + 8 {
                run_end += 1;
            }

            let run = &entries[run_start..run_end];
            if run.len() >= 2 {
                let table_id = format!("fptable_{:08X}", run[0].0);
                tables.push(FunctionPointerTableFact {
                    id: table_id.clone(),
                    start_rva: run[0].0,
                    start_va: pe.image_base + run[0].0 as u64,
                    section_name: section.name.clone(),
                    entry_count: run.len(),
                    target_rvas: run.iter().map(|(_, target_rva)| *target_rva).collect(),
                    confidence: "high",
                    reason: "contiguous_code_pointer_run",
                });
                for (idx, &(location_rva, target_rva)) in run.iter().enumerate() {
                    pointers.push(FunctionPointerFact {
                        location_rva,
                        location_va: pe.image_base + location_rva as u64,
                        section_name: section.name.clone(),
                        kind: "table_entry",
                        table_id: Some(table_id.clone()),
                        index: Some(idx),
                        target_rva,
                        target_va: pe.image_base + target_rva as u64,
                        confidence: "high",
                        reason: "contiguous_code_pointer_run",
                    });
                }
            } else {
                let (location_rva, target_rva) = run[0];
                pointers.push(FunctionPointerFact {
                    location_rva,
                    location_va: pe.image_base + location_rva as u64,
                    section_name: section.name.clone(),
                    kind: "callback_slot",
                    table_id: None,
                    index: None,
                    target_rva,
                    target_va: pe.image_base + target_rva as u64,
                    confidence: "medium",
                    reason: "isolated_code_pointer",
                });
            }

            run_start = run_end;
        }
    }

    pointers.sort_by_key(|pointer| pointer.location_rva);
    tables.sort_by_key(|table| table.start_rva);
    (pointers, tables)
}

const MAX_VTABLE_SLOTS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
struct DecodedThunkJump {
    target_rva: u32,
    instruction_len: usize,
    jump_kind: &'static str,
    reason: &'static str,
}

fn read_pointer_at_rva(pe: &PeParser, rva: u32) -> Option<u64> {
    if pe.is_64bit {
        read_u64_at_rva(pe, rva)
    } else {
        read_u32_at_rva(pe, rva).map(u64::from)
    }
}

fn relative_target_rva(instr_rva: u32, instr_len: usize, rel: i64) -> Option<u32> {
    let target = instr_rva as i64 + instr_len as i64 + rel;
    (0..=u32::MAX as i64)
        .contains(&target)
        .then_some(target as u32)
}

fn decode_simple_thunk_jump(
    pe: &PeParser,
    instr_rva: u32,
    bytes: &[u8],
    code_ranges: &[(u32, u32)],
) -> Option<DecodedThunkJump> {
    if bytes.len() >= 5 && bytes[0] == 0xE9 {
        let rel = i32::from_le_bytes(bytes[1..5].try_into().ok()?) as i64;
        let target_rva = relative_target_rva(instr_rva, 5, rel)?;
        if rva_in_ranges(target_rva, code_ranges) {
            return Some(DecodedThunkJump {
                target_rva,
                instruction_len: 5,
                jump_kind: "relative_jmp",
                reason: "direct_relative_jump_thunk",
            });
        }
    }

    if bytes.len() >= 2 && bytes[0] == 0xEB {
        let rel = bytes[1] as i8 as i64;
        let target_rva = relative_target_rva(instr_rva, 2, rel)?;
        if rva_in_ranges(target_rva, code_ranges) {
            return Some(DecodedThunkJump {
                target_rva,
                instruction_len: 2,
                jump_kind: "short_jmp",
                reason: "short_relative_jump_thunk",
            });
        }
    }

    let prefix_len = bytes
        .first()
        .filter(|&&byte| (0x40..=0x4F).contains(&byte))
        .map(|_| 1usize)
        .unwrap_or_default();
    if bytes.len() >= prefix_len + 6 && bytes[prefix_len] == 0xFF && bytes[prefix_len + 1] == 0x25 {
        let disp =
            i32::from_le_bytes(bytes[prefix_len + 2..prefix_len + 6].try_into().ok()?) as i64;
        let instruction_len = prefix_len + 6;
        let slot_rva = relative_target_rva(instr_rva, instruction_len, disp)?;
        let target_ptr = read_pointer_at_rva(pe, slot_rva)?;
        let target_rva = ptr_to_rva(pe, target_ptr)?;
        if rva_in_ranges(target_rva, code_ranges) {
            return Some(DecodedThunkJump {
                target_rva,
                instruction_len,
                jump_kind: "rip_indirect_jmp",
                reason: "rip_indirect_jump_thunk",
            });
        }
    }

    if bytes.len() >= 12
        && bytes[0] == 0x48
        && bytes[1] == 0xB8
        && bytes[10] == 0xFF
        && bytes[11] == 0xE0
    {
        let target_ptr = u64::from_le_bytes(bytes[2..10].try_into().ok()?);
        let target_rva = ptr_to_rva(pe, target_ptr)?;
        if rva_in_ranges(target_rva, code_ranges) {
            return Some(DecodedThunkJump {
                target_rva,
                instruction_len: 12,
                jump_kind: "mov_rax_jmp",
                reason: "absolute_jump_thunk",
            });
        }
    }

    None
}

fn decode_this_adjustment(bytes: &[u8]) -> Option<(usize, i32)> {
    if bytes.len() >= 4 && bytes[0] == 0x48 && bytes[1] == 0x83 {
        let imm = bytes[3] as i8 as i32;
        return match bytes[2] {
            0xC1 => Some((4, imm)),
            0xE9 => Some((4, imm.saturating_neg())),
            _ => None,
        };
    }

    if bytes.len() >= 7 && bytes[0] == 0x48 && bytes[1] == 0x81 {
        let imm = i32::from_le_bytes(bytes[3..7].try_into().ok()?);
        return match bytes[2] {
            0xC1 => Some((7, imm)),
            0xE9 => Some((7, imm.saturating_neg())),
            _ => None,
        };
    }

    if bytes.len() >= 4 && bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x49 {
        return Some((4, bytes[3] as i8 as i32));
    }

    if bytes.len() >= 7 && bytes[0] == 0x48 && bytes[1] == 0x8D && bytes[2] == 0x89 {
        return Some((7, i32::from_le_bytes(bytes[3..7].try_into().ok()?)));
    }

    None
}

fn analyze_thunk(
    pe: &PeParser,
    thunk_rva: u32,
    code_ranges: &[(u32, u32)],
) -> Option<ThunkAnalysis> {
    let bytes = read_bytes_at_rva(pe, thunk_rva, 16)?;
    if let Some(jump) = decode_simple_thunk_jump(pe, thunk_rva, bytes, code_ranges) {
        return Some(ThunkAnalysis {
            normalized_target_rva: jump.target_rva,
            thunk_kind: "jump_thunk",
            instruction_len: jump.instruction_len,
            this_adjustment: None,
            reason: jump.reason,
        });
    }

    let (adjust_len, this_adjustment) = decode_this_adjustment(bytes)?;
    let jump_rva = thunk_rva.checked_add(adjust_len as u32)?;
    let jump_bytes = bytes.get(adjust_len..)?;
    let jump = decode_simple_thunk_jump(pe, jump_rva, jump_bytes, code_ranges)?;
    Some(ThunkAnalysis {
        normalized_target_rva: jump.target_rva,
        thunk_kind: "adjustor_thunk",
        instruction_len: adjust_len + jump.instruction_len,
        this_adjustment: Some(this_adjustment),
        reason: "this_adjustment_then_jump",
    })
}

fn classify_vtable_slot(
    function_symbol: &str,
    thunk: Option<&ThunkAnalysis>,
) -> (&'static str, &'static str, &'static str, &'static str) {
    let lower = function_symbol.to_ascii_lowercase();
    if !function_symbol.is_empty() {
        if lower.contains("purecall") {
            return (
                "pure_virtual",
                "function",
                "high",
                "symbol_name_contains_purecall",
            );
        }
        if function_symbol.starts_with("??_G") || lower.contains("scalar deleting destructor") {
            return (
                "scalar_deleting_destructor",
                "function",
                "high",
                "msvc_deleting_destructor_symbol",
            );
        }
        if function_symbol.starts_with("??_E") || lower.contains("vector deleting destructor") {
            return (
                "vector_deleting_destructor",
                "function",
                "high",
                "msvc_deleting_destructor_symbol",
            );
        }
        if function_symbol.starts_with("??1")
            || lower.contains("destructor")
            || lower.contains("dtor")
        {
            return ("destructor", "function", "high", "destructor_symbol");
        }
    }

    if let Some(thunk) = thunk {
        if thunk.thunk_kind == "adjustor_thunk" {
            return (
                "adjustor_thunk",
                "normalized_function",
                "high",
                thunk.reason,
            );
        }
        return ("jump_thunk", "normalized_function", "high", thunk.reason);
    }

    (
        "virtual_function",
        "function",
        "medium",
        "module_code_pointer_slot",
    )
}

fn analyze_vtable_slots(
    pe: &PeParser,
    facts: &[EnrichedVtableFact],
) -> (Vec<VtableSlotFact>, Vec<ThunkNormalizationFact>) {
    let code_ranges = executable_ranges(pe);
    if code_ranges.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let pointer_size = if pe.is_64bit { 8usize } else { 4usize };
    let function_symbols = parse_coff_function_symbols(pe);
    let mut vtables = BTreeMap::<u32, Option<String>>::new();
    for enriched in facts {
        vtables
            .entry(enriched.fact.vtable_rva)
            .and_modify(|name| {
                if name.is_none() && enriched.type_name.is_some() {
                    *name = enriched.type_name.clone();
                }
            })
            .or_insert_with(|| enriched.type_name.clone());
    }

    let mut slots = Vec::new();
    let mut thunks = BTreeMap::<u32, ThunkNormalizationFact>::new();
    for (vtable_rva, type_name) in vtables {
        for slot_index in 0..MAX_VTABLE_SLOTS {
            let Some(slot_offset) = (slot_index * pointer_size).try_into().ok() else {
                break;
            };
            let Some(slot_rva) = vtable_rva.checked_add(slot_offset) else {
                break;
            };
            if !rva_in_image(pe, slot_rva, pointer_size) {
                break;
            }
            let Some(entry_ptr) = read_pointer_at_rva(pe, slot_rva) else {
                break;
            };
            let Some(entry_rva) = ptr_to_rva(pe, entry_ptr) else {
                break;
            };
            if !rva_in_ranges(entry_rva, &code_ranges) {
                break;
            }

            let thunk = analyze_thunk(pe, entry_rva, &code_ranges);
            let normalized_target_rva = thunk
                .as_ref()
                .map(|analysis| analysis.normalized_target_rva)
                .unwrap_or(entry_rva);
            let function_symbol = function_symbols
                .get(&normalized_target_rva)
                .or_else(|| function_symbols.get(&entry_rva))
                .cloned()
                .unwrap_or_default();
            let (slot_kind, target_kind, confidence, reason) =
                classify_vtable_slot(&function_symbol, thunk.as_ref());

            if let Some(thunk) = &thunk {
                thunks
                    .entry(entry_rva)
                    .or_insert_with(|| ThunkNormalizationFact {
                        thunk_rva: entry_rva,
                        thunk_va: pe.image_base + entry_rva as u64,
                        normalized_target_rva: thunk.normalized_target_rva,
                        normalized_target_va: pe.image_base + thunk.normalized_target_rva as u64,
                        thunk_kind: thunk.thunk_kind,
                        instruction_len: thunk.instruction_len,
                        this_adjustment: thunk.this_adjustment,
                        confidence: "high",
                        reason: thunk.reason,
                    });
            }

            slots.push(VtableSlotFact {
                vtable_rva,
                type_name: type_name.clone(),
                slot_index,
                slot_offset,
                entry_rva,
                entry_va: pe.image_base + entry_rva as u64,
                normalized_target_rva,
                normalized_target_va: pe.image_base + normalized_target_rva as u64,
                slot_kind,
                target_kind,
                function_symbol,
                confidence,
                reason,
            });
        }
    }

    (slots, thunks.into_values().collect())
}

const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
const MAX_CFG_FUNCTIONS: usize = 200_000;
const MAX_EXCEPTION_FUNCTIONS: usize = 200_000;

fn optional_header_u32(pe: &PeParser, offset: usize) -> Option<u32> {
    let bytes = pe.optional_header_raw.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn pe_data_directory(pe: &PeParser, index: usize) -> Option<(u32, u32)> {
    let directory_start = if pe.is_64bit { 112usize } else { 96usize };
    let number_of_rva_and_sizes_offset = if pe.is_64bit { 108usize } else { 92usize };
    let number_of_rva_and_sizes = optional_header_u32(pe, number_of_rva_and_sizes_offset)? as usize;
    if index >= number_of_rva_and_sizes {
        return None;
    }

    let offset = directory_start.checked_add(index.checked_mul(8)?)?;
    let rva = optional_header_u32(pe, offset)?;
    let size = optional_header_u32(pe, offset + 4)?;
    (rva != 0 && size != 0).then_some((rva, size))
}

fn analyze_cfg_functions(pe: &PeParser) -> Vec<CfgFunctionFact> {
    let Some((load_config_rva, load_config_size)) =
        pe_data_directory(pe, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
    else {
        return Vec::new();
    };
    if !rva_in_image(pe, load_config_rva, 4) {
        return Vec::new();
    }

    let declared_size = read_u32_at_rva(pe, load_config_rva).unwrap_or(load_config_size);
    let code_ranges = executable_ranges(pe);
    let (table_va, function_count, guard_flags) = if pe.is_64bit {
        if declared_size < 148 || !rva_in_image(pe, load_config_rva, 148) {
            return Vec::new();
        }
        (
            read_u64_at_rva(pe, load_config_rva + 128).unwrap_or_default(),
            read_u64_at_rva(pe, load_config_rva + 136).unwrap_or_default(),
            read_u32_at_rva(pe, load_config_rva + 144).unwrap_or_default(),
        )
    } else {
        if declared_size < 92 || !rva_in_image(pe, load_config_rva, 92) {
            return Vec::new();
        }
        (
            read_u32_at_rva(pe, load_config_rva + 80)
                .map(u64::from)
                .unwrap_or_default(),
            read_u32_at_rva(pe, load_config_rva + 84)
                .map(u64::from)
                .unwrap_or_default(),
            read_u32_at_rva(pe, load_config_rva + 88).unwrap_or_default(),
        )
    };

    let Some(table_rva) = ptr_to_rva(pe, table_va) else {
        return Vec::new();
    };
    let extra_entry_bytes = ((guard_flags >> 28) & 0xF) as usize;
    let stride = 4usize.saturating_add(extra_entry_bytes).max(4);
    let count = (function_count as usize).min(MAX_CFG_FUNCTIONS);
    let mut functions = Vec::new();
    for entry_index in 0..count {
        let Some(entry_offset) = entry_index.checked_mul(stride) else {
            break;
        };
        let Some(entry_rva) = table_rva.checked_add(entry_offset as u32) else {
            break;
        };
        if !rva_in_image(pe, entry_rva, 4) {
            break;
        }
        let Some(raw_entry) = read_u32_at_rva(pe, entry_rva) else {
            break;
        };
        let target_rva = raw_entry & !0x3;
        if !code_ranges.is_empty() && !rva_in_ranges(target_rva, &code_ranges) {
            continue;
        }
        functions.push(CfgFunctionFact {
            table_rva,
            entry_index,
            entry_rva,
            raw_entry,
            target_rva,
            target_va: pe.image_base + target_rva as u64,
            suppressed: (raw_entry & 0x1) != 0,
            export_suppressed: (raw_entry & 0x2) != 0,
            guard_flags,
            confidence: "high",
            reason: "pe_load_config_guard_cf_function_table",
        });
    }

    functions
}

fn unwind_flag_names(flags: u8) -> String {
    let mut names = Vec::new();
    if (flags & 0x1) != 0 {
        names.push("EHANDLER");
    }
    if (flags & 0x2) != 0 {
        names.push("UHANDLER");
    }
    if (flags & 0x4) != 0 {
        names.push("CHAININFO");
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(";")
    }
}

fn analyze_exception_functions(pe: &PeParser) -> Vec<ExceptionFunctionFact> {
    if !pe.is_64bit {
        return Vec::new();
    }
    let Some((exception_rva, exception_size)) =
        pe_data_directory(pe, IMAGE_DIRECTORY_ENTRY_EXCEPTION)
    else {
        return Vec::new();
    };

    let count = (exception_size as usize / 12).min(MAX_EXCEPTION_FUNCTIONS);
    let mut functions = Vec::new();
    for index in 0..count {
        let Some(entry_offset) = index.checked_mul(12) else {
            break;
        };
        let Some(entry_rva) = exception_rva.checked_add(entry_offset as u32) else {
            break;
        };
        if !rva_in_image(pe, entry_rva, 12) {
            break;
        }

        let begin_rva = read_u32_at_rva(pe, entry_rva).unwrap_or_default();
        let end_rva = read_u32_at_rva(pe, entry_rva + 4).unwrap_or_default();
        let unwind_info_rva = read_u32_at_rva(pe, entry_rva + 8).unwrap_or_default();
        if begin_rva == 0 && end_rva == 0 || !rva_in_image(pe, unwind_info_rva, 4) {
            continue;
        }
        let Some(unwind_header) = read_bytes_at_rva(pe, unwind_info_rva, 4) else {
            continue;
        };

        let unwind_flags = unwind_header[0] >> 3;
        let prolog_size = unwind_header[1];
        let unwind_code_count = unwind_header[2];
        let frame_register = unwind_header[3] & 0xF;
        let frame_offset = unwind_header[3] >> 4;
        let aligned_unwind_codes = (unwind_code_count as usize + 1) & !1;
        let handler_offset = 4usize.saturating_add(aligned_unwind_codes.saturating_mul(2));
        let handler_field_rva = unwind_info_rva.saturating_add(handler_offset as u32);

        let mut handler_rva = None;
        let mut chained_begin_rva = None;
        let mut chained_end_rva = None;
        let mut chained_unwind_info_rva = None;
        if (unwind_flags & 0x4) != 0 {
            if rva_in_image(pe, handler_field_rva, 12) {
                chained_begin_rva = read_u32_at_rva(pe, handler_field_rva);
                chained_end_rva = read_u32_at_rva(pe, handler_field_rva + 4);
                chained_unwind_info_rva = read_u32_at_rva(pe, handler_field_rva + 8);
            }
        } else if (unwind_flags & 0x3) != 0 && rva_in_image(pe, handler_field_rva, 4) {
            handler_rva = read_u32_at_rva(pe, handler_field_rva);
        }

        let reason = if handler_rva.is_some() {
            "x64_unwind_info_with_handler"
        } else if chained_begin_rva.is_some() {
            "x64_chained_unwind_info"
        } else {
            "x64_runtime_function"
        };

        functions.push(ExceptionFunctionFact {
            entry_rva,
            begin_rva,
            end_rva,
            unwind_info_rva,
            unwind_flags,
            unwind_flag_names: unwind_flag_names(unwind_flags),
            prolog_size,
            unwind_code_count,
            frame_register,
            frame_offset,
            handler_rva,
            handler_va: handler_rva.map(|rva| pe.image_base + rva as u64),
            chained_begin_rva,
            chained_end_rva,
            chained_unwind_info_rva,
            confidence: "high",
            reason,
        });
    }

    functions
}

const REVDMP_BINARY_MAGIC: &[u8; 8] = b"REVDMPB\0";
const REVDMP_BINARY_VERSION: u32 = 2;
const REVDMP_ENDIAN_MARKER: u32 = 0x0102_0304;
const REVDMP_NONE_U32: u32 = u32::MAX;
const REVDMP_CHECKSUM_KIND_SHA256: u32 = 1;
const REVDMP_CHECKSUM_OFFSET: usize = 40;
const REVDMP_CHECKSUM_SIZE: usize = 32;
const REVDMP_HEADER_SIZE: usize = REVDMP_CHECKSUM_OFFSET + REVDMP_CHECKSUM_SIZE;

const BLOCK_OBJECTS: u32 = 1;
const BLOCK_VTABLE_FACTS: u32 = 2;
const BLOCK_MSVC_RTTI: u32 = 3;
const BLOCK_MSVC_BASE_CLASSES: u32 = 4;
const BLOCK_GLOBAL_POINTERS: u32 = 5;
const BLOCK_HEAP_EDGES: u32 = 6;
const BLOCK_CONTAINERS: u32 = 7;
const BLOCK_FIELD_TYPES: u32 = 8;
const BLOCK_CONTAINER_ELEMENTS: u32 = 9;
const BLOCK_INDIRECT_CALLS: u32 = 10;
const BLOCK_FUNCTION_POINTERS: u32 = 11;
const BLOCK_FUNCTION_POINTER_TABLES: u32 = 12;
const BLOCK_VTABLE_SLOTS: u32 = 13;
const BLOCK_THUNK_NORMALIZATIONS: u32 = 14;
const BLOCK_CFG_FUNCTIONS: u32 = 15;
const BLOCK_EXCEPTION_FUNCTIONS: u32 = 16;
const BLOCK_SYNTHETIC_STRUCTS: u32 = 17;

#[derive(Default)]
struct RevdmpRecord(Vec<u8>);

impl RevdmpRecord {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn pad(&mut self, count: usize) {
        self.0.resize(self.0.len() + count, 0);
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

struct RevdmpBlock {
    record_size: u32,
    count: u32,
    data: Vec<u8>,
}

struct RevdmpBinaryBuilder {
    strings: Vec<u8>,
    string_offsets: BTreeMap<String, u32>,
    blocks: BTreeMap<u32, RevdmpBlock>,
}

impl RevdmpBinaryBuilder {
    fn new() -> Self {
        let mut string_offsets = BTreeMap::new();
        string_offsets.insert(String::new(), 0);
        Self {
            strings: vec![0],
            string_offsets,
            blocks: BTreeMap::new(),
        }
    }

    fn string(&mut self, value: &str) -> u32 {
        if value.is_empty() {
            return 0;
        }
        if let Some(&offset) = self.string_offsets.get(value) {
            return offset;
        }
        let offset = self.strings.len() as u32;
        self.strings.extend_from_slice(value.as_bytes());
        self.strings.push(0);
        self.string_offsets.insert(value.to_string(), offset);
        offset
    }

    fn add_record(&mut self, kind: u32, record: Vec<u8>) {
        let record_size = record.len() as u32;
        let block = self.blocks.entry(kind).or_insert_with(|| RevdmpBlock {
            record_size,
            count: 0,
            data: Vec::new(),
        });
        debug_assert_eq!(block.record_size, record_size);
        if block.record_size != record_size {
            return;
        }
        block.count = block.count.saturating_add(1);
        block.data.extend_from_slice(&record);
    }

    fn finish(self, image_base: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(REVDMP_BINARY_MAGIC);
        out.extend_from_slice(&REVDMP_BINARY_VERSION.to_le_bytes());
        out.extend_from_slice(&REVDMP_ENDIAN_MARKER.to_le_bytes());
        out.extend_from_slice(&(self.blocks.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&image_base.to_le_bytes());
        out.extend_from_slice(&REVDMP_CHECKSUM_KIND_SHA256.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&[0u8; REVDMP_CHECKSUM_SIZE]);

        for (&kind, block) in &self.blocks {
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&block.record_size.to_le_bytes());
            out.extend_from_slice(&block.count.to_le_bytes());
            out.extend_from_slice(&(block.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&block.data);
        }

        out.extend_from_slice(&self.strings);
        let checksum = revdmp_checksum(&out);
        out[REVDMP_CHECKSUM_OFFSET..REVDMP_HEADER_SIZE].copy_from_slice(&checksum);
        out
    }
}

fn revdmp_checksum(data: &[u8]) -> [u8; REVDMP_CHECKSUM_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(&data[..REVDMP_CHECKSUM_OFFSET]);
    hasher.update([0u8; REVDMP_CHECKSUM_SIZE]);
    hasher.update(&data[REVDMP_HEADER_SIZE..]);
    hasher.finalize().into()
}

fn opt_rva(value: Option<u32>) -> u32 {
    value.unwrap_or(REVDMP_NONE_U32)
}

fn opt_va(value: Option<u64>) -> u64 {
    value.unwrap_or(u64::MAX)
}

fn bool_byte(value: bool) -> u8 {
    u8::from(value)
}

fn joined_u64(values: &[u64]) -> String {
    values
        .iter()
        .map(|value| format!("0x{value:X}"))
        .collect::<Vec<_>>()
        .join(";")
}

/// Build the embedded binary `.revdmp` metadata section.
pub fn build_revdmp_metadata(
    facts: &[EnrichedVtableFact],
    heap_ptr_locs: &[(u32, u64)],
    heap_edges: &[HeapPointerEdge],
    containers: &[ContainerFact],
    indirect_calls: &[IndirectCallFact],
    function_pointers: &[FunctionPointerFact],
    function_pointer_tables: &[FunctionPointerTableFact],
    vtable_slots: &[VtableSlotFact],
    thunk_normalizations: &[ThunkNormalizationFact],
    cfg_functions: &[CfgFunctionFact],
    exception_functions: &[ExceptionFunctionFact],
    image_base: u64,
    stub_generator: &StubGenerator,
) -> Vec<u8> {
    let mut out = RevdmpBinaryBuilder::new();
    let runtime_objects = build_runtime_objects(
        facts,
        heap_ptr_locs,
        heap_edges,
        containers,
        image_base,
        stub_generator,
    );
    let object_ids = object_id_map(stub_generator);
    let type_names_by_heap = collect_type_names_by_heap(facts);
    let mut msvc_rtti_by_vtable = BTreeMap::new();
    for enriched in facts {
        if let Some(rtti) = &enriched.msvc_rtti {
            msvc_rtti_by_vtable
                .entry(rtti.vtable_rva)
                .or_insert_with(|| rtti.clone());
        }
    }

    for object in &runtime_objects {
        let mut record = RevdmpRecord::default();
        let type_names = object.type_names.join(";");
        record.u32(out.string(&object.id));
        record.u64(object.heap_addr);
        record.u32(object.stub_rva);
        record.u64(object.stub_va);
        record.u32(object.stub_size as u32);
        record.u32(object.vfptr_offsets.len() as u32);
        record.u32(out.string(&join_hex_u32(&object.vfptr_offsets)));
        record.u32(out.string(&join_hex_u32(&object.vtable_rvas)));
        record.u32(out.string(&type_names));
        record.u32(out.string(&join_hex_u32(&object.root_rvas)));
        record.u32(object.incoming_edges as u32);
        record.u32(object.outgoing_edges as u32);
        record.u32(object.container_owner_count as u32);
        record.u32(object.container_element_count as u32);
        record.u32(out.string(object.confidence));
        record.u32(out.string(object.provenance));
        out.add_record(BLOCK_OBJECTS, record.finish());
    }

    for enriched in facts {
        let fact = &enriched.fact;
        let mut record = RevdmpRecord::default();
        record.u32(opt_rva(fact.source_rva));
        record.u64(fact.heap_addr);
        record.u32(fact.stub_rva);
        record.u32(fact.vfptr_offset);
        record.u32(fact.vtable_rva);
        record.u64(image_base + fact.vtable_rva as u64);
        record.u32(out.string(enriched.type_name.as_deref().unwrap_or("")));
        out.add_record(BLOCK_VTABLE_FACTS, record.finish());
    }

    for rtti in msvc_rtti_by_vtable.values() {
        let mut record = RevdmpRecord::default();
        record.u32(rtti.vtable_rva);
        record.u32(rtti.col_rva);
        record.u32(rtti.object_offset);
        record.u32(rtti.constructor_displacement);
        record.u32(rtti.type_descriptor_rva);
        record.u32(out.string(&rtti.type_name));
        record.u32(opt_rva(rtti.hierarchy_rva));
        record.u32(rtti.hierarchy_attributes);
        record.u32(rtti.base_classes.len() as u32);
        out.add_record(BLOCK_MSVC_RTTI, record.finish());

        for base in &rtti.base_classes {
            let mut base_record = RevdmpRecord::default();
            base_record.u32(rtti.vtable_rva);
            base_record.u32(out.string(&base.type_name));
            base_record.u32(base.type_descriptor_rva);
            base_record.u32(base.num_contained_bases);
            base_record.i32(base.mdisp);
            base_record.i32(base.pdisp);
            base_record.i32(base.vdisp);
            base_record.u32(base.attributes);
            out.add_record(BLOCK_MSVC_BASE_CLASSES, base_record.finish());
        }
    }

    for slot in vtable_slots {
        let mut record = RevdmpRecord::default();
        record.u32(slot.vtable_rva);
        record.u32(out.string(slot.type_name.as_deref().unwrap_or("")));
        record.u32(slot.slot_index as u32);
        record.u32(slot.slot_offset);
        record.u32(slot.entry_rva);
        record.u64(slot.entry_va);
        record.u32(slot.normalized_target_rva);
        record.u64(slot.normalized_target_va);
        record.u32(out.string(slot.slot_kind));
        record.u32(out.string(slot.target_kind));
        record.u32(out.string(&slot.function_symbol));
        record.u32(out.string(slot.confidence));
        record.u32(out.string(slot.reason));
        out.add_record(BLOCK_VTABLE_SLOTS, record.finish());
    }

    for thunk in thunk_normalizations {
        let mut record = RevdmpRecord::default();
        record.u32(thunk.thunk_rva);
        record.u64(thunk.thunk_va);
        record.u32(thunk.normalized_target_rva);
        record.u64(thunk.normalized_target_va);
        record.u32(out.string(thunk.thunk_kind));
        record.u32(thunk.instruction_len as u32);
        record.i32(thunk.this_adjustment.unwrap_or_default());
        record.u8(bool_byte(thunk.this_adjustment.is_some()));
        record.pad(3);
        record.u32(out.string(thunk.confidence));
        record.u32(out.string(thunk.reason));
        out.add_record(BLOCK_THUNK_NORMALIZATIONS, record.finish());
    }

    for cfg in cfg_functions {
        let mut record = RevdmpRecord::default();
        record.u32(cfg.table_rva);
        record.u32(cfg.entry_index as u32);
        record.u32(cfg.entry_rva);
        record.u32(cfg.raw_entry);
        record.u32(cfg.target_rva);
        record.u64(cfg.target_va);
        record.u8(bool_byte(cfg.suppressed));
        record.u8(bool_byte(cfg.export_suppressed));
        record.pad(2);
        record.u32(cfg.guard_flags);
        record.u32(out.string(cfg.confidence));
        record.u32(out.string(cfg.reason));
        out.add_record(BLOCK_CFG_FUNCTIONS, record.finish());
    }

    for function in exception_functions {
        let mut record = RevdmpRecord::default();
        record.u32(function.entry_rva);
        record.u32(function.begin_rva);
        record.u32(function.end_rva);
        record.u32(function.unwind_info_rva);
        record.u8(function.unwind_flags);
        record.u8(function.prolog_size);
        record.u8(function.unwind_code_count);
        record.u8(function.frame_register);
        record.u8(function.frame_offset);
        record.u8(bool_byte(function.handler_rva.is_some()));
        record.u8(bool_byte(function.chained_begin_rva.is_some()));
        record.pad(1);
        record.u32(opt_rva(function.handler_rva));
        record.u64(opt_va(function.handler_va));
        record.u32(opt_rva(function.chained_begin_rva));
        record.u32(opt_rva(function.chained_end_rva));
        record.u32(opt_rva(function.chained_unwind_info_rva));
        record.u32(out.string(&function.unwind_flag_names));
        record.u32(out.string(function.confidence));
        record.u32(out.string(function.reason));
        out.add_record(BLOCK_EXCEPTION_FUNCTIONS, record.finish());
    }

    for &(source_rva, target_heap_addr) in heap_ptr_locs {
        let target_heap_addr = strip_pointer_tags(target_heap_addr);
        let target_stub = stub_generator.get_stub(target_heap_addr).map(|s| s.new_rva);
        let (confidence, reason, target_has_vtable) = if target_stub.is_some() {
            ("high", "target_has_vtable", true)
        } else {
            ("low", "raw_heap_pointer", false)
        };
        let mut record = RevdmpRecord::default();
        record.u32(source_rva);
        record.u64(target_heap_addr);
        record.u32(opt_rva(target_stub));
        record.u8(bool_byte(target_has_vtable));
        record.pad(3);
        record.u32(out.string(confidence));
        record.u32(out.string(reason));
        out.add_record(BLOCK_GLOBAL_POINTERS, record.finish());
    }
    for edge in heap_edges {
        let source_stub = stub_generator
            .get_stub(edge.source_heap_addr)
            .map(|s| s.new_rva);
        let target_stub = stub_generator
            .get_stub(edge.target_heap_addr)
            .map(|s| s.new_rva);
        let mut record = RevdmpRecord::default();
        record.u64(edge.source_heap_addr);
        record.u32(opt_rva(source_stub));
        record.u32(edge.field_offset);
        record.u64(edge.target_heap_addr);
        record.u32(opt_rva(target_stub));
        record.u8(bool_byte(edge.target_has_vtable));
        record.pad(3);
        record.u32(out.string(edge.confidence.as_str()));
        record.u32(out.string(edge.reason));
        out.add_record(BLOCK_HEAP_EDGES, record.finish());
    }

    for container in containers {
        let source_stub = stub_generator
            .get_stub(container.source_heap_addr)
            .map(|s| s.new_rva);
        let mut record = RevdmpRecord::default();
        record.u64(container.source_heap_addr);
        record.u32(opt_rva(source_stub));
        record.u32(container.field_offset);
        record.u32(out.string(container.kind));
        record.u32(container.element_count as u32);
        record.u32(out.string(&joined_u64(&container.targets)));
        out.add_record(BLOCK_CONTAINERS, record.finish());
    }

    for enriched in facts {
        let fact = &enriched.fact;
        let owner_id = object_ids
            .get(&fact.heap_addr)
            .cloned()
            .unwrap_or_else(|| runtime_object_id(fact.stub_rva));
        let mut record = RevdmpRecord::default();
        record.u32(out.string(&owner_id));
        record.u64(fact.heap_addr);
        record.u32(fact.stub_rva);
        record.u32(fact.vfptr_offset);
        record.u32(out.string("vfptr"));
        record.u32(out.string("vtable"));
        record.u32(out.string(&format!("vtable_{:08X}", fact.vtable_rva)));
        record.u32(out.string(enriched.type_name.as_deref().unwrap_or("")));
        record.u32(1);
        record.u32(out.string("high"));
        record.u32(out.string("vfptr_points_to_module_vtable"));
        out.add_record(BLOCK_FIELD_TYPES, record.finish());
    }
    for edge in heap_edges {
        let source_stub = stub_generator
            .get_stub(edge.source_heap_addr)
            .map(|stub| stub.new_rva);
        let owner_id = object_ids
            .get(&edge.source_heap_addr)
            .cloned()
            .unwrap_or_else(|| format!("heap_{:016X}", edge.source_heap_addr));
        let target_id = object_ids
            .get(&edge.target_heap_addr)
            .cloned()
            .unwrap_or_else(|| format!("heap_{:016X}", edge.target_heap_addr));
        let target_type_names = join_type_names(type_names_by_heap.get(&edge.target_heap_addr));
        let mut record = RevdmpRecord::default();
        record.u32(out.string(&owner_id));
        record.u64(edge.source_heap_addr);
        record.u32(opt_rva(source_stub));
        record.u32(edge.field_offset);
        record.u32(out.string("object_pointer"));
        record.u32(out.string("heap_object"));
        record.u32(out.string(&target_id));
        record.u32(out.string(&target_type_names));
        record.u32(1);
        record.u32(out.string(edge.confidence.as_str()));
        record.u32(out.string(edge.reason));
        out.add_record(BLOCK_FIELD_TYPES, record.finish());
    }
    for container in containers {
        let source_stub = stub_generator
            .get_stub(container.source_heap_addr)
            .map(|stub| stub.new_rva);
        let owner_id = object_ids
            .get(&container.source_heap_addr)
            .cloned()
            .unwrap_or_else(|| format!("heap_{:016X}", container.source_heap_addr));
        let target_ids = container
            .targets
            .iter()
            .map(|target| {
                object_ids
                    .get(target)
                    .cloned()
                    .unwrap_or_else(|| format!("heap_{target:016X}"))
            })
            .collect::<Vec<_>>()
            .join(";");
        let target_type_names = container
            .targets
            .iter()
            .filter_map(|target| type_names_by_heap.get(target))
            .flat_map(|names| names.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(";");
        let mut record = RevdmpRecord::default();
        record.u32(out.string(&owner_id));
        record.u64(container.source_heap_addr);
        record.u32(opt_rva(source_stub));
        record.u32(container.field_offset);
        record.u32(out.string(container.kind));
        record.u32(out.string("heap_object_set"));
        record.u32(out.string(&target_ids));
        record.u32(out.string(&target_type_names));
        record.u32(container.element_count as u32);
        record.u32(out.string("high"));
        record.u32(out.string("container_shape_analysis"));
        out.add_record(BLOCK_FIELD_TYPES, record.finish());
    }

    for container in containers {
        let owner_id = object_ids
            .get(&container.source_heap_addr)
            .cloned()
            .unwrap_or_else(|| format!("heap_{:016X}", container.source_heap_addr));
        let container_id = format!(
            "container_{:016X}_{:X}",
            container.source_heap_addr, container.field_offset
        );
        for (idx, target) in container.targets.iter().enumerate() {
            let target_id = object_ids
                .get(target)
                .cloned()
                .unwrap_or_else(|| format!("heap_{target:016X}"));
            let target_type_names = join_type_names(type_names_by_heap.get(target));
            let mut record = RevdmpRecord::default();
            record.u32(out.string(&container_id));
            record.u32(out.string(&owner_id));
            record.u64(container.source_heap_addr);
            record.u32(container.field_offset);
            record.u32(out.string(container.kind));
            record.u32(idx as u32);
            record.u64(*target);
            record.u32(out.string(&target_id));
            record.u32(out.string(&target_type_names));
            record.u32(out.string("high"));
            record.u32(out.string("container_element_has_vtable"));
            out.add_record(BLOCK_CONTAINER_ELEMENTS, record.finish());
        }
    }

    for call in indirect_calls {
        let mut record = RevdmpRecord::default();
        record.u32(call.instruction_rva);
        record.u32(call.instruction_len as u32);
        record.u32(out.string(indirect_call_kind_name(call.kind)));
        record.u32(call.global_rva);
        record.u32(call.target_rva);
        record.u64(call.target_va);
        record.u8(bool_byte(call.via_register));
        record.pad(3);
        record.u32(out.string(call.confidence));
        record.u32(out.string(call.reason));
        out.add_record(BLOCK_INDIRECT_CALLS, record.finish());
    }

    for pointer in function_pointers {
        let mut record = RevdmpRecord::default();
        record.u32(pointer.location_rva);
        record.u64(pointer.location_va);
        record.u32(out.string(&pointer.section_name));
        record.u32(out.string(pointer.kind));
        record.u32(out.string(pointer.table_id.as_deref().unwrap_or("")));
        record.u32(
            pointer
                .index
                .map(|idx| idx as u32)
                .unwrap_or(REVDMP_NONE_U32),
        );
        record.u32(pointer.target_rva);
        record.u64(pointer.target_va);
        record.u32(out.string(pointer.confidence));
        record.u32(out.string(pointer.reason));
        out.add_record(BLOCK_FUNCTION_POINTERS, record.finish());
    }

    for table in function_pointer_tables {
        let mut record = RevdmpRecord::default();
        record.u32(out.string(&table.id));
        record.u32(table.start_rva);
        record.u64(table.start_va);
        record.u32(out.string(&table.section_name));
        record.u32(table.entry_count as u32);
        record.u32(out.string(&join_hex_u32(&table.target_rvas)));
        record.u32(out.string(table.confidence));
        record.u32(out.string(table.reason));
        out.add_record(BLOCK_FUNCTION_POINTER_TABLES, record.finish());
    }

    let mut stubs = stub_generator.stubs().collect::<Vec<_>>();
    stubs.sort_by_key(|stub| stub.new_rva);
    for stub in stubs {
        let vfptr_offsets = stub
            .vtable_refs
            .iter()
            .map(|r| format!("0x{:X}", r.offset))
            .collect::<Vec<_>>()
            .join(";");
        let mut record = RevdmpRecord::default();
        record.u32(stub.new_rva);
        record.u64(stub.original_addr);
        record.u32(out.string(&synthetic_struct_name(stub.new_rva)));
        record.u32(stub.size as u32);
        record.u32(out.string(&vfptr_offsets));
        out.add_record(BLOCK_SYNTHETIC_STRUCTS, record.finish());
    }

    out.finish(image_base)
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

fn synthetic_struct_name(stub_rva: u32) -> String {
    format!("revdump_obj_{stub_rva:X}")
}

fn indirect_call_kind_name(kind: VcallKind) -> &'static str {
    match kind {
        VcallKind::GlobalIndirectCall => "call",
        VcallKind::GlobalIndirectJmp => "jmp",
        _ => "unknown",
    }
}

fn read_bytes_at_rva(pe: &PeParser, rva: u32, len: usize) -> Option<&[u8]> {
    let off = rva as usize;
    if off.checked_add(len)? > pe.size {
        return None;
    }
    let ptr = unsafe { pe.base.add(off) };
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

fn read_u32_at_rva(pe: &PeParser, rva: u32) -> Option<u32> {
    let bytes = read_bytes_at_rva(pe, rva, 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_i32_at_rva(pe: &PeParser, rva: u32) -> Option<i32> {
    Some(read_u32_at_rva(pe, rva)? as i32)
}

fn read_u64_at_rva(pe: &PeParser, rva: u32) -> Option<u64> {
    let bytes = read_bytes_at_rva(pe, rva, 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn rva_in_image(pe: &PeParser, rva: u32, len: usize) -> bool {
    (rva as usize)
        .checked_add(len)
        .is_some_and(|end| end <= pe.size)
}

fn read_c_string_at_rva(pe: &PeParser, rva: u32, max_len: usize) -> Option<String> {
    let off = rva as usize;
    if off >= pe.size {
        return None;
    }
    let len = max_len.min(pe.size - off);
    let ptr = unsafe { pe.base.add(off) };
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if nul == 0
        || !bytes[..nul]
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ')
    {
        return None;
    }
    String::from_utf8(bytes[..nul].to_vec()).ok()
}

fn ptr_to_rva(pe: &PeParser, ptr: u64) -> Option<u32> {
    let ptr = strip_pointer_tags(ptr);
    let runtime_base = pe.base as u64;
    let image_end = pe.image_base.checked_add(pe.size as u64)?;
    let runtime_end = runtime_base.checked_add(pe.size as u64)?;

    if ptr >= pe.image_base && ptr < image_end {
        Some((ptr - pe.image_base) as u32)
    } else if ptr >= runtime_base && ptr < runtime_end {
        Some((ptr - runtime_base) as u32)
    } else {
        None
    }
}

fn demangle_msvc_type_name(name: &str) -> String {
    let mut s = name.trim_start_matches('.');
    for prefix in ["?AV", "?AU", "?AW", "?A"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            break;
        }
    }
    if let Some(rest) = s.strip_suffix("@@") {
        s = rest;
    }
    let parts: Vec<&str> = s.split('@').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        name.to_string()
    } else {
        parts.into_iter().rev().collect::<Vec<_>>().join("::")
    }
}

fn demangle_itanium_type_name(name: &str) -> String {
    let name = name.trim_start_matches("_ZTI");
    let name = name
        .strip_prefix('N')
        .and_then(|nested| nested.strip_suffix('E'))
        .unwrap_or(name);
    let bytes = name.as_bytes();
    let mut idx = 0usize;
    let mut parts = Vec::new();

    while idx < bytes.len() {
        if !bytes[idx].is_ascii_digit() {
            return name.to_string();
        }
        let start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        let Ok(len) = name[start..idx].parse::<usize>() else {
            return name.to_string();
        };
        if idx + len > bytes.len() {
            return name.to_string();
        }
        parts.push(&name[idx..idx + len]);
        idx += len;
    }

    if parts.is_empty() {
        name.to_string()
    } else {
        parts.join("::")
    }
}

#[cfg(test)]
fn resolve_vtable_type_name(
    pe: &PeParser,
    vtable_rva: u32,
    symbol_names: &HashMap<u32, String>,
) -> Option<String> {
    resolve_msvc_rtti_fact(pe, vtable_rva)
        .map(|fact| fact.type_name)
        .or_else(|| resolve_itanium_rtti_type_name(pe, vtable_rva))
        .or_else(|| symbol_names.get(&vtable_rva).cloned())
}

fn read_msvc_rtti_ref(pe: &PeParser, rva: u32, image_relative: bool) -> Option<u32> {
    if image_relative {
        read_u32_at_rva(pe, rva)
    } else if pe.is_64bit {
        read_u64_at_rva(pe, rva).and_then(|ptr| ptr_to_rva(pe, ptr))
    } else {
        read_u32_at_rva(pe, rva).and_then(|ptr| ptr_to_rva(pe, ptr as u64))
    }
}

fn read_msvc_type_descriptor_name(pe: &PeParser, type_descriptor_rva: u32) -> Option<String> {
    let name_offset = if pe.is_64bit { 16 } else { 8 };
    if !rva_in_image(pe, type_descriptor_rva, name_offset + 1) {
        return None;
    }
    let raw = read_c_string_at_rva(pe, type_descriptor_rva + name_offset as u32, 256)?;
    Some(demangle_msvc_type_name(&raw))
}

fn resolve_msvc_rtti_fact(pe: &PeParser, vtable_rva: u32) -> Option<MsvcRttiFact> {
    let col_slot_rva = if pe.is_64bit {
        vtable_rva.checked_sub(8)?
    } else {
        vtable_rva.checked_sub(4)?
    };
    let col_ptr = if pe.is_64bit {
        read_u64_at_rva(pe, col_slot_rva)?
    } else {
        read_u32_at_rva(pe, col_slot_rva)? as u64
    };
    let col_rva = ptr_to_rva(pe, col_ptr)?;
    if !rva_in_image(pe, col_rva, 24) {
        return None;
    }
    let signature = read_u32_at_rva(pe, col_rva)?;
    if signature > 1 {
        return None;
    }
    let image_relative = signature == 1;
    let object_offset = read_u32_at_rva(pe, col_rva + 4)?;
    let constructor_displacement = read_u32_at_rva(pe, col_rva + 8)?;
    let type_descriptor_rva = read_msvc_rtti_ref(pe, col_rva + 12, image_relative)?;
    let type_name = read_msvc_type_descriptor_name(pe, type_descriptor_rva)?;
    let hierarchy_rva = read_msvc_rtti_ref(pe, col_rva + 16, image_relative);

    let mut hierarchy_attributes = 0;
    let mut base_classes = Vec::new();
    if let Some(hierarchy_rva) = hierarchy_rva.filter(|&rva| rva_in_image(pe, rva, 16)) {
        hierarchy_attributes = read_u32_at_rva(pe, hierarchy_rva + 4).unwrap_or_default();
        let base_count = read_u32_at_rva(pe, hierarchy_rva + 8).unwrap_or_default();
        if let Some(base_array_rva) = read_msvc_rtti_ref(pe, hierarchy_rva + 12, image_relative) {
            let entry_size = if image_relative || !pe.is_64bit { 4 } else { 8 };
            for idx in 0..base_count.min(128) {
                let entry_rva = base_array_rva.saturating_add(idx * entry_size);
                let Some(base_descriptor_rva) = read_msvc_rtti_ref(pe, entry_rva, image_relative)
                else {
                    continue;
                };
                if !rva_in_image(pe, base_descriptor_rva, 24) {
                    continue;
                }
                let Some(base_type_descriptor_rva) =
                    read_msvc_rtti_ref(pe, base_descriptor_rva, image_relative)
                else {
                    continue;
                };
                let Some(base_type_name) =
                    read_msvc_type_descriptor_name(pe, base_type_descriptor_rva)
                else {
                    continue;
                };

                base_classes.push(MsvcBaseClassFact {
                    type_name: base_type_name,
                    type_descriptor_rva: base_type_descriptor_rva,
                    num_contained_bases: read_u32_at_rva(pe, base_descriptor_rva + 4)
                        .unwrap_or_default(),
                    mdisp: read_i32_at_rva(pe, base_descriptor_rva + 8).unwrap_or_default(),
                    pdisp: read_i32_at_rva(pe, base_descriptor_rva + 12).unwrap_or_default(),
                    vdisp: read_i32_at_rva(pe, base_descriptor_rva + 16).unwrap_or_default(),
                    attributes: read_u32_at_rva(pe, base_descriptor_rva + 20).unwrap_or_default(),
                });
            }
        }
    }

    Some(MsvcRttiFact {
        vtable_rva,
        col_rva,
        object_offset,
        constructor_displacement,
        type_descriptor_rva,
        type_name,
        hierarchy_rva,
        hierarchy_attributes,
        base_classes,
    })
}

fn resolve_itanium_rtti_type_name(pe: &PeParser, vtable_rva: u32) -> Option<String> {
    if vtable_rva < 8 {
        return None;
    }
    let typeinfo_ptr = read_u64_at_rva(pe, vtable_rva - 8)?;
    let typeinfo_rva = ptr_to_rva(pe, typeinfo_ptr)?;
    if !rva_in_image(pe, typeinfo_rva, 16) {
        return None;
    }
    let name_ptr = read_u64_at_rva(pe, typeinfo_rva + 8)?;
    let name_rva = ptr_to_rva(pe, name_ptr)?;
    let raw = read_c_string_at_rva(pe, name_rva, 256)?;
    Some(demangle_itanium_type_name(&raw))
}

fn parse_coff_function_symbols(pe: &PeParser) -> BTreeMap<u32, String> {
    const COFF_SYMBOL_SIZE: usize = 18;
    let mut out = BTreeMap::new();
    let raw = &pe.coff_symbol_table_raw;
    let symbol_bytes = pe.number_of_symbols as usize * COFF_SYMBOL_SIZE;
    if raw.len() < symbol_bytes + 4 {
        return out;
    }
    let strings = &raw[symbol_bytes..];
    let code_ranges = executable_ranges(pe);

    let mut idx = 0usize;
    while idx < pe.number_of_symbols as usize {
        let off = idx * COFF_SYMBOL_SIZE;
        if off + COFF_SYMBOL_SIZE > raw.len() {
            break;
        }

        let name = if raw[off..off + 4] == [0, 0, 0, 0] {
            let string_off = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap()) as usize;
            if string_off >= 4 && string_off < strings.len() {
                let bytes = &strings[string_off..];
                let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..nul]).to_string()
            } else {
                String::new()
            }
        } else {
            let nul = raw[off..off + 8].iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw[off..off + nul]).to_string()
        };

        let value = u32::from_le_bytes(raw[off + 8..off + 12].try_into().unwrap());
        let section_number = i16::from_le_bytes(raw[off + 12..off + 14].try_into().unwrap());
        let aux_count = raw[off + 17] as usize;
        if section_number > 0 {
            if let Some(section) = pe.sections.get(section_number as usize - 1) {
                let rva = section.virtual_address.saturating_add(value);
                if rva_in_ranges(rva, &code_ranges) && !name.is_empty() {
                    out.entry(rva).or_insert(name);
                }
            }
        }
        idx += 1 + aux_count;
    }

    out
}

fn parse_coff_vtable_symbols(pe: &PeParser) -> HashMap<u32, String> {
    const COFF_SYMBOL_SIZE: usize = 18;
    let mut out = HashMap::new();
    let raw = &pe.coff_symbol_table_raw;
    let symbol_bytes = pe.number_of_symbols as usize * COFF_SYMBOL_SIZE;
    if raw.len() < symbol_bytes + 4 {
        return out;
    }
    let strings = &raw[symbol_bytes..];

    let mut idx = 0usize;
    while idx < pe.number_of_symbols as usize {
        let off = idx * COFF_SYMBOL_SIZE;
        if off + COFF_SYMBOL_SIZE > raw.len() {
            break;
        }

        let name = if raw[off..off + 4] == [0, 0, 0, 0] {
            let string_off = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap()) as usize;
            if string_off >= 4 && string_off < strings.len() {
                let bytes = &strings[string_off..];
                let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..nul]).to_string()
            } else {
                String::new()
            }
        } else {
            let nul = raw[off..off + 8].iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&raw[off..off + nul]).to_string()
        };

        let value = u32::from_le_bytes(raw[off + 8..off + 12].try_into().unwrap());
        let section_number = i16::from_le_bytes(raw[off + 12..off + 14].try_into().unwrap());
        let aux_count = raw[off + 17] as usize;
        if section_number > 0 {
            if let Some(section) = pe.sections.get(section_number as usize - 1) {
                let rva = section.virtual_address.saturating_add(value);
                let lower = name.to_ascii_lowercase();
                if lower.contains("vftable") || lower.contains("vtable") {
                    out.insert(rva, demangle_symbol_type_name(&name));
                }
            }
        }
        idx += 1 + aux_count;
    }

    out
}

fn demangle_symbol_type_name(name: &str) -> String {
    let trimmed = name.trim_start_matches("_ZTV");
    if trimmed != name {
        return demangle_itanium_type_name(trimmed);
    }
    name.replace("::`vftable'", "")
        .replace("vftable", "")
        .replace("vtable", "")
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != ':' && ch != '_')
        .to_string()
}

fn enrich_vtable_facts(
    pe: &PeParser,
    facts: &[VtableFact],
    parse_rtti: bool,
) -> Vec<EnrichedVtableFact> {
    let symbol_names = parse_coff_vtable_symbols(pe);
    let mut fallback_type_cache = HashMap::new();
    let mut msvc_rtti_cache = HashMap::new();
    facts
        .iter()
        .cloned()
        .map(|fact| {
            let msvc_rtti = if parse_rtti {
                msvc_rtti_cache
                    .entry(fact.vtable_rva)
                    .or_insert_with(|| resolve_msvc_rtti_fact(pe, fact.vtable_rva))
                    .clone()
            } else {
                None
            };
            let type_name = if let Some(rtti) = &msvc_rtti {
                Some(rtti.type_name.clone())
            } else if parse_rtti {
                fallback_type_cache
                    .entry(fact.vtable_rva)
                    .or_insert_with(|| {
                        resolve_itanium_rtti_type_name(pe, fact.vtable_rva)
                            .or_else(|| symbol_names.get(&fact.vtable_rva).cloned())
                    })
                    .clone()
            } else {
                symbol_names.get(&fact.vtable_rva).cloned()
            };
            EnrichedVtableFact {
                type_name,
                msvc_rtti,
                fact,
            }
        })
        .collect()
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
    /// Emit `.revdmp` metadata section.
    pub emit_revdmp: bool,
    /// Parse RTTI/type names for metadata.
    pub parse_rtti: bool,
    /// Maximum heap graph edges to retain after scoring.
    pub max_graph_edges: usize,
    /// Minimum confidence required for retained heap graph edges.
    pub min_edge_confidence: EdgeConfidence,
    /// Detect conservative container-like heap patterns.
    pub detect_containers: bool,
    /// Enable stronger but still bounded devirtualization analysis.
    pub strong_devirt: bool,
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
            .field("emit_revdmp", &self.emit_revdmp)
            .field("parse_rtti", &self.parse_rtti)
            .field("max_graph_edges", &self.max_graph_edges)
            .field("min_edge_confidence", &self.min_edge_confidence)
            .field("detect_containers", &self.detect_containers)
            .field("strong_devirt", &self.strong_devirt)
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
            enable_devirt: true,
            devirt_config: DevirtConfig::default(),
            max_heap_scan_size: 0x1000,
            recursive_heap_scan_depth: 4,
            emit_revdmp: true,
            parse_rtti: true,
            max_graph_edges: 100_000,
            min_edge_confidence: EdgeConfidence::Low,
            detect_containers: true,
            strong_devirt: true,
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
            max_graph_edges: self.max_graph_edges,
            min_edge_confidence: self.min_edge_confidence,
            detect_containers: self.detect_containers,
        }
    }

    fn effective_devirt_config(&self) -> DevirtConfig {
        let mut config = self.devirt_config.clone();
        config.strong_analysis = self.strong_devirt;
        config
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
        progress.stub_debug = None;
        report(&progress);

        stub_generator.process_heap_pointers_with_progress(&heap_ptr_locs, |stub_progress| {
            progress.current = stub_progress.current;
            progress.total = stub_progress.total;
            progress.stubs_created = stub_progress.created;
            progress.stub_debug = Some(stub_progress);
            report(&progress);
        });
        progress.stubs_created = stub_generator.stub_count();
        progress.current = progress.total;
        report(&progress);

        if stub_generator.stub_count() == 0 {
            return self.standard_dump(output_path, config);
        }

        // Assign RVAs
        progress.stage = ProgressStage::AssigningRvas;
        progress.stub_debug = None;
        report(&progress);

        let heap_section_va = pe.next_section_va();
        let heap_section_size = stub_generator.assign_rvas(heap_section_va);
        let vtable_facts = stub_generator.vtable_facts(&heap_ptr_locs);
        if config.emit_revdmp {
            progress.stage = ProgressStage::AnalyzingMetadata;
            progress.current = 1;
            progress.total = 7;
            progress.current_item = Some("Resolving RTTI/type names".to_string());
            report(&progress);
        }
        let enriched_facts = enrich_vtable_facts(pe, &vtable_facts, config.parse_rtti);
        let indirect_calls = if config.emit_revdmp {
            progress.stage = ProgressStage::AnalyzingMetadata;
            progress.current = 2;
            progress.total = 7;
            progress.current_item = Some("Resolving indirect calls".to_string());
            report(&progress);

            pe.sections
                .iter()
                .find(|s| s.name == ".text" || (s.characteristics & 0x20) != 0)
                .and_then(|text_section| {
                    let text_addr = unsafe { self.base.add(text_section.virtual_address as usize) };
                    is_memory_readable(text_addr, text_section.virtual_size as usize).then(|| {
                        devirt::analyze_global_indirect_calls(
                            self.base,
                            pe.image_base,
                            text_section.virtual_address,
                            text_section.virtual_size,
                            &config.effective_devirt_config(),
                        )
                    })
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let (function_pointers, function_pointer_tables) = if config.emit_revdmp {
            progress.stage = ProgressStage::AnalyzingMetadata;
            progress.current = 3;
            progress.total = 7;
            progress.current_item = Some("Scanning function pointer tables".to_string());
            report(&progress);

            analyze_function_pointer_tables(pe)
        } else {
            (Vec::new(), Vec::new())
        };
        let (vtable_slots, thunk_normalizations) = if config.emit_revdmp {
            progress.stage = ProgressStage::AnalyzingMetadata;
            progress.current = 4;
            progress.total = 7;
            progress.current_item = Some("Analyzing vtable slots".to_string());
            report(&progress);

            analyze_vtable_slots(pe, &enriched_facts)
        } else {
            (Vec::new(), Vec::new())
        };
        let cfg_functions = if config.emit_revdmp {
            progress.stage = ProgressStage::AnalyzingMetadata;
            progress.current = 5;
            progress.total = 7;
            progress.current_item = Some("Reading CFG function table".to_string());
            report(&progress);

            analyze_cfg_functions(pe)
        } else {
            Vec::new()
        };
        let exception_functions = if config.emit_revdmp {
            progress.stage = ProgressStage::AnalyzingMetadata;
            progress.current = 6;
            progress.total = 7;
            progress.current_item = Some("Reading exception directory".to_string());
            report(&progress);

            analyze_exception_functions(pe)
        } else {
            Vec::new()
        };
        let metadata_data = if config.emit_revdmp {
            progress.stage = ProgressStage::BuildingMetadata;
            progress.current = 7;
            progress.total = 7;
            progress.current_item = Some("Encoding metadata section".to_string());
            report(&progress);

            build_revdmp_metadata(
                &enriched_facts,
                &heap_ptr_locs,
                stub_generator.heap_edges(),
                stub_generator.containers(),
                &indirect_calls,
                &function_pointers,
                &function_pointer_tables,
                &vtable_slots,
                &thunk_normalizations,
                &cfg_functions,
                &exception_functions,
                pe.image_base,
                &stub_generator,
            )
        } else {
            Vec::new()
        };
        let metadata_section_va = PeParser::align_up(
            heap_section_va as usize + heap_section_size,
            pe.section_alignment as usize,
        ) as u32;

        // Build output PE
        progress.stage = ProgressStage::BuildingOutput;
        progress.current_item = None;
        progress.current = 0;
        progress.total = 0;
        progress.stub_debug = None;
        progress.eh_progress = None;
        progress.devirt_progress = None;
        report(&progress);

        let (mut output, section_mappings) = self.build_output_pe(
            pe,
            &stub_generator,
            &heap_ptr_locs,
            heap_section_va,
            heap_section_size,
            metadata_section_va,
            config.emit_revdmp.then_some(metadata_data.as_slice()),
            &mut progress,
            &report,
        )?;

        // Devirtualize vcalls if enabled
        if config.enable_devirt {
            progress.stage = ProgressStage::Devirtualizing;
            progress.current_item = Some("starting".to_string());
            progress.current = 0;
            progress.total = 0;
            progress.eh_progress = None;
            progress.devirt_progress = None;
            progress.fixups_applied = 0;
            progress.fixups_skipped = 0;
            progress.protected_fixups_skipped = 0;
            report(&progress);

            let devirt_stats = self.apply_devirt(
                &mut output,
                pe,
                &vtable_facts,
                stub_generator.heap_edges(),
                &section_mappings,
                config,
                &mut progress,
                &report,
            )?;

            eprintln!(
                "Devirt: {} indirect sites found ({} global), {} resolved, {} patched",
                devirt_stats.vcalls_detected,
                devirt_stats.global_indirect_calls_detected,
                devirt_stats.vcalls_resolved,
                devirt_stats.patches_applied,
            );
        }

        // Write to file
        progress.stage = ProgressStage::WritingFile;
        progress.current = 0;
        progress.total = output.len();
        progress.current_item = None;
        progress.devirt_progress = None;
        progress.eh_progress = None;
        progress.fixups_applied = 0;
        progress.fixups_skipped = 0;
        progress.protected_fixups_skipped = 0;
        report(&progress);

        self.write_output(output_path.as_ref(), &output)?;

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
        progress.stage = ProgressStage::ProtectingExceptionData;
        progress.current_item = Some("heap scan exclusions".to_string());
        progress.eh_progress = None;
        report(progress);
        let protected_ranges = protected_exception_ranges_with_progress(pe, |eh_progress| {
            progress.stage = ProgressStage::ProtectingExceptionData;
            progress.current = eh_progress.current;
            progress.total = eh_progress.total;
            progress.eh_progress = Some(eh_progress);
            report(progress);
        });
        progress.eh_progress = None;

        // Calculate total bytes to scan
        let mut total_bytes = 0usize;
        let mut sections_to_scan = 0usize;

        for (idx, section) in pe.sections.iter().enumerate() {
            if config.skip_sections.contains(&idx) || !should_scan_for_heap_pointers(section) {
                continue;
            }
            let scan_ranges = unprotected_section_ranges(section, &protected_ranges);
            if scan_ranges.is_empty() {
                continue;
            }
            total_bytes += scan_ranges
                .iter()
                .map(|range| (range.end - range.start).min(0x2000_0000) as usize)
                .sum::<usize>();
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
            if config.skip_sections.contains(&idx) || !should_scan_for_heap_pointers(section) {
                continue;
            }
            let scan_ranges = unprotected_section_ranges(section, &protected_ranges);
            if scan_ranges.is_empty() {
                continue;
            }

            progress.current_item = Some(section.name.clone());
            progress.current = section_idx;
            report(progress);

            for scan_range in scan_ranges {
                let scan_size = ((scan_range.end - scan_range.start) as usize).min(0x2000_0000);
                let scan_addr = unsafe { self.base.add(scan_range.start as usize) };

                let mut chunk_off = 0;
                while chunk_off < scan_size {
                    let read_size = CHUNK_SIZE.min(scan_size - chunk_off);
                    let chunk_ptr = unsafe { scan_addr.add(chunk_off) };

                    if is_memory_readable(chunk_ptr, read_size) {
                        let buffer = unsafe { std::slice::from_raw_parts(chunk_ptr, read_size) };
                        let base_rva = scan_range.start + chunk_off as u32;

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
        metadata_data: Option<&[u8]>,
        progress: &mut ProgressInfo,
        report: &impl Fn(&ProgressInfo),
    ) -> Result<(Vec<u8>, Vec<SectionMapping>)> {
        // Calculate sizes
        let has_metadata = metadata_data.is_some();
        let metadata_data = metadata_data.unwrap_or(&[]);
        let num_sections = pe.sections.len() + 1 + usize::from(has_metadata); // +.heap, optional .revdmp
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

        // Build embedded binary metadata for native analysis consumers.
        let metadata_raw_size = if has_metadata {
            PeParser::align_up(metadata_data.len(), pe.file_alignment as usize)
        } else {
            0
        };
        let metadata_raw_offset = if has_metadata {
            let offset = current_raw_offset as u32;
            current_raw_offset += metadata_raw_size;
            offset
        } else {
            0
        };

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
        let image_end = if has_metadata {
            metadata_section_va + metadata_data.len() as u32
        } else {
            heap_section_va + heap_section_size as u32
        };
        let new_size_of_image =
            PeParser::align_up(image_end as usize, pe.section_alignment as usize) as u32;

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
        if has_metadata {
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
        if has_metadata {
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
                    s.characteristics,
                )
            })
            .collect();

        progress.stage = ProgressStage::ProtectingExceptionData;
        progress.current_item = Some("fixup exclusions".to_string());
        progress.eh_progress = None;
        report(progress);
        let protected_ranges = protected_exception_ranges_with_progress(pe, |eh_progress| {
            progress.stage = ProgressStage::ProtectingExceptionData;
            progress.current = eh_progress.current;
            progress.total = eh_progress.total;
            progress.eh_progress = Some(eh_progress);
            report(progress);
        });
        progress.eh_progress = None;
        let exception_snapshot = exception_directory_file_range(pe, &section_mappings)
            .filter(|range| range.end <= output.len())
            .map(|range| (range.clone(), output[range].to_vec()));

        let first_section_rva = sections_info
            .iter()
            .map(|s| s.virtual_address)
            .min()
            .unwrap_or(0);

        progress.stage = ProgressStage::ApplyingFixups;
        progress.current_item = Some("heap pointer fixups".to_string());
        progress.current = 0;
        progress.total = fixups.len();
        progress.fixups_applied = 0;
        progress.fixups_skipped = 0;
        progress.protected_fixups_skipped = 0;
        report(progress);

        let fixup_stats = apply_fixups(
            &mut output,
            &fixups,
            &section_mappings,
            &protected_ranges,
            first_section_rva,
            aligned_headers,
        );
        progress.current = fixups.len();
        progress.fixups_applied = fixup_stats.applied;
        progress.fixups_skipped = fixup_stats.skipped;
        progress.protected_fixups_skipped = fixup_stats.protected_skipped;
        report(progress);

        if let Some((range, original_bytes)) = exception_snapshot {
            if output[range.clone()] != original_bytes[..] {
                output[range].copy_from_slice(&original_bytes);
                eprintln!("Restored exception directory after blocked unsafe heap fixups");
            }
        }

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
        heap_edges: &[HeapPointerEdge],
        section_mappings: &[SectionMapping],
        config: &DumpConfig,
        progress: &mut ProgressInfo,
        report: &impl Fn(&ProgressInfo),
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
        let num_sections = pe.sections.len() + 1 + usize::from(config.emit_revdmp);
        let headers_size = pe.pe_offset as usize
            + 4  // PE signature
            + std::mem::size_of::<FileHeader>()
            + pe.size_of_optional_header as usize
            + num_sections * std::mem::size_of::<SectionHeader>();
        let aligned_headers = PeParser::align_up(headers_size, pe.file_alignment as usize);

        // Call devirtualization
        devirt::devirtualize_with_progress(
            output,
            self.base,
            pe.image_base,
            text_section.virtual_address,
            text_section.virtual_size,
            vtable_facts,
            heap_edges,
            section_mappings,
            aligned_headers,
            &config.effective_devirt_config(),
            |devirt_progress| {
                progress.stage = ProgressStage::Devirtualizing;
                progress.current_item = Some(devirt_progress.phase.to_string());
                progress.current = devirt_progress.current;
                progress.total = devirt_progress.total;
                progress.bytes_processed = devirt_progress.current;
                progress.total_bytes = devirt_progress.total;
                progress.devirt_progress = Some(devirt_progress);
                report(progress);
            },
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
    use crate::stub::{VtableRef, VtableStub};

    struct ParsedRevdmp {
        image_base: u64,
        strings: Vec<u8>,
        blocks: BTreeMap<u32, Vec<Vec<u8>>>,
    }

    impl ParsedRevdmp {
        fn block(&self, kind: u32) -> &[Vec<u8>] {
            self.blocks.get(&kind).map(Vec::as_slice).unwrap_or(&[])
        }

        fn string(&self, offset: u32) -> &str {
            let offset = offset as usize;
            let end = self.strings[offset..]
                .iter()
                .position(|&byte| byte == 0)
                .map(|pos| offset + pos)
                .unwrap();
            std::str::from_utf8(&self.strings[offset..end]).unwrap()
        }
    }

    fn read_u32(record: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(record[offset..offset + 4].try_into().unwrap())
    }

    fn read_u64(record: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(record[offset..offset + 8].try_into().unwrap())
    }

    fn read_i32(record: &[u8], offset: usize) -> i32 {
        i32::from_le_bytes(record[offset..offset + 4].try_into().unwrap())
    }

    fn parse_revdmp(data: &[u8]) -> ParsedRevdmp {
        assert!(data.starts_with(REVDMP_BINARY_MAGIC));
        assert!(data.len() >= REVDMP_HEADER_SIZE);
        assert_eq!(
            data[REVDMP_CHECKSUM_OFFSET..REVDMP_HEADER_SIZE],
            revdmp_checksum(data)
        );
        let mut offset = REVDMP_BINARY_MAGIC.len();
        assert_eq!(read_u32(data, offset), REVDMP_BINARY_VERSION);
        offset += 4;
        assert_eq!(read_u32(data, offset), REVDMP_ENDIAN_MARKER);
        offset += 4;
        let block_count = read_u32(data, offset) as usize;
        offset += 4;
        let string_len = read_u32(data, offset) as usize;
        offset += 4;
        let image_base = read_u64(data, offset);
        offset += 8;
        assert_eq!(read_u32(data, offset), REVDMP_CHECKSUM_KIND_SHA256);
        offset += 4;
        assert_eq!(read_u32(data, offset), 0);
        offset = REVDMP_HEADER_SIZE;

        let mut blocks = BTreeMap::new();
        for _ in 0..block_count {
            let kind = read_u32(data, offset);
            offset += 4;
            let record_size = read_u32(data, offset) as usize;
            offset += 4;
            let count = read_u32(data, offset) as usize;
            offset += 4;
            let data_len = read_u32(data, offset) as usize;
            offset += 4;
            assert_eq!(data_len, record_size * count);

            let mut records = Vec::with_capacity(count);
            for record in data[offset..offset + data_len].chunks_exact(record_size) {
                records.push(record.to_vec());
            }
            offset += data_len;
            blocks.insert(kind, records);
        }

        let strings = data[offset..offset + string_len].to_vec();
        assert_eq!(strings[0], 0);
        ParsedRevdmp {
            image_base,
            strings,
            blocks,
        }
    }

    #[test]
    fn test_dump_config_default() {
        let config = DumpConfig::default();
        assert_eq!(config.max_vfptr_probe, 256);
        assert!(config.skip_sections.is_empty());
        assert!(config.enable_devirt);
        assert_eq!(config.recursive_heap_scan_depth, 4);
        assert_eq!(config.max_graph_edges, 100_000);
        assert!(config.strong_devirt);
    }

    #[test]
    fn test_dump_config_skip_code() {
        let config = DumpConfig::skip_code();
        assert_eq!(config.skip_sections, vec![0]);
    }

    #[test]
    fn test_heap_pointer_scan_uses_non_executable_data_sections() {
        let mut section = SectionInfo {
            name: ".rdata".to_string(),
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x1000,
            pointer_to_raw_data: 0x400,
            characteristics: 0,
            new_pointer_to_raw_data: 0,
            new_size_of_raw_data: 0,
        };

        assert!(should_scan_for_heap_pointers(&section));
        let protected = 0x1200..0x1400;
        assert_eq!(
            unprotected_section_ranges(&section, std::slice::from_ref(&protected)),
            vec![0x1000..0x1200, 0x1400..0x2000]
        );

        section.name = ".text".to_string();
        section.characteristics = IMAGE_SCN_MEM_EXECUTE;
        assert!(!should_scan_for_heap_pointers(&section));
    }

    #[test]
    fn test_revdmp_metadata_lists_heap_only_and_sourced_facts() {
        let facts = vec![
            EnrichedVtableFact {
                type_name: Some("AudioService".to_string()),
                msvc_rtti: Some(MsvcRttiFact {
                    vtable_rva: 0x5000,
                    col_rva: 0x4800,
                    object_offset: 0,
                    constructor_displacement: 0,
                    type_descriptor_rva: 0x4900,
                    type_name: "AudioService".to_string(),
                    hierarchy_rva: Some(0x4A00),
                    hierarchy_attributes: 3,
                    base_classes: vec![MsvcBaseClassFact {
                        type_name: "IService".to_string(),
                        type_descriptor_rva: 0x4B00,
                        num_contained_bases: 1,
                        mdisp: 0,
                        pdisp: -1,
                        vdisp: 0,
                        attributes: 0x40,
                    }],
                }),
                fact: VtableFact {
                    source_rva: Some(0x2000),
                    heap_addr: 0x1000_0000,
                    stub_rva: 0x8000,
                    vfptr_offset: 0x20,
                    vtable_rva: 0x5000,
                },
            },
            EnrichedVtableFact {
                type_name: Some("Mixer".to_string()),
                msvc_rtti: None,
                fact: VtableFact {
                    source_rva: None,
                    heap_addr: 0x2000_0000,
                    stub_rva: 0x9000,
                    vfptr_offset: 0,
                    vtable_rva: 0x7000,
                },
            },
        ];
        let stub_generator = StubGenerator::from_test_stubs(
            0x1400_0000,
            0x100000,
            vec![
                VtableStub {
                    original_addr: 0x1000_0000,
                    size: 0x28,
                    data: vec![0; 0x28],
                    new_rva: 0x8000,
                    vtable_refs: vec![VtableRef {
                        offset: 0x20,
                        vtable_rva: 0x5000,
                    }],
                    vfptr_offsets: [0x20].into_iter().collect(),
                },
                VtableStub {
                    original_addr: 0x2000_0000,
                    size: 0x8,
                    data: vec![0; 0x8],
                    new_rva: 0x9000,
                    vtable_refs: vec![VtableRef {
                        offset: 0,
                        vtable_rva: 0x7000,
                    }],
                    vfptr_offsets: [0].into_iter().collect(),
                },
            ],
        );
        let indirect_calls = vec![IndirectCallFact {
            instruction_rva: 0x1234,
            instruction_len: 6,
            global_rva: 0x3000,
            target_rva: 0x4560,
            target_va: 0x1400_4560,
            kind: VcallKind::GlobalIndirectCall,
            via_register: false,
            confidence: "high",
            reason: "rip_relative_global_function_pointer",
        }];
        let function_pointers = vec![FunctionPointerFact {
            location_rva: 0x6000,
            location_va: 0x1400_6000,
            section_name: ".rdata".to_string(),
            kind: "callback_slot",
            table_id: None,
            index: None,
            target_rva: 0x4560,
            target_va: 0x1400_4560,
            confidence: "medium",
            reason: "isolated_code_pointer",
        }];
        let function_pointer_tables = vec![FunctionPointerTableFact {
            id: "fptable_00006100".to_string(),
            start_rva: 0x6100,
            start_va: 0x1400_6100,
            section_name: ".rdata".to_string(),
            entry_count: 2,
            target_rvas: vec![0x4560, 0x4570],
            confidence: "high",
            reason: "contiguous_code_pointer_run",
        }];
        let vtable_slots = vec![VtableSlotFact {
            vtable_rva: 0x5000,
            type_name: Some("AudioService".to_string()),
            slot_index: 0,
            slot_offset: 0,
            entry_rva: 0x7100,
            entry_va: 0x1400_7100,
            normalized_target_rva: 0x7200,
            normalized_target_va: 0x1400_7200,
            slot_kind: "adjustor_thunk",
            target_kind: "normalized_function",
            function_symbol: "AudioService::tick".to_string(),
            confidence: "high",
            reason: "this_adjustment_then_jump",
        }];
        let thunk_normalizations = vec![ThunkNormalizationFact {
            thunk_rva: 0x7100,
            thunk_va: 0x1400_7100,
            normalized_target_rva: 0x7200,
            normalized_target_va: 0x1400_7200,
            thunk_kind: "adjustor_thunk",
            instruction_len: 9,
            this_adjustment: Some(-8),
            confidence: "high",
            reason: "this_adjustment_then_jump",
        }];
        let cfg_functions = vec![CfgFunctionFact {
            table_rva: 0x7300,
            entry_index: 0,
            entry_rva: 0x7300,
            raw_entry: 0x7200,
            target_rva: 0x7200,
            target_va: 0x1400_7200,
            suppressed: false,
            export_suppressed: false,
            guard_flags: 0x500,
            confidence: "high",
            reason: "pe_load_config_guard_cf_function_table",
        }];
        let exception_functions = vec![ExceptionFunctionFact {
            entry_rva: 0x7400,
            begin_rva: 0x7200,
            end_rva: 0x7250,
            unwind_info_rva: 0x7500,
            unwind_flags: 1,
            unwind_flag_names: "EHANDLER".to_string(),
            prolog_size: 4,
            unwind_code_count: 0,
            frame_register: 0,
            frame_offset: 0,
            handler_rva: Some(0x7600),
            handler_va: Some(0x1400_7600),
            chained_begin_rva: None,
            chained_end_rva: None,
            chained_unwind_info_rva: None,
            confidence: "high",
            reason: "x64_unwind_info_with_handler",
        }];

        let metadata = build_revdmp_metadata(
            &facts,
            &[(0x2000, 0x1000_0000)],
            &[HeapPointerEdge {
                source_heap_addr: 0x1000_0000,
                field_offset: 0x18,
                target_heap_addr: 0x2000_0000,
                confidence: EdgeConfidence::Low,
                reason: "raw_heap_pointer",
                target_has_vtable: true,
            }],
            &[ContainerFact {
                source_heap_addr: 0x1000_0000,
                field_offset: 0x30,
                kind: "vector_triple",
                element_count: 1,
                targets: vec![0x2000_0000],
            }],
            &indirect_calls,
            &function_pointers,
            &function_pointer_tables,
            &vtable_slots,
            &thunk_normalizations,
            &cfg_functions,
            &exception_functions,
            0x1400_0000,
            &stub_generator,
        );
        let parsed = parse_revdmp(&metadata);
        assert_eq!(parsed.image_base, 0x1400_0000);

        let mut corrupted = metadata.clone();
        corrupted[REVDMP_HEADER_SIZE] ^= 0x80;
        assert_ne!(
            corrupted[REVDMP_CHECKSUM_OFFSET..REVDMP_HEADER_SIZE],
            revdmp_checksum(&corrupted)
        );

        let objects = parsed.block(BLOCK_OBJECTS);
        assert_eq!(objects.len(), 2);
        assert_eq!(parsed.string(read_u32(&objects[0], 0)), "obj_00008000");
        assert_eq!(read_u64(&objects[0], 4), 0x1000_0000);
        assert_eq!(read_u32(&objects[0], 12), 0x8000);
        assert_eq!(read_u64(&objects[0], 16), 0x1400_8000);
        assert_eq!(read_u32(&objects[0], 24), 0x28);
        assert_eq!(read_u32(&objects[0], 28), 1);
        assert_eq!(parsed.string(read_u32(&objects[0], 32)), "0x20");
        assert_eq!(parsed.string(read_u32(&objects[0], 36)), "0x5000");
        assert_eq!(parsed.string(read_u32(&objects[0], 40)), "AudioService");
        assert_eq!(parsed.string(read_u32(&objects[0], 44)), "0x2000");
        assert_eq!(read_u32(&objects[0], 52), 1);
        assert_eq!(read_u32(&objects[0], 56), 1);
        assert_eq!(parsed.string(read_u32(&objects[0], 64)), "rtti_confirmed");
        assert_eq!(
            parsed.string(read_u32(&objects[0], 68)),
            "module_pointer_scan"
        );

        let vtable_facts = parsed.block(BLOCK_VTABLE_FACTS);
        assert_eq!(vtable_facts.len(), 2);
        assert_eq!(read_u32(&vtable_facts[0], 0), 0x2000);
        assert_eq!(read_u64(&vtable_facts[0], 4), 0x1000_0000);
        assert_eq!(read_u32(&vtable_facts[0], 12), 0x8000);
        assert_eq!(read_u32(&vtable_facts[0], 16), 0x20);
        assert_eq!(read_u32(&vtable_facts[0], 20), 0x5000);
        assert_eq!(read_u64(&vtable_facts[0], 24), 0x1400_5000);
        assert_eq!(
            parsed.string(read_u32(&vtable_facts[0], 32)),
            "AudioService"
        );
        assert_eq!(read_u32(&vtable_facts[1], 0), REVDMP_NONE_U32);

        let rtti = parsed.block(BLOCK_MSVC_RTTI);
        assert_eq!(rtti.len(), 1);
        assert_eq!(read_u32(&rtti[0], 0), 0x5000);
        assert_eq!(read_u32(&rtti[0], 4), 0x4800);
        assert_eq!(parsed.string(read_u32(&rtti[0], 20)), "AudioService");
        assert_eq!(read_u32(&rtti[0], 24), 0x4A00);
        assert_eq!(read_u32(&rtti[0], 32), 1);

        let bases = parsed.block(BLOCK_MSVC_BASE_CLASSES);
        assert_eq!(bases.len(), 1);
        assert_eq!(read_u32(&bases[0], 0), 0x5000);
        assert_eq!(parsed.string(read_u32(&bases[0], 4)), "IService");
        assert_eq!(read_i32(&bases[0], 20), -1);
        assert_eq!(read_u32(&bases[0], 28), 0x40);

        let globals = parsed.block(BLOCK_GLOBAL_POINTERS);
        assert_eq!(globals.len(), 1);
        assert_eq!(read_u32(&globals[0], 0), 0x2000);
        assert_eq!(read_u64(&globals[0], 4), 0x1000_0000);
        assert_eq!(read_u32(&globals[0], 12), 0x8000);
        assert_eq!(globals[0][16], 1);

        let heap_edges = parsed.block(BLOCK_HEAP_EDGES);
        assert_eq!(heap_edges.len(), 1);
        assert_eq!(read_u64(&heap_edges[0], 0), 0x1000_0000);
        assert_eq!(read_u32(&heap_edges[0], 12), 0x18);
        assert_eq!(read_u64(&heap_edges[0], 16), 0x2000_0000);
        assert_eq!(
            parsed.string(read_u32(&heap_edges[0], 36)),
            "raw_heap_pointer"
        );

        let containers = parsed.block(BLOCK_CONTAINERS);
        assert_eq!(containers.len(), 1);
        assert_eq!(parsed.string(read_u32(&containers[0], 16)), "vector_triple");
        assert_eq!(read_u32(&containers[0], 20), 1);
        assert_eq!(parsed.string(read_u32(&containers[0], 24)), "0x20000000");

        let field_types = parsed.block(BLOCK_FIELD_TYPES);
        assert_eq!(field_types.len(), 4);
        assert_eq!(parsed.string(read_u32(&field_types[0], 0)), "obj_00008000");
        assert_eq!(read_u32(&field_types[0], 16), 0x20);
        assert_eq!(parsed.string(read_u32(&field_types[0], 20)), "vfptr");
        assert_eq!(parsed.string(read_u32(&field_types[1], 20)), "vfptr");
        assert_eq!(
            parsed.string(read_u32(&field_types[2], 20)),
            "object_pointer"
        );
        assert_eq!(
            parsed.string(read_u32(&field_types[3], 20)),
            "vector_triple"
        );

        let container_elements = parsed.block(BLOCK_CONTAINER_ELEMENTS);
        assert_eq!(container_elements.len(), 1);
        assert_eq!(
            parsed.string(read_u32(&container_elements[0], 0)),
            "container_0000000010000000_30"
        );
        assert_eq!(read_u32(&container_elements[0], 24), 0);
        assert_eq!(read_u64(&container_elements[0], 28), 0x2000_0000);

        let indirect_calls = parsed.block(BLOCK_INDIRECT_CALLS);
        assert_eq!(indirect_calls.len(), 1);
        assert_eq!(read_u32(&indirect_calls[0], 0), 0x1234);
        assert_eq!(read_u32(&indirect_calls[0], 4), 6);
        assert_eq!(parsed.string(read_u32(&indirect_calls[0], 8)), "call");
        assert_eq!(read_u32(&indirect_calls[0], 16), 0x4560);
        assert_eq!(read_u64(&indirect_calls[0], 20), 0x1400_4560);

        let function_pointers = parsed.block(BLOCK_FUNCTION_POINTERS);
        assert_eq!(function_pointers.len(), 1);
        assert_eq!(read_u32(&function_pointers[0], 0), 0x6000);
        assert_eq!(parsed.string(read_u32(&function_pointers[0], 12)), ".rdata");
        assert_eq!(
            parsed.string(read_u32(&function_pointers[0], 16)),
            "callback_slot"
        );
        assert_eq!(read_u32(&function_pointers[0], 24), REVDMP_NONE_U32);
        assert_eq!(read_u32(&function_pointers[0], 28), 0x4560);

        let function_pointer_tables = parsed.block(BLOCK_FUNCTION_POINTER_TABLES);
        assert_eq!(function_pointer_tables.len(), 1);
        assert_eq!(
            parsed.string(read_u32(&function_pointer_tables[0], 0)),
            "fptable_00006100"
        );
        assert_eq!(read_u32(&function_pointer_tables[0], 20), 2);
        assert_eq!(
            parsed.string(read_u32(&function_pointer_tables[0], 24)),
            "0x4560;0x4570"
        );

        let slots = parsed.block(BLOCK_VTABLE_SLOTS);
        assert_eq!(slots.len(), 1);
        assert_eq!(read_u32(&slots[0], 0), 0x5000);
        assert_eq!(parsed.string(read_u32(&slots[0], 4)), "AudioService");
        assert_eq!(read_u32(&slots[0], 16), 0x7100);
        assert_eq!(read_u32(&slots[0], 28), 0x7200);
        assert_eq!(parsed.string(read_u32(&slots[0], 40)), "adjustor_thunk");
        assert_eq!(parsed.string(read_u32(&slots[0], 48)), "AudioService::tick");

        let thunks = parsed.block(BLOCK_THUNK_NORMALIZATIONS);
        assert_eq!(thunks.len(), 1);
        assert_eq!(read_u32(&thunks[0], 0), 0x7100);
        assert_eq!(read_u32(&thunks[0], 28), 9);
        assert_eq!(read_i32(&thunks[0], 32), -8);
        assert_eq!(thunks[0][36], 1);

        let cfg = parsed.block(BLOCK_CFG_FUNCTIONS);
        assert_eq!(cfg.len(), 1);
        assert_eq!(read_u32(&cfg[0], 0), 0x7300);
        assert_eq!(read_u32(&cfg[0], 16), 0x7200);
        assert_eq!(cfg[0][28], 0);
        assert_eq!(read_u32(&cfg[0], 32), 0x500);

        let exceptions = parsed.block(BLOCK_EXCEPTION_FUNCTIONS);
        assert_eq!(exceptions.len(), 1);
        assert_eq!(read_u32(&exceptions[0], 0), 0x7400);
        assert_eq!(read_u32(&exceptions[0], 4), 0x7200);
        assert_eq!(exceptions[0][16], 1);
        assert_eq!(exceptions[0][21], 1);
        assert_eq!(read_u32(&exceptions[0], 24), 0x7600);
        assert_eq!(read_u64(&exceptions[0], 28), 0x1400_7600);
        assert_eq!(parsed.string(read_u32(&exceptions[0], 48)), "EHANDLER");

        let synthetic_structs = parsed.block(BLOCK_SYNTHETIC_STRUCTS);
        assert_eq!(synthetic_structs.len(), 2);
        assert_eq!(read_u32(&synthetic_structs[0], 0), 0x8000);
        assert_eq!(
            parsed.string(read_u32(&synthetic_structs[0], 12)),
            "revdump_obj_8000"
        );
        assert_eq!(parsed.string(read_u32(&synthetic_structs[0], 20)), "0x20");
    }

    #[test]
    fn test_itanium_rtti_type_name_resolution() {
        let mut module = vec![0u8; 0x1000];
        let image_base = module.as_ptr() as u64;
        let vtable_rva = 0x300u32;
        let typeinfo_rva = 0x500u32;
        let name_rva = 0x600u32;

        module[vtable_rva as usize - 8..vtable_rva as usize]
            .copy_from_slice(&(image_base + typeinfo_rva as u64).to_le_bytes());
        module[typeinfo_rva as usize + 8..typeinfo_rva as usize + 16]
            .copy_from_slice(&(image_base + name_rva as u64).to_le_bytes());
        module[name_rva as usize..name_rva as usize + 15].copy_from_slice(b"12AudioService\0");

        let pe = PeParser {
            base: module.as_ptr(),
            size: module.len(),
            pe_offset: 0,
            machine: 0x8664,
            number_of_sections: 0,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
            characteristics: 0,
            image_base,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: module.len() as u32,
            size_of_headers: 0,
            is_64bit: true,
            optional_header_raw: Vec::new(),
            coff_symbol_table_raw: Vec::new(),
            sections: Vec::new(),
        };

        assert_eq!(
            resolve_vtable_type_name(&pe, vtable_rva, &HashMap::new()).as_deref(),
            Some("AudioService")
        );
    }

    #[test]
    fn test_msvc_rtti_hierarchy_resolution() {
        let mut module = vec![0u8; 0x1000];
        let image_base = module.as_ptr() as u64;
        let vtable_rva = 0x300u32;
        let col_rva = 0x400u32;
        let derived_type_rva = 0x500u32;
        let hierarchy_rva = 0x620u32;
        let base_array_rva = 0x660u32;
        let derived_base_rva = 0x680u32;
        let base_base_rva = 0x6A0u32;
        let base_type_rva = 0x700u32;

        fn write_u32(buf: &mut [u8], rva: u32, value: u32) {
            buf[rva as usize..rva as usize + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn write_i32(buf: &mut [u8], rva: u32, value: i32) {
            buf[rva as usize..rva as usize + 4].copy_from_slice(&value.to_le_bytes());
        }

        module[vtable_rva as usize - 8..vtable_rva as usize]
            .copy_from_slice(&(image_base + col_rva as u64).to_le_bytes());

        write_u32(&mut module, col_rva, 1); // image-relative COL
        write_u32(&mut module, col_rva + 4, 0);
        write_u32(&mut module, col_rva + 8, 0);
        write_u32(&mut module, col_rva + 12, derived_type_rva);
        write_u32(&mut module, col_rva + 16, hierarchy_rva);
        write_u32(&mut module, col_rva + 20, col_rva);

        module[derived_type_rva as usize + 16..derived_type_rva as usize + 30]
            .copy_from_slice(b".?AVDerived@@\0");
        module[base_type_rva as usize + 16..base_type_rva as usize + 27]
            .copy_from_slice(b".?AVBase@@\0");

        write_u32(&mut module, hierarchy_rva, 0);
        write_u32(&mut module, hierarchy_rva + 4, 3);
        write_u32(&mut module, hierarchy_rva + 8, 2);
        write_u32(&mut module, hierarchy_rva + 12, base_array_rva);

        write_u32(&mut module, base_array_rva, derived_base_rva);
        write_u32(&mut module, base_array_rva + 4, base_base_rva);

        write_u32(&mut module, derived_base_rva, derived_type_rva);
        write_u32(&mut module, derived_base_rva + 4, 2);
        write_i32(&mut module, derived_base_rva + 8, 0);
        write_i32(&mut module, derived_base_rva + 12, -1);
        write_i32(&mut module, derived_base_rva + 16, 0);
        write_u32(&mut module, derived_base_rva + 20, 0);

        write_u32(&mut module, base_base_rva, base_type_rva);
        write_u32(&mut module, base_base_rva + 4, 1);
        write_i32(&mut module, base_base_rva + 8, 0x10);
        write_i32(&mut module, base_base_rva + 12, -1);
        write_i32(&mut module, base_base_rva + 16, 0);
        write_u32(&mut module, base_base_rva + 20, 0x40);

        let pe = PeParser {
            base: module.as_ptr(),
            size: module.len(),
            pe_offset: 0,
            machine: 0x8664,
            number_of_sections: 0,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
            characteristics: 0,
            image_base,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: module.len() as u32,
            size_of_headers: 0,
            is_64bit: true,
            optional_header_raw: Vec::new(),
            coff_symbol_table_raw: Vec::new(),
            sections: Vec::new(),
        };

        let rtti = resolve_msvc_rtti_fact(&pe, vtable_rva).unwrap();
        assert_eq!(rtti.type_name, "Derived");
        assert_eq!(rtti.hierarchy_rva, Some(hierarchy_rva));
        assert_eq!(rtti.hierarchy_attributes, 3);
        assert_eq!(rtti.base_classes.len(), 2);
        assert_eq!(rtti.base_classes[1].type_name, "Base");
        assert_eq!(rtti.base_classes[1].mdisp, 0x10);
        assert_eq!(rtti.base_classes[1].attributes, 0x40);
    }

    #[test]
    fn test_function_pointer_table_analysis() {
        let mut module = vec![0u8; 0x1000];
        let image_base = module.as_ptr() as u64;
        let text_rva = 0x100u32;
        let rdata_rva = 0x400u32;

        module[rdata_rva as usize..rdata_rva as usize + 8]
            .copy_from_slice(&(image_base + 0x110).to_le_bytes());
        module[rdata_rva as usize + 8..rdata_rva as usize + 16]
            .copy_from_slice(&(image_base + 0x120).to_le_bytes());
        module[rdata_rva as usize + 0x20..rdata_rva as usize + 0x28]
            .copy_from_slice(&(image_base + 0x130).to_le_bytes());

        let pe = PeParser {
            base: module.as_ptr(),
            size: module.len(),
            pe_offset: 0,
            machine: 0x8664,
            number_of_sections: 2,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
            characteristics: 0,
            image_base,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: module.len() as u32,
            size_of_headers: 0,
            is_64bit: true,
            optional_header_raw: Vec::new(),
            coff_symbol_table_raw: Vec::new(),
            sections: vec![
                SectionInfo {
                    name: ".text".to_string(),
                    virtual_size: 0x100,
                    virtual_address: text_rva,
                    size_of_raw_data: 0x100,
                    pointer_to_raw_data: 0,
                    characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE,
                    new_pointer_to_raw_data: 0,
                    new_size_of_raw_data: 0,
                },
                SectionInfo {
                    name: ".rdata".to_string(),
                    virtual_size: 0x80,
                    virtual_address: rdata_rva,
                    size_of_raw_data: 0x80,
                    pointer_to_raw_data: 0,
                    characteristics: 0,
                    new_pointer_to_raw_data: 0,
                    new_size_of_raw_data: 0,
                },
            ],
        };

        let (pointers, tables) = analyze_function_pointer_tables(&pe);

        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].id, "fptable_00000400");
        assert_eq!(tables[0].target_rvas, vec![0x110, 0x120]);
        assert_eq!(pointers.len(), 3);
        assert_eq!(pointers[0].kind, "table_entry");
        assert_eq!(pointers[0].table_id.as_deref(), Some("fptable_00000400"));
        assert_eq!(pointers[2].kind, "callback_slot");
        assert_eq!(pointers[2].target_rva, 0x130);
    }

    #[test]
    fn test_vtable_slot_analysis_normalizes_adjustor_thunk() {
        let mut module = vec![0u8; 0x1000];
        let image_base = module.as_ptr() as u64;
        let text_rva = 0x100u32;
        let thunk_rva = 0x120u32;
        let target_rva = 0x180u32;
        let direct_rva = 0x190u32;
        let vtable_rva = 0x400u32;

        module[vtable_rva as usize..vtable_rva as usize + 8]
            .copy_from_slice(&(image_base + thunk_rva as u64).to_le_bytes());
        module[vtable_rva as usize + 8..vtable_rva as usize + 16]
            .copy_from_slice(&(image_base + direct_rva as u64).to_le_bytes());

        module[thunk_rva as usize..thunk_rva as usize + 4]
            .copy_from_slice(&[0x48, 0x83, 0xE9, 0x08]);
        let jump_rva = thunk_rva + 4;
        let rel = target_rva as i32 - (jump_rva as i32 + 5);
        module[jump_rva as usize] = 0xE9;
        module[jump_rva as usize + 1..jump_rva as usize + 5].copy_from_slice(&rel.to_le_bytes());
        module[target_rva as usize] = 0xC3;
        module[direct_rva as usize] = 0xC3;

        let pe = PeParser {
            base: module.as_ptr(),
            size: module.len(),
            pe_offset: 0,
            machine: 0x8664,
            number_of_sections: 2,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
            characteristics: 0,
            image_base,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: module.len() as u32,
            size_of_headers: 0,
            is_64bit: true,
            optional_header_raw: Vec::new(),
            coff_symbol_table_raw: Vec::new(),
            sections: vec![
                SectionInfo {
                    name: ".text".to_string(),
                    virtual_size: 0x200,
                    virtual_address: text_rva,
                    size_of_raw_data: 0x200,
                    pointer_to_raw_data: 0,
                    characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE,
                    new_pointer_to_raw_data: 0,
                    new_size_of_raw_data: 0,
                },
                SectionInfo {
                    name: ".rdata".to_string(),
                    virtual_size: 0x100,
                    virtual_address: vtable_rva,
                    size_of_raw_data: 0x100,
                    pointer_to_raw_data: 0,
                    characteristics: 0,
                    new_pointer_to_raw_data: 0,
                    new_size_of_raw_data: 0,
                },
            ],
        };
        let facts = vec![EnrichedVtableFact {
            type_name: Some("AudioService".to_string()),
            msvc_rtti: None,
            fact: VtableFact {
                source_rva: Some(0x500),
                heap_addr: 0x1000_0000,
                stub_rva: 0x8000,
                vfptr_offset: 0,
                vtable_rva,
            },
        }];

        let (slots, thunks) = analyze_vtable_slots(&pe, &facts);

        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].entry_rva, thunk_rva);
        assert_eq!(slots[0].normalized_target_rva, target_rva);
        assert_eq!(slots[0].slot_kind, "adjustor_thunk");
        assert_eq!(slots[0].target_kind, "normalized_function");
        assert_eq!(slots[1].entry_rva, direct_rva);
        assert_eq!(slots[1].slot_kind, "virtual_function");
        assert_eq!(thunks.len(), 1);
        assert_eq!(thunks[0].thunk_rva, thunk_rva);
        assert_eq!(thunks[0].normalized_target_rva, target_rva);
        assert_eq!(thunks[0].this_adjustment, Some(-8));
        assert_eq!(thunks[0].instruction_len, 9);
    }

    #[test]
    fn test_cfg_and_exception_metadata_analysis() {
        fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
            buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
            buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        let mut module = vec![0u8; 0x1000];
        let image_base = module.as_ptr() as u64;
        let load_config_rva = 0x500usize;
        let cfg_table_rva = 0x600usize;
        let exception_rva = 0x700usize;
        let unwind_info_rva = 0x800usize;

        write_u32(&mut module, load_config_rva, 148);
        write_u64(
            &mut module,
            load_config_rva + 128,
            image_base + cfg_table_rva as u64,
        );
        write_u64(&mut module, load_config_rva + 136, 2);
        write_u32(&mut module, load_config_rva + 144, 0x500);
        write_u32(&mut module, cfg_table_rva, 0x120);
        write_u32(&mut module, cfg_table_rva + 4, 0x181);

        write_u32(&mut module, exception_rva, 0x120);
        write_u32(&mut module, exception_rva + 4, 0x150);
        write_u32(&mut module, exception_rva + 8, unwind_info_rva as u32);
        module[unwind_info_rva] = 0x09;
        module[unwind_info_rva + 1] = 4;
        module[unwind_info_rva + 2] = 0;
        module[unwind_info_rva + 3] = 0;
        write_u32(&mut module, unwind_info_rva + 4, 0x190);

        let mut optional_header_raw = vec![0u8; 112 + 16 * 8];
        write_u32(&mut optional_header_raw, 108, 16);
        write_u32(
            &mut optional_header_raw,
            112 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8,
            exception_rva as u32,
        );
        write_u32(
            &mut optional_header_raw,
            112 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8 + 4,
            12,
        );
        write_u32(
            &mut optional_header_raw,
            112 + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8,
            load_config_rva as u32,
        );
        write_u32(
            &mut optional_header_raw,
            112 + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8 + 4,
            148,
        );

        let pe = PeParser {
            base: module.as_ptr(),
            size: module.len(),
            pe_offset: 0,
            machine: 0x8664,
            number_of_sections: 3,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: optional_header_raw.len() as u16,
            characteristics: 0,
            image_base,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: module.len() as u32,
            size_of_headers: 0,
            is_64bit: true,
            optional_header_raw,
            coff_symbol_table_raw: Vec::new(),
            sections: vec![
                SectionInfo {
                    name: ".text".to_string(),
                    virtual_size: 0x200,
                    virtual_address: 0x100,
                    size_of_raw_data: 0x200,
                    pointer_to_raw_data: 0,
                    characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE,
                    new_pointer_to_raw_data: 0,
                    new_size_of_raw_data: 0,
                },
                SectionInfo {
                    name: ".rdata".to_string(),
                    virtual_size: 0x200,
                    virtual_address: load_config_rva as u32,
                    size_of_raw_data: 0x200,
                    pointer_to_raw_data: 0,
                    characteristics: 0,
                    new_pointer_to_raw_data: 0,
                    new_size_of_raw_data: 0,
                },
                SectionInfo {
                    name: ".pdata".to_string(),
                    virtual_size: 0x100,
                    virtual_address: exception_rva as u32,
                    size_of_raw_data: 0x100,
                    pointer_to_raw_data: 0,
                    characteristics: 0,
                    new_pointer_to_raw_data: 0,
                    new_size_of_raw_data: 0,
                },
            ],
        };

        let cfg = analyze_cfg_functions(&pe);
        assert_eq!(cfg.len(), 2);
        assert_eq!(cfg[0].target_rva, 0x120);
        assert_eq!(cfg[1].target_rva, 0x180);
        assert!(cfg[1].suppressed);
        assert_eq!(cfg[0].guard_flags, 0x500);

        let exception_functions = analyze_exception_functions(&pe);
        assert_eq!(exception_functions.len(), 1);
        assert_eq!(exception_functions[0].begin_rva, 0x120);
        assert_eq!(exception_functions[0].end_rva, 0x150);
        assert_eq!(exception_functions[0].unwind_flags, 1);
        assert_eq!(exception_functions[0].unwind_flag_names, "EHANDLER");
        assert_eq!(exception_functions[0].handler_rva, Some(0x190));
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
        assert_eq!(
            u32::from_le_bytes(table[0..4].try_into().unwrap()) as usize,
            table.len()
        );
        assert!(table[4..].starts_with(b".sec01\0"));
    }

    #[test]
    fn test_progress_stage_names() {
        assert_eq!(ProgressStage::Initializing.name(), "Initializing");
        assert_eq!(ProgressStage::Complete.name(), "Complete");
    }
}
