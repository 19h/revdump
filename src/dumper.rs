//! Main PE dumper implementation.
//!
//! This module ties together all components to perform the full dump process:
//! 1. Parse the target module's PE headers
//! 2. Scan sections for heap pointers
//! 3. Create minimal vtable stubs
//! 4. Generate fixups
//! 5. Build and write the output PE

use crate::devirt::{self, DevirtConfig, DevirtStats, IndirectCallFact, VcallKind};
use crate::error::{Error, Result};
use crate::fixup::{apply_fixups, generate_fixups, SectionMapping};
use crate::memory::{is_memory_readable, strip_pointer_tags};
use crate::pe::{
    FileHeader, OptionalHeader32, OptionalHeader64, PeParser, SectionHeader, SectionInfo,
    HEAP_SECTION_CHARACTERISTICS, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, PE_SIGNATURE,
};
use crate::scanner::{PointerScanner, ScanResult};
use crate::stub::{
    ContainerFact, EdgeConfidence, HeapPointerEdge, StubConfig, StubGenerator, VtableFact,
};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn runtime_object_id(stub_rva: u32) -> String {
    format!("obj_{stub_rva:08X}")
}

fn object_id_map(stub_generator: &StubGenerator) -> BTreeMap<u64, String> {
    stub_generator
        .stubs()
        .map(|stub| (stub.original_addr, runtime_object_id(stub.new_rva)))
        .collect()
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

/// Build an IDA-friendly metadata section that lists every flattened vtable fact.
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
    let mut text = String::new();
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

    let _ = writeln!(text, "REVDMP_SCHEMA v3");
    let _ = writeln!(text, "key,value");
    let _ = writeln!(text, "sidecar_required,false");
    let _ = writeln!(text, "relationship_model,runtime_graph_v3");
    let _ = writeln!(text, "target_consumers,ida;ghidra;binaryninja;custom");
    let _ = writeln!(text);

    let _ = writeln!(text, "REVDMP_OBJECTS v1");
    let _ = writeln!(
        text,
        "object_id,heap_addr,stub_rva,stub_va,stub_size,vfptr_count,vfptr_offsets,vtable_rvas,type_names,root_rvas,in_edges,out_edges,container_owner_count,container_element_count,confidence,provenance"
    );
    for object in &runtime_objects {
        let type_names = object.type_names.join(";");
        let _ = writeln!(
            text,
            "{},0x{:X},0x{:X},0x{:X},0x{:X},{},{},{},{},{},{},{},{},{},{},{}",
            object.id,
            object.heap_addr,
            object.stub_rva,
            object.stub_va,
            object.stub_size,
            object.vfptr_offsets.len(),
            join_hex_u32(&object.vfptr_offsets),
            join_hex_u32(&object.vtable_rvas),
            type_names,
            join_hex_u32(&object.root_rvas),
            object.incoming_edges,
            object.outgoing_edges,
            object.container_owner_count,
            object.container_element_count,
            object.confidence,
            object.provenance,
        );
    }
    let _ = writeln!(text);

    let _ = writeln!(text, "REVDMP_VTABLE_FACTS v1");
    let _ = writeln!(
        text,
        "source_rva,heap_addr,stub_rva,vfptr_offset,vtable_rva,vtable_va,type_name"
    );

    for enriched in facts {
        let fact = &enriched.fact;
        let source = fact
            .source_rva
            .map(|rva| format!("0x{rva:X}"))
            .unwrap_or_else(|| "heap".to_string());
        let _ = writeln!(
            text,
            "{},0x{:X},0x{:X},0x{:X},0x{:X},0x{:X},{}",
            source,
            fact.heap_addr,
            fact.stub_rva,
            fact.vfptr_offset,
            fact.vtable_rva,
            image_base + fact.vtable_rva as u64,
            enriched.type_name.as_deref().unwrap_or(""),
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_MSVC_RTTI v1");
    let _ = writeln!(
        text,
        "vtable_rva,col_rva,object_offset,constructor_displacement,type_descriptor_rva,type_name,hierarchy_rva,hierarchy_attributes,base_count,bases"
    );
    for rtti in msvc_rtti_by_vtable.values() {
        let hierarchy_rva = rtti
            .hierarchy_rva
            .map(|rva| format!("0x{rva:X}"))
            .unwrap_or_default();
        let _ = writeln!(
            text,
            "0x{:X},0x{:X},0x{:X},0x{:X},0x{:X},{},{},0x{:X},{},{}",
            rtti.vtable_rva,
            rtti.col_rva,
            rtti.object_offset,
            rtti.constructor_displacement,
            rtti.type_descriptor_rva,
            rtti.type_name,
            hierarchy_rva,
            rtti.hierarchy_attributes,
            rtti.base_classes.len(),
            format_msvc_base_classes(&rtti.base_classes),
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_VTABLE_SLOTS v1");
    let _ = writeln!(
        text,
        "vtable_rva,type_name,slot_index,slot_offset,entry_rva,entry_va,normalized_target_rva,normalized_target_va,slot_kind,target_kind,function_symbol,confidence,reason"
    );
    for slot in vtable_slots {
        let _ = writeln!(
            text,
            "0x{:X},{},{},0x{:X},0x{:X},0x{:X},0x{:X},0x{:X},{},{},{},{},{}",
            slot.vtable_rva,
            slot.type_name.as_deref().unwrap_or(""),
            slot.slot_index,
            slot.slot_offset,
            slot.entry_rva,
            slot.entry_va,
            slot.normalized_target_rva,
            slot.normalized_target_va,
            slot.slot_kind,
            slot.target_kind,
            slot.function_symbol,
            slot.confidence,
            slot.reason,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_THUNK_NORMALIZATIONS v1");
    let _ = writeln!(
        text,
        "thunk_rva,thunk_va,normalized_target_rva,normalized_target_va,thunk_kind,instruction_len,this_adjustment,confidence,reason"
    );
    for thunk in thunk_normalizations {
        let this_adjustment = thunk
            .this_adjustment
            .map(|adjustment| adjustment.to_string())
            .unwrap_or_default();
        let _ = writeln!(
            text,
            "0x{:X},0x{:X},0x{:X},0x{:X},{},0x{:X},{},{},{}",
            thunk.thunk_rva,
            thunk.thunk_va,
            thunk.normalized_target_rva,
            thunk.normalized_target_va,
            thunk.thunk_kind,
            thunk.instruction_len,
            this_adjustment,
            thunk.confidence,
            thunk.reason,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_CFG_FUNCTIONS v1");
    let _ = writeln!(
        text,
        "table_rva,entry_index,entry_rva,raw_entry,target_rva,target_va,suppressed,export_suppressed,guard_flags,confidence,reason"
    );
    for cfg in cfg_functions {
        let _ = writeln!(
            text,
            "0x{:X},{},0x{:X},0x{:X},0x{:X},0x{:X},{},{},0x{:X},{},{}",
            cfg.table_rva,
            cfg.entry_index,
            cfg.entry_rva,
            cfg.raw_entry,
            cfg.target_rva,
            cfg.target_va,
            cfg.suppressed,
            cfg.export_suppressed,
            cfg.guard_flags,
            cfg.confidence,
            cfg.reason,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_EXCEPTION_FUNCTIONS v1");
    let _ = writeln!(
        text,
        "entry_rva,begin_rva,end_rva,unwind_info_rva,unwind_flags,unwind_flag_names,prolog_size,unwind_code_count,frame_register,frame_offset,handler_rva,handler_va,chained_begin_rva,chained_end_rva,chained_unwind_info_rva,confidence,reason"
    );
    for function in exception_functions {
        let handler_rva = function
            .handler_rva
            .map(|rva| format!("0x{rva:X}"))
            .unwrap_or_default();
        let handler_va = function
            .handler_va
            .map(|va| format!("0x{va:X}"))
            .unwrap_or_default();
        let chained_begin_rva = function
            .chained_begin_rva
            .map(|rva| format!("0x{rva:X}"))
            .unwrap_or_default();
        let chained_end_rva = function
            .chained_end_rva
            .map(|rva| format!("0x{rva:X}"))
            .unwrap_or_default();
        let chained_unwind_info_rva = function
            .chained_unwind_info_rva
            .map(|rva| format!("0x{rva:X}"))
            .unwrap_or_default();
        let _ = writeln!(
            text,
            "0x{:X},0x{:X},0x{:X},0x{:X},0x{:X},{},0x{:X},0x{:X},0x{:X},0x{:X},{},{},{},{},{},{},{}",
            function.entry_rva,
            function.begin_rva,
            function.end_rva,
            function.unwind_info_rva,
            function.unwind_flags,
            function.unwind_flag_names,
            function.prolog_size,
            function.unwind_code_count,
            function.frame_register,
            function.frame_offset,
            handler_rva,
            handler_va,
            chained_begin_rva,
            chained_end_rva,
            chained_unwind_info_rva,
            function.confidence,
            function.reason,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_OBJECT_GRAPH v1");
    let _ = writeln!(
        text,
        "source_kind,source_rva,source_heap_addr,source_stub_rva,field_offset,target_heap_addr,target_stub_rva,confidence,reason,target_has_vtable"
    );
    for &(source_rva, target_heap_addr) in heap_ptr_locs {
        let target_heap_addr = strip_pointer_tags(target_heap_addr);
        let target_stub = stub_generator.get_stub(target_heap_addr).map(|s| s.new_rva);
        let (confidence, reason, target_has_vtable) = if target_stub.is_some() {
            ("high", "target_has_vtable", true)
        } else {
            ("low", "raw_heap_pointer", false)
        };
        let _ = writeln!(
            text,
            "global,0x{:X},,,0x0,0x{:X},{},{},{},{}",
            source_rva,
            target_heap_addr,
            target_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            confidence,
            reason,
            target_has_vtable,
        );
    }
    for edge in heap_edges {
        let source_stub = stub_generator
            .get_stub(edge.source_heap_addr)
            .map(|s| s.new_rva);
        let target_stub = stub_generator
            .get_stub(edge.target_heap_addr)
            .map(|s| s.new_rva);
        let _ = writeln!(
            text,
            "heap,,0x{:X},{},0x{:X},0x{:X},{},{},{},{}",
            edge.source_heap_addr,
            source_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            edge.field_offset,
            edge.target_heap_addr,
            target_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            edge.confidence.as_str(),
            edge.reason,
            edge.target_has_vtable,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_CONTAINERS v1");
    let _ = writeln!(
        text,
        "source_heap_addr,source_stub_rva,field_offset,kind,element_count,target_heap_addrs"
    );
    for container in containers {
        let source_stub = stub_generator
            .get_stub(container.source_heap_addr)
            .map(|s| s.new_rva);
        let targets = container
            .targets
            .iter()
            .map(|addr| format!("0x{addr:X}"))
            .collect::<Vec<_>>()
            .join(";");
        let _ = writeln!(
            text,
            "0x{:X},{},0x{:X},{},{},{}",
            container.source_heap_addr,
            source_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            container.field_offset,
            container.kind,
            container.element_count,
            targets,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_FIELD_TYPES v1");
    let _ = writeln!(
        text,
        "owner_id,owner_heap_addr,owner_stub_rva,field_offset,field_kind,target_kind,target_id,target_type_names,evidence_count,confidence,reason"
    );
    for enriched in facts {
        let fact = &enriched.fact;
        let owner_id = object_ids
            .get(&fact.heap_addr)
            .cloned()
            .unwrap_or_else(|| runtime_object_id(fact.stub_rva));
        let _ = writeln!(
            text,
            "{},0x{:X},0x{:X},0x{:X},vfptr,vtable,vtable_{:08X},{},1,high,vfptr_points_to_module_vtable",
            owner_id,
            fact.heap_addr,
            fact.stub_rva,
            fact.vfptr_offset,
            fact.vtable_rva,
            enriched.type_name.as_deref().unwrap_or(""),
        );
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
        let _ = writeln!(
            text,
            "{},0x{:X},{},0x{:X},object_pointer,heap_object,{},{},1,{},{}",
            owner_id,
            edge.source_heap_addr,
            source_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            edge.field_offset,
            target_id,
            target_type_names,
            edge.confidence.as_str(),
            edge.reason,
        );
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
        let _ = writeln!(
            text,
            "{},0x{:X},{},0x{:X},{},heap_object_set,{},{},{},high,container_shape_analysis",
            owner_id,
            container.source_heap_addr,
            source_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            container.field_offset,
            container.kind,
            target_ids,
            target_type_names,
            container.element_count,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_CONTAINER_ELEMENTS v1");
    let _ = writeln!(
        text,
        "container_id,owner_id,owner_heap_addr,field_offset,kind,element_index,target_heap_addr,target_id,target_type_names,confidence,reason"
    );
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
            let _ = writeln!(
                text,
                "{},{},0x{:X},0x{:X},{},{},0x{:X},{},{},high,container_element_has_vtable",
                container_id,
                owner_id,
                container.source_heap_addr,
                container.field_offset,
                container.kind,
                idx,
                target,
                target_id,
                target_type_names,
            );
        }
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_INDIRECT_CALLS v1");
    let _ = writeln!(
        text,
        "instruction_rva,instruction_len,kind,global_rva,target_rva,target_va,via_register,confidence,reason"
    );
    for call in indirect_calls {
        let _ = writeln!(
            text,
            "0x{:X},0x{:X},{},0x{:X},0x{:X},0x{:X},{},{},{}",
            call.instruction_rva,
            call.instruction_len,
            indirect_call_kind_name(call.kind),
            call.global_rva,
            call.target_rva,
            call.target_va,
            call.via_register,
            call.confidence,
            call.reason,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_FUNCTION_POINTERS v1");
    let _ = writeln!(
        text,
        "location_rva,location_va,section,kind,table_id,index,target_rva,target_va,confidence,reason"
    );
    for pointer in function_pointers {
        let table_id = pointer.table_id.as_deref().unwrap_or("");
        let index = pointer.index.map(|idx| idx.to_string()).unwrap_or_default();
        let _ = writeln!(
            text,
            "0x{:X},0x{:X},{},{},{},{},0x{:X},0x{:X},{},{}",
            pointer.location_rva,
            pointer.location_va,
            pointer.section_name,
            pointer.kind,
            table_id,
            index,
            pointer.target_rva,
            pointer.target_va,
            pointer.confidence,
            pointer.reason,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_FUNCTION_POINTER_TABLES v1");
    let _ = writeln!(
        text,
        "table_id,start_rva,start_va,section,entry_count,target_rvas,confidence,reason"
    );
    for table in function_pointer_tables {
        let _ = writeln!(
            text,
            "{},0x{:X},0x{:X},{},{},{},{},{}",
            table.id,
            table.start_rva,
            table.start_va,
            table.section_name,
            table.entry_count,
            join_hex_u32(&table.target_rvas),
            table.confidence,
            table.reason,
        );
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_RUNTIME_RELATIONSHIPS v3");
    let _ = writeln!(
        text,
        "id,kind,source_id,target_id,source_kind,source_rva,source_heap_addr,source_stub_rva,source_offset,target_kind,target_rva,target_va,target_heap_addr,target_stub_rva,confidence,reason,provenance"
    );
    let mut relationship_id = 0usize;
    for enriched in facts {
        let fact = &enriched.fact;
        relationship_id += 1;
        let provenance = fact
            .source_rva
            .map(|rva| format!("global:0x{rva:X}"))
            .unwrap_or_else(|| "heap_recursive".to_string());
        let _ = writeln!(
            text,
            "{},vfptr_to_vtable,{},vtable_{:08X},stub_vfptr,,0x{:X},0x{:X},0x{:X},vtable,0x{:X},0x{:X},,,high,vfptr_points_to_module_vtable,{}",
            relationship_id,
            object_ids
                .get(&fact.heap_addr)
                .cloned()
                .unwrap_or_else(|| runtime_object_id(fact.stub_rva)),
            fact.vtable_rva,
            fact.heap_addr,
            fact.stub_rva,
            fact.vfptr_offset,
            fact.vtable_rva,
            image_base + fact.vtable_rva as u64,
            provenance,
        );
    }
    for &(source_rva, target_heap_addr) in heap_ptr_locs {
        let target_heap_addr = strip_pointer_tags(target_heap_addr);
        let target_stub = stub_generator.get_stub(target_heap_addr).map(|s| s.new_rva);
        relationship_id += 1;
        let (confidence, reason) = if target_stub.is_some() {
            ("high", "global_targets_vtable_object")
        } else {
            ("low", "global_targets_heap_pointer")
        };
        let _ = writeln!(
            text,
            "{},global_to_heap_object,global_{:08X},{},global,0x{:X},,,0x0,heap_object,,,0x{:X},{},{},{},module_pointer_scan",
            relationship_id,
            source_rva,
            target_stub
                .map(runtime_object_id)
                .unwrap_or_else(|| format!("heap_{target_heap_addr:016X}")),
            source_rva,
            target_heap_addr,
            target_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            confidence,
            reason,
        );
    }
    for edge in heap_edges {
        let source_stub = stub_generator
            .get_stub(edge.source_heap_addr)
            .map(|s| s.new_rva);
        let target_stub = stub_generator
            .get_stub(edge.target_heap_addr)
            .map(|s| s.new_rva);
        relationship_id += 1;
        let _ = writeln!(
            text,
            "{},heap_field_to_heap_object,{},{},heap_object,,0x{:X},{},0x{:X},heap_object,,,0x{:X},{},{},{},recursive_heap_scan",
            relationship_id,
            object_ids
                .get(&edge.source_heap_addr)
                .cloned()
                .unwrap_or_else(|| format!("heap_{:016X}", edge.source_heap_addr)),
            object_ids
                .get(&edge.target_heap_addr)
                .cloned()
                .unwrap_or_else(|| format!("heap_{:016X}", edge.target_heap_addr)),
            edge.source_heap_addr,
            source_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            edge.field_offset,
            edge.target_heap_addr,
            target_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            edge.confidence.as_str(),
            edge.reason,
        );
    }
    for container in containers {
        let source_stub = stub_generator
            .get_stub(container.source_heap_addr)
            .map(|s| s.new_rva);
        let target_heap_addrs = container
            .targets
            .iter()
            .map(|addr| format!("0x{addr:X}"))
            .collect::<Vec<_>>()
            .join(";");
        let target_stub_rvas = container
            .targets
            .iter()
            .filter_map(|addr| {
                stub_generator
                    .get_stub(*addr)
                    .map(|stub| format!("0x{:X}", stub.new_rva))
            })
            .collect::<Vec<_>>()
            .join(";");
        let target_object_ids = container
            .targets
            .iter()
            .map(|addr| {
                object_ids
                    .get(addr)
                    .cloned()
                    .unwrap_or_else(|| format!("heap_{addr:016X}"))
            })
            .collect::<Vec<_>>()
            .join(";");
        relationship_id += 1;
        let _ = writeln!(
            text,
            "{},container_to_heap_objects,{},{},heap_container,,0x{:X},{},0x{:X},heap_object_set,,,{},{},high,{},container_shape_analysis",
            relationship_id,
            object_ids
                .get(&container.source_heap_addr)
                .cloned()
                .unwrap_or_else(|| format!("heap_{:016X}", container.source_heap_addr)),
            target_object_ids,
            container.source_heap_addr,
            source_stub
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_default(),
            container.field_offset,
            target_heap_addrs,
            target_stub_rvas,
            container.kind,
        );
    }
    for call in indirect_calls {
        relationship_id += 1;
        let _ = writeln!(
            text,
            "{},global_indirect_call,call_{:08X},func_{:08X},instruction,0x{:X},,,0x{:X},function,0x{:X},0x{:X},,,{},{},global_function_pointer_resolution",
            relationship_id,
            call.instruction_rva,
            call.target_rva,
            call.instruction_rva,
            call.global_rva,
            call.target_rva,
            call.target_va,
            call.confidence,
            call.reason,
        );
    }
    for pointer in function_pointers {
        relationship_id += 1;
        let _ = writeln!(
            text,
            "{},function_pointer_slot,fptr_{:08X},func_{:08X},data_pointer,0x{:X},,,{},function,0x{:X},0x{:X},,,{},{},function_pointer_scan",
            relationship_id,
            pointer.location_rva,
            pointer.target_rva,
            pointer.location_rva,
            pointer.index
                .map(|idx| idx.to_string())
                .unwrap_or_default(),
            pointer.target_rva,
            pointer.target_va,
            pointer.confidence,
            pointer.reason,
        );
    }
    for slot in vtable_slots {
        relationship_id += 1;
        let slot_rva = slot.vtable_rva.saturating_add(slot.slot_offset);
        let _ = writeln!(
            text,
            "{},vtable_slot_to_function,vslot_{:08X}_{:03},func_{:08X},vtable_slot,0x{:X},,,0x{:X},function,0x{:X},0x{:X},,,{},{},vtable_slot_analysis",
            relationship_id,
            slot.vtable_rva,
            slot.slot_index,
            slot.normalized_target_rva,
            slot_rva,
            slot.slot_offset,
            slot.normalized_target_rva,
            slot.normalized_target_va,
            slot.confidence,
            slot.reason,
        );
    }
    for thunk in thunk_normalizations {
        relationship_id += 1;
        let _ = writeln!(
            text,
            "{},thunk_to_function,thunk_{:08X},func_{:08X},thunk,0x{:X},,,0x0,function,0x{:X},0x{:X},,,{},{},thunk_normalization",
            relationship_id,
            thunk.thunk_rva,
            thunk.normalized_target_rva,
            thunk.thunk_rva,
            thunk.normalized_target_rva,
            thunk.normalized_target_va,
            thunk.confidence,
            thunk.reason,
        );
    }
    for cfg in cfg_functions {
        relationship_id += 1;
        let _ = writeln!(
            text,
            "{},cfg_valid_indirect_target,cfg_{:08X}_{:06},func_{:08X},cfg_table,0x{:X},,,0x{:X},function,0x{:X},0x{:X},,,{},{},pe_load_config",
            relationship_id,
            cfg.table_rva,
            cfg.entry_index,
            cfg.target_rva,
            cfg.table_rva,
            cfg.entry_index,
            cfg.target_rva,
            cfg.target_va,
            cfg.confidence,
            cfg.reason,
        );
    }
    for function in exception_functions {
        relationship_id += 1;
        let _ = writeln!(
            text,
            "{},exception_function_unwind,func_{:08X},unwind_{:08X},function,0x{:X},,,0x0,unwind_info,0x{:X},,,,high,{},x64_exception_directory",
            relationship_id,
            function.begin_rva,
            function.unwind_info_rva,
            function.begin_rva,
            function.unwind_info_rva,
            function.reason,
        );
        if let (Some(handler_rva), Some(handler_va)) = (function.handler_rva, function.handler_va) {
            relationship_id += 1;
            let _ = writeln!(
                text,
                "{},exception_handler,func_{:08X},func_{:08X},function,0x{:X},,,0x0,function,0x{:X},0x{:X},,,high,{},x64_unwind_info",
                relationship_id,
                function.begin_rva,
                handler_rva,
                function.begin_rva,
                handler_rva,
                handler_va,
                function.reason,
            );
        }
    }
    for rtti in msvc_rtti_by_vtable.values() {
        for base in &rtti.base_classes {
            if base.type_descriptor_rva == rtti.type_descriptor_rva {
                continue;
            }
            relationship_id += 1;
            let _ = writeln!(
                text,
                "{},msvc_inheritance,{},{},type,0x{:X},,,{},type,0x{:X},,,,high,msvc_base_class_descriptor,msvc_rtti",
                relationship_id,
                type_graph_id(&rtti.type_name),
                type_graph_id(&base.type_name),
                rtti.vtable_rva,
                base.mdisp,
                base.type_descriptor_rva,
            );
        }
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "REVDMP_SYNTHETIC_STRUCTS v1");
    let _ = writeln!(text, "stub_rva,heap_addr,struct_name,size,vfptr_offsets");
    for stub in stub_generator.stubs() {
        let offsets = stub
            .vtable_refs
            .iter()
            .map(|r| format!("0x{:X}", r.offset))
            .collect::<Vec<_>>()
            .join(";");
        let _ = writeln!(
            text,
            "0x{:X},0x{:X},{},0x{:X},{}",
            stub.new_rva,
            stub.original_addr,
            synthetic_struct_name(stub.new_rva),
            stub.size,
            offsets,
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

fn type_graph_id(type_name: &str) -> String {
    format!("type_{}", sanitize_ida_name(type_name))
}

fn format_msvc_base_classes(base_classes: &[MsvcBaseClassFact]) -> String {
    base_classes
        .iter()
        .map(|base| {
            format!(
                "{}@td=0x{:X}:contained={}:mdisp={}:pdisp={}:vdisp={}:attrs=0x{:X}",
                base.type_name,
                base.type_descriptor_rva,
                base.num_contained_bases,
                base.mdisp,
                base.pdisp,
                base.vdisp,
                base.attributes,
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn ida_script_path(output_path: &Path) -> PathBuf {
    let file_name = output_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "dump.exe".to_string());
    output_path.with_file_name(format!("{file_name}.ida.py"))
}

fn find_ida_executable() -> Option<String> {
    if let Ok(path) = std::env::var("IDA_PATH") {
        if !path.trim().is_empty() {
            return Some(path);
        }
    }
    for candidate in ["idat64", "ida64"] {
        if Command::new(candidate).arg("-h").output().is_ok() {
            return Some(candidate.to_string());
        }
    }
    None
}

fn sanitize_ida_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else if ch == ':' {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else if out.as_bytes()[0].is_ascii_digit() {
        format!("_{out}")
    } else {
        out
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

pub fn build_ida_script(
    facts: &[EnrichedVtableFact],
    heap_ptr_locs: &[(u32, u64)],
    heap_edges: &[HeapPointerEdge],
    containers: &[ContainerFact],
    image_base: u64,
    stub_generator: &StubGenerator,
) -> String {
    let mut script = String::new();
    let _ = writeln!(
        script,
        "# Auto-generated by revdump. Load after opening the dumped PE in IDA."
    );
    let _ = writeln!(script, "import ida_bytes");
    let _ = writeln!(script, "import ida_name");
    let _ = writeln!(script, "import ida_offset");
    let _ = writeln!(script, "import ida_struct");
    let _ = writeln!(script, "import idc");
    let _ = writeln!(script, "BADADDR = 0xFFFFFFFFFFFFFFFF");
    let _ = writeln!(script, "revdump_selfcheck = []");
    let _ = writeln!(
        script,
        "revdump_counts = {{'offsets': 0, 'names': 0, 'structs': 0, 'comments': 0}}"
    );
    let _ = writeln!(script, "def check(ok, text):");
    let _ = writeln!(script, "    revdump_selfcheck.append((bool(ok), text))");
    let _ = writeln!(script, "def qword_off(ea, target=0):");
    let _ = writeln!(script, "    ida_bytes.create_qword(ea, 8)");
    let _ = writeln!(script, "    ida_offset.op_plain_offset(ea, 0, 0)");
    let _ = writeln!(script, "    revdump_counts['offsets'] += 1");
    let _ = writeln!(script, "def set_name(ea, name):");
    let _ = writeln!(
        script,
        "    if ida_name.set_name(ea, name, ida_name.SN_CHECK | ida_name.SN_FORCE) or ida_name.get_name(ea):"
    );
    let _ = writeln!(script, "        revdump_counts['names'] += 1");
    let _ = writeln!(script, "def cmt(ea, text):");
    let _ = writeln!(script, "    ida_bytes.set_cmt(ea, text, False)");
    let _ = writeln!(script, "    if ida_bytes.get_cmt(ea, False):");
    let _ = writeln!(script, "        revdump_counts['comments'] += 1");
    let _ = writeln!(script, "def make_struct(name, members):");
    let _ = writeln!(script, "    sid = ida_struct.get_struc_id(name)");
    let _ = writeln!(script, "    if sid == BADADDR:");
    let _ = writeln!(
        script,
        "        sid = ida_struct.add_struc(BADADDR, name, False)"
    );
    let _ = writeln!(script, "    sptr = ida_struct.get_struc(sid)");
    let _ = writeln!(script, "    if sptr:");
    let _ = writeln!(script, "        for off, mname in members:");
    let _ = writeln!(script, "            ida_struct.add_struc_member(sptr, mname, off, ida_bytes.FF_QWORD | ida_bytes.FF_DATA, None, 8)");
    let _ = writeln!(script, "        revdump_counts['structs'] += 1");
    let _ = writeln!(script);

    for stub in stub_generator.stubs() {
        let struct_name = synthetic_struct_name(stub.new_rva);
        let members = stub
            .vtable_refs
            .iter()
            .map(|r| format!("(0x{:X}, 'vfptr_{:X}')", r.offset, r.offset))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(script, "make_struct('{}', [{}])", struct_name, members);
        let _ = writeln!(
            script,
            "set_name(0x{:X}, '{}_instance')",
            image_base + stub.new_rva as u64,
            struct_name
        );
        let _ = writeln!(
            script,
            "cmt(0x{:X}, 'original heap object 0x{:X}, synthetic size 0x{:X}')",
            image_base + stub.new_rva as u64,
            stub.original_addr,
            stub.size
        );
    }

    for enriched in facts {
        let fact = &enriched.fact;
        let vfptr_va = image_base + fact.stub_rva as u64 + fact.vfptr_offset as u64;
        let vtable_va = image_base + fact.vtable_rva as u64;
        let type_suffix = enriched
            .type_name
            .as_deref()
            .map(sanitize_ida_name)
            .unwrap_or_else(|| format!("{:X}", fact.vtable_rva));
        let _ = writeln!(script, "qword_off(0x{vfptr_va:X}, 0x{vtable_va:X})");
        let _ = writeln!(
            script,
            "set_name(0x{vfptr_va:X}, 'vfptr_{}_off_{:X}')",
            type_suffix, fact.vfptr_offset
        );
        let _ = writeln!(
            script,
            "set_name(0x{vtable_va:X}, 'vftable_{}')",
            type_suffix
        );
        let _ = writeln!(
            script,
            "cmt(0x{vfptr_va:X}, 'vfptr -> vtable 0x{:X}; heap=0x{:X}; source={}')",
            fact.vtable_rva,
            fact.heap_addr,
            fact.source_rva
                .map(|rva| format!("0x{rva:X}"))
                .unwrap_or_else(|| "heap-only".to_string())
        );
    }

    for &(source_rva, heap_addr) in heap_ptr_locs {
        let heap_addr = strip_pointer_tags(heap_addr);
        let source_va = image_base + source_rva as u64;
        if let Some(stub) = stub_generator.get_stub(heap_addr) {
            let stub_va = image_base + stub.new_rva as u64;
            let _ = writeln!(script, "qword_off(0x{source_va:X}, 0x{stub_va:X})");
            let _ = writeln!(
                script,
                "cmt(0x{source_va:X}, 'revdump global -> stub 0x{:X}; original heap 0x{:X}')",
                stub.new_rva, heap_addr
            );
        }
    }

    for edge in heap_edges {
        if let (Some(source), Some(target)) = (
            stub_generator.get_stub(edge.source_heap_addr),
            stub_generator.get_stub(edge.target_heap_addr),
        ) {
            let field_va = image_base + source.new_rva as u64 + edge.field_offset as u64;
            let target_va = image_base + target.new_rva as u64;
            let _ = writeln!(
                script,
                "cmt(0x{field_va:X}, 'heap edge +0x{:X} -> stub 0x{:X} (heap 0x{:X}); confidence={}; reason={}')",
                edge.field_offset,
                target.new_rva,
                edge.target_heap_addr,
                edge.confidence.as_str(),
                edge.reason,
            );
            let _ = writeln!(script, "qword_off(0x{field_va:X}, 0x{target_va:X})");
        }
    }

    for container in containers {
        if let Some(source) = stub_generator.get_stub(container.source_heap_addr) {
            let field_va = image_base + source.new_rva as u64 + container.field_offset as u64;
            let _ = writeln!(
                script,
                "cmt(0x{field_va:X}, 'container {}; elements={}; targets={}')",
                container.kind,
                container.element_count,
                container
                    .targets
                    .iter()
                    .map(|addr| format!("0x{addr:X}"))
                    .collect::<Vec<_>>()
                    .join(";")
            );
        }
    }

    let expected_structs = stub_generator.stub_count();
    let expected_offsets = facts.len() + heap_ptr_locs.len() + heap_edges.len();
    let expected_names = stub_generator.stub_count() + facts.len() * 2;
    let expected_comments =
        stub_generator.stub_count() + facts.len() + heap_ptr_locs.len() + heap_edges.len();
    let _ = writeln!(
        script,
        "check(revdump_counts['structs'] >= {expected_structs}, 'expected structs applied')"
    );
    let _ = writeln!(
        script,
        "check(revdump_counts['offsets'] >= {expected_offsets}, 'expected offsets applied')"
    );
    let _ = writeln!(
        script,
        "check(revdump_counts['names'] >= {expected_names}, 'expected names applied')"
    );
    let _ = writeln!(
        script,
        "check(revdump_counts['comments'] >= {expected_comments}, 'expected comments applied')"
    );
    let _ = writeln!(
        script,
        "failed = [text for ok, text in revdump_selfcheck if not ok]"
    );
    let _ = writeln!(script, "if failed:");
    let _ = writeln!(
        script,
        "    print('revdump IDA self-check failed: ' + '; '.join(failed))"
    );
    let _ = writeln!(script, "else:");
    let _ = writeln!(script, "    print('revdump IDA self-check passed')");

    let _ = writeln!(script, "print('revdump IDA annotations applied')");
    script
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
    /// Emit IDAPython sidecar script.
    pub emit_ida_script: bool,
    /// Emit `.revdmp` metadata section.
    pub emit_revdmp: bool,
    /// Parse RTTI/type names for metadata and IDA annotations.
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
            .field("emit_ida_script", &self.emit_ida_script)
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
            enable_devirt: false,
            devirt_config: DevirtConfig::default(),
            max_heap_scan_size: 0x1000,
            recursive_heap_scan_depth: 2,
            emit_ida_script: true,
            emit_revdmp: true,
            parse_rtti: true,
            max_graph_edges: 50_000,
            min_edge_confidence: EdgeConfidence::Low,
            detect_containers: true,
            strong_devirt: false,
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
        let enriched_facts = enrich_vtable_facts(pe, &vtable_facts, config.parse_rtti);
        let indirect_calls = if config.emit_revdmp {
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
            analyze_function_pointer_tables(pe)
        } else {
            (Vec::new(), Vec::new())
        };
        let (vtable_slots, thunk_normalizations) = if config.emit_revdmp {
            analyze_vtable_slots(pe, &enriched_facts)
        } else {
            (Vec::new(), Vec::new())
        };
        let cfg_functions = if config.emit_revdmp {
            analyze_cfg_functions(pe)
        } else {
            Vec::new()
        };
        let exception_functions = if config.emit_revdmp {
            analyze_exception_functions(pe)
        } else {
            Vec::new()
        };
        let metadata_data = if config.emit_revdmp {
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
        let ida_script = if config.emit_ida_script {
            Some(build_ida_script(
                &enriched_facts,
                &heap_ptr_locs,
                stub_generator.heap_edges(),
                stub_generator.containers(),
                pe.image_base,
                &stub_generator,
            ))
        } else {
            None
        };
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
            config.emit_revdmp.then_some(metadata_data.as_slice()),
        )?;

        // Devirtualize vcalls if enabled
        if config.enable_devirt {
            progress.stage = ProgressStage::Devirtualizing;
            report(&progress);

            let devirt_stats = self.apply_devirt(
                &mut output,
                pe,
                &vtable_facts,
                stub_generator.heap_edges(),
                &section_mappings,
                config,
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
        progress.total = output.len();
        report(&progress);

        self.write_output(output_path.as_ref(), &output)?;
        if let Some(ida_script) = ida_script {
            self.write_ida_script(output_path.as_ref(), &ida_script)?;
        }

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
        metadata_data: Option<&[u8]>,
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

        // Build metadata section data for IDA/Ghidra sidecar consumers.
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
        heap_edges: &[HeapPointerEdge],
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
        let num_sections = pe.sections.len() + 1 + usize::from(config.emit_revdmp);
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
            heap_edges,
            section_mappings,
            aligned_headers,
            &config.effective_devirt_config(),
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

    fn write_ida_script(&self, output_path: &Path, script: &str) -> Result<()> {
        let script_path = ida_script_path(output_path);
        let mut file =
            File::create(&script_path).map_err(|e| Error::OutputCreationFailed(e.to_string()))?;
        file.write_all(script.as_bytes())
            .map_err(|e| Error::OutputWriteFailed(e.to_string()))?;
        eprintln!("IDA script: {}", script_path.display());
        if let Some(ida) = find_ida_executable() {
            eprintln!(
                "IDA smoke command: {} -A -S{} {}",
                ida,
                script_path.display(),
                output_path.display()
            );
        } else {
            eprintln!(
                "IDA smoke command: idat64 -A -S{} {} (set IDA_PATH or add idat64/ida64 to PATH)",
                script_path.display(),
                output_path.display()
            );
        }
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
        let text = String::from_utf8(metadata).unwrap();
        assert!(text.contains("REVDMP_SCHEMA v3"));
        assert!(text.contains("sidecar_required,false"));
        assert!(text.contains("REVDMP_OBJECTS v1"));
        assert!(text.contains(
            "obj_00008000,0x10000000,0x8000,0x14008000,0x28,1,0x20,0x5000,AudioService,0x2000,0,1,1,0,rtti_confirmed,module_pointer_scan"
        ));
        assert!(text.contains("REVDMP_VTABLE_FACTS v1"));
        assert!(text.contains("0x2000,0x10000000,0x8000,0x20,0x5000,0x14005000,AudioService"));
        assert!(text.contains("heap,0x20000000,0x9000,0x0,0x7000,0x14007000,"));
        assert!(text.contains("REVDMP_MSVC_RTTI v1"));
        assert!(text.contains(
            "0x5000,0x4800,0x0,0x0,0x4900,AudioService,0x4A00,0x3,1,IService@td=0x4B00:contained=1:mdisp=0:pdisp=-1:vdisp=0:attrs=0x40"
        ));
        assert!(text.contains("REVDMP_OBJECT_GRAPH v1"));
        assert!(text.contains("global,0x2000,,,0x0,0x10000000,0x8000"));
        assert!(text.contains("heap,,0x10000000,0x8000,0x18,0x20000000,"));
        assert!(text.contains("REVDMP_CONTAINERS v1"));
        assert!(text.contains("0x10000000,0x8000,0x30,vector_triple,1,0x20000000"));
        assert!(text.contains("REVDMP_VTABLE_SLOTS v1"));
        assert!(text.contains(
            "0x5000,AudioService,0,0x0,0x7100,0x14007100,0x7200,0x14007200,adjustor_thunk,normalized_function,AudioService::tick,high,this_adjustment_then_jump"
        ));
        assert!(text.contains("REVDMP_THUNK_NORMALIZATIONS v1"));
        assert!(text.contains(
            "0x7100,0x14007100,0x7200,0x14007200,adjustor_thunk,0x9,-8,high,this_adjustment_then_jump"
        ));
        assert!(text.contains("REVDMP_CFG_FUNCTIONS v1"));
        assert!(text.contains(
            "0x7300,0,0x7300,0x7200,0x7200,0x14007200,false,false,0x500,high,pe_load_config_guard_cf_function_table"
        ));
        assert!(text.contains("REVDMP_EXCEPTION_FUNCTIONS v1"));
        assert!(text.contains(
            "0x7400,0x7200,0x7250,0x7500,0x1,EHANDLER,0x4,0x0,0x0,0x0,0x7600,0x14007600,,,,high,x64_unwind_info_with_handler"
        ));
        assert!(text.contains("REVDMP_FIELD_TYPES v1"));
        assert!(text.contains(
            "obj_00008000,0x10000000,0x8000,0x20,vfptr,vtable,vtable_00005000,AudioService,1,high,vfptr_points_to_module_vtable"
        ));
        assert!(text.contains(
            "obj_00008000,0x10000000,0x8000,0x18,object_pointer,heap_object,obj_00009000,Mixer,1,low,raw_heap_pointer"
        ));
        assert!(text.contains(
            "obj_00008000,0x10000000,0x8000,0x30,vector_triple,heap_object_set,obj_00009000,Mixer,1,high,container_shape_analysis"
        ));
        assert!(text.contains("REVDMP_CONTAINER_ELEMENTS v1"));
        assert!(text.contains(
            "container_0000000010000000_30,obj_00008000,0x10000000,0x30,vector_triple,0,0x20000000,obj_00009000,Mixer,high,container_element_has_vtable"
        ));
        assert!(text.contains("REVDMP_INDIRECT_CALLS v1"));
        assert!(text.contains("0x1234,0x6,call,0x3000,0x4560,0x14004560,false,high"));
        assert!(text.contains("REVDMP_FUNCTION_POINTERS v1"));
        assert!(text.contains(
            "0x6000,0x14006000,.rdata,callback_slot,,,0x4560,0x14004560,medium,isolated_code_pointer"
        ));
        assert!(text.contains("REVDMP_FUNCTION_POINTER_TABLES v1"));
        assert!(text.contains(
            "fptable_00006100,0x6100,0x14006100,.rdata,2,0x4560;0x4570,high,contiguous_code_pointer_run"
        ));
        assert!(text.contains("REVDMP_RUNTIME_RELATIONSHIPS v3"));
        assert!(text.contains("vfptr_to_vtable,obj_00008000,vtable_00005000"));
        assert!(text.contains("function_pointer_slot,fptr_00006000,func_00004560"));
        assert!(text.contains("vtable_slot_to_function,vslot_00005000_000,func_00007200"));
        assert!(text.contains("thunk_to_function,thunk_00007100,func_00007200"));
        assert!(text.contains("cfg_valid_indirect_target,cfg_00007300_000000,func_00007200"));
        assert!(text.contains("exception_handler,func_00007200,func_00007600"));
        assert!(text.contains("msvc_inheritance,type_AudioService,type_IService"));
        assert!(
            text.contains("global_indirect_call,call_00001234,func_00004560,instruction,0x1234")
        );
        assert!(text.contains("REVDMP_SYNTHETIC_STRUCTS v1"));
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
    fn test_ida_script_contains_offsets_names_structs_and_edges() {
        let stub_generator = StubGenerator::from_test_stubs(
            0x1400_0000,
            0x100000,
            vec![VtableStub {
                original_addr: 0x1000_0000,
                size: 0x28,
                data: vec![0; 0x28],
                new_rva: 0x8000,
                vtable_refs: vec![VtableRef {
                    offset: 0x20,
                    vtable_rva: 0x5000,
                }],
                vfptr_offsets: [0x20].into_iter().collect(),
            }],
        );
        let facts = vec![EnrichedVtableFact {
            type_name: Some("AudioService".to_string()),
            msvc_rtti: None,
            fact: VtableFact {
                source_rva: Some(0x2000),
                heap_addr: 0x1000_0000,
                stub_rva: 0x8000,
                vfptr_offset: 0x20,
                vtable_rva: 0x5000,
            },
        }];

        let script = build_ida_script(
            &facts,
            &[(0x2000, 0x1000_0000)],
            &[],
            &[],
            0x1400_0000,
            &stub_generator,
        );
        assert!(script.contains("make_struct('revdump_obj_8000'"));
        assert!(script.contains("qword_off(0x14008020, 0x14005000)"));
        assert!(script.contains("vftable_AudioService"));
        assert!(script.contains("qword_off(0x14002000, 0x14008000)"));
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
