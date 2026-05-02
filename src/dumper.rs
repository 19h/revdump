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
    HEAP_SECTION_CHARACTERISTICS, PE_SIGNATURE,
};
use crate::scanner::{PointerScanner, ScanResult};
use crate::stub::{
    ContainerFact, EdgeConfidence, HeapPointerEdge, StubConfig, StubGenerator, VtableFact,
};

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug)]
pub struct EnrichedVtableFact {
    pub fact: VtableFact,
    pub type_name: Option<String>,
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

/// Build an IDA-friendly metadata section that lists every flattened vtable fact.
pub fn build_revdmp_metadata(
    facts: &[EnrichedVtableFact],
    heap_ptr_locs: &[(u32, u64)],
    heap_edges: &[HeapPointerEdge],
    containers: &[ContainerFact],
    indirect_calls: &[IndirectCallFact],
    image_base: u64,
    stub_generator: &StubGenerator,
) -> Vec<u8> {
    let mut text = String::new();
    let _ = writeln!(text, "REVDMP_SCHEMA v2");
    let _ = writeln!(text, "key,value");
    let _ = writeln!(text, "sidecar_required,false");
    let _ = writeln!(text, "relationship_model,runtime_graph_v2");
    let _ = writeln!(text, "target_consumers,ida;ghidra;binaryninja;custom");
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
    let _ = writeln!(text, "REVDMP_RUNTIME_RELATIONSHIPS v2");
    let _ = writeln!(
        text,
        "id,kind,source_kind,source_rva,source_heap_addr,source_stub_rva,source_offset,target_kind,target_rva,target_va,target_heap_addr,target_stub_rva,confidence,reason,provenance"
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
            "{},vfptr_to_vtable,stub_vfptr,,0x{:X},0x{:X},0x{:X},vtable,0x{:X},0x{:X},,,high,vfptr_points_to_module_vtable,{}",
            relationship_id,
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
            "{},global_to_heap_object,global,0x{:X},,,0x0,heap_object,,,0x{:X},{},{},{},module_pointer_scan",
            relationship_id,
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
            "{},heap_field_to_heap_object,heap_object,,0x{:X},{},0x{:X},heap_object,,,0x{:X},{},{},{},recursive_heap_scan",
            relationship_id,
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
        relationship_id += 1;
        let _ = writeln!(
            text,
            "{},container_to_heap_objects,heap_container,,0x{:X},{},0x{:X},heap_object_set,,,{},{},high,{},container_shape_analysis",
            relationship_id,
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
            "{},global_indirect_call,instruction,0x{:X},,,0x{:X},function,0x{:X},0x{:X},,,{},{},global_function_pointer_resolution",
            relationship_id,
            call.instruction_rva,
            call.global_rva,
            call.target_rva,
            call.target_va,
            call.confidence,
            call.reason,
        );
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

fn read_u32_at_rva(pe: &PeParser, rva: u32) -> Option<u32> {
    let off = rva as usize;
    if off + 4 > pe.size {
        return None;
    }
    let ptr = unsafe { pe.base.add(off) };
    let bytes = unsafe { std::slice::from_raw_parts(ptr, 4) };
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u64_at_rva(pe: &PeParser, rva: u32) -> Option<u64> {
    let off = rva as usize;
    if off + 8 > pe.size {
        return None;
    }
    let ptr = unsafe { pe.base.add(off) };
    let bytes = unsafe { std::slice::from_raw_parts(ptr, 8) };
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

fn resolve_vtable_type_name(
    pe: &PeParser,
    vtable_rva: u32,
    symbol_names: &HashMap<u32, String>,
) -> Option<String> {
    resolve_msvc_rtti_type_name(pe, vtable_rva)
        .or_else(|| resolve_itanium_rtti_type_name(pe, vtable_rva))
        .or_else(|| symbol_names.get(&vtable_rva).cloned())
}

fn resolve_msvc_rtti_type_name(pe: &PeParser, vtable_rva: u32) -> Option<String> {
    if vtable_rva < 8 {
        return None;
    }
    let col_ptr = read_u64_at_rva(pe, vtable_rva - 8)?;
    let col_rva = ptr_to_rva(pe, col_ptr)?;
    if !rva_in_image(pe, col_rva, 24) {
        return None;
    }
    let signature = read_u32_at_rva(pe, col_rva)?;
    if signature > 1 {
        return None;
    }
    let type_descriptor_rva = if signature == 1 {
        read_u32_at_rva(pe, col_rva + 12)?
    } else {
        let ptr = read_u64_at_rva(pe, col_rva + 12)?;
        ptr_to_rva(pe, ptr)?
    };
    if !rva_in_image(pe, type_descriptor_rva, 24) {
        return None;
    }
    let hierarchy = if signature == 1 {
        read_u32_at_rva(pe, col_rva + 16)
    } else {
        read_u64_at_rva(pe, col_rva + 16).and_then(|ptr| ptr_to_rva(pe, ptr))
    };
    if let Some(hierarchy_rva) = hierarchy {
        let _ = read_u32_at_rva(pe, hierarchy_rva + 8); // base class count when present
    }
    let raw = read_c_string_at_rva(pe, type_descriptor_rva + 16, 256)?;
    Some(demangle_msvc_type_name(&raw))
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
    let mut cache = HashMap::new();
    facts
        .iter()
        .cloned()
        .map(|fact| {
            let type_name = if parse_rtti {
                cache
                    .entry(fact.vtable_rva)
                    .or_insert_with(|| resolve_vtable_type_name(pe, fact.vtable_rva, &symbol_names))
                    .clone()
            } else {
                symbol_names.get(&fact.vtable_rva).cloned()
            };
            EnrichedVtableFact { type_name, fact }
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
        let metadata_data = if config.emit_revdmp {
            build_revdmp_metadata(
                &enriched_facts,
                &heap_ptr_locs,
                stub_generator.heap_edges(),
                stub_generator.containers(),
                &indirect_calls,
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
                fact: VtableFact {
                    source_rva: Some(0x2000),
                    heap_addr: 0x1000_0000,
                    stub_rva: 0x8000,
                    vfptr_offset: 0x20,
                    vtable_rva: 0x5000,
                },
            },
            EnrichedVtableFact {
                type_name: None,
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

        let metadata = build_revdmp_metadata(
            &facts,
            &[(0x2000, 0x1000_0000)],
            &[HeapPointerEdge {
                source_heap_addr: 0x1000_0000,
                field_offset: 0x18,
                target_heap_addr: 0x2000_0000,
                confidence: EdgeConfidence::Low,
                reason: "raw_heap_pointer",
                target_has_vtable: false,
            }],
            &[],
            &indirect_calls,
            0x1400_0000,
            &stub_generator,
        );
        let text = String::from_utf8(metadata).unwrap();
        assert!(text.contains("REVDMP_SCHEMA v2"));
        assert!(text.contains("sidecar_required,false"));
        assert!(text.contains("REVDMP_VTABLE_FACTS v1"));
        assert!(text.contains("0x2000,0x10000000,0x8000,0x20,0x5000,0x14005000,AudioService"));
        assert!(text.contains("heap,0x20000000,0x9000,0x0,0x7000,0x14007000,"));
        assert!(text.contains("REVDMP_OBJECT_GRAPH v1"));
        assert!(text.contains("global,0x2000,,,0x0,0x10000000,0x8000"));
        assert!(text.contains("heap,,0x10000000,0x8000,0x18,0x20000000,"));
        assert!(text.contains("REVDMP_CONTAINERS v1"));
        assert!(text.contains("REVDMP_INDIRECT_CALLS v1"));
        assert!(text.contains("0x1234,0x6,call,0x3000,0x4560,0x14004560,false,high"));
        assert!(text.contains("REVDMP_RUNTIME_RELATIONSHIPS v2"));
        assert!(text.contains("global_indirect_call,instruction,0x1234"));
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
