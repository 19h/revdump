//! Vtable stub generation.
//!
//! This module creates minimal synthetic stubs for heap-allocated class instances.
//! Each stub contains only the vtable pointer(s) at the offsets actually used by vcalls,
//! not the entire heap object.
//!
//! ## Design
//!
//! For a global like `qword_149FEB028` pointing to a heap object at runtime:
//!
//! ```text
//! Runtime:
//!   .data:149FEB028  ->  0x7C80B805F500 (heap)
//!   heap[0x7C80...]: [vtable=0x140500000, field1, field2, ...]
//!
//! After dump:
//!   .data:149FEB028  ->  stub_rva (points into .heap section)
//!   .heap[stub]:     [0x140500000]  (just the vtable pointer, 8 bytes)
//! ```
//!
//! This allows decompilers to resolve vcalls like:
//! ```text
//!   (*(void (**)(int64))(*qword_149FEB028 + 0x10))(qword_149FEB028)
//!   ─────────────────────┬─────────────────────
//!                        └── *qword_149FEB028 now resolves to vtable in .rdata
//! ```

use crate::error::Result;
use crate::memory::{probe_memory_byte, safe_read_memory, strip_pointer_tags, MemoryRegionCache};
use crate::scanner::ScannerConfig;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// Statistics for stub creation debugging.
#[derive(Default)]
struct StubCreationStats {
    total: usize,
    already_visited: usize,
    invalid_heap_ptr: usize,
    no_vfptr_found: usize,
    vtable_not_in_module: usize,
    created: usize,
}

/// Progress snapshot emitted by verbose heap-stub debugging.
#[derive(Clone, Copy, Debug, Default)]
pub struct StubDebugProgress {
    pub current: usize,
    pub total: usize,
    pub current_rva: u32,
    pub current_heap_addr: u64,
    pub created: usize,
    pub already_visited: usize,
    pub invalid_heap_ptr: usize,
    pub no_vfptr_found: usize,
    pub vtable_not_in_module: usize,
    pub recursive_discovered: usize,
    pub phase: &'static str,
}

fn emit_stub_debug_progress(
    progress: &mut Option<&mut dyn FnMut(StubDebugProgress)>,
    stats: &StubCreationStats,
    total: usize,
    current_rva: u32,
    current_heap_addr: u64,
    recursive_discovered: usize,
    phase: &'static str,
) {
    if let Some(progress) = progress.as_deref_mut() {
        progress(StubDebugProgress {
            current: stats.total,
            total,
            current_rva,
            current_heap_addr,
            created: stats.created,
            already_visited: stats.already_visited,
            invalid_heap_ptr: stats.invalid_heap_ptr,
            no_vfptr_found: stats.no_vfptr_found,
            vtable_not_in_module: stats.vtable_not_in_module,
            recursive_discovered,
            phase,
        });
    }
}

/// Information about a vtable pointer within a stub.
#[derive(Clone, Debug)]
pub struct VtableRef {
    /// Offset within the stub where this vtable pointer lives.
    pub offset: usize,
    /// RVA of the vtable within the module.
    pub vtable_rva: u32,
}

/// A flattened vtable reference discovered while analyzing module and heap data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VtableFact {
    /// Module RVA that held the original heap pointer, if one exists.
    pub source_rva: Option<u32>,
    /// Original heap address whose object/subobject contained the vfptr.
    pub heap_addr: u64,
    /// RVA of the synthetic stub representing `heap_addr`.
    pub stub_rva: u32,
    /// Offset inside the heap object/stub where the vfptr was found.
    pub vfptr_offset: u32,
    /// RVA of the final vtable inside the module image.
    pub vtable_rva: u32,
}

/// A pointer edge discovered inside a heap object while recursively scanning.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HeapPointerEdge {
    /// Heap object that contained the pointer.
    pub source_heap_addr: u64,
    /// Offset inside `source_heap_addr` where the pointer was found.
    pub field_offset: u32,
    /// Heap object pointed to by the source field.
    pub target_heap_addr: u64,
    /// Confidence assigned after graph deduplication/scoring.
    pub confidence: EdgeConfidence,
    /// Short machine-readable reason for the score.
    pub reason: &'static str,
    /// Whether the target has a synthetic vtable stub.
    pub target_has_vtable: bool,
}

/// Confidence assigned to a heap graph edge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeConfidence {
    #[default]
    Low,
    Medium,
    High,
}

impl EdgeConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Conservative container-like heap pattern found during recursive scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerFact {
    /// Heap object that owns the container field/pointer array.
    pub source_heap_addr: u64,
    /// Offset in the source heap object where the pattern starts.
    pub field_offset: u32,
    /// Pattern kind, e.g. `pointer_array` or `vector_triple`.
    pub kind: &'static str,
    /// Number of recognized heap object elements.
    pub element_count: usize,
    /// Heap addresses of recognized element objects.
    pub targets: Vec<u64>,
}

/// A minimal stub for a heap-allocated class instance.
///
/// Contains only vtable pointers at the offsets where they're actually needed,
/// not the entire heap object.
#[derive(Clone, Debug)]
pub struct VtableStub {
    /// Original heap address this stub represents.
    pub original_addr: u64,
    /// Size of the stub (rounded up to accommodate all vfptr offsets).
    pub size: usize,
    /// Stub data (contains vtable pointers at their respective offsets).
    pub data: Vec<u8>,
    /// Assigned RVA in the .heap section.
    pub new_rva: u32,
    /// Vtable references within this stub.
    pub vtable_refs: Vec<VtableRef>,
    /// Set of offsets where vfptrs are located (for multiple inheritance).
    pub vfptr_offsets: BTreeSet<usize>,
}

/// Configuration for stub generation.
#[derive(Clone, Debug)]
pub struct StubConfig {
    /// Minimum valid pointer value.
    pub min_ptr_value: u64,
    /// Maximum valid pointer value.
    pub max_ptr_value: u64,
    /// Maximum offset to probe for vfptrs (handles multiple inheritance).
    pub max_vfptr_probe: usize,
    /// Maximum bytes to scan in a heap allocation for embedded heap pointers.
    pub max_heap_scan_size: usize,
    /// Maximum recursive heap-pointer scan depth.
    pub recursive_heap_scan_depth: usize,
    /// Maximum heap graph edges to retain after scoring.
    pub max_graph_edges: usize,
    /// Minimum confidence required for retained graph edges.
    pub min_edge_confidence: EdgeConfidence,
    /// Detect conservative container-like heap patterns.
    pub detect_containers: bool,
}

impl Default for StubConfig {
    fn default() -> Self {
        Self {
            min_ptr_value: 0x10000,
            max_ptr_value: 0x7FFF_FFFF_FFFF,
            // Probe up to 256 bytes for multiple vfptrs (typical MI depth)
            max_vfptr_probe: 256,
            max_heap_scan_size: 0x1000,
            recursive_heap_scan_depth: 4,
            max_graph_edges: 100_000,
            min_edge_confidence: EdgeConfidence::Low,
            detect_containers: true,
        }
    }
}

/// Stub generator for creating minimal vtable stubs.
pub struct StubGenerator {
    /// Module base address.
    mod_base: u64,
    /// Module end address.
    mod_end: u64,
    /// Configuration.
    config: StubConfig,
    /// Memory region cache.
    region_cache: MemoryRegionCache,
    /// Generated stubs, keyed by original heap address.
    stubs: HashMap<u64, VtableStub>,
    /// Visited addresses to avoid cycles.
    visited: HashSet<u64>,
    /// Heap-to-heap pointer edges found during recursive scanning.
    heap_edges: Vec<HeapPointerEdge>,
    /// Container-like heap patterns found during recursive scanning.
    containers: Vec<ContainerFact>,
}

impl StubGenerator {
    /// Create a new stub generator.
    pub fn new(mod_base: *const u8, mod_size: usize, config: StubConfig) -> Result<Self> {
        let mod_base_num = mod_base as u64;

        let mut region_cache = MemoryRegionCache::new();
        region_cache.build()?;

        Ok(Self {
            mod_base: mod_base_num,
            mod_end: mod_base_num + mod_size as u64,
            config,
            region_cache,
            stubs: HashMap::with_capacity(8192),
            visited: HashSet::with_capacity(16384),
            heap_edges: Vec::new(),
            containers: Vec::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_test_stubs(mod_base: u64, mod_size: usize, stubs: Vec<VtableStub>) -> Self {
        let mut map = HashMap::new();
        for stub in stubs {
            map.insert(stub.original_addr, stub);
        }
        Self {
            mod_base,
            mod_end: mod_base + mod_size as u64,
            config: StubConfig::default(),
            region_cache: MemoryRegionCache::new(),
            stubs: map,
            visited: HashSet::new(),
            heap_edges: Vec::new(),
            containers: Vec::new(),
        }
    }

    /// Check if an address is within the module (potential vtable).
    #[inline]
    pub fn is_in_module(&self, addr: u64) -> bool {
        let addr = strip_pointer_tags(addr);
        addr >= self.mod_base && addr < self.mod_end
    }

    /// Check if a value looks like a valid heap pointer.
    #[inline]
    pub fn is_valid_heap_ptr(&self, val: u64) -> bool {
        let val = strip_pointer_tags(val);
        if val < self.config.min_ptr_value || val > self.config.max_ptr_value {
            return false;
        }
        if self.is_in_module(val) {
            return false;
        }
        if !self.region_cache.is_valid_heap_region(val) {
            return false;
        }
        probe_memory_byte(val as *const u8)
    }

    #[inline]
    fn is_cached_heap_ptr(&self, val: u64) -> bool {
        let val = strip_pointer_tags(val);
        val >= self.config.min_ptr_value
            && val <= self.config.max_ptr_value
            && !self.is_in_module(val)
            && self.region_cache.is_cached_heap_region(val)
    }

    /// Debug: Check why a specific pointer might be rejected.
    #[allow(dead_code)]
    pub fn debug_check_pointer(&self, val: u64) -> String {
        let raw_val = val;
        let val = strip_pointer_tags(val);
        let mut reasons = Vec::new();

        if val < self.config.min_ptr_value {
            reasons.push(format!(
                "below min_ptr (0x{:X} < 0x{:X})",
                val, self.config.min_ptr_value
            ));
        }
        if val > self.config.max_ptr_value {
            reasons.push(format!(
                "above max_ptr (0x{:X} > 0x{:X})",
                val, self.config.max_ptr_value
            ));
        }
        if self.is_in_module(val) {
            reasons.push(format!(
                "in module range (0x{:X} - 0x{:X})",
                self.mod_base, self.mod_end
            ));
        }
        if !self.region_cache.is_valid_heap_region(val) {
            reasons.push("not in valid heap region".to_string());
        }
        if !probe_memory_byte(val as *const u8) {
            reasons.push("memory probe failed".to_string());
        }

        if reasons.is_empty() {
            "VALID".to_string()
        } else if raw_val != val {
            format!("tagged 0x{raw_val:X} -> 0x{val:X}: {}", reasons.join(", "))
        } else {
            reasons.join(", ")
        }
    }

    /// Check if a value looks like a vtable pointer.
    ///
    /// A vtable pointer should point into the module's readable sections (.rdata typically).
    /// We don't validate vtable entries anymore - if it points into the module, it's likely
    /// a vtable. This is more permissive but handles edge cases better (external vtables,
    /// vtables with RTTI at negative offsets, etc.)
    #[inline]
    fn is_likely_vtable(&self, ptr: u64) -> bool {
        // Just check if it's in module - that's sufficient for our purposes
        self.is_in_module(ptr)
    }

    #[allow(dead_code)]
    fn is_likely_vtable_verbose(&self, ptr: u64) -> bool {
        let result = self.is_in_module(ptr);
        eprintln!("            vtable check: 0x{:X} in_module={}", ptr, result);
        result
    }

    /// Probe a heap object to find vtable pointer offsets.
    ///
    /// Returns a set of offsets where vfptrs are located.
    /// Handles multiple inheritance where objects have multiple vfptrs.
    fn probe_vfptr_offsets(&self, addr: u64) -> BTreeSet<usize> {
        self.probe_vfptr_offsets_inner(addr, false)
    }

    /// Verbose version for debugging.
    fn probe_vfptr_offsets_verbose(&self, addr: u64) -> BTreeSet<usize> {
        self.probe_vfptr_offsets_inner(addr, true)
    }

    fn probe_vfptr_offsets_inner(&self, addr: u64, verbose: bool) -> BTreeSet<usize> {
        let addr = strip_pointer_tags(addr);
        let mut offsets = BTreeSet::new();
        let max_probe = self.config.max_vfptr_probe;

        // Read the object header region
        let mut buf = vec![0u8; max_probe];
        let read_size = if safe_read_memory(addr as *const u8, &mut buf) {
            max_probe
        } else {
            // Try smaller read
            if safe_read_memory(addr as *const u8, &mut buf[..8]) {
                8
            } else {
                if verbose {
                    eprintln!("        could not read memory at 0x{:X}", addr);
                }
                return offsets;
            }
        };

        // Scan qwords for vtable pointers
        let num_qwords = read_size / 8;
        let qwords: &[u64] =
            unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u64, num_qwords) };

        if verbose {
            eprintln!(
                "        probing {} qwords at heap object:",
                num_qwords.min(8)
            );
        }

        for (i, &raw_val) in qwords.iter().enumerate() {
            let val = strip_pointer_tags(raw_val);
            // Only show first 8 qwords in verbose mode
            if verbose && i < 8 {
                let in_module = self.is_in_module(val);
                let likely_vtable = if in_module {
                    self.is_likely_vtable_verbose(val)
                } else {
                    false
                };
                eprintln!(
                    "          [+0x{:02X}] 0x{:016X} in_module={} likely_vtable={}",
                    i * 8,
                    raw_val,
                    in_module,
                    likely_vtable
                );
            }

            if val >= self.config.min_ptr_value
                && val <= self.config.max_ptr_value
                && self.is_likely_vtable(val)
            {
                offsets.insert(i * 8);
            }
        }

        // Always include offset 0 if we found nothing (assume single inheritance)
        if offsets.is_empty() && num_qwords > 0 {
            let first_qword = strip_pointer_tags(qwords[0]);
            if self.is_in_module(first_qword) {
                offsets.insert(0);
                if verbose {
                    eprintln!("        fallback: using offset 0 (first qword in module)");
                }
            }
        }

        if verbose && !offsets.is_empty() {
            eprintln!("        found vfptr offsets: {:?}", offsets);
        }

        offsets
    }

    /// Create a stub for a heap object.
    ///
    /// The stub is sized to accommodate all vfptr offsets found, with vtable
    /// pointers placed at their original offsets.
    pub fn create_stub(&mut self, addr: u64) -> Option<&VtableStub> {
        let addr = strip_pointer_tags(addr);

        // Check if already processed
        if self.visited.contains(&addr) {
            return self.stubs.get(&addr);
        }

        // Validate heap pointer
        if !self.is_valid_heap_ptr(addr) {
            return None;
        }

        self.visited.insert(addr);

        // Find vfptr offsets
        let vfptr_offsets = self.probe_vfptr_offsets(addr);

        if vfptr_offsets.is_empty() {
            return None;
        }

        self.create_stub_internal(addr, vfptr_offsets)
    }

    /// Process all heap pointer locations and create stubs.
    pub fn process_heap_pointers(&mut self, heap_ptr_locs: &[(u32, u64)]) {
        self.process_heap_pointers_inner(heap_ptr_locs, false, false, None)
    }

    /// Process heap pointers with optional verbose debugging.
    pub fn process_heap_pointers_verbose(&mut self, heap_ptr_locs: &[(u32, u64)]) {
        self.process_heap_pointers_inner(heap_ptr_locs, true, true, None)
    }

    /// Process heap pointers with progress snapshots.
    pub fn process_heap_pointers_with_progress<F>(
        &mut self,
        heap_ptr_locs: &[(u32, u64)],
        mut progress: F,
    ) where
        F: FnMut(StubDebugProgress),
    {
        self.process_heap_pointers_inner(heap_ptr_locs, false, false, Some(&mut progress))
    }

    /// Process heap pointers with verbose debugging and progress snapshots.
    pub fn process_heap_pointers_verbose_with_progress<F>(
        &mut self,
        heap_ptr_locs: &[(u32, u64)],
        mut progress: F,
    ) where
        F: FnMut(StubDebugProgress),
    {
        self.process_heap_pointers_inner(heap_ptr_locs, true, false, Some(&mut progress))
    }

    fn process_heap_pointers_inner(
        &mut self,
        heap_ptr_locs: &[(u32, u64)],
        verbose: bool,
        print_skipped: bool,
        mut progress: Option<&mut dyn FnMut(StubDebugProgress)>,
    ) {
        let mut stats = StubCreationStats::default();

        if verbose {
            eprintln!("\n=== Heap Pointer Analysis (verbose) ===");
            eprintln!("Module range: 0x{:X} - 0x{:X}", self.mod_base, self.mod_end);
            eprintln!("Total pointers to analyze: {}\n", heap_ptr_locs.len());
        }

        for &(rva, target_addr) in heap_ptr_locs {
            let target_addr = strip_pointer_tags(target_addr);
            stats.total += 1;

            if verbose && print_skipped {
                eprintln!(
                    "  [{}] RVA 0x{:X} -> heap 0x{:X}",
                    stats.total, rva, target_addr
                );
            }

            // Track why stubs fail to be created
            if self.visited.contains(&target_addr) {
                stats.already_visited += 1;
                if verbose && print_skipped {
                    eprintln!("      SKIP: already visited");
                }
                emit_stub_debug_progress(
                    &mut progress,
                    &stats,
                    heap_ptr_locs.len(),
                    rva,
                    target_addr,
                    0,
                    "heap roots",
                );
                continue;
            }

            if !self.is_valid_heap_ptr(target_addr) {
                stats.invalid_heap_ptr += 1;
                if verbose && print_skipped {
                    eprintln!("      SKIP: not a valid heap pointer");
                    eprintln!("        reason: {}", self.debug_check_pointer(target_addr));
                }
                emit_stub_debug_progress(
                    &mut progress,
                    &stats,
                    heap_ptr_locs.len(),
                    rva,
                    target_addr,
                    0,
                    "heap roots",
                );
                continue;
            }

            self.visited.insert(target_addr);

            let vfptr_offsets = if verbose && print_skipped {
                self.probe_vfptr_offsets_verbose(target_addr)
            } else {
                self.probe_vfptr_offsets(target_addr)
            };

            if vfptr_offsets.is_empty() {
                stats.no_vfptr_found += 1;
                if verbose && print_skipped {
                    eprintln!("      SKIP: no vfptr found at any offset");
                }
                emit_stub_debug_progress(
                    &mut progress,
                    &stats,
                    heap_ptr_locs.len(),
                    rva,
                    target_addr,
                    0,
                    "heap roots",
                );
                continue;
            }

            // Try to create the stub
            if self
                .create_stub_internal(target_addr, vfptr_offsets)
                .is_some()
            {
                stats.created += 1;
                if verbose {
                    if !print_skipped {
                        eprintln!(
                            "  [{}] RVA 0x{:X} -> heap 0x{:X}",
                            stats.total, rva, target_addr
                        );
                    }
                    eprintln!("      OK: stub created");
                }
            } else {
                stats.vtable_not_in_module += 1;
                if verbose && print_skipped {
                    eprintln!("      SKIP: vtable not in module");
                }
            }
            emit_stub_debug_progress(
                &mut progress,
                &stats,
                heap_ptr_locs.len(),
                rva,
                target_addr,
                0,
                "heap roots",
            );
        }

        // Log summary
        eprintln!(
            "Stubs: {} created from {} pointers ({} duplicates, {} non-vtable)",
            stats.created, stats.total, stats.already_visited, stats.no_vfptr_found
        );

        if self.config.recursive_heap_scan_depth > 0 {
            if let Some(progress) = progress.as_mut() {
                (*progress)(StubDebugProgress {
                    current: 0,
                    total: 0,
                    created: stats.created,
                    already_visited: stats.already_visited,
                    invalid_heap_ptr: stats.invalid_heap_ptr,
                    no_vfptr_found: stats.no_vfptr_found,
                    vtable_not_in_module: stats.vtable_not_in_module,
                    phase: "recursive heap graph",
                    ..Default::default()
                });
            }
            let discovered = self.discover_recursive_stubs(heap_ptr_locs);
            if let Some(progress) = progress.as_mut() {
                (*progress)(StubDebugProgress {
                    current: 1,
                    total: 1,
                    created: stats.created,
                    already_visited: stats.already_visited,
                    invalid_heap_ptr: stats.invalid_heap_ptr,
                    no_vfptr_found: stats.no_vfptr_found,
                    vtable_not_in_module: stats.vtable_not_in_module,
                    recursive_discovered: discovered,
                    phase: "recursive heap graph",
                    ..Default::default()
                });
            }
            if discovered > 0 {
                eprintln!(
                    "Stubs: {} recursively discovered from heap data",
                    discovered
                );
            }
        }
    }

    /// Recursively scan heap allocations for embedded heap pointers and create stubs for
    /// any referenced heap objects that expose vfptrs. This finds vtables that are only
    /// reachable through runtime heap-owned structs/containers.
    fn discover_recursive_stubs(&mut self, heap_ptr_locs: &[(u32, u64)]) -> usize {
        let mut queue = VecDeque::new();
        let mut scanned = HashSet::new();
        let mut discovered = 0usize;

        let mut queued = HashSet::new();
        for &(_, heap_addr) in heap_ptr_locs {
            let heap_addr = strip_pointer_tags(heap_addr);
            if queued.insert(heap_addr) {
                queue.push_back((heap_addr, 0usize));
            }
        }

        while let Some((addr, depth)) = queue.pop_front() {
            if self.config.max_graph_edges > 0
                && self.heap_edges.len() >= self.config.max_graph_edges
            {
                break;
            }
            if depth >= self.config.recursive_heap_scan_depth {
                continue;
            }
            if !scanned.insert(addr) {
                continue;
            }
            if !self.is_valid_heap_ptr(addr) {
                continue;
            }

            for (field_offset, child) in self.scan_heap_object_for_heap_pointers(addr) {
                if self.config.max_graph_edges > 0
                    && self.heap_edges.len() >= self.config.max_graph_edges
                {
                    break;
                }
                self.heap_edges.push(HeapPointerEdge {
                    source_heap_addr: addr,
                    field_offset,
                    target_heap_addr: child,
                    confidence: EdgeConfidence::Low,
                    reason: "raw_heap_pointer",
                    target_has_vtable: false,
                });
                let had_stub = self.stubs.contains_key(&child);
                if self.create_stub(child).is_some() && !had_stub {
                    discovered += 1;
                }
                if !scanned.contains(&child) && queued.insert(child) {
                    queue.push_back((child, depth + 1));
                }
            }
        }

        self.finalize_heap_graph();

        discovered
    }

    /// Deduplicate heap graph edges, score them, apply config limits, and derive
    /// conservative container facts from the retained high-confidence graph.
    fn finalize_heap_graph(&mut self) {
        let mut unique: HashMap<(u64, u32, u64), HeapPointerEdge> =
            HashMap::with_capacity(self.heap_edges.len());
        for mut edge in self.heap_edges.drain(..) {
            edge.source_heap_addr = strip_pointer_tags(edge.source_heap_addr);
            edge.target_heap_addr = strip_pointer_tags(edge.target_heap_addr);
            unique
                .entry((
                    edge.source_heap_addr,
                    edge.field_offset,
                    edge.target_heap_addr,
                ))
                .or_insert(edge);
        }

        let graph_sources: HashSet<u64> = unique.keys().map(|(source, _, _)| *source).collect();
        let mut scored = Vec::with_capacity(unique.len());
        for (_, mut edge) in unique {
            edge.target_has_vtable = self.stubs.contains_key(&edge.target_heap_addr);
            if edge.target_has_vtable {
                edge.confidence = EdgeConfidence::High;
                edge.reason = "target_has_vtable";
            } else if graph_sources.contains(&edge.target_heap_addr) {
                edge.confidence = EdgeConfidence::Medium;
                edge.reason = "target_points_to_heap";
            } else {
                edge.confidence = EdgeConfidence::Low;
                edge.reason = "raw_heap_pointer";
            }
            scored.push(edge);
        }

        scored.sort_by_key(|edge| {
            (
                std::cmp::Reverse(edge.confidence),
                edge.source_heap_addr,
                edge.field_offset,
                edge.target_heap_addr,
            )
        });
        scored.retain(|edge| edge.confidence >= self.config.min_edge_confidence);
        if self.config.max_graph_edges > 0 && scored.len() > self.config.max_graph_edges {
            scored.truncate(self.config.max_graph_edges);
        }

        self.heap_edges = scored;
        if self.config.detect_containers {
            self.containers = self.detect_container_facts();
            let mut existing = self
                .heap_edges
                .iter()
                .map(|edge| {
                    (
                        edge.source_heap_addr,
                        edge.field_offset,
                        edge.target_heap_addr,
                    )
                })
                .collect::<HashSet<_>>();
            for container in &self.containers {
                if container.kind != "vector_triple" {
                    continue;
                }
                for &target in &container.targets {
                    if existing.insert((container.source_heap_addr, container.field_offset, target))
                    {
                        self.heap_edges.push(HeapPointerEdge {
                            source_heap_addr: container.source_heap_addr,
                            field_offset: container.field_offset,
                            target_heap_addr: target,
                            confidence: EdgeConfidence::High,
                            reason: "container_element_has_vtable",
                            target_has_vtable: true,
                        });
                    }
                }
            }
            self.heap_edges.sort_by_key(|edge| {
                (
                    std::cmp::Reverse(edge.confidence),
                    edge.source_heap_addr,
                    edge.field_offset,
                    edge.target_heap_addr,
                )
            });
            if self.config.max_graph_edges > 0
                && self.heap_edges.len() > self.config.max_graph_edges
            {
                self.heap_edges.truncate(self.config.max_graph_edges);
            }
        }
    }

    fn detect_container_facts(&self) -> Vec<ContainerFact> {
        let mut containers = Vec::new();
        let mut by_source: BTreeMap<u64, Vec<&HeapPointerEdge>> = BTreeMap::new();
        for edge in &self.heap_edges {
            if edge.target_has_vtable {
                by_source
                    .entry(edge.source_heap_addr)
                    .or_default()
                    .push(edge);
            }
        }

        for (source_heap_addr, mut edges) in by_source {
            edges.sort_by_key(|edge| edge.field_offset);

            let mut run_start = 0usize;
            while run_start < edges.len() {
                let mut run_end = run_start + 1;
                while run_end < edges.len()
                    && edges[run_end].field_offset == edges[run_end - 1].field_offset + 8
                {
                    run_end += 1;
                }

                if run_end - run_start >= 2 {
                    containers.push(ContainerFact {
                        source_heap_addr,
                        field_offset: edges[run_start].field_offset,
                        kind: "pointer_array",
                        element_count: run_end - run_start,
                        targets: edges[run_start..run_end]
                            .iter()
                            .map(|edge| edge.target_heap_addr)
                            .collect(),
                    });
                }

                run_start = run_end;
            }

            containers.extend(self.detect_vector_triples(source_heap_addr));
        }

        containers.sort_by_key(|c| (c.source_heap_addr, c.field_offset, c.kind));
        containers
    }

    fn detect_vector_triples(&self, source_heap_addr: u64) -> Vec<ContainerFact> {
        let source_heap_addr = strip_pointer_tags(source_heap_addr);
        let mut facts = Vec::new();
        let region_remaining = self
            .region_cache
            .get_region(source_heap_addr)
            .map(|r| (r.end_addr - source_heap_addr) as usize)
            .unwrap_or(self.config.max_heap_scan_size);
        let max_scan = self.config.max_heap_scan_size.max(24).min(region_remaining) & !7usize;
        if max_scan < 24 {
            return facts;
        }

        let mut buf = vec![0u8; max_scan];
        if !safe_read_memory(source_heap_addr as *const u8, &mut buf) {
            return facts;
        }

        for off in (0..=max_scan - 24).step_by(8) {
            let begin =
                strip_pointer_tags(u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()));
            let end = strip_pointer_tags(u64::from_le_bytes(
                buf[off + 8..off + 16].try_into().unwrap(),
            ));
            let cap = strip_pointer_tags(u64::from_le_bytes(
                buf[off + 16..off + 24].try_into().unwrap(),
            ));
            if begin == 0
                || end < begin
                || cap < end
                || end - begin > self.config.max_heap_scan_size as u64
            {
                continue;
            }
            let byte_len = (end - begin) as usize;
            if byte_len < 16 || !byte_len.is_multiple_of(8) || !self.is_valid_heap_ptr(begin) {
                continue;
            }

            let mut elements = vec![0u8; byte_len.min(self.config.max_heap_scan_size)];
            if !safe_read_memory(begin as *const u8, &mut elements) {
                continue;
            }

            let targets = elements
                .chunks_exact(8)
                .map(|chunk| strip_pointer_tags(u64::from_le_bytes(chunk.try_into().unwrap())))
                .filter(|addr| self.stubs.contains_key(addr))
                .collect::<Vec<_>>();
            if targets.len() >= 2 {
                facts.push(ContainerFact {
                    source_heap_addr,
                    field_offset: off as u32,
                    kind: "vector_triple",
                    element_count: targets.len(),
                    targets,
                });
            }
        }

        facts
    }

    /// Scan a bounded prefix of a heap allocation for qword-aligned heap pointers.
    fn scan_heap_object_for_heap_pointers(&self, addr: u64) -> Vec<(u32, u64)> {
        let addr = strip_pointer_tags(addr);
        let region_remaining = self
            .region_cache
            .get_region(addr)
            .map(|r| (r.end_addr - addr) as usize)
            .unwrap_or(self.config.max_heap_scan_size);
        let max_scan = self.config.max_heap_scan_size.max(8).min(region_remaining) & !7usize;
        if max_scan < 8 {
            return Vec::new();
        }
        let mut read_size = max_scan;
        let mut buf = vec![0u8; read_size];

        while read_size >= 8 {
            if safe_read_memory(addr as *const u8, &mut buf[..read_size]) {
                break;
            }
            read_size /= 2;
        }

        if read_size < 8 {
            return Vec::new();
        }

        let num_qwords = read_size / 8;
        let qwords: &[u64] =
            unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u64, num_qwords) };

        let mut results = Vec::with_capacity(num_qwords.min(64));
        let mut seen = HashSet::with_capacity(num_qwords.min(64));
        for (idx, &raw_val) in qwords.iter().enumerate() {
            let val = strip_pointer_tags(raw_val);
            if seen.insert(val) && self.is_cached_heap_ptr(val) {
                results.push(((idx * 8) as u32, val));
            }
        }

        results
    }

    /// Internal stub creation with pre-computed vfptr offsets.
    fn create_stub_internal(
        &mut self,
        addr: u64,
        vfptr_offsets: BTreeSet<usize>,
    ) -> Option<&VtableStub> {
        let addr = strip_pointer_tags(addr);

        // Calculate stub size: large enough to hold all vfptrs
        let max_offset = *vfptr_offsets.iter().max().unwrap_or(&0);
        let stub_size = (max_offset + 8).div_ceil(8) * 8; // Align to 8 bytes

        // Build stub data
        let mut data = vec![0u8; stub_size];
        let mut vtable_refs = Vec::with_capacity(vfptr_offsets.len());

        for &offset in &vfptr_offsets {
            // Read the vtable pointer from the heap object
            let vfptr_addr = addr + offset as u64;
            let mut vfptr_buf = [0u8; 8];

            if safe_read_memory(vfptr_addr as *const u8, &mut vfptr_buf) {
                let vtable_ptr = strip_pointer_tags(u64::from_le_bytes(vfptr_buf));

                if self.is_in_module(vtable_ptr) {
                    // Store vtable pointer in stub at same offset
                    data[offset..offset + 8].copy_from_slice(&vtable_ptr.to_le_bytes());

                    let vtable_rva = (vtable_ptr - self.mod_base) as u32;
                    vtable_refs.push(VtableRef { offset, vtable_rva });
                }
            }
        }

        if vtable_refs.is_empty() {
            return None;
        }

        let stub = VtableStub {
            original_addr: addr,
            size: stub_size,
            data,
            new_rva: 0, // Assigned later
            vtable_refs,
            vfptr_offsets,
        };

        self.stubs.insert(addr, stub);
        self.stubs.get(&addr)
    }

    /// Assign RVAs to all stubs.
    ///
    /// Returns the total size of the .heap section.
    pub fn assign_rvas(&mut self, base_rva: u32) -> usize {
        let mut current_rva = base_rva;

        let mut heap_addrs = self.stubs.keys().copied().collect::<Vec<_>>();
        heap_addrs.sort_unstable();

        for heap_addr in heap_addrs {
            if let Some(stub) = self.stubs.get_mut(&heap_addr) {
                stub.new_rva = current_rva;
                current_rva += stub.size as u32;
            }
        }

        (current_rva - base_rva) as usize
    }

    /// Build the .heap section data.
    pub fn build_section_data(
        &self,
        total_size: usize,
        file_alignment: u32,
        image_base: u64,
    ) -> Vec<u8> {
        let aligned_size =
            (total_size + file_alignment as usize - 1) & !(file_alignment as usize - 1);
        let mut data = vec![0u8; aligned_size];

        if self.stubs.is_empty() {
            return data;
        }

        let base_rva = self.stubs.values().map(|s| s.new_rva).min().unwrap_or(0);

        for stub in self.stubs.values() {
            let offset = (stub.new_rva - base_rva) as usize;
            if offset + stub.data.len() <= data.len() {
                data[offset..offset + stub.data.len()].copy_from_slice(&stub.data);
                for vtable_ref in &stub.vtable_refs {
                    let vfptr_offset = offset + vtable_ref.offset;
                    if vfptr_offset + 8 <= data.len() {
                        let normalized = image_base + vtable_ref.vtable_rva as u64;
                        data[vfptr_offset..vfptr_offset + 8]
                            .copy_from_slice(&normalized.to_le_bytes());
                    }
                }
            }
        }

        data
    }

    /// Build flattened vtable facts for every discovered stub/vfptr pair.
    pub fn vtable_facts(&self, heap_ptr_locs: &[(u32, u64)]) -> Vec<VtableFact> {
        let mut sources_by_heap: HashMap<u64, Vec<u32>> = HashMap::new();
        for &(source_rva, heap_addr) in heap_ptr_locs {
            let heap_addr = strip_pointer_tags(heap_addr);
            sources_by_heap
                .entry(heap_addr)
                .or_default()
                .push(source_rva);
        }

        let mut facts = Vec::new();
        let mut seen = HashSet::new();

        for stub in self.stubs.values() {
            let sources = sources_by_heap.get(&stub.original_addr);
            for vtable_ref in &stub.vtable_refs {
                if let Some(sources) = sources {
                    for &source_rva in sources {
                        let fact = VtableFact {
                            source_rva: Some(source_rva),
                            heap_addr: stub.original_addr,
                            stub_rva: stub.new_rva,
                            vfptr_offset: vtable_ref.offset as u32,
                            vtable_rva: vtable_ref.vtable_rva,
                        };
                        if seen.insert(fact.clone()) {
                            facts.push(fact);
                        }
                    }
                } else {
                    let fact = VtableFact {
                        source_rva: None,
                        heap_addr: stub.original_addr,
                        stub_rva: stub.new_rva,
                        vfptr_offset: vtable_ref.offset as u32,
                        vtable_rva: vtable_ref.vtable_rva,
                    };
                    if seen.insert(fact.clone()) {
                        facts.push(fact);
                    }
                }
            }
        }

        facts.sort_by_key(|f| {
            (
                f.source_rva.unwrap_or(u32::MAX),
                f.heap_addr,
                f.vfptr_offset,
            )
        });
        facts
    }

    /// Get the number of stubs.
    pub fn stub_count(&self) -> usize {
        self.stubs.len()
    }

    /// Get an iterator over all stubs.
    pub fn stubs(&self) -> impl Iterator<Item = &VtableStub> {
        self.stubs.values()
    }

    /// Get a stub by original address.
    pub fn get_stub(&self, addr: u64) -> Option<&VtableStub> {
        let addr = strip_pointer_tags(addr);
        self.stubs.get(&addr)
    }

    /// Get heap-to-heap pointer edges found during recursive scanning.
    pub fn heap_edges(&self) -> &[HeapPointerEdge] {
        &self.heap_edges
    }

    /// Get container-like heap patterns found during recursive scanning.
    pub fn containers(&self) -> &[ContainerFact] {
        &self.containers
    }

    /// Get scanner config.
    pub fn scanner_config(&self) -> ScannerConfig {
        ScannerConfig {
            min_ptr: self.config.min_ptr_value,
            max_ptr: self.config.max_ptr_value,
            mod_base: self.mod_base,
            mod_end: self.mod_end,
        }
    }

    /// Get memory cache reference.
    pub fn cache(&self) -> &MemoryRegionCache {
        &self.region_cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_config_default() {
        let config = StubConfig::default();
        assert_eq!(config.max_vfptr_probe, 256);
    }

    #[test]
    fn test_vtable_stub_creation() {
        let stub = VtableStub {
            original_addr: 0x7C80B805F500,
            size: 8,
            data: vec![0; 8],
            new_rva: 0x1000,
            vtable_refs: vec![VtableRef {
                offset: 0,
                vtable_rva: 0x500000,
            }],
            vfptr_offsets: [0].into_iter().collect(),
        };
        assert_eq!(stub.size, 8);
        assert_eq!(stub.vtable_refs.len(), 1);
    }

    #[test]
    fn test_heap_section_data_normalizes_vtable_ptrs() {
        let runtime_base = 0x7FFF_0000_0000u64;
        let image_base = 0x1400_0000u64;
        let vtable_rva = 0x5000u32;
        let heap_addr = 0x1000_0000u64;

        let mut generator = StubGenerator {
            mod_base: runtime_base,
            mod_end: runtime_base + 0x100000,
            config: StubConfig::default(),
            region_cache: MemoryRegionCache::new(),
            stubs: HashMap::new(),
            visited: HashSet::new(),
            heap_edges: Vec::new(),
            containers: Vec::new(),
        };

        generator.stubs.insert(
            heap_addr,
            VtableStub {
                original_addr: heap_addr,
                size: 8,
                data: (runtime_base + vtable_rva as u64).to_le_bytes().to_vec(),
                new_rva: 0x3000,
                vtable_refs: vec![VtableRef {
                    offset: 0,
                    vtable_rva,
                }],
                vfptr_offsets: [0].into_iter().collect(),
            },
        );

        let data = generator.build_section_data(8, 0x200, image_base);
        let stored = u64::from_le_bytes(data[0..8].try_into().unwrap());
        assert_eq!(stored, image_base + vtable_rva as u64);
    }

    #[test]
    fn test_assign_rvas_is_deterministic_by_heap_address() {
        let mut generator = StubGenerator {
            mod_base: 0x1400_0000,
            mod_end: 0x1410_0000,
            config: StubConfig::default(),
            region_cache: MemoryRegionCache::new(),
            stubs: HashMap::new(),
            visited: HashSet::new(),
            heap_edges: Vec::new(),
            containers: Vec::new(),
        };

        for heap_addr in [0x3000u64, 0x1000, 0x2000] {
            generator.stubs.insert(
                heap_addr,
                VtableStub {
                    original_addr: heap_addr,
                    size: 8,
                    data: vec![0; 8],
                    new_rva: 0,
                    vtable_refs: vec![VtableRef {
                        offset: 0,
                        vtable_rva: 0x5000,
                    }],
                    vfptr_offsets: [0].into_iter().collect(),
                },
            );
        }

        assert_eq!(generator.assign_rvas(0x8000), 0x18);
        assert_eq!(generator.get_stub(0x1000).unwrap().new_rva, 0x8000);
        assert_eq!(generator.get_stub(0x2000).unwrap().new_rva, 0x8008);
        assert_eq!(generator.get_stub(0x3000).unwrap().new_rva, 0x8010);
    }

    #[test]
    fn test_create_stub_strips_tagged_vtable_pointer_bits() {
        let mut module = vec![0u8; 0x1000];
        let mod_base = module.as_mut_ptr() as u64;
        let vtable_rva = 0x100u32;
        let vtable = mod_base + vtable_rva as u64;
        let tagged_vtable = 0xABCD_0000_0000_0000u64 | vtable;
        let heap_object = Box::new([tagged_vtable]);
        let heap_addr = heap_object.as_ptr() as u64;

        let mut cache = MemoryRegionCache::new();
        cache.add_test_region(heap_addr, 8, true);

        let mut generator = StubGenerator {
            mod_base,
            mod_end: mod_base + module.len() as u64,
            config: StubConfig::default(),
            region_cache: cache,
            stubs: HashMap::new(),
            visited: HashSet::new(),
            heap_edges: Vec::new(),
            containers: Vec::new(),
        };

        let stub = generator.create_stub(heap_addr).unwrap();
        let stored = u64::from_le_bytes(stub.data[0..8].try_into().unwrap());

        assert_eq!(stored, vtable);
        assert_eq!(stub.vtable_refs[0].vtable_rva, vtable_rva);

        drop(heap_object);
    }

    #[test]
    fn test_vtable_facts_include_secondary_and_heap_only_refs() {
        let mut generator = StubGenerator {
            mod_base: 0x1400_0000,
            mod_end: 0x1410_0000,
            config: StubConfig::default(),
            region_cache: MemoryRegionCache::new(),
            stubs: HashMap::new(),
            visited: HashSet::new(),
            heap_edges: Vec::new(),
            containers: Vec::new(),
        };

        generator.stubs.insert(
            0x1000_0000,
            VtableStub {
                original_addr: 0x1000_0000,
                size: 0x28,
                data: vec![0; 0x28],
                new_rva: 0x3000,
                vtable_refs: vec![
                    VtableRef {
                        offset: 0,
                        vtable_rva: 0x5000,
                    },
                    VtableRef {
                        offset: 0x20,
                        vtable_rva: 0x7000,
                    },
                ],
                vfptr_offsets: [0, 0x20].into_iter().collect(),
            },
        );
        generator.stubs.insert(
            0x2000_0000,
            VtableStub {
                original_addr: 0x2000_0000,
                size: 8,
                data: vec![0; 8],
                new_rva: 0x4000,
                vtable_refs: vec![VtableRef {
                    offset: 0,
                    vtable_rva: 0x9000,
                }],
                vfptr_offsets: [0].into_iter().collect(),
            },
        );

        let facts = generator.vtable_facts(&[(0xA000, 0x1000_0000)]);
        assert!(facts.iter().any(|f| f.source_rva == Some(0xA000)
            && f.vfptr_offset == 0x20
            && f.vtable_rva == 0x7000));
        assert!(facts.iter().any(|f| f.source_rva.is_none()
            && f.heap_addr == 0x2000_0000
            && f.vtable_rva == 0x9000));
    }

    #[test]
    fn test_recursive_heap_scan_discovers_heap_only_vtable_stub() {
        let mut module = vec![0u8; 0x1000];
        let mod_base = module.as_mut_ptr() as u64;
        let child = Box::new([mod_base + 0x100, 0u64]);
        let parent = Box::new([child.as_ptr() as u64, 0u64]);
        let child_addr = child.as_ptr() as u64;
        let parent_addr = parent.as_ptr() as u64;

        let mut cache = MemoryRegionCache::new();
        cache.add_test_region(child_addr, 16, true);
        cache.add_test_region(parent_addr, 16, true);

        let mut generator = StubGenerator {
            mod_base,
            mod_end: mod_base + module.len() as u64,
            config: StubConfig {
                max_heap_scan_size: 16,
                recursive_heap_scan_depth: 2,
                ..Default::default()
            },
            region_cache: cache,
            stubs: HashMap::new(),
            visited: HashSet::new(),
            heap_edges: Vec::new(),
            containers: Vec::new(),
        };

        let discovered = generator.discover_recursive_stubs(&[(0xA000, parent_addr)]);
        assert_eq!(discovered, 1);
        assert!(generator.get_stub(child_addr).is_some());
        assert!(generator.heap_edges().iter().any(|edge| {
            edge.source_heap_addr == parent_addr
                && edge.field_offset == 0
                && edge.target_heap_addr == child_addr
        }));

        drop(parent);
        drop(child);
    }

    #[test]
    fn test_heap_edges_are_deduped_scored_and_limited() {
        let mut generator = StubGenerator {
            mod_base: 0x1400_0000,
            mod_end: 0x1410_0000,
            config: StubConfig {
                max_graph_edges: 1,
                min_edge_confidence: EdgeConfidence::Medium,
                detect_containers: false,
                ..Default::default()
            },
            region_cache: MemoryRegionCache::new(),
            stubs: HashMap::new(),
            visited: HashSet::new(),
            heap_edges: vec![
                HeapPointerEdge {
                    source_heap_addr: 0x1000,
                    field_offset: 0x8,
                    target_heap_addr: 0x2000,
                    confidence: EdgeConfidence::Low,
                    reason: "raw_heap_pointer",
                    target_has_vtable: false,
                },
                HeapPointerEdge {
                    source_heap_addr: 0x1000,
                    field_offset: 0x8,
                    target_heap_addr: 0x2000,
                    confidence: EdgeConfidence::Low,
                    reason: "raw_heap_pointer",
                    target_has_vtable: false,
                },
                HeapPointerEdge {
                    source_heap_addr: 0x1000,
                    field_offset: 0x10,
                    target_heap_addr: 0x3000,
                    confidence: EdgeConfidence::Low,
                    reason: "raw_heap_pointer",
                    target_has_vtable: false,
                },
            ],
            containers: Vec::new(),
        };
        generator.stubs.insert(
            0x2000,
            VtableStub {
                original_addr: 0x2000,
                size: 8,
                data: vec![0; 8],
                new_rva: 0x8000,
                vtable_refs: vec![VtableRef {
                    offset: 0,
                    vtable_rva: 0x5000,
                }],
                vfptr_offsets: [0].into_iter().collect(),
            },
        );

        generator.finalize_heap_graph();

        assert_eq!(generator.heap_edges.len(), 1);
        assert_eq!(generator.heap_edges[0].target_heap_addr, 0x2000);
        assert_eq!(generator.heap_edges[0].confidence, EdgeConfidence::High);
        assert_eq!(generator.heap_edges[0].reason, "target_has_vtable");
    }
}
