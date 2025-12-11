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

use crate::memory::{probe_memory_byte, safe_read_memory, MemoryRegionCache};
use crate::scanner::ScannerConfig;
use crate::error::Result;

use std::collections::{HashMap, HashSet, BTreeSet};

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

/// Information about a vtable pointer within a stub.
#[derive(Clone, Debug)]
pub struct VtableRef {
    /// Offset within the stub where this vtable pointer lives.
    pub offset: usize,
    /// RVA of the vtable within the module.
    pub vtable_rva: u32,
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
}

impl Default for StubConfig {
    fn default() -> Self {
        Self {
            min_ptr_value: 0x10000,
            max_ptr_value: 0x7FFF_FFFF_FFFF,
            // Probe up to 256 bytes for multiple vfptrs (typical MI depth)
            max_vfptr_probe: 256,
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
        })
    }

    /// Check if an address is within the module (potential vtable).
    #[inline]
    pub fn is_in_module(&self, addr: u64) -> bool {
        addr >= self.mod_base && addr < self.mod_end
    }

    /// Check if a value looks like a valid heap pointer.
    #[inline]
    pub fn is_valid_heap_ptr(&self, val: u64) -> bool {
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

    /// Debug: Check why a specific pointer might be rejected.
    #[allow(dead_code)]
    pub fn debug_check_pointer(&self, val: u64) -> String {
        let mut reasons = Vec::new();

        if val < self.config.min_ptr_value {
            reasons.push(format!("below min_ptr (0x{:X} < 0x{:X})", val, self.config.min_ptr_value));
        }
        if val > self.config.max_ptr_value {
            reasons.push(format!("above max_ptr (0x{:X} > 0x{:X})", val, self.config.max_ptr_value));
        }
        if self.is_in_module(val) {
            reasons.push(format!("in module range (0x{:X} - 0x{:X})", self.mod_base, self.mod_end));
        }
        if !self.region_cache.is_valid_heap_region(val) {
            reasons.push("not in valid heap region".to_string());
        }
        if !probe_memory_byte(val as *const u8) {
            reasons.push("memory probe failed".to_string());
        }

        if reasons.is_empty() {
            "VALID".to_string()
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
        let qwords: &[u64] = unsafe {
            std::slice::from_raw_parts(buf.as_ptr() as *const u64, num_qwords)
        };

        if verbose {
            eprintln!("        probing {} qwords at heap object:", num_qwords.min(8));
        }

        for (i, &val) in qwords.iter().enumerate() {
            // Only show first 8 qwords in verbose mode
            if verbose && i < 8 {
                let in_module = self.is_in_module(val);
                let likely_vtable = if in_module { self.is_likely_vtable_verbose(val) } else { false };
                eprintln!(
                    "          [+0x{:02X}] 0x{:016X} in_module={} likely_vtable={}",
                    i * 8, val, in_module, likely_vtable
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
            let first_qword = qwords[0];
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
        self.process_heap_pointers_inner(heap_ptr_locs, false)
    }

    /// Process heap pointers with optional verbose debugging.
    pub fn process_heap_pointers_verbose(&mut self, heap_ptr_locs: &[(u32, u64)]) {
        self.process_heap_pointers_inner(heap_ptr_locs, true)
    }

    fn process_heap_pointers_inner(&mut self, heap_ptr_locs: &[(u32, u64)], verbose: bool) {
        let mut stats = StubCreationStats::default();

        if verbose {
            eprintln!("\n=== Heap Pointer Analysis (verbose) ===");
            eprintln!("Module range: 0x{:X} - 0x{:X}", self.mod_base, self.mod_end);
            eprintln!("Total pointers to analyze: {}\n", heap_ptr_locs.len());
        }

        for &(rva, target_addr) in heap_ptr_locs {
            stats.total += 1;

            if verbose {
                eprintln!("  [{}] RVA 0x{:X} -> heap 0x{:X}", stats.total, rva, target_addr);
            }

            // Track why stubs fail to be created
            if self.visited.contains(&target_addr) {
                stats.already_visited += 1;
                if verbose {
                    eprintln!("      SKIP: already visited");
                }
                continue;
            }

            if !self.is_valid_heap_ptr(target_addr) {
                stats.invalid_heap_ptr += 1;
                if verbose {
                    eprintln!("      SKIP: not a valid heap pointer");
                    eprintln!("        reason: {}", self.debug_check_pointer(target_addr));
                }
                continue;
            }

            self.visited.insert(target_addr);

            let vfptr_offsets = if verbose {
                self.probe_vfptr_offsets_verbose(target_addr)
            } else {
                self.probe_vfptr_offsets(target_addr)
            };

            if vfptr_offsets.is_empty() {
                stats.no_vfptr_found += 1;
                if verbose {
                    eprintln!("      SKIP: no vfptr found at any offset");
                }
                continue;
            }

            // Try to create the stub
            if self.create_stub_internal(target_addr, vfptr_offsets).is_some() {
                stats.created += 1;
                if verbose {
                    eprintln!("      OK: stub created");
                }
            } else {
                stats.vtable_not_in_module += 1;
                if verbose {
                    eprintln!("      SKIP: vtable not in module");
                }
            }
        }

        // Log summary
        eprintln!(
            "Stubs: {} created from {} pointers ({} duplicates, {} non-vtable)",
            stats.created,
            stats.total,
            stats.already_visited,
            stats.no_vfptr_found
        );
    }

    /// Internal stub creation with pre-computed vfptr offsets.
    fn create_stub_internal(&mut self, addr: u64, vfptr_offsets: BTreeSet<usize>) -> Option<&VtableStub> {
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
                let vtable_ptr = u64::from_le_bytes(vfptr_buf);

                if self.is_in_module(vtable_ptr) {
                    // Store vtable pointer in stub at same offset
                    data[offset..offset + 8].copy_from_slice(&vfptr_buf);

                    let vtable_rva = (vtable_ptr - self.mod_base) as u32;
                    vtable_refs.push(VtableRef {
                        offset,
                        vtable_rva,
                    });
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

        for stub in self.stubs.values_mut() {
            stub.new_rva = current_rva;
            current_rva += stub.size as u32;
        }

        (current_rva - base_rva) as usize
    }

    /// Build the .heap section data.
    pub fn build_section_data(&self, total_size: usize, file_alignment: u32) -> Vec<u8> {
        let aligned_size = (total_size + file_alignment as usize - 1)
            & !(file_alignment as usize - 1);
        let mut data = vec![0u8; aligned_size];

        if self.stubs.is_empty() {
            return data;
        }

        let base_rva = self.stubs.values()
            .map(|s| s.new_rva)
            .min()
            .unwrap_or(0);

        for stub in self.stubs.values() {
            let offset = (stub.new_rva - base_rva) as usize;
            if offset + stub.data.len() <= data.len() {
                data[offset..offset + stub.data.len()].copy_from_slice(&stub.data);
            }
        }

        data
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
        self.stubs.get(&addr)
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
            vtable_refs: vec![VtableRef { offset: 0, vtable_rva: 0x500000 }],
            vfptr_offsets: [0].into_iter().collect(),
        };
        assert_eq!(stub.size, 8);
        assert_eq!(stub.vtable_refs.len(), 1);
    }
}
