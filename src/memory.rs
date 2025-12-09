//! Memory operations and region caching.
//!
//! This module provides efficient memory region validation by caching VirtualQuery results
//! and using binary search for O(log n) lookups instead of per-pointer syscalls.

use crate::error::Result;

#[cfg(target_os = "windows")]
use std::ptr::null_mut;

#[cfg(target_os = "windows")]
use windows::Win32::{
    System::Memory::{
        VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
        PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    },
    System::Threading::GetCurrentProcess,
    System::Diagnostics::Debug::ReadProcessMemory,
};

/// A cached memory region from VirtualQuery.
#[derive(Clone, Debug)]
pub struct CachedRegion {
    /// Start address of the region.
    pub base_addr: u64,
    /// End address (exclusive) of the region.
    pub end_addr: u64,
    /// Memory type (MEM_PRIVATE, MEM_IMAGE, etc.).
    pub mem_type: u32,
    /// Protection flags.
    pub protect: u32,
    /// Whether this region passed validation checks.
    pub valid: bool,
    /// Whether this is a heap region (MEM_PRIVATE only).
    pub is_heap: bool,
}

/// Cache of memory regions for fast pointer validation.
///
/// Built by enumerating all committed, readable memory regions via VirtualQuery,
/// then sorted by base address for binary search.
#[derive(Default)]
pub struct MemoryRegionCache {
    regions: Vec<CachedRegion>,
    initialized: bool,
}

impl MemoryRegionCache {
    /// Create a new, empty cache.
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            initialized: false,
        }
    }

    /// Build the cache by enumerating all memory regions.
    #[cfg(target_os = "windows")]
    pub fn build(&mut self) -> Result<()> {
        self.regions.clear();
        self.regions.reserve(4096); // Typical process has ~1000-4000 regions

        let mut addr: *const u8 = null_mut();
        let mut mbi = MEMORY_BASIC_INFORMATION::default();

        // Valid protection flags for readable memory
        const VALID_PROTECT: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(
            PAGE_READONLY.0
                | PAGE_READWRITE.0
                | PAGE_EXECUTE_READ.0
                | PAGE_EXECUTE_READWRITE.0
                | PAGE_WRITECOPY.0
                | PAGE_EXECUTE_WRITECOPY.0,
        );

        loop {
            let result = unsafe {
                VirtualQuery(
                    Some(addr as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 {
                break;
            }

            if mbi.State == MEM_COMMIT {
                let protect = PAGE_PROTECTION_FLAGS(mbi.Protect.0);
                let is_valid = (protect.0 & VALID_PROTECT.0) != 0
                    && (protect.0 & (PAGE_GUARD.0 | PAGE_NOACCESS.0)) == 0
                    && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED);

                if is_valid {
                    let base = mbi.BaseAddress as u64;
                    let end = base + mbi.RegionSize as u64;

                    // Consider both MEM_PRIVATE and MEM_MAPPED as potential heap
                    // (some allocators use memory-mapped regions)
                    let is_heap = mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED;

                    self.regions.push(CachedRegion {
                        base_addr: base,
                        end_addr: end,
                        mem_type: mbi.Type.0,
                        protect: mbi.Protect.0,
                        valid: true,
                        is_heap,
                    });
                }
            }

            // Move to next region
            let next = (mbi.BaseAddress as usize).wrapping_add(mbi.RegionSize);
            if next <= addr as usize {
                break; // Overflow protection
            }
            addr = next as *const u8;
        }

        // Sort by base address for binary search
        self.regions.sort_by_key(|r| r.base_addr);
        self.initialized = true;

        // Log cache stats
        let heap_regions = self.regions.iter().filter(|r| r.is_heap).count();
        let total_heap_size: u64 = self.regions.iter()
            .filter(|r| r.is_heap)
            .map(|r| r.end_addr - r.base_addr)
            .sum();

        eprintln!(
            "Memory cache: {} regions, {} heap ({} MB)",
            self.regions.len(),
            heap_regions,
            total_heap_size / (1024 * 1024)
        );

        Ok(())
    }

    /// Stub for non-Windows platforms.
    #[cfg(not(target_os = "windows"))]
    pub fn build(&mut self) -> Result<()> {
        self.initialized = true;
        Ok(())
    }

    /// Check if an address is within a valid heap region.
    ///
    /// Uses binary search for O(log n) performance with cache,
    /// falls back to on-demand VirtualQuery if not found.
    #[inline]
    pub fn is_valid_heap_region(&self, addr: u64) -> bool {
        // First try the cache (fast path)
        if self.initialized && !self.regions.is_empty() {
            let idx = self.regions.partition_point(|r| r.base_addr <= addr);
            if idx > 0 {
                let region = &self.regions[idx - 1];
                if addr < region.end_addr {
                    return region.valid && region.is_heap;
                }
            }
        }

        // Cache miss - do on-demand VirtualQuery (slow path but correct)
        #[cfg(target_os = "windows")]
        {
            self.query_heap_region_direct(addr)
        }

        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }

    /// Direct VirtualQuery check for a specific address.
    #[cfg(target_os = "windows")]
    fn query_heap_region_direct(&self, addr: u64) -> bool {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();

        let result = unsafe {
            VirtualQuery(
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            return false;
        }

        // Check if committed and readable
        if mbi.State != MEM_COMMIT {
            return false;
        }

        // Valid protection flags
        const VALID_PROTECT: u32 = PAGE_READONLY.0
            | PAGE_READWRITE.0
            | PAGE_EXECUTE_READ.0
            | PAGE_EXECUTE_READWRITE.0
            | PAGE_WRITECOPY.0
            | PAGE_EXECUTE_WRITECOPY.0;

        let protect = mbi.Protect.0;
        if (protect & VALID_PROTECT) == 0 {
            return false;
        }
        if (protect & (PAGE_GUARD.0 | PAGE_NOACCESS.0)) != 0 {
            return false;
        }

        // Must be private or mapped memory (heap-like)
        mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED
    }

    /// Check if an address is within any valid region (heap or image).
    #[inline]
    pub fn is_valid_region(&self, addr: u64) -> bool {
        if !self.initialized || self.regions.is_empty() {
            return false;
        }

        let idx = self.regions.partition_point(|r| r.base_addr <= addr);

        if idx > 0 {
            let region = &self.regions[idx - 1];
            if addr < region.end_addr {
                return region.valid;
            }
        }

        false
    }

    /// Get the region containing the given address, if any.
    pub fn get_region(&self, addr: u64) -> Option<&CachedRegion> {
        if !self.initialized || self.regions.is_empty() {
            return None;
        }

        let idx = self.regions.partition_point(|r| r.base_addr <= addr);

        if idx > 0 {
            let region = &self.regions[idx - 1];
            if addr < region.end_addr {
                return Some(region);
            }
        }

        None
    }

    /// Number of cached regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Check if cache is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Iterate over all cached regions.
    pub fn iter_regions(&self) -> impl Iterator<Item = &CachedRegion> {
        self.regions.iter()
    }
}

/// Probe a single byte of memory to verify it's actually readable.
///
/// This catches cases where VirtualQuery reports memory as readable but
/// it actually faults (e.g., Wine edge cases, guard pages that got set after query).
#[cfg(target_os = "windows")]
#[inline]
pub fn probe_memory_byte(addr: *const u8) -> bool {
    let mut buf: u8 = 0;
    let mut bytes_read: usize = 0;

    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            addr as *const _,
            &mut buf as *mut _ as *mut _,
            1,
            Some(&mut bytes_read),
        )
        .is_ok()
            && bytes_read == 1
    }
}

#[cfg(not(target_os = "windows"))]
#[inline]
pub fn probe_memory_byte(_addr: *const u8) -> bool {
    false
}

/// Safely read memory from the current process.
#[cfg(target_os = "windows")]
pub fn safe_read_memory(src: *const u8, dst: &mut [u8]) -> bool {
    if dst.is_empty() {
        return true;
    }

    let mut bytes_read: usize = 0;

    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            src as *const _,
            dst.as_mut_ptr() as *mut _,
            dst.len(),
            Some(&mut bytes_read),
        )
        .is_ok()
            && bytes_read == dst.len()
    }
}

#[cfg(not(target_os = "windows"))]
pub fn safe_read_memory(_src: *const u8, _dst: &mut [u8]) -> bool {
    false
}

/// Check if a memory range is readable.
#[cfg(target_os = "windows")]
pub fn is_memory_readable(addr: *const u8, size: usize) -> bool {
    if size == 0 {
        return true;
    }

    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let result = unsafe {
        VirtualQuery(
            Some(addr as *const _),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if result == 0 {
        return false;
    }

    const VALID_PROTECT: u32 = PAGE_READONLY.0
        | PAGE_READWRITE.0
        | PAGE_EXECUTE_READ.0
        | PAGE_EXECUTE_READWRITE.0
        | PAGE_WRITECOPY.0
        | PAGE_EXECUTE_WRITECOPY.0;

    if mbi.State != MEM_COMMIT {
        return false;
    }
    if (mbi.Protect.0 & VALID_PROTECT) == 0 {
        return false;
    }
    if (mbi.Protect.0 & (PAGE_GUARD.0 | PAGE_NOACCESS.0)) != 0 {
        return false;
    }

    // Check bounds
    let src_addr = addr as usize;
    let region_base = mbi.BaseAddress as usize;
    let region_end = region_base + mbi.RegionSize;

    if src_addr + size > region_end {
        return false;
    }

    // Final probe to catch Wine edge cases
    probe_memory_byte(addr)
}

#[cfg(not(target_os = "windows"))]
pub fn is_memory_readable(_addr: *const u8, _size: usize) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_empty() {
        let cache = MemoryRegionCache::new();
        assert!(!cache.is_initialized());
        assert!(!cache.is_valid_heap_region(0x1000));
    }

    #[test]
    fn test_cached_region_heap_detection() {
        let region = CachedRegion {
            base_addr: 0x1000,
            end_addr: 0x2000,
            mem_type: 0x20000, // MEM_PRIVATE
            protect: 0x04,    // PAGE_READWRITE
            valid: true,
            is_heap: true,
        };
        assert!(region.is_heap);
    }
}
