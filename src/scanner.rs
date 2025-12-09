//! SIMD-optimized pointer scanning.
//!
//! This module provides high-performance scanning of memory buffers for potential
//! heap pointers using SIMD instructions where available.

use crate::memory::MemoryRegionCache;

/// Result of scanning: (RVA where pointer was found, target address).
pub type ScanResult = (u32, u64);

/// Configuration for the pointer scanner.
#[derive(Clone, Debug)]
pub struct ScannerConfig {
    /// Minimum valid pointer value (filters out small integers).
    pub min_ptr: u64,
    /// Maximum valid pointer value (filters out implausible addresses).
    pub max_ptr: u64,
    /// Module base address (to exclude intra-module pointers).
    pub mod_base: u64,
    /// Module end address.
    pub mod_end: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            min_ptr: 0x10000,           // Skip NULL and low addresses
            max_ptr: 0x7FFF_FFFF_FFFF,  // User-mode address space limit
            mod_base: 0,
            mod_end: 0,
        }
    }
}

/// SIMD-optimized pointer scanner.
///
/// Scans memory buffers for qword values that look like valid heap pointers:
/// - Within the valid pointer range [min_ptr, max_ptr]
/// - Not within the module's own address space
/// - Point to valid heap memory (verified via cache)
pub struct PointerScanner {
    config: ScannerConfig,
}

impl PointerScanner {
    /// Create a new scanner with the given configuration.
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    /// Scan a buffer for heap pointers.
    ///
    /// Returns a vector of (RVA, target_address) pairs.
    ///
    /// # Arguments
    /// * `buffer` - The memory buffer to scan (must be 8-byte aligned for best performance)
    /// * `base_rva` - The RVA of the start of this buffer
    /// * `cache` - Memory region cache for validation
    #[inline]
    pub fn scan_buffer(
        &self,
        buffer: &[u8],
        base_rva: u32,
        cache: &MemoryRegionCache,
    ) -> Vec<ScanResult> {
        let mut results = Vec::new();

        // Dispatch to best available implementation
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        {
            self.scan_buffer_avx2(buffer, base_rva, cache, &mut results);
        }

        #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            // Runtime feature detection
            if is_x86_feature_detected!("avx2") {
                // SAFETY: We just checked that AVX2 is available
                unsafe {
                    self.scan_buffer_avx2_unchecked(buffer, base_rva, cache, &mut results);
                }
            } else if is_x86_feature_detected!("sse4.2") {
                unsafe {
                    self.scan_buffer_sse42_unchecked(buffer, base_rva, cache, &mut results);
                }
            } else {
                self.scan_buffer_scalar(buffer, base_rva, cache, &mut results);
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            self.scan_buffer_scalar(buffer, base_rva, cache, &mut results);
        }

        results
    }

    /// Scalar fallback implementation with manual loop unrolling.
    #[inline(never)]
    #[allow(dead_code)]
    fn scan_buffer_scalar(
        &self,
        buffer: &[u8],
        base_rva: u32,
        cache: &MemoryRegionCache,
        results: &mut Vec<ScanResult>,
    ) {
        let num_qwords = buffer.len() / 8;
        // SAFETY: We're reinterpreting bytes as u64s, which is safe for aligned data
        let qwords = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr() as *const u64, num_qwords)
        };

        let min_ptr = self.config.min_ptr;
        let max_ptr = self.config.max_ptr;
        let mod_base = self.config.mod_base;
        let mod_end = self.config.mod_end;

        // Process 4 qwords at a time (manual unroll)
        let mut i = 0;
        while i + 4 <= num_qwords {
            // Prefetch ahead
            if i + 32 < num_qwords {
                unsafe {
                    let prefetch_ptr = qwords.as_ptr().add(i + 32);
                    #[cfg(target_arch = "x86_64")]
                    {
                        use std::arch::x86_64::_mm_prefetch;
                        _mm_prefetch(prefetch_ptr as *const i8, std::arch::x86_64::_MM_HINT_T0);
                    }
                }
            }

            // Unrolled loop
            for j in 0..4 {
                let val = qwords[i + j];
                if Self::is_candidate(val, min_ptr, max_ptr, mod_base, mod_end)
                    && cache.is_valid_heap_region(val)
                {
                    let rva = base_rva + ((i + j) * 8) as u32;
                    results.push((rva, val));
                }
            }
            i += 4;
        }

        // Handle remaining elements
        while i < num_qwords {
            let val = qwords[i];
            if Self::is_candidate(val, min_ptr, max_ptr, mod_base, mod_end)
                && cache.is_valid_heap_region(val)
            {
                let rva = base_rva + (i * 8) as u32;
                results.push((rva, val));
            }
            i += 1;
        }
    }

    /// Check if a value is a candidate pointer (fast path filter).
    #[inline(always)]
    fn is_candidate(val: u64, min_ptr: u64, max_ptr: u64, mod_base: u64, mod_end: u64) -> bool {
        // Range check: val in [min_ptr, max_ptr]
        // Module exclusion: val not in [mod_base, mod_end)
        val >= min_ptr && val <= max_ptr && (val < mod_base || val >= mod_end)
    }

    /// AVX2 implementation (compile-time enabled).
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    fn scan_buffer_avx2(
        &self,
        buffer: &[u8],
        base_rva: u32,
        cache: &MemoryRegionCache,
        results: &mut Vec<ScanResult>,
    ) {
        // SAFETY: AVX2 is available at compile time
        unsafe {
            self.scan_buffer_avx2_impl(buffer, base_rva, cache, results);
        }
    }

    /// AVX2 implementation (runtime checked).
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    #[allow(dead_code)]
    unsafe fn scan_buffer_avx2_unchecked(
        &self,
        buffer: &[u8],
        base_rva: u32,
        cache: &MemoryRegionCache,
        results: &mut Vec<ScanResult>,
    ) {
        self.scan_buffer_avx2_impl(buffer, base_rva, cache, results);
    }

    /// Core AVX2 implementation.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    unsafe fn scan_buffer_avx2_impl(
        &self,
        buffer: &[u8],
        base_rva: u32,
        cache: &MemoryRegionCache,
        results: &mut Vec<ScanResult>,
    ) {
        use std::arch::x86_64::*;

        let num_qwords = buffer.len() / 8;
        let qwords = buffer.as_ptr() as *const u64;

        let min_ptr = self.config.min_ptr;
        let max_ptr = self.config.max_ptr;
        let mod_base = self.config.mod_base;
        let mod_end = self.config.mod_end;

        // AVX2 processes 4 qwords (32 bytes) at a time
        const VEC_SIZE: usize = 4;
        let vec_count = num_qwords / VEC_SIZE;

        // We can't easily do 64-bit comparisons in AVX2 (no _mm256_cmpgt_epu64),
        // so we extract and check each value. The benefit is from the prefetching
        // and memory access patterns.

        let mut v = 0;
        while v < vec_count {
            // Prefetch ahead (8 vectors = 256 bytes ahead)
            if v + 8 < vec_count {
                _mm_prefetch(
                    qwords.add((v + 8) * VEC_SIZE) as *const i8,
                    _MM_HINT_T0,
                );
            }

            // Load 4 qwords
            let vals = _mm256_loadu_si256(qwords.add(v * VEC_SIZE) as *const __m256i);

            // Extract and check each value
            // Using a properly aligned buffer for extraction
            let mut extracted: [u64; 4] = [0; 4];
            _mm256_storeu_si256(extracted.as_mut_ptr() as *mut __m256i, vals);

            for (j, &val) in extracted.iter().enumerate() {
                if Self::is_candidate(val, min_ptr, max_ptr, mod_base, mod_end)
                    && cache.is_valid_heap_region(val)
                {
                    let rva = base_rva + ((v * VEC_SIZE + j) * 8) as u32;
                    results.push((rva, val));
                }
            }

            v += 1;
        }

        // Handle remaining qwords with scalar path
        let remaining_start = vec_count * VEC_SIZE;
        for i in remaining_start..num_qwords {
            let val = *qwords.add(i);
            if Self::is_candidate(val, min_ptr, max_ptr, mod_base, mod_end)
                && cache.is_valid_heap_region(val)
            {
                let rva = base_rva + (i * 8) as u32;
                results.push((rva, val));
            }
        }
    }

    /// SSE4.2 implementation.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.2")]
    #[allow(dead_code)]
    unsafe fn scan_buffer_sse42_unchecked(
        &self,
        buffer: &[u8],
        base_rva: u32,
        cache: &MemoryRegionCache,
        results: &mut Vec<ScanResult>,
    ) {
        use std::arch::x86_64::*;

        let num_qwords = buffer.len() / 8;
        let qwords = buffer.as_ptr() as *const u64;

        let min_ptr = self.config.min_ptr;
        let max_ptr = self.config.max_ptr;
        let mod_base = self.config.mod_base;
        let mod_end = self.config.mod_end;

        // SSE4.2 processes 2 qwords (16 bytes) at a time
        const VEC_SIZE: usize = 2;
        let vec_count = num_qwords / VEC_SIZE;

        let mut v = 0;
        while v < vec_count {
            // Prefetch ahead
            if v + 8 < vec_count {
                _mm_prefetch(
                    qwords.add((v + 8) * VEC_SIZE) as *const i8,
                    _MM_HINT_T0,
                );
            }

            // Load 2 qwords
            let vals = _mm_loadu_si128(qwords.add(v * VEC_SIZE) as *const __m128i);

            // Extract and check each value
            let mut extracted: [u64; 2] = [0; 2];
            _mm_storeu_si128(extracted.as_mut_ptr() as *mut __m128i, vals);

            for (j, &val) in extracted.iter().enumerate() {
                if Self::is_candidate(val, min_ptr, max_ptr, mod_base, mod_end)
                    && cache.is_valid_heap_region(val)
                {
                    let rva = base_rva + ((v * VEC_SIZE + j) * 8) as u32;
                    results.push((rva, val));
                }
            }

            v += 1;
        }

        // Handle remaining
        let remaining_start = vec_count * VEC_SIZE;
        for i in remaining_start..num_qwords {
            let val = *qwords.add(i);
            if Self::is_candidate(val, min_ptr, max_ptr, mod_base, mod_end)
                && cache.is_valid_heap_region(val)
            {
                let rva = base_rva + (i * 8) as u32;
                results.push((rva, val));
            }
        }
    }
}

/// Scan a memory buffer directly (convenience function).
pub fn scan_buffer_for_pointers(
    buffer: &[u8],
    base_rva: u32,
    config: &ScannerConfig,
    cache: &MemoryRegionCache,
) -> Vec<ScanResult> {
    let scanner = PointerScanner::new(config.clone());
    scanner.scan_buffer(buffer, base_rva, cache)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_candidate() {
        // Valid pointer in range, outside module
        assert!(PointerScanner::is_candidate(
            0x7FF0_0000_0000,
            0x10000,
            0x7FFF_FFFF_FFFF,
            0x1_4000_0000,
            0x1_5000_0000,
        ));

        // Below minimum
        assert!(!PointerScanner::is_candidate(
            0x1000,
            0x10000,
            0x7FFF_FFFF_FFFF,
            0x1_4000_0000,
            0x1_5000_0000,
        ));

        // Inside module
        assert!(!PointerScanner::is_candidate(
            0x1_4500_0000,
            0x10000,
            0x7FFF_FFFF_FFFF,
            0x1_4000_0000,
            0x1_5000_0000,
        ));
    }

    #[test]
    fn test_scanner_empty_buffer() {
        let config = ScannerConfig::default();
        let scanner = PointerScanner::new(config);
        let cache = MemoryRegionCache::new();
        let results = scanner.scan_buffer(&[], 0, &cache);
        assert!(results.is_empty());
    }
}
