//! Pointer fixup generation and application.
//!
//! This module handles creating and applying fixups that rewrite pointers
//! from their runtime values to their new locations in the dumped PE.

use crate::memory::strip_pointer_tags;
use crate::pe::IMAGE_SCN_MEM_EXECUTE;
use crate::stub::StubGenerator;
use std::ops::Range;

/// The kind of pointer fixup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixupKind {
    /// Pointer in module section pointing to vtable stub.
    ModuleToStub,
}

/// A pointer fixup to apply to the output PE.
#[derive(Clone, Debug)]
pub struct PointerFixup {
    /// Kind of fixup.
    pub kind: FixupKind,
    /// RVA where the pointer is located.
    pub rva: u32,
    /// Original pointer value (runtime address).
    pub old_value: u64,
    /// New pointer value (image-based address).
    pub new_value: u64,
}

/// Statistics about generated fixups.
#[derive(Clone, Debug, Default)]
pub struct FixupStats {
    /// Module -> stub fixups.
    pub module_to_stub: usize,
}

/// Statistics about applied fixups.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FixupApplyStats {
    pub applied: usize,
    pub skipped: usize,
    pub protected_skipped: usize,
}

impl FixupStats {
    /// Total number of fixups.
    pub fn total(&self) -> usize {
        self.module_to_stub
    }
}

/// Generate all fixups for the dumped PE.
///
/// # Arguments
/// * `heap_ptr_locs` - List of (RVA, target_addr) pairs found during scanning
/// * `stub_generator` - The stub generator with created stubs
/// * `image_base` - The image base address
///
/// # Returns
/// A vector of fixups and statistics.
pub fn generate_fixups(
    heap_ptr_locs: &[(u32, u64)],
    stub_generator: &StubGenerator,
    image_base: u64,
) -> (Vec<PointerFixup>, FixupStats) {
    let mut fixups = Vec::with_capacity(heap_ptr_locs.len());
    let mut stats = FixupStats::default();

    // Module -> Stub fixups
    // These are the original pointers in module sections that point to heap objects.
    // We rewrite them to point to our minimal vtable stubs.
    for &(rva, target_addr) in heap_ptr_locs {
        let target_addr = strip_pointer_tags(target_addr);
        if let Some(stub) = stub_generator.get_stub(target_addr) {
            fixups.push(PointerFixup {
                kind: FixupKind::ModuleToStub,
                rva,
                old_value: target_addr,
                new_value: image_base + stub.new_rva as u64,
            });
            stats.module_to_stub += 1;
        }
    }

    (fixups, stats)
}

/// Apply fixups to an output buffer.
///
/// This modifies the output PE data in-place, rewriting pointer values.
///
/// # Arguments
/// * `output` - The output PE buffer
/// * `fixups` - The fixups to apply
/// * `sections` - Section information for RVA to file offset conversion
/// * `first_section_rva` - RVA of the first section (to protect headers)
/// * `headers_size` - Size of headers (to protect them)
///
/// # Returns
/// The number of fixups applied and skipped.
pub fn apply_fixups(
    output: &mut [u8],
    fixups: &[PointerFixup],
    sections: &[SectionMapping],
    protected_ranges: &[Range<u32>],
    first_section_rva: u32,
    headers_size: usize,
) -> FixupApplyStats {
    let mut stats = FixupApplyStats::default();

    for fix in fixups {
        // Skip fixups in header region
        if fix.rva < first_section_rva {
            stats.skipped += 1;
            continue;
        }
        if rva_range_overlaps(protected_ranges, fix.rva, 8) {
            stats.skipped += 1;
            stats.protected_skipped += 1;
            continue;
        }

        let file_offset = match section_file_offset_for_rva(sections, fix.rva) {
            Some(sec) if sec.section.allows_heap_pointer_fixups() => sec.file_offset,
            _ => {
                stats.skipped += 1;
                continue;
            }
        };

        // Universal header protection
        if (file_offset as usize) < headers_size {
            stats.skipped += 1;
            continue;
        }

        // Bounds check
        let offset = file_offset as usize;
        if offset + 8 > output.len() {
            stats.skipped += 1;
            continue;
        }

        // Write the new pointer value (little-endian)
        output[offset..offset + 8].copy_from_slice(&fix.new_value.to_le_bytes());
        stats.applied += 1;
    }

    stats
}

/// Mapping information for a section (for fixup application).
#[derive(Clone, Debug)]
pub struct SectionMapping {
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Virtual size.
    pub virtual_size: u32,
    /// Raw size in file.
    pub raw_size: u32,
    /// File offset.
    pub raw_offset: u32,
    /// Section characteristics.
    pub characteristics: u32,
}

/// Resolved file offset for an RVA inside an output section.
#[derive(Clone, Copy, Debug)]
pub struct SectionFileOffset<'a> {
    pub section: &'a SectionMapping,
    pub file_offset: u32,
}

impl SectionMapping {
    /// Create from PE section info.
    pub fn new(va: u32, vsize: u32, raw_size: u32, raw_offset: u32, characteristics: u32) -> Self {
        Self {
            virtual_address: va,
            virtual_size: vsize,
            raw_size,
            raw_offset,
            characteristics,
        }
    }

    /// Heap pointer fixups may rewrite data sections, but never executable code.
    pub fn allows_heap_pointer_fixups(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0
    }

    fn contains_rva(&self, rva: u32) -> bool {
        let end = self
            .virtual_address
            .saturating_add(self.virtual_size.max(self.raw_size));
        rva >= self.virtual_address && rva < end
    }
}

/// Map an RVA to an output file offset using a binary search over section RVAs.
pub fn section_file_offset_for_rva(
    sections: &[SectionMapping],
    rva: u32,
) -> Option<SectionFileOffset<'_>> {
    let idx = sections.partition_point(|section| section.virtual_address <= rva);
    let section = idx.checked_sub(1).and_then(|idx| sections.get(idx))?;
    if !section.contains_rva(rva) || section.raw_offset == 0 {
        return None;
    }
    Some(SectionFileOffset {
        section,
        file_offset: section.raw_offset + (rva - section.virtual_address),
    })
}

fn rva_range_overlaps(ranges: &[Range<u32>], rva: u32, len: u32) -> bool {
    let Some(end) = rva.checked_add(len) else {
        return true;
    };
    let idx = ranges.partition_point(|range| range.start < end);
    idx > 0 && ranges[idx - 1].end > rva
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixup_stats() {
        let stats = FixupStats {
            module_to_stub: 100,
        };
        assert_eq!(stats.total(), 100);
    }

    #[test]
    fn test_section_mapping() {
        let mapping = SectionMapping::new(0x1000, 0x500, 0x600, 0x400, 0);
        assert_eq!(mapping.virtual_address, 0x1000);
        assert_eq!(mapping.raw_offset, 0x400);
        assert!(mapping.allows_heap_pointer_fixups());
    }

    #[test]
    fn test_section_file_offset_binary_search() {
        let sections = vec![
            SectionMapping::new(0x1000, 0x100, 0x100, 0x400, 0),
            SectionMapping::new(0x3000, 0x200, 0x200, 0x800, 0),
            SectionMapping::new(0x8000, 0x100, 0x100, 0xC00, 0),
        ];

        let resolved = section_file_offset_for_rva(&sections, 0x3018).unwrap();
        assert_eq!(resolved.section.virtual_address, 0x3000);
        assert_eq!(resolved.file_offset, 0x818);
        assert!(section_file_offset_for_rva(&sections, 0x2500).is_none());
    }

    #[test]
    fn test_apply_fixups_skips_protected_metadata_ranges() {
        let mut output = vec![0u8; 0x800];
        output[0x400..0x408].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        let fixups = vec![PointerFixup {
            kind: FixupKind::ModuleToStub,
            rva: 0x1000,
            old_value: 0x1111_2222_3333_4444,
            new_value: 0x5555_6666_7777_8888,
        }];
        let sections = vec![SectionMapping::new(0x1000, 0x100, 0x100, 0x400, 0)];
        let protected_range = 0x1000..0x1100;

        let stats = apply_fixups(
            &mut output,
            &fixups,
            &sections,
            std::slice::from_ref(&protected_range),
            0x1000,
            0x400,
        );

        assert_eq!(stats.applied, 0);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.protected_skipped, 1);
        assert_eq!(
            u64::from_le_bytes(output[0x400..0x408].try_into().unwrap()),
            0x1111_2222_3333_4444
        );
    }

    #[test]
    fn test_apply_fixups_allows_read_only_data_sections() {
        let mut output = vec![0u8; 0x800];
        output[0x400..0x408].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        let fixups = vec![PointerFixup {
            kind: FixupKind::ModuleToStub,
            rva: 0x1000,
            old_value: 0x1111_2222_3333_4444,
            new_value: 0x5555_6666_7777_8888,
        }];
        let sections = vec![SectionMapping::new(0x1000, 0x100, 0x100, 0x400, 0)];

        let stats = apply_fixups(&mut output, &fixups, &sections, &[], 0x1000, 0x400);

        assert_eq!(stats.applied, 1);
        assert_eq!(stats.skipped, 0);
        assert_eq!(stats.protected_skipped, 0);
        assert_eq!(
            u64::from_le_bytes(output[0x400..0x408].try_into().unwrap()),
            0x5555_6666_7777_8888
        );
    }
}
