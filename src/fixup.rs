//! Pointer fixup generation and application.
//!
//! This module handles creating and applying fixups that rewrite pointers
//! from their runtime values to their new locations in the dumped PE.

use crate::stub::StubGenerator;

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
    first_section_rva: u32,
    headers_size: usize,
) -> (usize, usize) {
    let mut applied = 0;
    let mut skipped = 0;

    for fix in fixups {
        // Skip fixups in header region
        if fix.rva < first_section_rva {
            skipped += 1;
            continue;
        }

        // Find containing section
        let section = sections.iter().find(|s| {
            fix.rva >= s.virtual_address
                && fix.rva < s.virtual_address + s.virtual_size.max(s.raw_size)
        });

        let file_offset = match section {
            Some(sec) if sec.raw_offset > 0 => {
                // Ensure no underflow
                if fix.rva < sec.virtual_address {
                    skipped += 1;
                    continue;
                }
                sec.raw_offset + (fix.rva - sec.virtual_address)
            }
            _ => {
                skipped += 1;
                continue;
            }
        };

        // Universal header protection
        if (file_offset as usize) < headers_size {
            skipped += 1;
            continue;
        }

        // Bounds check
        let offset = file_offset as usize;
        if offset + 8 > output.len() {
            skipped += 1;
            continue;
        }

        // Write the new pointer value (little-endian)
        output[offset..offset + 8].copy_from_slice(&fix.new_value.to_le_bytes());
        applied += 1;
    }

    (applied, skipped)
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
}

impl SectionMapping {
    /// Create from PE section info.
    pub fn new(va: u32, vsize: u32, raw_size: u32, raw_offset: u32) -> Self {
        Self {
            virtual_address: va,
            virtual_size: vsize,
            raw_size,
            raw_offset,
        }
    }
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
        let mapping = SectionMapping::new(0x1000, 0x500, 0x600, 0x400);
        assert_eq!(mapping.virtual_address, 0x1000);
        assert_eq!(mapping.raw_offset, 0x400);
    }
}
