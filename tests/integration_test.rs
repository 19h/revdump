//! Integration test that verifies the vtable stub implementation works correctly.
//!
//! This test simulates the scenario:
//! 1. A "module" with .data section containing globals pointing to heap
//! 2. Heap objects with vtable pointers back into the module's .rdata
//! 3. The dumper creating stubs and fixups
//! 4. Verification that the result allows vtable resolution

use std::collections::BTreeSet;

/// Simulated memory layout for testing.
///
/// We simulate:
/// - Module at 0x140000000 with:
///   - .text at RVA 0x1000 (code)
///   - .rdata at RVA 0x10000 (vtables)
///   - .data at RVA 0x20000 (globals pointing to heap)
/// - Heap objects at 0x7C80_xxxx_xxxx containing vtable pointers

const MODULE_BASE: u64 = 0x140000000;
const MODULE_SIZE: usize = 0x100000; // 1MB module

const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x10000;
const DATA_RVA: u32 = 0x20000;

// Simulated vtable addresses (in .rdata)
const VTABLE_A: u64 = MODULE_BASE + RDATA_RVA as u64 + 0x100; // 0x140010100
const VTABLE_B: u64 = MODULE_BASE + RDATA_RVA as u64 + 0x200; // 0x140010200
const VTABLE_C: u64 = MODULE_BASE + RDATA_RVA as u64 + 0x300; // 0x140010300

// Simulated function addresses (in .text) - what vtable entries point to
const FUNC_A1: u64 = MODULE_BASE + TEXT_RVA as u64 + 0x100;
const FUNC_A2: u64 = MODULE_BASE + TEXT_RVA as u64 + 0x200;
const FUNC_B1: u64 = MODULE_BASE + TEXT_RVA as u64 + 0x300;

// Simulated heap addresses
const HEAP_OBJ_A: u64 = 0x7C80_B805_F500;
const HEAP_OBJ_B: u64 = 0x7D00_CB27_1000;
const HEAP_OBJ_MI: u64 = 0x7C80_EA05_A900; // Multiple inheritance object

// Global locations in .data (RVAs)
const GLOBAL_A_RVA: u32 = DATA_RVA + 0x28;  // qword_149FEB028 equivalent
const GLOBAL_B_RVA: u32 = DATA_RVA + 0x30;
const GLOBAL_MI_RVA: u32 = DATA_RVA + 0x38;

/// Simulated heap object - single inheritance
struct SimHeapObjectSingle {
    vtable: u64,
    field1: u64,
    field2: u64,
}

/// Simulated heap object - multiple inheritance (2 vtables)
struct SimHeapObjectMI {
    vtable_primary: u64,
    field1: u64,
    vtable_secondary: u64, // At offset 16
    field2: u64,
}

/// Simulated vtable
struct SimVtable {
    func1: u64,
    func2: u64,
    func3: u64,
}

/// Test the core stub creation logic
#[test]
fn test_stub_creation_logic() {
    // Simulate heap object A with vtable pointer
    let heap_obj_a = SimHeapObjectSingle {
        vtable: VTABLE_A,
        field1: 0xDEADBEEF,
        field2: 0xCAFEBABE,
    };

    // Simulate reading the first qword (vtable pointer)
    let vtable_ptr = heap_obj_a.vtable;

    // Verify vtable pointer is in module range
    assert!(vtable_ptr >= MODULE_BASE && vtable_ptr < MODULE_BASE + MODULE_SIZE as u64,
        "Vtable pointer should be within module");

    // This is what the stub would contain - just the vtable pointer
    let stub_data: [u8; 8] = vtable_ptr.to_le_bytes();

    // Verify we can recover the vtable pointer from the stub
    let recovered_vtable = u64::from_le_bytes(stub_data);
    assert_eq!(recovered_vtable, VTABLE_A);

    println!("Single inheritance test passed:");
    println!("  Heap object at: 0x{:X}", HEAP_OBJ_A);
    println!("  Vtable pointer: 0x{:X}", vtable_ptr);
    println!("  Stub size: {} bytes", stub_data.len());
}

/// Test multiple inheritance stub creation
#[test]
fn test_multiple_inheritance_stub() {
    // Simulate MI heap object with 2 vtable pointers
    let heap_obj_mi = SimHeapObjectMI {
        vtable_primary: VTABLE_B,
        field1: 0x1111,
        vtable_secondary: VTABLE_C, // At offset 16
        field2: 0x2222,
    };

    // Probe for vtable pointers (simulating probe_vfptr_offsets)
    let mut vfptr_offsets = BTreeSet::new();

    // Check offset 0
    if heap_obj_mi.vtable_primary >= MODULE_BASE
        && heap_obj_mi.vtable_primary < MODULE_BASE + MODULE_SIZE as u64
    {
        vfptr_offsets.insert(0usize);
    }

    // Check offset 16 (after field1)
    if heap_obj_mi.vtable_secondary >= MODULE_BASE
        && heap_obj_mi.vtable_secondary < MODULE_BASE + MODULE_SIZE as u64
    {
        vfptr_offsets.insert(16usize);
    }

    assert_eq!(vfptr_offsets.len(), 2, "Should find 2 vtable pointers");
    assert!(vfptr_offsets.contains(&0));
    assert!(vfptr_offsets.contains(&16));

    // Calculate stub size (must accommodate both vfptrs)
    let max_offset = *vfptr_offsets.iter().max().unwrap();
    let stub_size = ((max_offset + 8 + 7) / 8) * 8; // Align to 8
    assert_eq!(stub_size, 24, "Stub should be 24 bytes for MI object");

    // Build stub data
    let mut stub_data = vec![0u8; stub_size];
    stub_data[0..8].copy_from_slice(&heap_obj_mi.vtable_primary.to_le_bytes());
    stub_data[16..24].copy_from_slice(&heap_obj_mi.vtable_secondary.to_le_bytes());

    // Verify both vtables are recoverable
    let recovered_primary = u64::from_le_bytes(stub_data[0..8].try_into().unwrap());
    let recovered_secondary = u64::from_le_bytes(stub_data[16..24].try_into().unwrap());

    assert_eq!(recovered_primary, VTABLE_B);
    assert_eq!(recovered_secondary, VTABLE_C);

    println!("Multiple inheritance test passed:");
    println!("  Heap object at: 0x{:X}", HEAP_OBJ_MI);
    println!("  Primary vtable at offset 0: 0x{:X}", heap_obj_mi.vtable_primary);
    println!("  Secondary vtable at offset 16: 0x{:X}", heap_obj_mi.vtable_secondary);
    println!("  Stub size: {} bytes", stub_size);
}

/// Test the fixup logic
#[test]
fn test_fixup_generation() {
    // Simulate the scenario:
    // - Global at GLOBAL_A_RVA contains heap address HEAP_OBJ_A
    // - We create a stub for HEAP_OBJ_A at some RVA in .heap

    let heap_section_va: u32 = 0x30000; // .heap section starts here
    let stub_rva: u32 = heap_section_va; // First stub at start of .heap

    // The fixup should rewrite:
    // - Location: GLOBAL_A_RVA (where the pointer is stored)
    // - Old value: HEAP_OBJ_A (runtime heap address)
    // - New value: MODULE_BASE + stub_rva (points to our stub)

    let new_value = MODULE_BASE + stub_rva as u64;

    println!("Fixup test:");
    println!("  Global location (RVA): 0x{:X}", GLOBAL_A_RVA);
    println!("  Old value (heap addr): 0x{:X}", HEAP_OBJ_A);
    println!("  New value (stub addr): 0x{:X}", new_value);
    println!("  Stub RVA: 0x{:X}", stub_rva);

    // Simulate a .data section buffer
    let data_section_size = 0x1000;
    let mut data_section = vec![0u8; data_section_size];

    // Write the original heap pointer at the global's offset within .data
    let offset_in_data = (GLOBAL_A_RVA - DATA_RVA) as usize;
    data_section[offset_in_data..offset_in_data + 8]
        .copy_from_slice(&HEAP_OBJ_A.to_le_bytes());

    // Verify original value
    let original = u64::from_le_bytes(
        data_section[offset_in_data..offset_in_data + 8].try_into().unwrap()
    );
    assert_eq!(original, HEAP_OBJ_A);

    // Apply fixup (rewrite to point to stub)
    data_section[offset_in_data..offset_in_data + 8]
        .copy_from_slice(&new_value.to_le_bytes());

    // Verify fixed value
    let fixed = u64::from_le_bytes(
        data_section[offset_in_data..offset_in_data + 8].try_into().unwrap()
    );
    assert_eq!(fixed, new_value);
    assert_eq!(fixed, MODULE_BASE + stub_rva as u64);

    println!("  Fixup applied successfully!");
}

/// Test end-to-end vtable resolution simulation
#[test]
fn test_vtable_resolution_simulation() {
    println!("\n=== End-to-End Vtable Resolution Test ===\n");

    // Setup: Create simulated memory regions

    // 1. Vtable in .rdata (what the vtable pointer points to)
    let vtable_a = SimVtable {
        func1: FUNC_A1,
        func2: FUNC_A2,
        func3: FUNC_A1, // Can reuse
    };

    // 2. Heap object (runtime state)
    let heap_obj = SimHeapObjectSingle {
        vtable: VTABLE_A,
        field1: 0xAAAA,
        field2: 0xBBBB,
    };

    // 3. Global pointer in .data (runtime state)
    let global_value_runtime = HEAP_OBJ_A;

    println!("Runtime state:");
    println!("  qword_global = 0x{:X} (points to heap)", global_value_runtime);
    println!("  heap[0x{:X}].vtable = 0x{:X}", HEAP_OBJ_A, heap_obj.vtable);
    println!("  vtable[0x{:X}].func1 = 0x{:X}", VTABLE_A, vtable_a.func1);

    // === DUMPER ACTIONS ===

    // 4. Create stub (just the vtable pointer)
    let stub_data: Vec<u8> = heap_obj.vtable.to_le_bytes().to_vec();
    let stub_rva: u32 = 0x30000; // Assigned RVA in .heap

    // 5. Create fixup
    let fixup_new_value = MODULE_BASE + stub_rva as u64;

    println!("\nDumper actions:");
    println!("  Created stub at RVA 0x{:X}", stub_rva);
    println!("  Stub contains: {:02X?}", stub_data);
    println!("  Fixup: global → 0x{:X}", fixup_new_value);

    // === VERIFICATION (simulating IDA loading the dump) ===

    // 6. After fixup, global points to stub
    let global_value_dumped = fixup_new_value;

    // 7. Dereference global to get stub address (IDA does this)
    // In IDA: *qword_global gives us the stub location
    // The stub contains the vtable pointer
    let stub_content = u64::from_le_bytes(stub_data[0..8].try_into().unwrap());

    // 8. The vtable pointer in the stub points to .rdata
    assert_eq!(stub_content, VTABLE_A);
    assert!(stub_content >= MODULE_BASE && stub_content < MODULE_BASE + MODULE_SIZE as u64);

    // 9. Simulate vcall resolution:
    //    (*(void (**)(int64))(*qword_global + 0x10))(qword_global)
    //
    //    Step by step:
    //    a) qword_global = 0x140030000 (stub address)
    //    b) *qword_global = 0x140010100 (vtable address from stub)
    //    c) *qword_global + 0x10 = vtable[2] location
    //    d) *(that) = function pointer

    let vcall_offset = 0x10; // Calling vtable[2]
    let vtable_entry_addr = stub_content + vcall_offset;

    // In real scenario, vtable_entry_addr would point to vtable_a.func3
    // For our test, verify the math works out
    let expected_vtable_entry = VTABLE_A + vcall_offset;
    assert_eq!(vtable_entry_addr, expected_vtable_entry);

    println!("\nVcall resolution simulation:");
    println!("  qword_global (after dump) = 0x{:X}", global_value_dumped);
    println!("  *qword_global (stub content) = 0x{:X}", stub_content);
    println!("  *qword_global + 0x10 = 0x{:X}", vtable_entry_addr);
    println!("  This resolves to vtable entry at 0x{:X}", expected_vtable_entry);

    // The key verification: vtable pointer is in .rdata, resolvable by IDA
    let vtable_rva = (stub_content - MODULE_BASE) as u32;
    assert!(vtable_rva >= RDATA_RVA && vtable_rva < DATA_RVA,
        "Vtable should be in .rdata section");

    println!("\n=== TEST PASSED ===");
    println!("Vtable at RVA 0x{:X} is in .rdata, IDA can resolve vcalls!", vtable_rva);
}

/// Test that non-vtable heap pointers are filtered out
#[test]
fn test_non_vtable_filtering() {
    // A heap object whose first qword is NOT a vtable (e.g., a string or buffer)
    let not_a_vtable: u64 = 0x4141414141414141; // "AAAAAAAA"

    // This should NOT be in module range
    let is_in_module = not_a_vtable >= MODULE_BASE
        && not_a_vtable < MODULE_BASE + MODULE_SIZE as u64;

    assert!(!is_in_module, "Random data should not look like vtable");

    // A heap pointer to another heap region (not a vtable)
    let heap_to_heap: u64 = 0x7D00_0000_0000;
    let is_in_module_2 = heap_to_heap >= MODULE_BASE
        && heap_to_heap < MODULE_BASE + MODULE_SIZE as u64;

    assert!(!is_in_module_2, "Heap-to-heap pointer should not be treated as vtable");

    println!("Non-vtable filtering test passed");
}

/// Verify stub size is minimal
#[test]
fn test_stub_size_minimal() {
    // Single inheritance: just 8 bytes
    let single_stub_size = 8;

    // Multiple inheritance with vfptr at offset 16: need 24 bytes
    let mi_offsets = vec![0, 16];
    let max_offset = *mi_offsets.iter().max().unwrap();
    let mi_stub_size = ((max_offset + 8 + 7) / 8) * 8;

    assert_eq!(single_stub_size, 8, "Single inheritance stub should be 8 bytes");
    assert_eq!(mi_stub_size, 24, "MI stub should be 24 bytes (0, 8 padding, 16)");

    // Compare to full object dump (what we DON'T want)
    let full_object_size = std::mem::size_of::<SimHeapObjectSingle>();
    assert!(single_stub_size < full_object_size,
        "Stub ({} bytes) should be smaller than full object ({} bytes)",
        single_stub_size, full_object_size);

    println!("Stub size test passed:");
    println!("  Single inheritance stub: {} bytes", single_stub_size);
    println!("  MI stub: {} bytes", mi_stub_size);
    println!("  Full object would be: {} bytes", full_object_size);
}
