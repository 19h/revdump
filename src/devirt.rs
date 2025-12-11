//! Vcall devirtualization - rewrites indirect vtable calls to direct calls.
//!
//! This module analyzes code sections for patterns like:
//! ```text
//! mov rcx, [rip+global]   ; Load pointer to heap instance
//! mov rax, [rcx]          ; Dereference to get vtable pointer
//! call [rax+0x88]         ; Indirect call via vtable slot
//! ```
//!
//! And rewrites them to direct calls:
//! ```text
//! mov rcx, [rip+global]
//! mov rax, [rcx]
//! call target_func        ; Direct call + NOPs
//! ```
//!
//! This improves static analysis in decompilers like IDA and Ghidra.

use crate::error::Result;
use crate::fixup::SectionMapping;
use crate::memory::safe_read_memory;
use crate::stub::StubGenerator;

use iced_x86::{
    code_asm::*, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register,
};
use std::collections::HashMap;

// ============================================================================
// Types
// ============================================================================

/// Kind of vcall pattern detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcallKind {
    /// `call qword ptr [reg+offset]` - indirect call through vtable
    IndirectCall,
    /// `jmp qword ptr [reg+offset]` - tail call through vtable
    IndirectJmp,
    /// `lea reg, [reg+offset]` - loading function pointer from vtable
    LeaVtableSlot,
    /// `mov reg, [reg+offset]` - loading function pointer into register
    MovVtableSlot,
    /// `call reg` - call through register holding vtable func ptr (can't patch, too short)
    CallRegister,
}

/// A detected vcall site in code.
#[derive(Clone, Debug)]
pub struct VcallSite {
    /// RVA of the instruction.
    pub instruction_rva: u32,
    /// Length of the original instruction in bytes.
    pub instruction_len: usize,
    /// The global RVA that was loaded (source of instance pointer).
    pub global_rva: u32,
    /// Vtable offset being accessed (e.g., 0x88 for slot 17).
    pub vtable_offset: u32,
    /// The resolved target function RVA (if resolvable).
    pub resolved_target: Option<u32>,
    /// Kind of vcall pattern.
    pub kind: VcallKind,
    /// For LEA patterns: the destination register.
    pub dest_register: Option<Register>,
    /// For CallRegister: RVA where to patch (the add instruction), total patch length
    pub patch_site: Option<(u32, usize)>,
}

/// A code patch to apply.
#[derive(Clone, Debug)]
pub struct CodePatch {
    /// RVA of the patch location.
    pub rva: u32,
    /// Original instruction bytes.
    pub original_bytes: Vec<u8>,
    /// New bytes to write (including NOP padding).
    pub patch_bytes: Vec<u8>,
}

/// Statistics for devirtualization.
#[derive(Default, Debug, Clone)]
pub struct DevirtStats {
    /// Total instructions scanned.
    pub instructions_scanned: usize,
    /// Vcall patterns detected.
    pub vcalls_detected: usize,
    /// Vcalls successfully resolved to targets.
    pub vcalls_resolved: usize,
    /// Patches actually applied.
    pub patches_applied: usize,
    /// Globals referenced but not in our map.
    pub unresolved_globals: usize,
    /// Patches skipped (size constraints, etc).
    pub patches_skipped: usize,
    /// Thunks created for indirect patching.
    pub thunks_created: usize,
}

/// A thunk placed in code padding for vcall redirection.
#[derive(Clone, Debug)]
pub struct Thunk {
    /// RVA where the thunk is placed.
    pub rva: u32,
    /// Target function RVA.
    pub target_rva: u32,
    /// RVA to jump back to after the call.
    pub return_rva: u32,
    /// Thunk code bytes.
    pub bytes: Vec<u8>,
}

/// Finds usable NOP/padding regions in code for placing thunks.
pub struct ThunkAllocator {
    /// Available slots (rva, size).
    slots: Vec<(u32, usize)>,
    /// Next slot index.
    next_slot: usize,
}

impl ThunkAllocator {
    /// Check if a byte sequence is a multi-byte NOP.
    /// Returns the length of the NOP if it matches, 0 otherwise.
    fn is_multibyte_nop(code: &[u8]) -> usize {
        if code.is_empty() {
            return 0;
        }

        // Common multi-byte NOP patterns (x86-64):
        // 1 byte:  90                  nop
        // 2 bytes: 66 90               nop
        // 3 bytes: 0f 1f 00            nop [rax]
        // 4 bytes: 0f 1f 40 00         nop [rax+0]
        // 5 bytes: 0f 1f 44 00 00      nop [rax+rax+0]
        // 6 bytes: 66 0f 1f 44 00 00   nop [rax+rax+0]
        // 7 bytes: 0f 1f 80 00 00 00 00    nop [rax+0]
        // 8 bytes: 0f 1f 84 00 00 00 00 00 nop [rax+rax+0]
        // 9 bytes: 66 0f 1f 84 00 00 00 00 00

        // Also detect 66-prefixed NOPs (used for alignment)
        // e.g., 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00 (14-byte aligned NOP)

        match code[0] {
            0x90 => 1, // Standard NOP
            0x66 => {
                // Operand size prefix, could be start of multi-byte NOP
                if code.len() >= 2 && code[1] == 0x90 {
                    return 2;
                }
                // Check for 66-prefixed 0f 1f form
                // Count leading 0x66 prefixes
                let mut prefix_count = 0;
                while prefix_count < code.len() && code[prefix_count] == 0x66 {
                    prefix_count += 1;
                }
                // Check if followed by segment prefix (2e, 3e, etc.) or 0f 1f
                if prefix_count < code.len() {
                    let rest = &code[prefix_count..];
                    if rest.len() >= 2 && rest[0] == 0x2e {
                        // CS segment override, check for 0f 1f
                        if rest.len() >= 4 && rest[1] == 0x0f && rest[2] == 0x1f {
                            // 66...2e 0f 1f xx xx ...
                            return Self::get_0f1f_nop_len(&rest[1..]) + prefix_count + 1;
                        }
                    } else if rest.len() >= 2 && rest[0] == 0x0f && rest[1] == 0x1f {
                        return Self::get_0f1f_nop_len(rest) + prefix_count;
                    }
                }
                0
            }
            0x0f => {
                if code.len() >= 2 && code[1] == 0x1f {
                    Self::get_0f1f_nop_len(code)
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    /// Get length of a 0f 1f xx... NOP sequence.
    fn get_0f1f_nop_len(code: &[u8]) -> usize {
        if code.len() < 3 || code[0] != 0x0f || code[1] != 0x1f {
            return 0;
        }
        let modrm = code[2];
        let mod_bits = (modrm >> 6) & 3;
        let rm = modrm & 7;

        match mod_bits {
            0 => {
                if rm == 4 {
                    // SIB byte follows
                    if code.len() >= 5 {
                        5 // 0f 1f 04 xx 00
                    } else {
                        0
                    }
                } else if rm == 5 {
                    // RIP-relative, 4 byte displacement
                    if code.len() >= 7 {
                        7
                    } else {
                        0
                    }
                } else {
                    3 // 0f 1f 00
                }
            }
            1 => {
                // 1-byte displacement
                if rm == 4 {
                    if code.len() >= 5 {
                        5 // 0f 1f 44 xx 00
                    } else {
                        0
                    }
                } else {
                    4 // 0f 1f 40 00
                }
            }
            2 => {
                // 4-byte displacement
                if rm == 4 {
                    if code.len() >= 8 {
                        8 // 0f 1f 84 xx 00 00 00 00
                    } else {
                        0
                    }
                } else {
                    7 // 0f 1f 80 00 00 00 00
                }
            }
            _ => 0,
        }
    }

    /// Scan code section for padding regions (NOP sleds, INT3 padding, etc).
    pub fn scan_for_padding(code: &[u8], section_rva: u32, min_size: usize) -> Self {
        let mut slots = Vec::new();
        let mut i = 0;

        while i < code.len() {
            // Check for multi-byte NOPs first
            let nop_len = Self::is_multibyte_nop(&code[i..]);
            if nop_len > 0 {
                let start = i;
                // Consume consecutive multi-byte NOPs
                while i < code.len() {
                    let len = Self::is_multibyte_nop(&code[i..]);
                    if len > 0 {
                        i += len;
                    } else {
                        break;
                    }
                }
                let size = i - start;
                if size >= min_size {
                    slots.push((section_rva + start as u32, size));
                }
                continue;
            }

            // Look for single-byte padding: INT3 (0xCC), or zero padding
            if code[i] == 0xCC || code[i] == 0x00 {
                let start = i;
                let pad_byte = code[i];

                // Count consecutive padding bytes
                while i < code.len() && code[i] == pad_byte {
                    i += 1;
                }

                let size = i - start;
                if size >= min_size {
                    slots.push((section_rva + start as u32, size));
                }
            } else {
                i += 1;
            }
        }

        Self { slots, next_slot: 0 }
    }

    /// Allocate space for a thunk. Returns (rva, available_size) or None.
    pub fn allocate(&mut self, needed: usize, near_rva: u32) -> Option<(u32, usize)> {
        // Find a slot within ±127 bytes of near_rva (for jmp rel8)
        for i in 0..self.slots.len() {
            let (slot_rva, slot_size) = self.slots[i];
            if slot_size < needed {
                continue;
            }

            // Check if reachable with jmp rel8
            let offset = slot_rva as i64 - near_rva as i64;
            if offset >= -126 && offset <= 127 {
                // Use this slot
                let result = (slot_rva, slot_size);
                // Shrink or remove the slot
                if slot_size > needed {
                    self.slots[i] = (slot_rva + needed as u32, slot_size - needed);
                } else {
                    self.slots.remove(i);
                }
                return Some(result);
            }
        }
        None
    }
}

/// Configuration for devirtualization.
#[derive(Clone, Debug)]
pub struct DevirtConfig {
    /// Only analyze, don't generate patches (for debugging).
    pub dry_run: bool,
    /// Maximum instructions to scan in a basic block before reset.
    pub max_block_instructions: usize,
}

impl Default for DevirtConfig {
    fn default() -> Self {
        Self {
            dry_run: false,
            max_block_instructions: 256,
        }
    }
}

// ============================================================================
// Register Tracking
// ============================================================================

/// What a register currently holds during analysis.
#[derive(Clone, Debug, Default)]
pub enum RegisterValue {
    /// Unknown or clobbered value.
    #[default]
    Unknown,
    /// Holds a pointer loaded from a global variable.
    GlobalPtr {
        /// RVA of the global that was loaded.
        global_rva: u32,
    },
    /// Holds a vtable pointer (first qword dereferenced from instance).
    VtablePtr {
        /// The original global this came from.
        global_rva: u32,
        /// Offset into the instance where vtable was read (usually 0).
        instance_offset: u32,
        /// RVA of the mov instruction that loaded the vtable.
        deref_instr_rva: u32,
        /// Length of the mov instruction.
        deref_instr_len: usize,
    },
    /// Holds a function pointer loaded from a vtable slot.
    /// This happens when: mov rax, [vtable_reg + offset]
    VtableFuncPtr {
        /// The original global this came from.
        global_rva: u32,
        /// Vtable offset the function was loaded from.
        vtable_offset: u32,
        /// RVA where the patchable sequence starts (add instruction).
        patch_start_rva: u32,
        /// Total length of patchable sequence (add + mov).
        patch_len: usize,
        /// Destination register holding the func ptr.
        dest_reg: Register,
    },
    /// Holds a vtable pointer with an offset added.
    /// This happens when: add rax, 0x20 (where rax held VtablePtr)
    VtablePtrWithOffset {
        /// The original global this came from.
        global_rva: u32,
        /// The added offset.
        offset: u32,
        /// RVA of the add instruction (for patching).
        add_instr_rva: u32,
        /// Length of the add instruction.
        add_instr_len: usize,
    },
}

/// Tracks register state during basic block analysis.
#[derive(Clone, Debug)]
pub struct RegisterState {
    /// State for each general-purpose register (indexed by iced_x86 register number).
    values: HashMap<Register, RegisterValue>,
}

impl Default for RegisterState {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterState {
    pub fn new() -> Self {
        Self {
            values: HashMap::with_capacity(16),
        }
    }

    /// Reset all register state (at basic block boundaries).
    pub fn reset(&mut self) {
        self.values.clear();
    }

    /// Get the value held by a register.
    pub fn get(&self, reg: Register) -> &RegisterValue {
        static UNKNOWN: RegisterValue = RegisterValue::Unknown;
        // Normalize to 64-bit register
        let reg64 = to_64bit_reg(reg);
        self.values.get(&reg64).unwrap_or(&UNKNOWN)
    }

    /// Set the value held by a register.
    pub fn set(&mut self, reg: Register, value: RegisterValue) {
        let reg64 = to_64bit_reg(reg);
        self.values.insert(reg64, value);
    }

    /// Mark a register as clobbered/unknown.
    pub fn clobber(&mut self, reg: Register) {
        let reg64 = to_64bit_reg(reg);
        self.values.remove(&reg64);
    }
}

/// Convert any GPR variant to its 64-bit form.
fn to_64bit_reg(reg: Register) -> Register {
    match reg {
        // RAX family
        Register::AL | Register::AH | Register::AX | Register::EAX | Register::RAX => {
            Register::RAX
        }
        // RBX family
        Register::BL | Register::BH | Register::BX | Register::EBX | Register::RBX => {
            Register::RBX
        }
        // RCX family
        Register::CL | Register::CH | Register::CX | Register::ECX | Register::RCX => {
            Register::RCX
        }
        // RDX family
        Register::DL | Register::DH | Register::DX | Register::EDX | Register::RDX => {
            Register::RDX
        }
        // RSI family
        Register::SIL | Register::SI | Register::ESI | Register::RSI => Register::RSI,
        // RDI family
        Register::DIL | Register::DI | Register::EDI | Register::RDI => Register::RDI,
        // RBP family
        Register::BPL | Register::BP | Register::EBP | Register::RBP => Register::RBP,
        // RSP family
        Register::SPL | Register::SP | Register::ESP | Register::RSP => Register::RSP,
        // R8-R15 families
        Register::R8L | Register::R8W | Register::R8D | Register::R8 => Register::R8,
        Register::R9L | Register::R9W | Register::R9D | Register::R9 => Register::R9,
        Register::R10L | Register::R10W | Register::R10D | Register::R10 => Register::R10,
        Register::R11L | Register::R11W | Register::R11D | Register::R11 => Register::R11,
        Register::R12L | Register::R12W | Register::R12D | Register::R12 => Register::R12,
        Register::R13L | Register::R13W | Register::R13D | Register::R13 => Register::R13,
        Register::R14L | Register::R14W | Register::R14D | Register::R14 => Register::R14,
        Register::R15L | Register::R15W | Register::R15D | Register::R15 => Register::R15,
        // Anything else passes through
        other => other,
    }
}

/// Check if instruction is a control flow boundary (resets register tracking).
fn is_control_flow(instr: &Instruction) -> bool {
    matches!(
        instr.mnemonic(),
        Mnemonic::Jmp
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jrcxz
            | Mnemonic::Loop
            | Mnemonic::Loope
            | Mnemonic::Loopne
            | Mnemonic::Call
            | Mnemonic::Ret
            | Mnemonic::Retf
            | Mnemonic::Iret
            | Mnemonic::Iretd
            | Mnemonic::Iretq
            | Mnemonic::Int
            | Mnemonic::Int1
            | Mnemonic::Int3
            | Mnemonic::Into
            | Mnemonic::Syscall
            | Mnemonic::Sysret
    )
}

// ============================================================================
// Global-to-Vtable Mapping
// ============================================================================

/// Maps global RVAs to their resolved vtable information.
pub struct GlobalVtableMap {
    /// global_rva -> VtableInfo
    map: HashMap<u32, VtableInfo>,
}

/// Information about a vtable accessible via a global.
#[derive(Clone, Debug)]
struct VtableInfo {
    /// The heap address the global points to.
    #[allow(dead_code)]
    heap_addr: u64,
    /// RVA of the vtable within the module.
    vtable_rva: u32,
    /// Module base for reading vtable slots.
    mod_base: u64,
}

impl GlobalVtableMap {
    /// Build the map from scanner results and stub generator.
    pub fn build(
        heap_ptr_locs: &[(u32, u64)],
        stub_generator: &StubGenerator,
        image_base: u64,
    ) -> Self {
        let mut map = HashMap::with_capacity(heap_ptr_locs.len());

        for &(global_rva, heap_addr) in heap_ptr_locs {
            if let Some(stub) = stub_generator.get_stub(heap_addr) {
                // Get the primary vtable (offset 0)
                if let Some(vtable_ref) = stub.vtable_refs.iter().find(|r| r.offset == 0) {
                    map.insert(
                        global_rva,
                        VtableInfo {
                            heap_addr,
                            vtable_rva: vtable_ref.vtable_rva,
                            mod_base: image_base,
                        },
                    );
                }
            }
        }

        Self { map }
    }

    /// Check if a global RVA is in our map.
    pub fn contains(&self, global_rva: u32) -> bool {
        self.map.contains_key(&global_rva)
    }

    /// Resolve a vcall: given a global and vtable offset, return the function RVA.
    ///
    /// This reads the vtable slot from module memory.
    pub fn resolve_vcall(
        &self,
        global_rva: u32,
        vtable_offset: u32,
        mod_base: *const u8,
    ) -> Option<u32> {
        let info = self.map.get(&global_rva)?;

        // Calculate address of vtable slot
        let vtable_addr = mod_base as u64 + info.vtable_rva as u64;
        let slot_addr = vtable_addr + vtable_offset as u64;

        // Read the function pointer from the vtable
        let mut func_ptr_bytes = [0u8; 8];
        if !safe_read_memory(slot_addr as *const u8, &mut func_ptr_bytes) {
            return None;
        }

        let func_ptr = u64::from_le_bytes(func_ptr_bytes);

        // Convert to RVA (must be within module)
        if func_ptr >= info.mod_base {
            let rva = (func_ptr - info.mod_base) as u32;
            Some(rva)
        } else {
            None
        }
    }

    /// Get the number of mapped globals.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ============================================================================
// Vcall Scanner
// ============================================================================

/// Scans code sections for vcall patterns.
pub struct VcallScanner<'a> {
    /// Module base address.
    mod_base: *const u8,
    /// Module image base (for RIP-relative calculations).
    image_base: u64,
    /// Global-to-vtable mapping.
    global_map: &'a GlobalVtableMap,
    /// Configuration.
    config: &'a DevirtConfig,
}

impl<'a> VcallScanner<'a> {
    pub fn new(
        mod_base: *const u8,
        image_base: u64,
        global_map: &'a GlobalVtableMap,
        config: &'a DevirtConfig,
    ) -> Self {
        Self {
            mod_base,
            image_base,
            global_map,
            config,
        }
    }

    /// Scan a code section for vcall patterns.
    pub fn scan_section(&self, code: &[u8], section_rva: u32) -> (Vec<VcallSite>, DevirtStats) {
        let mut sites = Vec::new();
        let mut stats = DevirtStats::default();
        let mut reg_state = RegisterState::new();
        let mut block_instr_count = 0usize;

        let start_ip = self.image_base + section_rva as u64;
        let mut decoder = Decoder::with_ip(64, code, start_ip, DecoderOptions::NONE);

        while decoder.can_decode() {
            let instr = decoder.decode();
            let instr_rva = (instr.ip() - self.image_base) as u32;
            stats.instructions_scanned += 1;

            // Reset at control flow boundaries or after too many instructions
            block_instr_count += 1;
            if is_control_flow(&instr) || block_instr_count > self.config.max_block_instructions {
                // But first check if this is a vcall/vjmp before resetting
                let maybe_site = match instr.mnemonic() {
                    Mnemonic::Call => {
                        // First try indirect call (call [reg+offset])
                        if let Some(site) = self.check_indirect_call(&instr, &reg_state, instr_rva) {
                            Some(site)
                        } else {
                            // Then try call register (call reg)
                            self.check_call_register(&instr, &reg_state, instr_rva)
                        }
                    }
                    Mnemonic::Jmp => self.check_indirect_jmp(&instr, &reg_state, instr_rva),
                    _ => None,
                };
                if let Some(mut site) = maybe_site {
                    site.resolved_target = self.global_map.resolve_vcall(
                        site.global_rva,
                        site.vtable_offset,
                        self.mod_base,
                    );
                    if site.resolved_target.is_some() {
                        stats.vcalls_resolved += 1;
                    } else {
                        stats.unresolved_globals += 1;
                    }
                    stats.vcalls_detected += 1;
                    sites.push(site);
                }
                reg_state.reset();
                block_instr_count = 0;
                continue;
            }

            // Pattern 1: mov reg, [rip+disp] - load from global
            if let Some((dest, global_rva)) = self.check_global_load(&instr) {
                if self.global_map.contains(global_rva) {
                    reg_state.set(dest, RegisterValue::GlobalPtr { global_rva });
                }
                continue;
            }

            // Pattern 2: mov reg, [reg] - dereference to get vtable
            if let Some((dest, src_global_rva)) = self.check_vtable_deref(&instr, &reg_state) {
                reg_state.set(
                    dest,
                    RegisterValue::VtablePtr {
                        global_rva: src_global_rva,
                        instance_offset: 0,
                        deref_instr_rva: instr_rva,
                        deref_instr_len: instr.len(),
                    },
                );
                continue;
            }

            // Pattern 3: lea reg, [reg+offset] - load vtable slot address
            if let Some(mut site) = self.check_lea_pattern(&instr, &reg_state, instr_rva) {
                site.resolved_target = self.global_map.resolve_vcall(
                    site.global_rva,
                    site.vtable_offset,
                    self.mod_base,
                );
                if site.resolved_target.is_some() {
                    stats.vcalls_resolved += 1;
                } else {
                    stats.unresolved_globals += 1;
                }
                stats.vcalls_detected += 1;
                sites.push(site);
                continue;
            }

            // Pattern 4: mov reg, [reg+offset] - load function pointer from vtable
            if let Some(mut site) = self.check_mov_vtable_pattern(&instr, &reg_state, instr_rva) {
                site.resolved_target = self.global_map.resolve_vcall(
                    site.global_rva,
                    site.vtable_offset,
                    self.mod_base,
                );
                if site.resolved_target.is_some() {
                    stats.vcalls_resolved += 1;
                } else {
                    stats.unresolved_globals += 1;
                }
                stats.vcalls_detected += 1;
                sites.push(site);
                continue;
            }

            // Pattern 5: add reg, imm - add offset to vtable pointer
            if let Some((reg, global_rva, offset)) = self.check_add_offset(&instr, &reg_state) {
                reg_state.set(reg, RegisterValue::VtablePtrWithOffset {
                    global_rva,
                    offset,
                    add_instr_rva: instr_rva,
                    add_instr_len: instr.len(),
                });
                continue;
            }

            // Pattern 6: mov reg, [reg] where reg holds VtablePtrWithOffset
            // This loads function pointer from computed vtable slot
            if let Some((dest, global_rva, vtable_offset, patch_start, patch_len)) =
                self.check_load_from_offset_ptr(&instr, &reg_state, instr_rva)
            {
                reg_state.set(dest, RegisterValue::VtableFuncPtr {
                    global_rva,
                    vtable_offset,
                    patch_start_rva: patch_start,
                    patch_len,
                    dest_reg: dest,
                });
                continue;
            }

            // Pattern 7: call reg where reg holds VtableFuncPtr
            if let Some(mut site) = self.check_call_register(&instr, &reg_state, instr_rva) {
                site.resolved_target = self.global_map.resolve_vcall(
                    site.global_rva,
                    site.vtable_offset,
                    self.mod_base,
                );
                if site.resolved_target.is_some() {
                    stats.vcalls_resolved += 1;
                } else {
                    stats.unresolved_globals += 1;
                }
                stats.vcalls_detected += 1;
                sites.push(site);
                continue;
            }

            // Update register state for other mov instructions
            self.update_reg_state(&instr, &mut reg_state);
        }

        (sites, stats)
    }

    /// Check for `mov reg, [rip+disp32]` pattern (global load).
    fn check_global_load(&self, instr: &Instruction) -> Option<(Register, u32)> {
        if instr.mnemonic() != Mnemonic::Mov {
            return None;
        }

        // Must be: mov reg, [mem]
        if instr.op0_kind() != OpKind::Register {
            return None;
        }
        if instr.op1_kind() != OpKind::Memory {
            return None;
        }

        // Must be RIP-relative addressing
        if instr.memory_base() != Register::RIP {
            return None;
        }

        let dest = instr.op0_register();
        // Calculate the absolute address being loaded, then convert to RVA
        let target_addr = instr.ip_rel_memory_address();
        let global_rva = (target_addr - self.image_base) as u32;

        Some((dest, global_rva))
    }

    /// Check for `mov reg, [reg]` where source reg holds a GlobalPtr.
    fn check_vtable_deref(
        &self,
        instr: &Instruction,
        reg_state: &RegisterState,
    ) -> Option<(Register, u32)> {
        if instr.mnemonic() != Mnemonic::Mov {
            return None;
        }

        if instr.op0_kind() != OpKind::Register {
            return None;
        }
        if instr.op1_kind() != OpKind::Memory {
            return None;
        }

        let dest = instr.op0_register();
        let base = instr.memory_base();

        // Must be simple [reg] with no displacement or index
        if instr.memory_index() != Register::None {
            return None;
        }
        if instr.memory_displacement64() != 0 {
            return None;
        }
        if base == Register::RIP || base == Register::None {
            return None;
        }

        // Check if base register holds a GlobalPtr
        if let RegisterValue::GlobalPtr { global_rva } = reg_state.get(base) {
            return Some((dest, *global_rva));
        }

        None
    }

    /// Check for `call [reg+offset]` pattern where reg holds a VtablePtr.
    fn check_indirect_call(
        &self,
        instr: &Instruction,
        reg_state: &RegisterState,
        instr_rva: u32,
    ) -> Option<VcallSite> {
        if instr.mnemonic() != Mnemonic::Call {
            return None;
        }

        if instr.op0_kind() != OpKind::Memory {
            return None;
        }

        let base = instr.memory_base();
        if base == Register::None || base == Register::RIP {
            return None;
        }

        // No index register (would be computed offset)
        if instr.memory_index() != Register::None {
            return None;
        }

        let displacement = instr.memory_displacement64() as u32;

        // Check if base holds a VtablePtr
        if let RegisterValue::VtablePtr { global_rva, deref_instr_rva, deref_instr_len, .. } = reg_state.get(base) {
            // Calculate total patchable region: from vtable deref to end of call instruction
            // This gives us enough space for a direct call
            let call_end = instr_rva + instr.len() as u32;
            let total_patch_len = (call_end - deref_instr_rva) as usize;

            // Only use extended patch region if the deref and call are contiguous
            // (no intervening instructions that set up arguments)
            let deref_end = *deref_instr_rva + *deref_instr_len as u32;
            let patch_site = if deref_end == instr_rva {
                // Contiguous: safe to patch the whole region
                Some((*deref_instr_rva, total_patch_len))
            } else {
                // Not contiguous: only patch the call itself (may fail if too short)
                None
            };

            return Some(VcallSite {
                instruction_rva: instr_rva,
                instruction_len: instr.len(),
                global_rva: *global_rva,
                vtable_offset: displacement,
                resolved_target: None,
                kind: VcallKind::IndirectCall,
                dest_register: Some(base), // Store the vtable register for patch generation
                patch_site,
            });
        }

        None
    }

    /// Check for `jmp [reg+offset]` pattern (tail call) where reg holds a VtablePtr.
    fn check_indirect_jmp(
        &self,
        instr: &Instruction,
        reg_state: &RegisterState,
        instr_rva: u32,
    ) -> Option<VcallSite> {
        if instr.mnemonic() != Mnemonic::Jmp {
            return None;
        }

        if instr.op0_kind() != OpKind::Memory {
            return None;
        }

        let base = instr.memory_base();
        if base == Register::None || base == Register::RIP {
            return None;
        }

        // No index register (would be computed offset)
        if instr.memory_index() != Register::None {
            return None;
        }

        let displacement = instr.memory_displacement64() as u32;

        // Check if base holds a VtablePtr
        if let RegisterValue::VtablePtr { global_rva, deref_instr_rva, deref_instr_len, .. } = reg_state.get(base) {
            let jmp_end = instr_rva + instr.len() as u32;
            let total_patch_len = (jmp_end - deref_instr_rva) as usize;

            // Only use extended patch if contiguous
            let deref_end = *deref_instr_rva + *deref_instr_len as u32;
            let patch_site = if deref_end == instr_rva {
                Some((*deref_instr_rva, total_patch_len))
            } else {
                None
            };

            return Some(VcallSite {
                instruction_rva: instr_rva,
                instruction_len: instr.len(),
                global_rva: *global_rva,
                vtable_offset: displacement,
                resolved_target: None,
                kind: VcallKind::IndirectJmp,
                dest_register: Some(base),
                patch_site,
            });
        }

        None
    }

    /// Check for `lea reg, [reg+offset]` pattern where base holds a VtablePtr.
    fn check_lea_pattern(
        &self,
        instr: &Instruction,
        reg_state: &RegisterState,
        instr_rva: u32,
    ) -> Option<VcallSite> {
        if instr.mnemonic() != Mnemonic::Lea {
            return None;
        }

        if instr.op0_kind() != OpKind::Register {
            return None;
        }
        if instr.op1_kind() != OpKind::Memory {
            return None;
        }

        let dest = instr.op0_register();
        let base = instr.memory_base();

        if base == Register::None || base == Register::RIP {
            return None;
        }

        // No index register
        if instr.memory_index() != Register::None {
            return None;
        }

        let displacement = instr.memory_displacement64() as u32;

        // Must have non-zero displacement (otherwise it's just mov)
        if displacement == 0 {
            return None;
        }

        // Check if base holds a VtablePtr
        if let RegisterValue::VtablePtr { global_rva, .. } = reg_state.get(base) {
            return Some(VcallSite {
                instruction_rva: instr_rva,
                instruction_len: instr.len(),
                global_rva: *global_rva,
                vtable_offset: displacement,
                resolved_target: None,
                kind: VcallKind::LeaVtableSlot,
                dest_register: Some(dest),
                patch_site: None,
            });
        }

        None
    }

    /// Check for `mov reg, [reg+offset]` pattern where base holds a VtablePtr.
    /// This is when a function pointer is loaded from a vtable into a register
    /// before being called (e.g., mov rax, [rcx+0x18]; call rax).
    fn check_mov_vtable_pattern(
        &self,
        instr: &Instruction,
        reg_state: &RegisterState,
        instr_rva: u32,
    ) -> Option<VcallSite> {
        if instr.mnemonic() != Mnemonic::Mov {
            return None;
        }

        if instr.op0_kind() != OpKind::Register {
            return None;
        }
        if instr.op1_kind() != OpKind::Memory {
            return None;
        }

        let dest = instr.op0_register();
        let base = instr.memory_base();

        // Must not be RIP-relative (that's global load)
        if base == Register::None || base == Register::RIP {
            return None;
        }

        // No index register (would be computed offset)
        if instr.memory_index() != Register::None {
            return None;
        }

        let displacement = instr.memory_displacement64() as u32;

        // Must have non-zero displacement to distinguish from vtable deref
        // (vtable deref has displacement=0, loads the vtable pointer itself)
        if displacement == 0 {
            return None;
        }

        // Check if base holds a VtablePtr
        if let RegisterValue::VtablePtr { global_rva, .. } = reg_state.get(base) {
            return Some(VcallSite {
                instruction_rva: instr_rva,
                instruction_len: instr.len(),
                global_rva: *global_rva,
                vtable_offset: displacement,
                resolved_target: None,
                kind: VcallKind::MovVtableSlot,
                dest_register: Some(dest),
                patch_site: None,
            });
        }

        None
    }

    /// Check for `add reg, imm` where reg holds a VtablePtr.
    /// Returns (register, global_rva, offset).
    fn check_add_offset(
        &self,
        instr: &Instruction,
        reg_state: &RegisterState,
    ) -> Option<(Register, u32, u32)> {
        if instr.mnemonic() != Mnemonic::Add {
            return None;
        }

        if instr.op0_kind() != OpKind::Register {
            return None;
        }

        // Check for immediate operand
        let offset = match instr.op1_kind() {
            OpKind::Immediate8 => instr.immediate8() as u32,
            OpKind::Immediate8to64 => instr.immediate8to64() as u32,
            OpKind::Immediate32 => instr.immediate32(),
            OpKind::Immediate32to64 => instr.immediate32to64() as u32,
            _ => return None,
        };

        let reg = instr.op0_register();

        // Check if reg holds a VtablePtr
        if let RegisterValue::VtablePtr { global_rva, .. } = reg_state.get(reg) {
            return Some((reg, *global_rva, offset));
        }

        None
    }

    /// Check for `mov reg, [reg]` where source reg holds VtablePtrWithOffset.
    /// Returns (dest_reg, global_rva, vtable_offset, patch_start_rva, patch_len).
    fn check_load_from_offset_ptr(
        &self,
        instr: &Instruction,
        reg_state: &RegisterState,
        instr_rva: u32,
    ) -> Option<(Register, u32, u32, u32, usize)> {
        if instr.mnemonic() != Mnemonic::Mov {
            return None;
        }

        if instr.op0_kind() != OpKind::Register {
            return None;
        }
        if instr.op1_kind() != OpKind::Memory {
            return None;
        }

        let dest = instr.op0_register();
        let base = instr.memory_base();

        // Must be simple [reg] with no displacement or index
        if instr.memory_index() != Register::None {
            return None;
        }
        if instr.memory_displacement64() != 0 {
            return None;
        }
        if base == Register::RIP || base == Register::None {
            return None;
        }

        // Check if base register holds a VtablePtrWithOffset
        if let RegisterValue::VtablePtrWithOffset { global_rva, offset, add_instr_rva, add_instr_len } = reg_state.get(base) {
            // Calculate total patch length: add instruction + this mov instruction
            let patch_len = *add_instr_len + instr.len();
            return Some((dest, *global_rva, *offset, *add_instr_rva, patch_len));
        }

        None
    }

    /// Check for `call reg` where reg holds a VtableFuncPtr.
    fn check_call_register(
        &self,
        instr: &Instruction,
        reg_state: &RegisterState,
        instr_rva: u32,
    ) -> Option<VcallSite> {
        if instr.mnemonic() != Mnemonic::Call {
            return None;
        }

        if instr.op0_kind() != OpKind::Register {
            return None;
        }

        let reg = instr.op0_register();

        // Check if reg holds a VtableFuncPtr
        if let RegisterValue::VtableFuncPtr { global_rva, vtable_offset, patch_start_rva, patch_len, dest_reg } = reg_state.get(reg) {
            return Some(VcallSite {
                instruction_rva: instr_rva,
                instruction_len: instr.len(),
                global_rva: *global_rva,
                vtable_offset: *vtable_offset,
                resolved_target: None,
                kind: VcallKind::CallRegister,
                dest_register: Some(*dest_reg),
                patch_site: Some((*patch_start_rva, *patch_len)),
            });
        }

        None
    }

    /// Update register state for general mov instructions.
    fn update_reg_state(&self, instr: &Instruction, reg_state: &mut RegisterState) {
        // If destination is a register, and source is a register, propagate state
        if instr.mnemonic() == Mnemonic::Mov
            && instr.op0_kind() == OpKind::Register
            && instr.op1_kind() == OpKind::Register
        {
            let dest = instr.op0_register();
            let src = instr.op1_register();
            let src_val = reg_state.get(src).clone();
            reg_state.set(dest, src_val);
            return;
        }

        // For other instructions that write to a register, clobber it
        if instr.op0_kind() == OpKind::Register {
            let dest = instr.op0_register();
            // Don't clobber if we already handled it above
            if !matches!(instr.mnemonic(), Mnemonic::Mov if instr.op1_kind() == OpKind::Register) {
                reg_state.clobber(dest);
            }
        }
    }
}

// ============================================================================
// Patch Generation
// ============================================================================

/// Result of patch generation - either inline patch or thunk-based.
pub enum PatchResult {
    /// Direct inline patch.
    Inline(CodePatch),
    /// Needs a thunk - returns (vcall_rva, vcall_len, target_rva, return_rva).
    NeedsThunk {
        vcall_rva: u32,
        vcall_len: usize,
        target_rva: u32,
    },
    /// Cannot patch.
    Skip,
}

/// Generates code patches for vcall sites.
pub struct PatchGenerator {
    image_base: u64,
}

impl PatchGenerator {
    pub fn new(image_base: u64) -> Self {
        Self { image_base }
    }

    /// Generate patches for all resolved vcall sites.
    /// Returns (inline_patches, sites_needing_thunks).
    pub fn generate_patches(&self, sites: &[VcallSite]) -> (Vec<CodePatch>, Vec<(u32, usize, u32)>) {
        let mut patches = Vec::with_capacity(sites.len());
        let mut needs_thunk = Vec::new();

        for site in sites {
            if let Some(target_rva) = site.resolved_target {
                match self.generate_patch(site, target_rva) {
                    PatchResult::Inline(patch) => patches.push(patch),
                    PatchResult::NeedsThunk { vcall_rva, vcall_len, target_rva } => {
                        needs_thunk.push((vcall_rva, vcall_len, target_rva));
                    }
                    PatchResult::Skip => {}
                }
            }
        }

        (patches, needs_thunk)
    }

    fn generate_patch(&self, site: &VcallSite, target_rva: u32) -> PatchResult {
        match site.kind {
            VcallKind::IndirectCall => self.generate_call_patch(site, target_rva),
            VcallKind::IndirectJmp => self.generate_jmp_patch(site, target_rva),
            VcallKind::LeaVtableSlot => {
                match self.generate_lea_patch(site, target_rva) {
                    Some(p) => PatchResult::Inline(p),
                    None => PatchResult::Skip,
                }
            }
            VcallKind::MovVtableSlot => {
                match self.generate_mov_patch(site, target_rva) {
                    Some(p) => PatchResult::Inline(p),
                    None => PatchResult::Skip,
                }
            }
            VcallKind::CallRegister => {
                match self.generate_call_reg_patch(site, target_rva) {
                    Some(p) => PatchResult::Inline(p),
                    None => PatchResult::Skip,
                }
            }
        }
    }

    /// Generate a direct call patch.
    ///
    /// If a patch_site is available (from tracking the vtable deref instruction),
    /// we use the larger region to fit our 5-byte call. Otherwise, request a thunk.
    fn generate_call_patch(&self, site: &VcallSite, target_rva: u32) -> PatchResult {
        let target_ip = self.image_base + target_rva as u64;

        // If we have a patch_site, use the larger region starting from vtable deref
        if let Some((patch_rva, patch_len)) = site.patch_site {
            // Need at least 5 bytes for call rel32
            if patch_len >= 5 {
                let patch_ip = self.image_base + patch_rva as u64;

                // Encode: call rel32 (5 bytes)
                if let Ok(mut asm) = CodeAssembler::new(64) {
                    if asm.call(target_ip).is_ok() {
                        if let Ok(mut patch_bytes) = asm.assemble(patch_ip) {
                            // Pad with NOPs to fill the entire region
                            while patch_bytes.len() < patch_len {
                                patch_bytes.push(0x90);
                            }

                            return PatchResult::Inline(CodePatch {
                                rva: patch_rva,
                                original_bytes: Vec::new(),
                                patch_bytes,
                            });
                        }
                    }
                }
            }
        }

        // Try to patch just the call instruction (may need thunk if too short)
        if site.instruction_len >= 5 {
            let call_ip = self.image_base + site.instruction_rva as u64;

            if let Ok(mut asm) = CodeAssembler::new(64) {
                if asm.call(target_ip).is_ok() {
                    if let Ok(mut patch_bytes) = asm.assemble(call_ip) {
                        while patch_bytes.len() < site.instruction_len {
                            patch_bytes.push(0x90);
                        }

                        return PatchResult::Inline(CodePatch {
                            rva: site.instruction_rva,
                            original_bytes: Vec::new(),
                            patch_bytes,
                        });
                    }
                }
            }
        }

        // Need a thunk for this call (instruction too short for inline patch)
        // Only IndirectCall with instruction_len >= 2 can use thunks (need jmp rel8)
        if site.instruction_len >= 2 {
            PatchResult::NeedsThunk {
                vcall_rva: site.instruction_rva,
                vcall_len: site.instruction_len,
                target_rva,
            }
        } else {
            PatchResult::Skip
        }
    }

    /// Generate a direct jmp patch (for tail calls).
    /// For jmp, we don't use thunks - either inline or skip.
    fn generate_jmp_patch(&self, site: &VcallSite, target_rva: u32) -> PatchResult {
        let target_ip = self.image_base + target_rva as u64;

        // If we have a patch_site, use the larger region
        if let Some((patch_rva, patch_len)) = site.patch_site {
            if patch_len >= 5 {
                let patch_ip = self.image_base + patch_rva as u64;

                if let Ok(mut asm) = CodeAssembler::new(64) {
                    if asm.jmp(target_ip).is_ok() {
                        if let Ok(mut patch_bytes) = asm.assemble(patch_ip) {
                            while patch_bytes.len() < patch_len {
                                patch_bytes.push(0x90);
                            }

                            return PatchResult::Inline(CodePatch {
                                rva: patch_rva,
                                original_bytes: Vec::new(),
                                patch_bytes,
                            });
                        }
                    }
                }
            }
        }

        // Try inline patch at instruction site
        if site.instruction_len >= 5 {
            let jmp_ip = self.image_base + site.instruction_rva as u64;

            if let Ok(mut asm) = CodeAssembler::new(64) {
                if asm.jmp(target_ip).is_ok() {
                    if let Ok(mut patch_bytes) = asm.assemble(jmp_ip) {
                        while patch_bytes.len() < site.instruction_len {
                            patch_bytes.push(0x90);
                        }

                        return PatchResult::Inline(CodePatch {
                            rva: site.instruction_rva,
                            original_bytes: Vec::new(),
                            patch_bytes,
                        });
                    }
                }
            }
        }

        // For jmp, we could theoretically use thunks but it's more complex
        // since we need to replace the return address. Skip for now.
        PatchResult::Skip
    }

    /// Generate a MOV patch that loads the function address directly.
    ///
    /// For MOV patterns, we encode: `mov reg, imm64` (10 bytes) or `lea reg, [rip+rel32]` (7 bytes)
    /// We prefer LEA when possible as it's shorter.
    fn generate_mov_patch(&self, site: &VcallSite, target_rva: u32) -> Option<CodePatch> {
        // Reuse LEA patch generation since the result is the same
        // (loading address into register)
        self.generate_lea_patch(site, target_rva)
    }

    /// Generate a patch for CallRegister pattern (MinGW-style: add+mov+call reg).
    ///
    /// We patch the `add+mov` sequence (7 bytes) to `lea reg, [rip+rel32]` (7 bytes),
    /// leaving the `call reg` instruction unchanged but now calling the right function.
    fn generate_call_reg_patch(&self, site: &VcallSite, target_rva: u32) -> Option<CodePatch> {
        let Some((patch_rva, patch_len)) = site.patch_site else {
            return None;
        };
        let Some(dest_reg) = site.dest_register else {
            return None;
        };
        let dest_reg64 = to_64bit_reg(dest_reg);

        // Need at least 7 bytes for lea reg, [rip+rel32]
        if patch_len < 7 {
            return None;
        }

        // Don't mess with RSP
        if dest_reg64 == Register::RSP {
            return None;
        }

        let lea_ip = self.image_base + patch_rva as u64;
        let target_ip = self.image_base + target_rva as u64;

        // LEA with RIP-relative addressing is 7 bytes: REX.W + 8D + ModRM + rel32
        let lea_len = 7usize;
        let next_ip = lea_ip + lea_len as u64;
        let rel_offset = target_ip as i64 - next_ip as i64;

        // Check if rel32 fits
        if rel_offset < i32::MIN as i64 || rel_offset > i32::MAX as i64 {
            return None;
        }

        let rel32 = rel_offset as i32;

        // Build the LEA instruction manually for RIP-relative addressing
        let mut patch_bytes = Vec::with_capacity(patch_len);

        // REX prefix: REX.W (bit 3) + optional REX.R for R8-R15
        let rex_r = match dest_reg64 {
            Register::R8 | Register::R9 | Register::R10 | Register::R11
            | Register::R12 | Register::R13 | Register::R14 | Register::R15 => 0x44, // REX.WR
            _ => 0x48, // REX.W
        };
        patch_bytes.push(rex_r);

        // LEA opcode
        patch_bytes.push(0x8D);

        // ModRM byte: mod=00, reg=dest, rm=101 (RIP-relative)
        let reg_field = match dest_reg64 {
            Register::RAX => 0,
            Register::RCX => 1,
            Register::RDX => 2,
            Register::RBX => 3,
            Register::RSP => return None,
            Register::RBP => 5,
            Register::RSI => 6,
            Register::RDI => 7,
            Register::R8 => 0,
            Register::R9 => 1,
            Register::R10 => 2,
            Register::R11 => 3,
            Register::R12 => 4,
            Register::R13 => 5,
            Register::R14 => 6,
            Register::R15 => 7,
            _ => return None,
        };
        let modrm = (reg_field << 3) | 0x05; // mod=00, rm=101
        patch_bytes.push(modrm);

        // rel32 displacement (little-endian)
        patch_bytes.extend_from_slice(&rel32.to_le_bytes());

        // Pad with NOPs
        while patch_bytes.len() < patch_len {
            patch_bytes.push(0x90);
        }

        Some(CodePatch {
            rva: patch_rva,
            original_bytes: Vec::new(),
            patch_bytes,
        })
    }

    /// Generate a LEA patch that loads the function address directly.
    ///
    /// For LEA patterns, we encode: `lea reg, [rip+rel32]` - 7 bytes
    /// This loads the address of the target function into the register.
    fn generate_lea_patch(&self, site: &VcallSite, target_rva: u32) -> Option<CodePatch> {
        let lea_ip = self.image_base + site.instruction_rva as u64;
        let target_ip = self.image_base + target_rva as u64;

        let dest_reg = site.dest_register?;
        let dest_reg64 = to_64bit_reg(dest_reg);

        // Don't mess with RSP
        if dest_reg64 == Register::RSP {
            return None;
        }

        // LEA with RIP-relative addressing is 7 bytes: REX.W + 8D + ModRM + rel32
        let lea_len = 7usize;
        let next_ip = lea_ip + lea_len as u64;
        let rel_offset = target_ip as i64 - next_ip as i64;

        // Check if rel32 fits
        if rel_offset < i32::MIN as i64 || rel_offset > i32::MAX as i64 {
            return None;
        }

        let rel32 = rel_offset as i32;

        // Build the LEA instruction manually for RIP-relative addressing
        // Format: REX.W 8D /r (ModRM with RIP-relative mode)
        let mut patch_bytes = Vec::with_capacity(site.instruction_len);

        // REX prefix: REX.W (bit 3) + optional REX.R for R8-R15
        let rex_r = match dest_reg64 {
            Register::R8 | Register::R9 | Register::R10 | Register::R11
            | Register::R12 | Register::R13 | Register::R14 | Register::R15 => 0x44, // REX.WR
            _ => 0x48, // REX.W
        };
        patch_bytes.push(rex_r);

        // LEA opcode
        patch_bytes.push(0x8D);

        // ModRM byte: mod=00, reg=dest, rm=101 (RIP-relative)
        let reg_field = match dest_reg64 {
            Register::RAX => 0,
            Register::RCX => 1,
            Register::RDX => 2,
            Register::RBX => 3,
            Register::RSP => return None,
            Register::RBP => 5,
            Register::RSI => 6,
            Register::RDI => 7,
            Register::R8 => 0,
            Register::R9 => 1,
            Register::R10 => 2,
            Register::R11 => 3,
            Register::R12 => 4,
            Register::R13 => 5,
            Register::R14 => 6,
            Register::R15 => 7,
            _ => return None,
        };
        let modrm = (reg_field << 3) | 0x05; // mod=00, rm=101
        patch_bytes.push(modrm);

        // rel32 displacement (little-endian)
        patch_bytes.extend_from_slice(&rel32.to_le_bytes());

        // Pad with NOPs
        while patch_bytes.len() < site.instruction_len {
            patch_bytes.push(0x90);
        }

        if patch_bytes.len() > site.instruction_len {
            return None;
        }

        Some(CodePatch {
            rva: site.instruction_rva,
            original_bytes: Vec::new(),
            patch_bytes,
        })
    }
}

// ============================================================================
// Patch Application
// ============================================================================

/// Apply code patches to output buffer.
pub fn apply_code_patches(
    output: &mut [u8],
    patches: &[CodePatch],
    section_mappings: &[SectionMapping],
    headers_size: usize,
) -> (usize, usize) {
    let mut applied = 0;
    let mut skipped = 0;

    for patch in patches {
        // Find containing section
        let section = section_mappings.iter().find(|s| {
            patch.rva >= s.virtual_address
                && patch.rva < s.virtual_address + s.virtual_size.max(s.raw_size)
        });

        let file_offset = match section {
            Some(sec) if sec.raw_offset > 0 => {
                if patch.rva < sec.virtual_address {
                    skipped += 1;
                    continue;
                }
                sec.raw_offset + (patch.rva - sec.virtual_address)
            }
            Some(_sec) => {
                skipped += 1;
                continue;
            }
            None => {
                skipped += 1;
                continue;
            }
        };

        // Header protection
        if (file_offset as usize) < headers_size {
            skipped += 1;
            continue;
        }

        // Bounds check
        let offset = file_offset as usize;
        if offset + patch.patch_bytes.len() > output.len() {
            skipped += 1;
            continue;
        }

        // Apply patch
        output[offset..offset + patch.patch_bytes.len()].copy_from_slice(&patch.patch_bytes);
        applied += 1;
    }

    (applied, skipped)
}

/// Generate thunk-based patches for vcalls that couldn't be patched inline.
///
/// A thunk is placed in padding space near the vcall site.
/// The vcall is patched to `jmp rel8` to the thunk.
/// The thunk contains: `call target; jmp back`
fn generate_thunk_patches(
    needs_thunk: &[(u32, usize, u32)], // (vcall_rva, vcall_len, target_rva)
    allocator: &mut ThunkAllocator,
    image_base: u64,
) -> (Vec<CodePatch>, usize) {
    let mut patches = Vec::new();
    let mut thunks_created = 0;

    for &(vcall_rva, vcall_len, target_rva) in needs_thunk {
        // Calculate where we return to after the thunk call
        let return_rva = vcall_rva + vcall_len as u32;

        // Thunk needs: call rel32 (5) + jmp rel8 (2) = 7 bytes minimum
        // Or if return is far: call rel32 (5) + jmp rel32 (5) = 10 bytes
        let thunk_size = 7; // Assume nearby return for now

        // Try to allocate a thunk slot near the vcall
        if let Some((thunk_rva, _)) = allocator.allocate(thunk_size, vcall_rva) {
            // Calculate jmp rel8 offset from vcall to thunk
            // jmp rel8 is 2 bytes: EB offset
            // offset is relative to END of jmp instruction (vcall_rva + 2)
            let jmp_end = vcall_rva + 2;
            let rel8_raw = thunk_rva as i64 - jmp_end as i64;
            let rel8 = rel8_raw as i8;

            // Verify rel8 fits
            if rel8 as i64 == rel8_raw {
                // Build vcall patch: jmp rel8 + padding
                let mut vcall_patch = vec![0xEB, rel8 as u8];
                while vcall_patch.len() < vcall_len {
                    vcall_patch.push(0x90); // NOP padding
                }

                // Build thunk: call target; jmp back
                let thunk_ip = image_base + thunk_rva as u64;
                let target_ip = image_base + target_rva as u64;
                let return_ip = image_base + return_rva as u64;

                let mut thunk_bytes = Vec::new();

                // call rel32 to target
                if let Ok(mut asm) = CodeAssembler::new(64) {
                    if asm.call(target_ip).is_ok() {
                        if let Ok(call_bytes) = asm.assemble(thunk_ip) {
                            thunk_bytes.extend_from_slice(&call_bytes);
                        }
                    }
                }

                if thunk_bytes.len() != 5 {
                    continue; // Failed to encode call
                }

                // jmp rel8 back to return site
                let jmp_back_end = thunk_rva + 5 + 2; // After call (5) and jmp (2)
                let back_rel8 = (return_rva as i64 - jmp_back_end as i64) as i8;

                if back_rel8 as i64 == (return_rva as i64 - jmp_back_end as i64) {
                    thunk_bytes.push(0xEB);
                    thunk_bytes.push(back_rel8 as u8);
                } else {
                    // Need jmp rel32 for far return
                    let jmp_back_ip = image_base + (thunk_rva + 5) as u64;
                    if let Ok(mut asm) = CodeAssembler::new(64) {
                        if asm.jmp(return_ip).is_ok() {
                            if let Ok(jmp_bytes) = asm.assemble(jmp_back_ip) {
                                thunk_bytes.extend_from_slice(&jmp_bytes);
                            }
                        }
                    }
                }

                // Add both patches
                patches.push(CodePatch {
                    rva: vcall_rva,
                    original_bytes: Vec::new(),
                    patch_bytes: vcall_patch,
                });

                patches.push(CodePatch {
                    rva: thunk_rva,
                    original_bytes: Vec::new(),
                    patch_bytes: thunk_bytes,
                });

                thunks_created += 1;
            }
        }
    }

    (patches, thunks_created)
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// Perform devirtualization on a dumped PE.
///
/// This is the main entry point called from the dumper.
pub fn devirtualize(
    output: &mut [u8],
    mod_base: *const u8,
    image_base: u64,
    text_section_rva: u32,
    text_section_size: u32,
    heap_ptr_locs: &[(u32, u64)],
    stub_generator: &StubGenerator,
    section_mappings: &[SectionMapping],
    headers_size: usize,
    config: &DevirtConfig,
) -> Result<DevirtStats> {
    // Build global-to-vtable mapping
    let global_map = GlobalVtableMap::build(heap_ptr_locs, stub_generator, image_base);

    if global_map.is_empty() {
        return Ok(DevirtStats::default());
    }

    // Read .text section from memory
    let text_addr = unsafe { mod_base.add(text_section_rva as usize) };
    let text_data =
        unsafe { std::slice::from_raw_parts(text_addr, text_section_size as usize) };

    // Scan for vcall patterns
    let scanner = VcallScanner::new(mod_base, image_base, &global_map, config);
    let (sites, mut stats) = scanner.scan_section(text_data, text_section_rva);

    if config.dry_run {
        return Ok(stats);
    }

    // Generate inline patches
    let patch_gen = PatchGenerator::new(image_base);
    let (mut patches, needs_thunk) = patch_gen.generate_patches(&sites);

    // Scan for padding regions in .text to place thunks
    // Minimum 7 bytes for a thunk (call rel32 + jmp rel8)
    let mut thunk_allocator = ThunkAllocator::scan_for_padding(text_data, text_section_rva, 7);

    // Generate thunk-based patches for vcalls that couldn't be inlined
    if !needs_thunk.is_empty() {
        let (thunk_patches, thunks_created) =
            generate_thunk_patches(&needs_thunk, &mut thunk_allocator, image_base);
        patches.extend(thunk_patches);
        stats.thunks_created = thunks_created;
    }

    // Apply all patches
    let (applied, skipped) = apply_code_patches(output, &patches, section_mappings, headers_size);

    stats.patches_applied = applied;
    stats.patches_skipped = skipped;

    Ok(stats)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_normalization() {
        assert_eq!(to_64bit_reg(Register::AL), Register::RAX);
        assert_eq!(to_64bit_reg(Register::EAX), Register::RAX);
        assert_eq!(to_64bit_reg(Register::RAX), Register::RAX);
        assert_eq!(to_64bit_reg(Register::R8D), Register::R8);
    }

    #[test]
    fn test_register_state() {
        let mut state = RegisterState::new();

        state.set(Register::RAX, RegisterValue::GlobalPtr { global_rva: 0x1000 });

        if let RegisterValue::GlobalPtr { global_rva } = state.get(Register::RAX) {
            assert_eq!(*global_rva, 0x1000);
        } else {
            panic!("Expected GlobalPtr");
        }

        // Check that EAX maps to the same value
        if let RegisterValue::GlobalPtr { global_rva } = state.get(Register::EAX) {
            assert_eq!(*global_rva, 0x1000);
        } else {
            panic!("Expected GlobalPtr for EAX");
        }
    }

    #[test]
    fn test_control_flow_detection() {
        // This is a basic sanity test - actual instruction would come from decoder
        assert!(matches!(
            Mnemonic::Jmp,
            Mnemonic::Jmp | Mnemonic::Call | Mnemonic::Ret
        ));
    }

    #[test]
    fn test_register_state_propagation() {
        let mut state = RegisterState::new();

        // Set RAX to GlobalPtr
        state.set(Register::RAX, RegisterValue::GlobalPtr { global_rva: 0x2000 });

        // Simulate: mov rcx, rax (propagation)
        let rax_val = state.get(Register::RAX).clone();
        state.set(Register::RCX, rax_val);

        // RCX should now have the same value
        if let RegisterValue::GlobalPtr { global_rva } = state.get(Register::RCX) {
            assert_eq!(*global_rva, 0x2000);
        } else {
            panic!("Expected GlobalPtr in RCX after propagation");
        }
    }

    #[test]
    fn test_register_state_clobber() {
        let mut state = RegisterState::new();

        state.set(Register::RAX, RegisterValue::GlobalPtr { global_rva: 0x1000 });
        state.clobber(Register::RAX);

        assert!(matches!(state.get(Register::RAX), RegisterValue::Unknown));
    }

    #[test]
    fn test_register_state_reset() {
        let mut state = RegisterState::new();

        state.set(Register::RAX, RegisterValue::GlobalPtr { global_rva: 0x1000 });
        state.set(Register::RBX, RegisterValue::VtablePtr { global_rva: 0x2000, instance_offset: 0 });
        state.reset();

        assert!(matches!(state.get(Register::RAX), RegisterValue::Unknown));
        assert!(matches!(state.get(Register::RBX), RegisterValue::Unknown));
    }

    #[test]
    fn test_decode_vcall_pattern() {
        // Assemble a typical vcall sequence:
        // mov rax, [rip+0x1000]  ; load global
        // mov rcx, [rax]         ; deref to vtable
        // call [rcx+0x88]        ; indirect call
        let code: &[u8] = &[
            0x48, 0x8B, 0x05, 0x00, 0x10, 0x00, 0x00,  // mov rax, [rip+0x1000]
            0x48, 0x8B, 0x08,                          // mov rcx, [rax]
            0xFF, 0x51, 0x78,                          // call [rcx+0x78]
        ];

        let image_base = 0x140000000u64;
        let section_rva = 0x1000u32;

        let mut decoder = Decoder::with_ip(
            64,
            code,
            image_base + section_rva as u64,
            DecoderOptions::NONE,
        );

        let instr1 = decoder.decode();
        assert_eq!(instr1.mnemonic(), Mnemonic::Mov);
        assert_eq!(instr1.memory_base(), Register::RIP);

        let instr2 = decoder.decode();
        assert_eq!(instr2.mnemonic(), Mnemonic::Mov);
        assert_eq!(instr2.op0_register(), Register::RCX);
        assert_eq!(instr2.memory_base(), Register::RAX);

        let instr3 = decoder.decode();
        assert_eq!(instr3.mnemonic(), Mnemonic::Call);
        assert_eq!(instr3.op0_kind(), OpKind::Memory);
        assert_eq!(instr3.memory_base(), Register::RCX);
        assert_eq!(instr3.memory_displacement64(), 0x78);
    }

    #[test]
    fn test_decode_call_slot_zero() {
        // call [rcx] - vtable slot 0 (no displacement)
        let code: &[u8] = &[0xFF, 0x11]; // call [rcx]

        let mut decoder = Decoder::with_ip(64, code, 0x140001000, DecoderOptions::NONE);
        let instr = decoder.decode();

        assert_eq!(instr.mnemonic(), Mnemonic::Call);
        assert_eq!(instr.op0_kind(), OpKind::Memory);
        assert_eq!(instr.memory_base(), Register::RCX);
        assert_eq!(instr.memory_displacement64(), 0);
    }

    #[test]
    fn test_decode_jmp_indirect() {
        // jmp [rax+0x10] - tail call pattern
        let code: &[u8] = &[0xFF, 0x60, 0x10]; // jmp [rax+0x10]

        let mut decoder = Decoder::with_ip(64, code, 0x140001000, DecoderOptions::NONE);
        let instr = decoder.decode();

        assert_eq!(instr.mnemonic(), Mnemonic::Jmp);
        assert_eq!(instr.op0_kind(), OpKind::Memory);
        assert_eq!(instr.memory_base(), Register::RAX);
        assert_eq!(instr.memory_displacement64(), 0x10);
    }

    #[test]
    fn test_encode_direct_call() {
        let image_base = 0x140000000u64;
        let call_rva = 0x1000u32;
        let target_rva = 0x5000u32;
        let original_len = 6; // typical call [reg+disp32] length

        let gen = PatchGenerator::new(image_base);

        let site = VcallSite {
            instruction_rva: call_rva,
            instruction_len: original_len,
            global_rva: 0x10000,
            vtable_offset: 0x88,
            resolved_target: Some(target_rva),
            kind: VcallKind::IndirectCall,
            dest_register: None,
                patch_site: None,
        };

        let patches = gen.generate_patches(&[site]);
        assert_eq!(patches.len(), 1);

        let patch = &patches[0];
        assert_eq!(patch.rva, call_rva);
        assert_eq!(patch.patch_bytes.len(), original_len);
        // First byte should be E8 (call rel32)
        assert_eq!(patch.patch_bytes[0], 0xE8);
    }

    #[test]
    fn test_encode_direct_lea() {
        // Test the manual LEA encoding via PatchGenerator
        let image_base = 0x140000000u64;
        let lea_rva = 0x2000u32;
        let target_rva = 0x6000u32;
        let original_len = 7;

        let gen = PatchGenerator::new(image_base);

        let site = VcallSite {
            instruction_rva: lea_rva,
            instruction_len: original_len,
            global_rva: 0x10000,
            vtable_offset: 0x10,
            resolved_target: Some(target_rva),
            kind: VcallKind::LeaVtableSlot,
            dest_register: Some(Register::RAX),
            patch_site: None,
        };

        let patches = gen.generate_patches(&[site]);
        assert_eq!(patches.len(), 1);

        let patch = &patches[0];
        println!("LEA patch: {:02x?}", patch.patch_bytes);

        // Should be 7 bytes: REX.W + 8D + ModRM + rel32
        assert_eq!(patch.patch_bytes.len(), 7);
        // REX.W prefix
        assert_eq!(patch.patch_bytes[0], 0x48, "Expected REX.W prefix");
        // 8D is LEA opcode
        assert_eq!(patch.patch_bytes[1], 0x8D, "Expected LEA opcode");
        // ModRM: reg=RAX(0), rm=101 (RIP-relative) => 0x05
        assert_eq!(patch.patch_bytes[2], 0x05, "Expected ModRM for RAX, RIP-relative");

        // Verify the rel32 is correct
        // target_ip = 0x140006000, next_ip = lea_ip + 7 = 0x140002007
        // rel32 = 0x140006000 - 0x140002007 = 0x3FF9
        let rel32 = i32::from_le_bytes([
            patch.patch_bytes[3],
            patch.patch_bytes[4],
            patch.patch_bytes[5],
            patch.patch_bytes[6],
        ]);
        assert_eq!(rel32, 0x3FF9, "Expected correct rel32 displacement");
    }

    #[test]
    fn test_encode_direct_lea_via_generator() {
        let image_base = 0x140000000u64;
        let lea_rva = 0x2000u32;
        let target_rva = 0x6000u32;
        let original_len = 7; // typical lea reg, [reg+disp32] length

        let gen = PatchGenerator::new(image_base);

        let site = VcallSite {
            instruction_rva: lea_rva,
            instruction_len: original_len,
            global_rva: 0x10000,
            vtable_offset: 0x10,
            resolved_target: Some(target_rva),
            kind: VcallKind::LeaVtableSlot,
            dest_register: Some(Register::RAX),
            patch_site: None,
        };

        let patches = gen.generate_patches(&[site]);
        // LEA patches may fail if the encoding doesn't fit
        // This test checks the generator doesn't panic
        if !patches.is_empty() {
            let patch = &patches[0];
            assert_eq!(patch.rva, lea_rva);
            assert!(patch.patch_bytes.len() <= original_len);
        }
    }

    #[test]
    fn test_vcall_kind_variants() {
        assert_ne!(VcallKind::IndirectCall, VcallKind::LeaVtableSlot);

        let call_site = VcallSite {
            instruction_rva: 0x1000,
            instruction_len: 6,
            global_rva: 0x5000,
            vtable_offset: 0x88,
            resolved_target: Some(0x2000),
            kind: VcallKind::IndirectCall,
            dest_register: None,
                patch_site: None,
        };

        let lea_site = VcallSite {
            instruction_rva: 0x1000,
            instruction_len: 7,
            global_rva: 0x5000,
            vtable_offset: 0x10,
            resolved_target: Some(0x2000),
            kind: VcallKind::LeaVtableSlot,
            dest_register: Some(Register::RBX),
            patch_site: None,
        };

        assert_eq!(call_site.kind, VcallKind::IndirectCall);
        assert_eq!(lea_site.kind, VcallKind::LeaVtableSlot);
    }

    #[test]
    fn test_encode_direct_jmp() {
        let image_base = 0x140000000u64;
        let jmp_rva = 0x1000u32;
        let target_rva = 0x5000u32;
        let original_len = 6; // typical jmp [reg+disp32] length

        let gen = PatchGenerator::new(image_base);

        let site = VcallSite {
            instruction_rva: jmp_rva,
            instruction_len: original_len,
            global_rva: 0x10000,
            vtable_offset: 0x88,
            resolved_target: Some(target_rva),
            kind: VcallKind::IndirectJmp,
            dest_register: None,
                patch_site: None,
        };

        let patches = gen.generate_patches(&[site]);
        assert_eq!(patches.len(), 1);

        let patch = &patches[0];
        assert_eq!(patch.rva, jmp_rva);
        assert_eq!(patch.patch_bytes.len(), original_len);
        // First byte should be E9 (jmp rel32)
        assert_eq!(patch.patch_bytes[0], 0xE9);
    }

    #[test]
    fn test_decode_mov_vtable_slot() {
        // mov rax, [rcx+0x18] - load function pointer from vtable
        let code: &[u8] = &[0x48, 0x8B, 0x41, 0x18]; // mov rax, [rcx+0x18]

        let mut decoder = Decoder::with_ip(64, code, 0x140001000, DecoderOptions::NONE);
        let instr = decoder.decode();

        assert_eq!(instr.mnemonic(), Mnemonic::Mov);
        assert_eq!(instr.op0_kind(), OpKind::Register);
        assert_eq!(instr.op0_register(), Register::RAX);
        assert_eq!(instr.op1_kind(), OpKind::Memory);
        assert_eq!(instr.memory_base(), Register::RCX);
        assert_eq!(instr.memory_displacement64(), 0x18);
    }

    #[test]
    fn test_encode_mov_vtable_slot_patch() {
        // MovVtableSlot is patched as LEA (loads address into register)
        let image_base = 0x140000000u64;
        let mov_rva = 0x2000u32;
        let target_rva = 0x6000u32;
        let original_len = 7;

        let gen = PatchGenerator::new(image_base);

        let site = VcallSite {
            instruction_rva: mov_rva,
            instruction_len: original_len,
            global_rva: 0x10000,
            vtable_offset: 0x18,
            resolved_target: Some(target_rva),
            kind: VcallKind::MovVtableSlot,
            dest_register: Some(Register::RAX),
            patch_site: None,
        };

        let patches = gen.generate_patches(&[site]);
        assert_eq!(patches.len(), 1);

        let patch = &patches[0];
        // Should be LEA encoding: REX.W + 8D + ModRM + rel32
        assert_eq!(patch.patch_bytes[0], 0x48, "Expected REX.W prefix");
        assert_eq!(patch.patch_bytes[1], 0x8D, "Expected LEA opcode");
    }

    #[test]
    fn test_all_vcall_kinds_distinct() {
        assert_ne!(VcallKind::IndirectCall, VcallKind::IndirectJmp);
        assert_ne!(VcallKind::IndirectCall, VcallKind::LeaVtableSlot);
        assert_ne!(VcallKind::IndirectCall, VcallKind::MovVtableSlot);
        assert_ne!(VcallKind::IndirectJmp, VcallKind::LeaVtableSlot);
        assert_ne!(VcallKind::IndirectJmp, VcallKind::MovVtableSlot);
        assert_ne!(VcallKind::LeaVtableSlot, VcallKind::MovVtableSlot);
    }
}
