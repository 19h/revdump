# revdump

A PE process dumper that resolves virtual calls through heap-allocated class instances by creating synthetic vtable stubs.

## The Problem

When you dump a running process, global pointers to heap-allocated C++ objects become useless. The heap doesn't exist in the static image, so decompilers see:

```c
// In IDA/Ghidra after a normal dump:
g_audioEngine = 0x00007FFF12340000;  // Points to... nothing
```

Virtual calls through these globals become unresolvable:

```asm
mov  rcx, cs:g_audioEngine    ; Load pointer to heap object
mov  rax, [rcx]               ; Load vtable pointer (FAILS - heap is gone)
call qword ptr [rax+20h]      ; Which function? Nobody knows.
```

## The Solution

revdump creates a synthetic `.heap` section containing minimal **vtable stubs** - tiny structures that preserve only the vtable pointers at their correct offsets. Global pointers are rewritten to point to these stubs.

**Before (runtime):**
```
g_audioEngine → [heap object] → vtable → AudioService::setVolume
                     ↓
              (heap is lost on dump)
```

**After (revdump):**
```
g_audioEngine → [8-byte stub in .heap] → vtable → AudioService::setVolume
                     ↓
              (vtable pointer preserved!)
```

Now decompilers can resolve the virtual call chain statically.

## Features

### Core Dumping
- **Heap snapshot with vtable stubs** - Preserves virtual call resolution
- **Multiple inheritance support** - Handles objects with multiple vtables (probes up to 256 bytes for vfptrs)
- **Standard PE dump** - Simple copy without heap processing
- **Chunked scanning** - Processes large modules in 4MB chunks

### Vcall Devirtualization
- **Pattern detection** - Identifies `call [rax+offset]`, `jmp [rax+offset]`, and related patterns
- **Direct call patching** - Rewrites indirect vtable calls to direct `call target` instructions
- **Thunk generation** - Places call thunks in code padding for space-constrained patches
- **Multi-byte NOP detection** - Finds padding regions for thunk placement

### Performance
- **SIMD-optimized scanning** - AVX2, SSE4.2, and scalar paths with runtime detection
- **Memory region caching** - O(log n) pointer validation via cached VirtualQuery results
- **Parallel-ready architecture** - Rayon integration for future parallel scanning

### Interfaces
- **CLI tool** - Full-featured command-line interface with progress bars
- **DLL injection** - Interactive console when injected into target process
- **Auto-dump mode** - Set `REVDUMP_AUTO=1` for automatic dump on DLL load

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/revdump/revdump-rs
cd revdump-rs

# Build release binary and DLL (requires MinGW for Windows targets)
cargo build --release --target x86_64-pc-windows-gnu

# Outputs:
#   target/x86_64-pc-windows-gnu/release/revdump.exe  (CLI)
#   target/x86_64-pc-windows-gnu/release/revdump.dll  (Injectable DLL)
```

### Requirements

- Rust 1.70+ with `x86_64-pc-windows-gnu` target
- MinGW-w64 toolchain for cross-compilation
- Windows target (runs on Windows or via Wine)

## Usage

### CLI Mode

```bash
# Dump with heap snapshot and devirtualization
revdump dump --module game.exe --output dumped.exe --devirt

# Standard dump (no heap processing)
revdump standard-dump --module game.exe --output dump.exe

# List loaded modules
revdump list-modules

# Full options
revdump dump \
  --module target.exe \
  --output out.exe \
  --max-depth 16 \
  --max-region-size 131072 \
  --skip-sections 0,1 \
  --devirt
```

### DLL Injection Mode

1. Inject `revdump.dll` into target process using your preferred injector
2. An interactive console window opens automatically
3. Use commands to configure and execute dumps:

```
revdump> target game.exe          # Set target module
revdump> output dumped.exe        # Set output file
revdump> devirt on                # Enable devirtualization
revdump> dump                     # Execute dump

# Or quick dump with defaults:
revdump> go
```

### Auto-Dump Mode

For automated dumping without interaction:

```bash
# Windows
set REVDUMP_AUTO=1
# Then inject revdump.dll - it will dump to autodump.exe and exit

# Wine/Linux
REVDUMP_AUTO=1 wine target.exe  # If target loads revdump.dll
```

## Console Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `target <module>` | `module`, `t` | Set target module to dump |
| `output <path>` | `out`, `o` | Set output file path |
| `depth <n>` | `d` | Set max pointer chain depth (default: 8) |
| `regionsize <kb>` | `region`, `r` | Set max region size in KB (default: 64) |
| `skipcode` | `sc` | Toggle skip .text section |
| `skipsections <n,n>` | `ss` | Set section indices to skip |
| `devirt [on\|off]` | `dv` | Toggle vcall devirtualization |
| `dump` | `dumpheap`, `dh` | Interactive heap dump |
| `dumpstd` | `ds`, `standard` | Standard dump (no heap) |
| `go` | `run`, `!` | Quick dump with current settings |
| `status` | `s` | Show current settings |
| `modules` | `m`, `list` | List loaded modules |
| `debug` | `dbg` | Debug heap pointer analysis |
| `help` | `h`, `?` | Show help |
| `clear` | `cls` | Clear console |
| `quit` | `exit`, `q` | Exit console |

## How It Works

### Phase 1: Memory Region Caching

Build a cache of all memory regions via `VirtualQuery`. This enables O(log n) validation of whether an address is in heap memory (MEM_PRIVATE or MEM_MAPPED).

### Phase 2: Pointer Scanning

Scan module sections for values that look like heap pointers:
- Within valid address range (0x10000 - 0x7FFFFFFFFFFF)
- Points to cached heap region
- Not pointing back into the module itself

Uses SIMD (AVX2/SSE4.2) for high-performance scanning of 4MB chunks.

### Phase 3: Vtable Stub Generation

For each heap pointer found:
1. Read the heap object's first 8 bytes (vtable pointer)
2. Verify it points back into the module's `.rdata` section (where vtables live)
3. Probe for additional vtable pointers (multiple inheritance)
4. Create a minimal stub containing only the vtable pointer(s)

**Single inheritance:** 8-byte stub
```
[vtable_ptr]
```

**Multiple inheritance (e.g., IService + IAudioEngine):** 24-byte stub
```
[vtable_ptr_1][padding][vtable_ptr_2]
     0           8          16
```

### Phase 4: PE Construction

1. Copy original PE sections
2. Add new `.heap` section with all vtable stubs
3. Rewrite global pointers: `old_heap_addr` → `stub_rva + image_base`
4. Update PE headers (SizeOfImage, section count)

### Phase 5: Devirtualization (Optional)

Scan `.text` section for vcall patterns and rewrite them:

**Before:**
```asm
mov  rax, [rcx]           ; Load vtable
call qword ptr [rax+20h]  ; Indirect call through vtable
```

**After:**
```asm
call 0x140002710          ; Direct call to resolved function
nop                       ; Padding
```

For 3-byte indirect calls that can't fit a 5-byte direct call, revdump places thunks in nearby code padding:

```asm
; Original site (3 bytes)
jmp  short thunk          ; 2-byte jump to thunk
nop                       ; 1-byte padding

; Thunk (in NOP sled nearby)
thunk:
call 0x140002710          ; 5-byte direct call
jmp  short return_site    ; 2-byte jump back
```

## Architecture

```
src/
├── main.rs        # CLI entry point
├── lib.rs         # Library + DLL entry point
├── console.rs     # Interactive REPL for DLL mode
├── dumper.rs      # Main dump orchestration
├── pe.rs          # PE header parsing
├── scanner.rs     # SIMD pointer scanning
├── memory.rs      # Memory region caching
├── stub.rs        # Vtable stub generation
├── fixup.rs       # Pointer fixup application
├── devirt.rs      # Vcall devirtualization
└── error.rs       # Error types
```

## Configuration Reference

### DumpConfig

| Field | Default | Description |
|-------|---------|-------------|
| `min_ptr_value` | `0x10000` | Minimum valid pointer value |
| `max_ptr_value` | `0x7FFF_FFFF_FFFF` | Maximum valid pointer value |
| `max_vfptr_probe` | `256` | Max bytes to probe for multiple vtables |
| `skip_sections` | `[]` | Section indices to skip during scanning |
| `enable_devirt` | `false` | Enable vcall devirtualization |

### DevirtConfig

| Field | Default | Description |
|-------|---------|-------------|
| `dry_run` | `false` | Analyze only, don't patch |

## Limitations

### Devirtualization Constraints

- **3-byte vcalls without nearby padding** - Cannot patch `call [rax+N]` (3 bytes) if no code padding exists within ±127 bytes for thunk placement
- **x86-64 only** - Devirtualization patterns are 64-bit specific
- **Direct vtable access only** - Resolves calls through globals pointing directly to heap objects with vtables

### General Limitations

- **Windows PE only** - Designed for Windows executables
- **Runtime analysis** - Must be injected/attached to running process
- **Single process** - Cannot follow cross-process pointers

## Example Output

```
[revdump] Module base: 0x140000000, size: 0x57000
Memory cache: 3494 regions, 31 heap (12 MB)
Stubs: 9 created from 15 pointers (4 duplicates, 2 non-vtable)
Devirt: 18 vcalls found, 18 resolved, 14 patched
[revdump] Dump complete: autodump.exe
```

After loading in IDA:

```c
// Before revdump - unresolved:
(**(void (__fastcall ***)(void *, _QWORD))g_audioEngine)(g_audioEngine, 0x8000000000000001LL);

// After revdump - resolved:
AudioService::setVolume(g_audioEngine, 0.8f);
```

## Testing

```bash
# Build test target
cd test
x86_64-w64-mingw32-g++ -o test_vtable.exe test_vtable.cpp -static

# Run with revdump (via Wine if on Linux)
REVDUMP_AUTO=1 wine ./test_vtable.exe

# Verify output
file autodump.exe
# autodump.exe: PE32+ executable (console) x86-64, for MS Windows
```

The test program creates multiple inheritance hierarchies with global interface pointers - the exact patterns revdump is designed to handle.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [iced-x86](https://github.com/icedland/iced) - x86/x64 disassembler and assembler
- [windows-rs](https://github.com/microsoft/windows-rs) - Rust bindings for Windows APIs
