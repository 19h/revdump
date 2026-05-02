# revdump

A PE process dumper that turns runtime C++ heap objects into static-analysis-friendly PE data. revdump preserves just enough object/vtable state for IDA, Ghidra, and similar tools to recover virtual call targets that normal dumps lose.

## The Problem

When you dump a running process, global pointers to heap-allocated C++ objects often become useless. The heap does not exist in the static image, so decompilers see:

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

revdump creates a synthetic `.heap` section containing minimal **vtable stubs**: tiny structures that preserve only the vtable pointers at their correct offsets. Global pointers are rewritten to point to these stubs, so the dumped PE contains a compact static representation of the runtime object graph.

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

Now decompilers can resolve the virtual call chain statically, without importing the whole heap or hand-rebuilding object layouts.

## Why It Is Different

Most dumpers copy module memory and leave runtime heap relationships behind. Most vtable scanners find candidate tables but do not reconnect them to the global pointers and object fields that code actually uses.

revdump bridges that gap:

- It reconstructs C++ object references into a valid PE instead of producing a separate notes file only.
- It emits minimal synthetic objects, avoiding noisy full-heap dumps while keeping vfptr offsets intact.
- It supports secondary vfptrs and multiple inheritance, not just `object+0` vtables.
- It recursively follows heap-owned object references and records a scored object graph.
- It can patch resolved virtual calls and global function-pointer indirect calls into direct calls for better decompiler output.
- It embeds a self-describing `.revdmp` runtime graph so IDA, Ghidra, Binary Ninja, or custom tooling can consume the recovered context without a sidecar; IDAPython annotation output remains optional.

## Features

### Core Dumping
- **Heap snapshot with vtable stubs** - Preserves virtual call resolution
- **Multiple inheritance support** - Handles objects with multiple vtables (probes up to 256 bytes for vfptrs)
- **Recursive heap discovery** - Finds heap-only objects reachable through scanned heap pointers
- **Heap graph metadata** - Deduplicates and scores heap-to-heap edges by confidence
- **Container recognition** - Conservatively detects pointer arrays and vector-like triples
- **Standard PE dump** - Simple copy without heap processing
- **Chunked scanning** - Processes large modules in 4MB chunks

### Vcall Devirtualization
- **Pattern detection** - Identifies `call [rax+offset]`, `jmp [rax+offset]`, and related patterns
- **Direct call patching** - Rewrites indirect vtable calls to direct `call target` instructions
- **Global function-pointer resolution** - Resolves and patches `call [rip+global]` and `mov reg, [rip+global]; call reg` when the global stores a module function pointer
- **Thunk generation** - Places call thunks in code padding for space-constrained patches
- **Secondary vfptr support** - Resolves vcalls through nonzero object vfptr offsets
- **Strong analysis mode** - Optional bounded tracking through object fields, simple stack aliases, guarded call fallthrough, and global function-pointer registers
- **Multi-byte NOP detection** - Finds padding regions for thunk placement

### Analysis Metadata
- **Embedded `.revdmp` section** - Stores a schema manifest, vtable facts, object graph edges, containers, resolved global indirect calls, normalized runtime relationships, and synthetic structs
- **No sidecar required** - `.revdmp` is the authoritative in-PE representation for tooling; the generated `*.ida.py` annotations are compatibility sugar
- **IDA self-check** - Generated script records whether expected annotations were applied
- **RTTI recovery** - Resolves MSVC and Itanium-style type names where metadata is available
- **COFF symbol fallback** - Uses vtable-like COFF symbols when RTTI is unavailable

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
- Optional: IDA Pro `idat64`/`ida64` in `PATH`, or `IDA_PATH`, for headless sidecar smoke testing

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
  --max-depth 2 \
  --max-region-size 4096 \
  --skip-sections 0,1 \
  --devirt \
  --strong-devirt \
  --max-graph-edges 50000 \
  --min-edge-confidence medium
```

Useful toggles:

| Flag | Default | Description |
|------|---------|-------------|
| `--devirt` | off | Rewrite resolved virtual calls to direct calls |
| `--strong-devirt` | off | Track object field loads and simple stack aliases during devirt |
| `--no-ida-script` | off | Disable `*.ida.py` sidecar generation |
| `--no-revdmp` | off | Disable embedded `.revdmp` metadata section |
| `--no-rtti` | off | Disable RTTI parsing for type names |
| `--max-graph-edges <n>` | `50000` | Limit retained heap graph edges after scoring |
| `--min-edge-confidence <low|medium|high>` | `low` | Drop lower-confidence heap graph edges |
| `--no-containers` | off | Disable conservative container detection |

### DLL Injection Mode

1. Inject `revdump.dll` into target process using your preferred injector
2. An interactive console window opens automatically
3. Use commands to configure and execute dumps:

```
revdump> target                   # Prompt for target module
revdump> output                   # Prompt for output path
revdump> devirt                   # Toggle devirtualization
revdump> strongdevirt             # Toggle stronger devirtualization analysis
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

Auto-dump uses `DumpConfig::default()` plus devirtualization enabled by the library entry point. It emits `autodump.exe`, `autodump.exe.ida.py`, and an embedded `.revdmp` section by default.

## Console Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `target <module>` | `module`, `t` | Set target module to dump |
| `output <path>` | `out`, `o` | Set output file path |
| `depth <n>` | `d` | Set recursive heap scan depth (default: 2) |
| `regionsize <kb>` | `region`, `r` | Set max heap bytes scanned per object in KB (default: 4) |
| `skipcode` | `sc` | Toggle skip .text section |
| `skipsections <n,n>` | `ss` | Set section indices to skip |
| `devirt` | `dv` | Toggle vcall devirtualization |
| `strongdevirt` | `sdv` | Toggle stronger devirtualization analysis |
| `ida` | | Toggle IDA sidecar script generation |
| `revdmp` | | Toggle embedded `.revdmp` metadata |
| `rtti` | | Toggle RTTI parsing |
| `containers` | `ct` | Toggle conservative container detection |
| `edges` | | Set max retained graph edges |
| `edgeconf` | | Set minimum edge confidence (`low`, `medium`, `high`) |
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
5. Recursively scan bounded heap prefixes for child heap objects with vfptrs

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
3. Optionally add `.revdmp` metadata with vtable facts, heap graph edges, containers, and synthetic structs
4. Rewrite global pointers: `old_heap_addr` → `stub_rva + image_base`
5. Update PE headers (SizeOfImage, section count)

Heap graph edges are deduplicated by `(source_heap_addr, field_offset, target_heap_addr)` and scored:

| Confidence | Reason |
|------------|--------|
| `high` | Target has a synthetic vtable stub |
| `medium` | Target is a heap object that points to another known heap object |
| `low` | Raw heap pointer only |

Container recognition is intentionally conservative. It currently emits metadata for consecutive heap pointer arrays and vector-like `begin/end/end_cap` triples only when recognized elements resolve to heap objects with vtable stubs.

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

With `strong_devirt` enabled, the scanner also tracks simple patterns such as:

```asm
mov rcx, [global]
mov rcx, [rcx+field]
mov rax, [rcx+vfptr]
call qword ptr [rax+slot]
```

It also tracks simple stack aliases such as `mov [rsp+X], rcx` followed by `mov rcx, [rsp+X]`. This mode is bounded by `max_block_instructions` and is off by default from the CLI because it is more aggressive than direct global-vfptr tracking.

### Phase 6: IDA Annotation (Optional)

When `emit_ida_script` is enabled, revdump writes `<dump>.ida.py` next to the dumped PE. The script:

- Creates synthetic struct members for vfptr offsets
- Names synthetic heap instances and vtables
- Converts vfptr/global/heap-edge qwords to offsets
- Adds comments for original heap addresses, sources, confidence, and container facts
- Runs a lightweight self-check and prints pass/fail status

If `idat64`, `ida64`, or `IDA_PATH` is available, revdump prints a ready-to-run headless smoke command:

```bash
idat64 -A -Sautodump.exe.ida.py autodump.exe
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
| `max_heap_scan_size` | `0x1000` | Max bytes to scan per heap allocation for embedded heap pointers |
| `recursive_heap_scan_depth` | `2` | Max recursive heap-pointer scan depth |
| `emit_ida_script` | `true` | Emit `<dump>.ida.py` sidecar script |
| `emit_revdmp` | `true` | Embed `.revdmp` metadata section |
| `parse_rtti` | `true` | Parse RTTI/type names for metadata and IDA annotations |
| `max_graph_edges` | `50000` | Max retained heap graph edges after dedup/scoring |
| `min_edge_confidence` | `Low` | Minimum retained heap graph confidence |
| `detect_containers` | `true` | Enable conservative container detection |
| `strong_devirt` | `false` | Enable stronger bounded devirt tracking |

### DevirtConfig

| Field | Default | Description |
|-------|---------|-------------|
| `dry_run` | `false` | Analyze only, don't patch |
| `max_block_instructions` | `256` | Reset analysis state after this many instructions |
| `strong_analysis` | `false` | Track object fields and simple stack aliases |

## Output Artifacts

For a heap dump to `autodump.exe`, revdump normally produces:

| Artifact | Description |
|----------|-------------|
| `autodump.exe` | Rebuilt PE with original sections, `.heap`, and optional `.revdmp` |
| `.heap` section | Synthetic minimal heap objects containing normalized vfptrs |
| `.revdmp` section | Text metadata for vtable facts, object graph, containers, and synthetic structs |
| `autodump.exe.ida.py` | IDAPython sidecar for names, offsets, structs, comments, and self-checks |

`.revdmp` sections currently include:

- `REVDMP_VTABLE_FACTS v1`
- `REVDMP_OBJECT_GRAPH v1`
- `REVDMP_CONTAINERS v1`
- `REVDMP_SYNTHETIC_STRUCTS v1`

## Limitations

### Devirtualization Constraints

- **3-byte vcalls without nearby padding** - Cannot patch `call [rax+N]` (3 bytes) if no code padding exists within ±127 bytes for thunk placement
- **x86-64 only** - Devirtualization patterns are 64-bit specific
- **Conservative propagation** - Default mode resolves direct global/object vfptr patterns; `strong_devirt` adds bounded field and stack-alias tracking but still avoids full data-flow analysis
- **RTTI-dependent names** - Type names require usable RTTI or symbol fallback; stripped targets may still produce unnamed vtables
- **Container heuristics** - Container recognition intentionally prefers fewer false positives over broad coverage

### General Limitations

- **Windows PE only** - Designed for Windows executables
- **Runtime analysis** - Must be injected/attached to running process
- **Single process** - Cannot follow cross-process pointers

## Example Output

```
[revdump] Module base: 0x140000000, size: 0x57000
Memory cache: 7998 regions, 30 heap (12 MB)
Stubs: 9 created from 15 pointers (4 duplicates, 2 non-vtable)
Stubs: 6 recursively discovered from heap data
Devirt: 18 vcalls found, 18 resolved, 19 patched
IDA script: autodump.exe.ida.py
IDA smoke command: idat64 -A -Sautodump.exe.ida.py autodump.exe (set IDA_PATH or add idat64/ida64 to PATH)
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

# Verify PE sections and IDA script syntax
x86_64-w64-mingw32-objdump -h autodump.exe
llvm-readobj --sections autodump.exe
python3 -m py_compile autodump.exe.ida.py
```

The test program creates multiple inheritance hierarchies with global interface pointers - the exact patterns revdump is designed to handle.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [iced-x86](https://github.com/icedland/iced) - x86/x64 disassembler and assembler
- [windows-rs](https://github.com/microsoft/windows-rs) - Rust bindings for Windows APIs
