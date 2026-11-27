# Contra City SDK Dumper

Standalone Windows offset and metadata dumper for the Contra City Unity client,
builds **1.0.187 - 1.0.192**. It attaches to a running `ContraCity.exe`, locates
the Mono runtime image and the managed assemblies mapped by the game, parses the
CLR metadata, and writes a C++ SDK header plus a hierarchical JSON database.

The dumper does not inject code, patch memory, or call into the game's Mono
runtime. It only opens the process for `PROCESS_VM_READ` and walks the mapped
images.

Related research repository:
[vmprotector/contra-city-decompiled](https://github.com/vmprotector/contra-city-decompiled)

## Downloads

To use the offsets, simply grab the `ContraCity_SDK.hpp` or `ContraCity_SDK.json`
from the `output/` directory. You can also compile the dumper yourself using
CMake.

## What it extracts

- Native module bases: `ContraCity.exe`, `GameAssembly.dll` (when present),
  `UnityPlayer.dll` (when present), `mono*.dll`, and the rest of the module list.
- Managed assembly bases, including assemblies mapped as raw PE files rather
  than relocated images.
- Classes: namespace, full name, token, flags, base type, layout kind, instance
  size, and value-type size/alignment.
- Fields: Mono field offset, static offset, size, alignment, type, flags,
  literal values, and whether the field participates in GC layout.
- Methods: metadata token, RVA, optional runtime address, return/parameter
  types, parameter names, IL body size, and flags.
- String literals: value, `#US` heap token, and every `ldstr` usage with the
  declaring class, method, and IL offset.
- C++ output with `namespace ContraCity::SDK` and `constexpr` offsets/RVAs.
- JSON output with `modules -> classes -> fields -> offsets`, methods, strings,
  warnings, and dump statistics.

## Requirements

- Windows 10 or 11, x64 or x86 build.
- Visual Studio 2022 with the Desktop C++ workload, or another MSVC-compatible
  CMake toolchain.
- CMake 3.20 or newer.
- Administrator privileges when the game runs elevated or is protected by the
  system. `OpenProcess` returns `ACCESS_DENIED` otherwise.
- A Contra City client that ships Mono. Builds 1.0.187-1.0.192 use Unity 5.6
  with `ContraCity_Data\Mono\mono.dll` and `Assembly-CSharp.dll`.

The game itself is 32-bit. An x64 dumper can read a 32-bit process, so either
architecture works; build x64 unless you have a specific reason to match the
target.

## Build

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The executable is written to:

```text
build\Release\ContraCityDumper.exe
```

Optional 32-bit build:

```powershell
cmake -S . -B build32 -G "Visual Studio 17 2022" -A Win32
cmake --build build32 --config Release
```

No third-party libraries are linked. The project uses `kernel32` and the C++20
standard library.

## Run

Start the game first, then run the dumper elevated:

```powershell
.\ContraCityDumper.exe --output output
```

Default target name is `ContraCity.exe`. To attach to a specific process:

```powershell
.\ContraCityDumper.exe --pid 12345 --output output
```

To inspect the module table without writing files:

```powershell
.\ContraCityDumper.exe --list
```

Example filtered run, useful while working on one subsystem:

```powershell
.\ContraCityDumper.exe --output output `
  --class PlayerManager --class CombatPlayer --class WeaponController
```

### Offline assembly directory

If the game is not running, the same metadata parser can read a managed
directory directly:

```powershell
.\ContraCityDumper.exe --image-dir ".\ContraCity_Data\Managed" --output output
```

Offline mode has no runtime addresses. Module bases are the PE preferred bases
and are marked `baseKind: "preferred"` in JSON. Method RVAs and field offsets
are still real for that build.

### Options

| Option | Meaning |
|---|---|
| `--process <name>` | Process image name, default `ContraCity.exe`. |
| `--pid <pid>` | Attach to an explicit process id. |
| `--output <dir>` | Output directory, default `output`. |
| `--image-dir <dir>` | Offline mode: read `*.dll` from a managed directory. |
| `--all` | Emit framework assemblies as well as game assemblies. |
| `--include <text>` | Add an assembly-name substring to the game filter. |
| `--class <text>` | Emit only classes whose full name contains `<text>`. Repeatable. |
| `--no-strings` | Skip the IL walk and `#US` string extraction. |
| `--no-layout` | Do not compute field offsets. |
| `--no-gc-layout` | Disable Mono's GC-aware two-pass layout (debugging aid). |
| `--deep-scan` | Scan whole readable regions for PE headers, not just prefixes. |
| `--scan-budget <mb>` | Deep-scan budget in MiB, default 1024. |
| `--json-only` | Write only `ContraCity_SDK.json`. |
| `--hpp-only` | Write only `ContraCity_SDK.hpp`. |
| `--list` | Print the module table and exit. |
| `--verbose` | Print image-scan diagnostics. |

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Success. |
| `1` | Bad arguments or an unexpected error. |
| `2` | Process or image directory not found. |
| `3` | `OpenProcess` failed, usually because the dumper is not elevated. |
| `4` | Modules were resolved but no game classes were emitted. |
| `5` | Output directory or file could not be written. |

## Output

Both files are written to `--output`:

```text
output/
├── ContraCity_SDK.hpp
└── ContraCity_SDK.json
```

### C++ header

```cpp
namespace ContraCity::SDK {

inline constexpr std::uint32_t kPointerSize = 4u;
inline constexpr char kBuildVersion[] = "1.0.192";

namespace Modules {
inline constexpr std::uintptr_t ContraCity = 0x000D0000ull;
inline constexpr std::uintptr_t mono = 0x10000000ull;
inline constexpr std::uintptr_t Assembly_CSharp = 0x11D07020ull;
}

namespace Classes {

struct PlayerManager {
    static constexpr std::uint32_t kToken = 0x02000292u;
    static constexpr std::uint32_t kSize = 0x110u;

    static constexpr std::uint32_t kOffset_Players = 0x88u;      // Dictionary<Int32, CombatPlayer>
    static constexpr std::uint32_t kOffset_LocalPlayer = 0x8Cu;  // CombatPlayer

    static constexpr std::uint32_t kRva_InitEnvironment = 0x129AC7u;
    static constexpr std::uintptr_t kAddr_InitEnvironment = 0x11E2ECE7ull;
};

}
}
```

`kSize` is the full Mono instance size (including the object header). Field
offsets are relative to the managed object pointer, matching
`mono_field_get_offset`. Static fields use `kStaticOffset_*` and are relative to
the class vtable data block.

### JSON

```json
{
  "schema": "contracity-sdk/1",
  "target": {
    "process": "ContraCity.exe",
    "pid": 12345,
    "build": "1.0.192",
    "mode": "live",
    "pointerSize": 4
  },
  "runtime": {
    "kind": "mono",
    "metadataVersion": "v2.0.50727"
  },
  "modules": [
    {
      "name": "Assembly-CSharp.dll",
      "kind": "managed",
      "runtime": "mono",
      "base": "0x11D07020",
      "size": 5005312,
      "layout": "file",
      "assembly": "Assembly-CSharp",
      "assemblyVersion": "1.0.0.0",
      "classCount": 1249,
      "classes": [
        {
          "name": "PlayerManager",
          "fullName": "PlayerManager",
          "token": "0x02000292",
          "size": 272,
          "layout": "auto",
          "fields": [
            {
              "name": "Players",
              "type": "System.Collections.Generic.Dictionary`2<System.Int32,CombatPlayer>",
              "offset": 136,
              "offsetHex": "0x88",
              "size": 4,
              "static": false
            }
          ],
          "methods": [
            {
              "name": "InitEnvironment",
              "signature": "System.Void InitEnvironment()",
              "rva": 1219271,
              "rvaHex": "0x129AC7",
              "rvaPath": "Assembly-CSharp.dll+0x129AC7",
              "address": "0x11E2ECE7",
              "addressKind": "file"
            }
          ]
        }
      ]
    }
  ],
  "strings": [
    {
      "assembly": "Assembly-CSharp",
      "value": "ability_name_",
      "token": "0x70001234",
      "heapOffset": "0x1234",
      "usages": [
        {
          "class": "AbilityManager",
          "method": "Init",
          "signature": "System.Void Init()",
          "ilOffset": "0x002A"
        }
      ]
    }
  ],
  "stats": {
    "modules": 113,
    "classes": 1506,
    "fields": 20249,
    "methods": 18651,
    "strings": 12002
  }
}
```

`ContraCity_SDK.hpp` and `ContraCity_SDK.json` in `output/` are a full snapshot
from a real 1.0.192 session: 1506 classes, 20,249 fields, 18,651 methods, and
12,002 string literals. See `output/README.md`.

## How offsets are derived

The game is Mono, not IL2CPP. `Assembly-CSharp.dll` and the runtime modules are
mapped by Unity's Mono fork, so the dumper parses the CLR metadata directly from
process memory:

1. Locate a PE header in a committed, readable region.
2. Detect whether the image is a relocated PE image or a raw file view. Mono
   normally maps the assembly file with `mono_file_map` and later versions of
   the client place a small loader header in front of it, so the base is not
   always page-aligned.
3. Read the CLI header and the `BSJB` metadata root.
4. Parse `#~`, `#Strings`, `#US`, and `#Blob`, then the TypeDef/Field/MethodDef
   tables and their signature blobs.
5. Recreate Mono's layout rules:
   - reference types use Mono's GC-aware two-pass layout for `auto` classes:
     fields that contain references are placed first, then non-reference fields,
     preserving declaration order inside each pass;
   - value types use declaration order with the `MonoObject` header included in
     offsets;
   - `sequential` and `explicit` layouts and `ClassLayout` packing are honored;
   - parent instance sizes come from `UnityEngine.dll`, `mscorlib.dll`, and the
     other assemblies parsed as layout context.
6. Walk each IL body with a real opcode-length table, resolve `ldstr` tokens
   against the `#US` heap, and record the usage path.

The layout implementation was checked against runtime
`mono_field_get_offset` values on 1.0.192. Key examples:

| Class | Field | Offset |
|---|---|---:|
| `PlayerManager` | `Players` | `0x88` |
| `PlayerManager` | `LocalPlayer` | `0x8C` |
| `CombatPlayer` | `h` | `0x14` |
| `CombatPlayer` | `rp` | `0x34` |
| `CombatPlayer` | `playerID` | `0xB4` |
| `SoldierController` | `FPSCamera` | `0x0C` |
| `SoldierController` | `runSpeed` | `0x34` |
| `SoldierCamera` | `cvn` | `0x64` |
| `SoldierCamera` | `cvt` | `0x144` |
| `NetworkTransformReceiver` | `cfz` | `0x10` |
| `NetworkTransformInterpolation` | `lastPosition` | `0x68` |
| `CharacterMotorJumping` | `extraHeight` | `0x10` |

Names are obfuscated and can change between builds. Treat every output as
build-specific and regenerate it after a client update.

## RVA and address semantics

`rva` is the MethodDef RVA from metadata. It points at the method's IL body, not
at the JIT-compiled entry point.

- For a normal relocated image, `address = moduleBase + rva` and
  `addressKind = "image"`.
- For a Mono file-mapped assembly, `address = moduleBase + fileOffset(rva)` and
  `addressKind = "file"`.
- In offline mode, addresses are omitted and only RVAs are written.
- `rvaPath` is `<module>+<rva>`, which is stable across runs.

The JIT code for a managed method lives in a different allocation. If you need
JIT entry points, resolve them through the Mono runtime at execution time; the
dumper deliberately stays read-only.

## Mono and IL2CPP

Contra City 1.0.187-1.0.192 is Mono. The tool resolves `GameAssembly.dll` and
`UnityPlayer.dll` when present, and for `GameAssembly.dll` it reads the export
table and records `il2cpp_*` exports. Full IL2CPP metadata parsing is not
implemented, because these builds do not ship the corresponding
`global-metadata.dat` layout. If a future build switches to IL2CPP, the module
list and native exports still work, but class/field extraction will be empty
with an explicit warning.

`--deep-scan` exists for unusual loaders. The default scan checks every readable
region base and a 64 KiB prefix, which covers Mono file views and the small
header used by the current client.

## Repository layout

```text
.
├── CMakeLists.txt
├── CMakePresets.json
├── LICENSE
├── README.md
├── include/
│   └── contra/
│       ├── common.hpp
│       ├── json.hpp
│       ├── layout.hpp
│       ├── loader.hpp
│       ├── metadata.hpp
│       ├── model.hpp
│       ├── pe.hpp
│       └── process.hpp
├── src/
│   ├── common.cpp
│   ├── emit_hpp.cpp
│   ├── emit_json.cpp
│   ├── json.cpp
│   ├── layout.cpp
│   ├── loader.cpp
│   ├── main.cpp
│   ├── metadata.cpp
│   ├── model.cpp
│   ├── pe.cpp
│   └── process.cpp
└── output/
    ├── ContraCity_SDK.hpp
    ├── ContraCity_SDK.json
    └── README.md
```

## Scope

Use the dumper only on processes and files you own or are authorized to inspect.
It is a read-only metadata tool: it does not inject, hook, patch, or bypass
integrity checks. Contra City and its client assets belong to their respective
rights holders. This project is not affiliated with or endorsed by the game's
developer or publisher.

## License

The tool source is released under the Contra City SDK Dumper Research License.
See `LICENSE`. The license is not OSI-approved: it permits non-commercial
research and interoperability work and does not grant rights to the game's
binaries, assets, or trademarks.
