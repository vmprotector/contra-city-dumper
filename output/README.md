# Generated output

These files are a full offline snapshot generated from the 1.0.193 managed
assemblies (Mono, pointer size 4). They document the exact output format and
serve as a compilable example.

The snapshot contains 1575 classes, 20,993 fields, 19,336 methods, and 12,587
string literals. Because it was produced with `--image-dir`, module bases are PE
preferred bases rather than live process addresses, and method runtime addresses
are omitted. Field offsets and method RVAs are complete for this build.

To regenerate from a running client, log into the game so the runtime modules
are loaded, then run:

```powershell
ContraCityDumper.exe --output output
```

Live mode adds native module bases and per-method runtime addresses. Module base
addresses change between runs because the client is ASLR-enabled and some
assemblies are mapped as raw files rather than as relocated images. The field
offsets and method RVAs are the stable part of the output for a given build.

Files:

- `ContraCity_SDK.hpp` - `namespace ContraCity::SDK`, module constants, class
  structs with `static constexpr` field offsets and method RVAs.
- `ContraCity_SDK.json` - schema `contracity-sdk/1`, with `modules -> classes ->
  fields -> offsets`, plus method signatures, string literals, and stats.

The C++ header compiles with C++20:

```powershell
cl /std:c++20 /EHsc /utf-8 /I output test.cpp
```

where `test.cpp` is:

```cpp
#include "ContraCity_SDK.hpp"

int main() {
    return static_cast<int>(ContraCity::SDK::kPointerSize);
}
```
