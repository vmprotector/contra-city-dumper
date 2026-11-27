# Generated example

These files are a full snapshot produced from a live `ContraCity.exe` process
(build 1.0.192, Mono, pointer size 4). They document the exact output format and
serve as a compilable example.

The snapshot contains 1506 classes, 20,249 fields, 18,651 methods, and 12,002
string literals. Module bases, PIDs, and generated timestamps are runtime
values. Re-run the tool after restarting the game or installing a different
build:

```powershell
ContraCityDumper.exe --output output
```

Module base addresses change between runs because the client is ASLR-enabled and
some assemblies are mapped as raw files rather than as relocated images. The
field offsets and method RVAs are the stable part of the output for a given
build.

Files:

- `ContraCity_SDK.hpp` - `namespace ContraCity::SDK`, module constants, class
  structs with `static constexpr` field offsets and method RVAs/addresses.
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
