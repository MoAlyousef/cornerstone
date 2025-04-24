# Cornerstone

*In-process assembler & disassembler built on LLVM MC*

---

Cornerstone wraps the **LLVM** MC subsystem behind a thin, stable C++ façade — and a pure-C header for easy FFI — so you can assemble *and* disassemble machine code at runtime without spinning up external tools.

---

## Features

- **Multi-arch:** x86 / x86-64, ARM, AArch64, and RISC-V (32 & 64) and others!
  Enable or disable targets at compile time via `-DCORNERSTONE_ENABLE_ARCH_*`. The default build will enable all architectures enabled by LLVM.
- **Both directions:** `assemble()` → raw object bytes, `disassemble()` → one-instruction-per-line text.
- **Symbol resolver hook** lets you inject addresses for undefined labels during assembly.
- **Small error-handling model** (`Result<T>` / `CstnError`) that works with or without C++ exceptions.
- **Thread-safe initialisation; re-entrant usage.**

---

## Quick start

```bash
# Build & run the CLI demo (requires CMake ≥3.20 and LLVM 18 installed):
cmake -Bbin -DCMAKE_BUILD_TYPE=Release -DCORNERSTONE_BUILD_EXAMPLES=ON
cmake --build bin --target cornerstone_cli
./bin/cornerstone_cli examples/hello.s hello.o
```

---

## Build & install

### Requirements

| Tool      | Version |
|-----------|---------|
| **LLVM**  | ≥15.0   |
| **CMake** | ≥3.20   |
| **C++**   | 20      |

On Debian/Ubuntu you can grab LLVM packages:

```bash
sudo apt install llvm-dev
```

### Configure options

| CMake var                         | Default | Meaning                     |
|-----------------------------------|---------|-----------------------------|
| `CORNERSTONE_ENABLE_ARCH_X86`     | `ON`    | Build x86 / x86-64 back-end |
| `CORNERSTONE_ENABLE_ARCH_ARM`     | `ON`    | Build ARM32 back-end        |
| `CORNERSTONE_ENABLE_ARCH_AARCH64` | `ON`    | Build AArch64 back-end      |
| `CORNERSTONE_ENABLE_ARCH_RISCV`   | `ON`    | Build RISC-V back-end       |

Disable what you don’t need to speed up linking.

### Static vs. shared

Cornerstone can be built either as a **static** or **shared** (default) library:

```bash
cmake -DCORNERSTONE_BUILD_SHARED=ON ..  # OFF ⇒ static
```

---

## Usage from C++

```cpp
#include <cornerstone/cornerstone.hpp>

int main() {
    auto eng = cstn::Engine::create({ .arch = cstn::Arch::x86_64 }).unwrap();

    std::string obj = eng.assemble("mov eax, 42\nret", 0x401000).unwrap();

    std::string asm_text = eng.disassemble(obj, 0x401000).unwrap();

    std::cout << asm_text << std::endl; // → "mov eax, 42\nret"
}
```

Inclusion in your projects:

You can depend on this project via CMake's FetchContent which will automatically build it:
```cmake
include(FetchContent)
FetchContent_Declare(
    cornerstone
    GIT_REPOSITORY  https://github.com/MoAlyousef/cornerstone
    GIT_SHALLOW     True
    OVERRIDE_FIND_PACKAGE
)
FetchContent_MakeAvailable(cornerstone)
find_package(cornerstone CONFIG REQUIRED)
add_executable(app main.cpp)
target_link_libraries(app PRIVATE cornerstone::cornerstone)
```

---

## Usage from C

```c
#include <cornerstone/cornerstone.h>

static bool my_resolver(const char *sym, uint64_t *val) {
    if (strcmp(sym, "answer") == 0) { *val = 42; return true; }
    return false;
}

int main() {
    CstnError err = CstnError_none();
    CstnEngine *e = cstn_create((CstnOpts){
        .arch = CstnArch_x86_64,
        .syntax = CstnSyntax_Intel,
        .symbol_resolver = my_resolver }, &err);

    size_t sz;
    char *obj = cstn_assemble(e, "mov eax, answer\nret", 0x1000, &sz, &err);
    // ... use obj ...
    free(obj);
    cstn_destroy(e);
}
```

---

## Error handling

Both C and C++ APIs expose detailed diagnostics:

- **Category** – enum (`AsmError`, `DisasmError`, …).
- **Message** – human-readable explanation from LLVM.
- **Line/column** – only for assembly errors.

In C, always `CstnError_reset(&err)` after you’re done to free the internal string.

---

## Contributing

1. Fork & clone.  
2. `pre-commit install` (clang-format, clang-tidy hooks).  
3. Send a PR against `main`.

---

## License

Cornerstone is released under the Apache license. See `LICENSE` for full text.

---

## Acknowledgements

- LLVM Project for the phenomenal MC infrastructure.  
- Capstone & Keystone projects for inspiring the API ergonomics.