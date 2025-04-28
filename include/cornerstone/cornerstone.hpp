#ifndef CORNERSTONE_HPP
#define CORNERSTONE_HPP

/**
 * @file cornerstone.hpp
 * @brief Public C++ API for the Cornerstone in‑process assembler / disassembler
 *        built on top of LLVM MC.  Everything is header‑only except for the
 *        implementation (.cpp) file that wires the calls to LLVM.
 *
 * The header purposefully keeps the surface small so that it can be consumed
 * from C, C++, Rust (via cxx bridge) or Zig.  Error handling is modelled after
 * Rustʼs `Result<T, E>` while still remaining fully exception‑free unless you
 * voluntarily call one of the *expect()* helpers.
 *
 * Thread‑safety: Construction is internally synchronised (see
 * `std::call_once`), but individual `Engine` instances are *not* thread‑safe
 * once created.  Guard them with external mutexes if you share across threads.
 */

#include <memory>
#include <ostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace cstn {

/**
 * User‑supplied callback for resolving undefined symbols that appear while
 * assembling.  Return `true` and write the absolute value into @p value to
 * override the undefined symbol, or return `false` to propagate a
 * `ErrorEnum::MissingSymbol` back to the caller.
 */
using SymbolResolver = bool (*)(const char *symbol, uint64_t *value);

/**
 * Supported target architectures.  Enumerator values purposely mirror
 * `llvm::Triple::ArchType` so they can be `static_cast`‑ed directly.
 */
enum class Arch {
    UnknownArch,

    arm,            // ARM (little endian): arm, armv.*, xscale
    armeb,          // ARM (big endian): armeb
    aarch64,        // AArch64 (little endian): aarch64
    aarch64_be,     // AArch64 (big endian): aarch64_be
    aarch64_32,     // AArch64 (little endian) ILP32: aarch64_32
    arc,            // ARC: Synopsys ARC
    avr,            // AVR: Atmel AVR microcontroller
    bpfel,          // eBPF or extended BPF or 64-bit BPF (little endian)
    bpfeb,          // eBPF or extended BPF or 64-bit BPF (big endian)
    csky,           // CSKY: csky
    dxil,           // DXIL 32-bit DirectX bytecode
    hexagon,        // Hexagon: hexagon
    loongarch32,    // LoongArch (32-bit): loongarch32
    loongarch64,    // LoongArch (64-bit): loongarch64
    m68k,           // M68k: Motorola 680x0 family
    mips,           // MIPS: mips, mipsallegrex, mipsr6
    mipsel,         // MIPSEL: mipsel, mipsallegrexe, mipsr6el
    mips64,         // MIPS64: mips64, mips64r6, mipsn32, mipsn32r6
    mips64el,       // MIPS64EL: mips64el, mips64r6el, mipsn32el, mipsn32r6el
    msp430,         // MSP430: msp430
    ppc,            // PPC: powerpc
    ppcle,          // PPCLE: powerpc (little endian)
    ppc64,          // PPC64: powerpc64, ppu
    ppc64le,        // PPC64LE: powerpc64le
    r600,           // R600: AMD GPUs HD2XXX - HD6XXX
    amdgcn,         // AMDGCN: AMD GCN GPUs
    riscv32,        // RISC-V (32-bit): riscv32
    riscv64,        // RISC-V (64-bit): riscv64
    sparc,          // Sparc: sparc
    sparcv9,        // Sparcv9: Sparcv9
    sparcel,        // Sparc: (endianness = little). NB: 'Sparcle' is a CPU variant
    systemz,        // SystemZ: s390x
    tce,            // TCE (http://tce.cs.tut.fi/): tce
    tcele,          // TCE little endian (http://tce.cs.tut.fi/): tcele
    thumb,          // Thumb (little endian): thumb, thumbv.*
    thumbeb,        // Thumb (big endian): thumbeb
    x86,            // X86: i[3-9]86
    x86_64,         // X86-64: amd64, x86_64
    xcore,          // XCore: xcore
    xtensa,         // Tensilica: Xtensa
    nvptx,          // NVPTX: 32-bit
    nvptx64,        // NVPTX: 64-bit
    le32,           // le32: generic little-endian 32-bit CPU (PNaCl)
    le64,           // le64: generic little-endian 64-bit CPU (PNaCl)
    amdil,          // AMDIL
    amdil64,        // AMDIL with 64-bit pointers
    hsail,          // AMD HSAIL
    hsail64,        // AMD HSAIL with 64-bit pointers
    spir,           // SPIR: standard portable IR for OpenCL 32-bit version
    spir64,         // SPIR: standard portable IR for OpenCL 64-bit version
    spirv,          // SPIR-V with logical memory layout.
    spirv32,        // SPIR-V with 32-bit pointers
    spirv64,        // SPIR-V with 64-bit pointers
    kalimba,        // Kalimba: generic kalimba
    shave,          // SHAVE: Movidius vector VLIW processors
    lanai,          // Lanai: Lanai 32-bit
    wasm32,         // WebAssembly with 32-bit pointers
    wasm64,         // WebAssembly with 64-bit pointers
    renderscript32, // 32-bit RenderScript
    renderscript64, // 64-bit RenderScript
    ve,             // NEC SX-Aurora Vector Engine
};

/** Assembly / disassembly dialect. */
enum class Syntax {
    Intel = 0, ///< Intel style – e.g. `mov rax, rbx` (default).
    ATT   = 1, ///< AT&T style – e.g. `movq %rbx, %rax`.
};

/**
 * Immutable configuration used when constructing a new `Engine` instance.
 */
struct Opts {
    Arch arch     = Arch::UnknownArch; ///< Target ISA.
    Syntax syntax = Syntax::Intel;     ///< Printer/parser dialect.
    bool lex_masm = true; ///< Accept MASM‑style integer literals when @c syntax==Intel.
    SymbolResolver symbol_resolver = nullptr; ///< Optional symbol callback.
    std::string cpu;      // "", "cortex-m3", …
    std::string features; // "+thumb,+v7,+mclass", …
};

/**
 * High‑level diagnostic categories.  Fine‑grained text lives in
 * `Error::message`.
 */
enum class ErrorEnum {
    None,               ///< Success – no error.
    InitFailure,        ///< One‑time LLVM init failed.
    InsufficientMemory, ///< `new` or LLVM factory returned `nullptr`.
    TargetError,        ///< Target triple not supported by the current build.
    AsmError,           ///< Parser/semantic error while assembling.
    UnknownParserError, ///< Unknown parser error
    ReparseObjectError, ///< Reparse object error
    TextSectionMissing, ///< Text section missing
    DisasmError,        ///< Decoder failed for given byte sequence.
    MissingSymbol,      ///< Undefined symbol & no user override.
};

// clang‑tidy complains about non‑trivial destructor, suppress it for this POD.
// NOLINTBEGIN
/**
 * Rich error object returned through `Result<T>`.
 */
struct Error {
    ErrorEnum value = ErrorEnum::None;            ///< Error category.
    std::string message;                          ///< Human‑readable explanation.
    int line_no   = 0;                            ///< For assembly errors (1‑based).
    int column_no = 0;                            ///<                      (1‑based).
    explicit Error(ErrorEnum val) noexcept;       ///< Construct from category only.
    Error(ErrorEnum val, std::string s) noexcept; ///< Construct an error with a message
};
// NOLINTEND

template <class... Alts>
constexpr bool variant_never_valueless = (std::is_nothrow_move_constructible_v<Alts> && ...);

/**
 * Minimalistic monadic result type.  Either contains a value of @c T *or* an
 * `Error`.  Inspired by Rustʼs `Result` and C++23ʼs `std::expected`.
 *
 * @tparam T Success value type.
 */
template <typename T>
class Result {
    static_assert(variant_never_valueless<T, Error>);
    std::variant<T, Error> v = Error(ErrorEnum::None); ///< Success or error payload.

  public:
    /* implicit */ Result(T val) : v(std::move(val)) {}
    /* implicit */ Result(Error e) : v(std::move(e)) {}

    /// @returns @c true if state == OK.
    bool is_ok() { return std::holds_alternative<T>(v); }
    /// @returns @c true if state == ERR.
    bool is_err() { return !is_ok(); }

    /// Access the error object
    Error &unwrap_err() & { return std::get<Error>(v); }
    Error &&unwrap_err() && { return std::get<Error>(v); }

    /// Direct reference to contained value
    T &unwrap() & {
        T *t = std::get_if<T>(&v);
        if (!t) {
            std::stringstream ss;
            auto &e = unwrap_err();
            ss << "Cornerstone error " << static_cast<int>(e.value) << ": " << e.message << ":"
               << e.line_no << ":" << e.column_no << std::endl;
            throw std::runtime_error(ss.str().c_str());
        }
        return *t;
    }
    T &&unwrap() && {
        T *t = std::get_if<T>(&v);
        if (!t) {
            std::stringstream ss;
            auto &e = unwrap_err();
            ss << "Cornerstone error " << static_cast<int>(e.value) << ": " << e.message << ":"
               << e.line_no << ":" << e.column_no << std::endl;
            throw std::runtime_error(ss.str().c_str());
        }
        return std::move(*t);
    }

    /**
     * Safely access the value.  Throws `std::runtime_error` with @p why if the
     * result is an error.
     */
    T &expect(const char *why) & {
        T *t = std::get_if<T>(&v);
        if (!t)
            throw std::runtime_error(why);
        return *t;
    }
    T &&expect(const char *why) && {
        T *t = std::get_if<T>(&v);
        if (!t)
            throw std::runtime_error(why);
        return std::move(*t);
    }
};

/** A wrapper around LLVM's MCInst */
struct Instruction {
    uint64_t address;
    uint32_t size;
    std::string mnemonic; // e.g. "ret"
    std::string op_str;   // e.g. "rax, [rbx]"
    // NOLINTNEXTLINE
    std::array<uint8_t, 24> bytes; // fits every ISA that LLVM supports
};

/// A vector of @class Instruction.
/// Allows pretty printing.
struct InstructionList {
    std::vector<Instruction> insns;
    /** Format instructions into one‑instruction‑per‑line text.
     */
    std::string pretty_format();
    friend std::ostream &operator<<(std::ostream &os, InstructionList &i);
};

/**
 * @class Engine
 * @brief High‑level façade over LLVM MC that can assemble **or** disassemble
 *        for a single target architecture/dialect.
 *
 * Expensive to construct – cache where possible.  Copying is cheap because the
 * heavy implementation lives in a shared `std::shared_ptr<Impl>`.
 */
class Engine {
    struct Impl;                ///< Private, defined in .cpp.
    std::shared_ptr<Impl> impl; ///< PIMPL to keep header clean.
    explicit Engine(Opts opts); ///< Internal – use `create()` instead.

  public:
    /** Factory that performs safe construction.
     *  @returns `Result<Engine>` that contains a fully‑initialised engine or a
     *           diagnostic error.
     */
    static Result<Engine> create(Opts opts);

    /**
     * Assemble @p assembly into an object‑file byte stream starting at
     * @p address (insertion point for labels like ".").
     * @p create_obj Creates an object-file format which includes an explict text section
     */
    Result<std::string> assemble(
        std::string_view assembly, size_t address = 0, bool create_obj = false
    );

    /** Disassemble @p bytes (machine code) into an @struct Instruction list, @p from_obj determines
     * whether the bytes contain a text section that requires extraction */
    Result<InstructionList> disassemble(
        std::string_view bytes, uint64_t address = 0, bool from_obj = false
    );
};

} // namespace cstn

#endif /* CORNERSTONE_HPP */