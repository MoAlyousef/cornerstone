#ifndef CORNERSTONE_H
#define CORNERSTONE_H

/**
 * @file cornerstone.h
 * @brief C99 façade for the Cornerstone LLVM‑based assembler / disassembler.
 *
 * This header mirrors the C++ API (`cornerstone.hpp`) but uses only C types so
 * that it can be consumed from *any* language capable of a C FFI (Rust, Zig,
 * Swift, Python ctypes, …).  All objects are opaque handles returned from the
 * library and must be destroyed with their designated `destroy` function.
 *
 * Memory ownership rules
 * ----------------------
 * * All strings returned by the library (assembly text, error messages) are
 *   **heap‑allocated** with the *process allocator* (`malloc`).  Call `free()`
 *   when you no longer need them.
 * * `CstnEngine` itself is created via `cstn_create()` and must be released
 *   with `cstn_destroy()`.
 *
 * Thread safety
 * -------------
 * Engine creation is thread‑safe; instances themselves are *not* – guard with
 * a mutex if you share across threads.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// NOLINTBEGIN
/** Opaque handle to an engine instance (see `cstn_create()`). */
typedef void CstnEngine;

/**
 * @typedef CstnSymbolResolver
 * @brief User hook invoked for each *undefined* symbol encountered during
 *        assembly.
 *
 * @param symbol Zero‑terminated UTF‑8 identifier being resolved.
 * @param value  [out]  Absolute value to substitute if the callback returns
 *               `true`.
 *
 * @return `true`  – symbol was resolved and *value* is valid.
 * @return `false` – keep symbol undefined → `CstnError_MissingSymbol`.
 */
typedef bool (*CstnSymbolResolver)(const char *symbol, uint64_t *value);

/* -------------------------------------------------------------------------- */
/*                              Enumerations                                  */
/* -------------------------------------------------------------------------- */

/** Supported target instruction sets (matches LLVM Triple values). */
typedef enum {
    CstnArch_UnknownArch,

    CstnArch_arm,            // ARM (little endian): arm, armv.*, xscale
    CstnArch_armeb,          // ARM (big endian): armeb
    CstnArch_aarch64,        // AArch64 (little endian): aarch64
    CstnArch_aarch64_be,     // AArch64 (big endian): aarch64_be
    CstnArch_aarch64_32,     // AArch64 (little endian) ILP32: aarch64_32
    CstnArch_arc,            // ARC: Synopsys ARC
    CstnArch_avr,            // AVR: Atmel AVR microcontroller
    CstnArch_bpfel,          // eBPF or extended BPF or 64-bit BPF (little endian)
    CstnArch_bpfeb,          // eBPF or extended BPF or 64-bit BPF (big endian)
    CstnArch_csky,           // CSKY: csky
    CstnArch_dxil,           // DXIL 32-bit DirectX bytecode
    CstnArch_hexagon,        // Hexagon: hexagon
    CstnArch_loongarch32,    // LoongArch (32-bit): loongarch32
    CstnArch_loongarch64,    // LoongArch (64-bit): loongarch64
    CstnArch_m68k,           // M68k: Motorola 680x0 family
    CstnArch_mips,           // MIPS: mips, mipsallegrex, mipsr6
    CstnArch_mipsel,         // MIPSEL: mipsel, mipsallegrexe, mipsr6el
    CstnArch_mips64,         // MIPS64: mips64, mips64r6, mipsn32, mipsn32r6
    CstnArch_mips64el,       // MIPS64EL: mips64el, mips64r6el, mipsn32el, mipsn32r6el
    CstnArch_msp430,         // MSP430: msp430
    CstnArch_ppc,            // PPC: powerpc
    CstnArch_ppcle,          // PPCLE: powerpc (little endian)
    CstnArch_ppc64,          // PPC64: powerpc64, ppu
    CstnArch_ppc64le,        // PPC64LE: powerpc64le
    CstnArch_r600,           // R600: AMD GPUs HD2XXX - HD6XXX
    CstnArch_amdgcn,         // AMDGCN: AMD GCN GPUs
    CstnArch_riscv32,        // RISC-V (32-bit): riscv32
    CstnArch_riscv64,        // RISC-V (64-bit): riscv64
    CstnArch_sparc,          // Sparc: sparc
    CstnArch_sparcv9,        // Sparcv9: Sparcv9
    CstnArch_sparcel,        // Sparc: (endianness = little). NB: 'Sparcle' is a CPU variant
    CstnArch_systemz,        // SystemZ: s390x
    CstnArch_tce,            // TCE (http://tce.cs.tut.fi/): tce
    CstnArch_tcele,          // TCE little endian (http://tce.cs.tut.fi/): tcele
    CstnArch_thumb,          // Thumb (little endian): thumb, thumbv.*
    CstnArch_thumbeb,        // Thumb (big endian): thumbeb
    CstnArch_x86,            // X86: i[3-9]86
    CstnArch_x86_64,         // X86-64: amd64, x86_64
    CstnArch_xcore,          // XCore: xcore
    CstnArch_xtensa,         // Tensilica: Xtensa
    CstnArch_nvptx,          // NVPTX: 32-bit
    CstnArch_nvptx64,        // NVPTX: 64-bit
    CstnArch_le32,           // le32: generic little-endian 32-bit CPU (PNaCl)
    CstnArch_le64,           // le64: generic little-endian 64-bit CPU (PNaCl)
    CstnArch_amdil,          // AMDIL
    CstnArch_amdil64,        // AMDIL with 64-bit pointers
    CstnArch_hsail,          // AMD HSAIL
    CstnArch_hsail64,        // AMD HSAIL with 64-bit pointers
    CstnArch_spir,           // SPIR: standard portable IR for OpenCL 32-bit version
    CstnArch_spir64,         // SPIR: standard portable IR for OpenCL 64-bit version
    CstnArch_spirv,          // SPIR-V with logical memory layout.
    CstnArch_spirv32,        // SPIR-V with 32-bit pointers
    CstnArch_spirv64,        // SPIR-V with 64-bit pointers
    CstnArch_kalimba,        // Kalimba: generic kalimba
    CstnArch_shave,          // SHAVE: Movidius vector VLIW processors
    CstnArch_lanai,          // Lanai: Lanai 32-bit
    CstnArch_wasm32,         // WebAssembly with 32-bit pointers
    CstnArch_wasm64,         // WebAssembly with 64-bit pointers
    CstnArch_renderscript32, // 32-bit RenderScript
    CstnArch_renderscript64, // 64-bit RenderScript
    CstnArch_ve,             // NEC SX-Aurora Vector Engine
} CstnArch;

/** Assembly / disassembly dialect. */
typedef enum {
    CstnSyntax_Intel = 0, /**< Intel style – default */
    CstnSyntax_ATT   = 1, /**< AT&T  style */
} CstnSyntax;

/** High‑level error categories returned via #CstnError. */
typedef enum {
    CstnError_None = 0,           /**< No error */
    CstnError_InitFailure,        /**< LLVM initialisation failed */
    CstnError_InsufficientMemory, /**< Allocation or factory failure */
    CstnError_TargetError,        /**< Unsupported arch/triple */
    CstnError_AsmError,           /**< Parse / semantic assembly error */
    CstnError_UnknownParserError, /**< Unknown parser error */
    ReparseObjectError,           /**< Reparse object error */
    TextSectionMissing,           /**< Text section missing */
    CstnError_DisasmError,        /**< Could not decode bytes */
    CstnError_MissingSymbol,      /**< Undefined symbol w/o resolver */
} CstnErrorEnum;

/* -------------------------------------------------------------------------- */
/*                                 Structs                                    */
/* -------------------------------------------------------------------------- */

/**
 * Immutable configuration for `cstn_create()`.  Zero‑initialise (`{0}`) or
 * populate the fields individually.
 */
typedef struct {
    CstnArch arch;                      /**< Target ISA. */
    CstnSyntax syntax;                  /**< Dialect for both assembler & printer. */
    bool lex_masm;                      /**< Accept MASM integer literals (only Intel syntax). */
    CstnSymbolResolver symbol_resolver; /**< Optional symbol callback. */
} CstnOpts;

/**
 * Rich diagnostic information associated with an error.
 *
 * * `message` is `NULL` when #value == #CstnError_None.
 * * The string is malloc‑owned; free it with `free()`.
 */
typedef struct {
    CstnErrorEnum value; /**< Category. */
    char *message;       /**< utf‑8 text – may be NULL. */
    int line_no;         /**< 1‑based line (for assembler). */
    int column_no;       /**< 1‑based column. */
} CstnError;

/** A wrapper around LLVM's MCInst */
typedef struct {
    uint64_t address;
    uint32_t size;
    char *mnemonic; /* strdup’ed */
    char *op_str;   /* strdup’ed */
    // NOLINTNEXTLINE
    uint8_t bytes[24];
} CstnInstr;
// NOLINTEND

/** Convenience initializer – returns a zeroed #CstnError. */
CstnError CstnError_none(void);

/**
 * Create a new engine according to @p opts.
 *
 * @param opts Configuration struct (passed by value).
 * @param err  [out] Detailed error info.  May be `NULL` if you only care about
 *             success/failure: in that case construction problems are written
 *             to `stderr`.
 *
 * @return Non‑NULL on success; NULL on failure (see @p err).
 */
CstnEngine *cstn_create(CstnOpts opts, CstnError *err);

/** Destroy an engine previously returned from #cstn_create. */
void cstn_destroy(CstnEngine *cs);

/* -------------------------------------------------------------------------- */
/*                              Core functions                                */
/* -------------------------------------------------------------------------- */

/**
 * Assemble textual @p string into raw machine code.
 *
 * @param cs            Engine handle.
 * @param string        UTF‑8 assembly source (null‑terminated).
 * @param address       Origin address that “.” and label references start from.
 * @param create_obj    Whether cornerstone should create an object-file format output.
 * @param sz            [out] size in bytes of the returned buffer.
 * @param err           [out] diagnostic info (see #CstnError).  Must not be NULL.
 *
 * @return Pointer to heap‑allocated memory (use `free()`).  NULL on error.
 */
char *cstn_assemble(
    CstnEngine *cs, const char *string, uint64_t address, bool create_obj, size_t *sz, CstnError *err
);

/**
 * Assemble textual @p string into an object‑file byte buffer.
 *
 * @param cs      Engine handle.
 * @param string  UTF‑8 assembly source (null‑terminated).
 * @param address Origin address that “.” and label references start from.
 * @param sz      [out] size in bytes of the returned buffer.
 * @param err     [out] diagnostic info (see #CstnError).  Must not be NULL.
 *
 * @return Pointer to heap‑allocated memory (use `free()`).  NULL on error.
 */
char *cstn_assemble_to_obj(
    CstnEngine *cs, const char *string, uint64_t address, size_t *sz, CstnError *err
);

/**
 * Disassemble raw machine code @p code into a dynamic array of instructions.
 *
 * @param cs        Engine handle.
 * @param code      Pointer to bytes to decode.
 * @param code_sz   Number of bytes in @p code.
 * @param address   Base address used for PC‑relative operands.
 * @param from_obj  Whether the cornerstone-engine should extract the text section.
 * @param out       Dynamic array of instructions.
 * @param err       [out] diagnostic info.
 *
 * @return The size of the dynamic array of instructions.
 */
size_t cstn_disassemble(
    CstnEngine *cs,
    const char *code,
    size_t code_sz,
    uint64_t address,
    bool from_obj,
    CstnInstr **out,
    CstnError *err
);

/** Formats the instructions in a one line per instruction format */
char *cstn_format_insns(CstnInstr *ins, size_t n);

/** Cleanup the returned dynamic array of instructions */
void cstn_free_insns(CstnInstr *ins, size_t n);

/** Reset an existing error struct, freeing the message string (if any). */
void CstnError_reset(CstnError *err);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CORNERSTONE_H */