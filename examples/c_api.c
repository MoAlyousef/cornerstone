#include <stdio.h>
#include <string.h>

#include <cornerstone/cornerstone.h>

const char * const LINUX_X64_SH =
    "push 0x68\n"
    "mov rax, 0x732f2f2f6e69622f\n"
    "push rax\n"
    "mov rdi, rsp\n"
    "/* push argument array ['sh\\x00'] */\n"
    "/* push b'sh\\x00' */\n"
    "push 0x1010101 ^ 0x6873\n"
    "xor dword ptr [rsp], 0x1010101\n"
    "xor esi, esi /* 0 */\n"
    "push rsi /* null terminate */\n"
    "push 8\n"
    "pop rsi\n"
    "add rsi, rsp\n"
    "push rsi /* 'sh\\x00' */\n"
    "mov rsi, rsp\n"
    "xor edx, edx /* 0 */\n"
    "/* call execve() */\n"
    "push 0x3b /* SYS_execve */\n"
    "pop rax\n"
    "syscall\n";

int assemble(CstnArch arch, CstnSyntax syntax, bool radix16, const char *assembly) {
    CstnOpts opts = {
        .syntax = syntax, .lex_masm = radix16, .symbol_resolver = NULL
    };
    CstnError err  = CstnError_none();
    CstnEngine *cs = cstn_create(arch, opts, &err);

    if (err.value != CstnError_None) {
        printf("Error code: %d, Error message: %s\n", (int)err.value, err.message);
        if (err.message) {
            puts(err.message);
            CstnError_reset(&err);
        }
        return -1;
    }

    size_t size        = 0;
    unsigned char *ret = NULL;
    if ((ret = (unsigned char *)cstn_assemble(cs, assembly, 0, false, &size, &err))) {
        for (size_t i = 0; i < size; i++) {
            printf("0x%02x ", ret[i]);
        }
        puts("");
        free(ret);
    } else {
        printf("Error code: %d, Error message: %s\n", (int)err.value, err.message);
        CstnError_reset(&err);
    }

    cstn_destroy(cs);

    puts("");
    return 0;
}

int disassemble(CstnArch arch, CstnSyntax syntax, bool radix16, const char *assembly) {
    CstnOpts opts = {
        .syntax = syntax, .lex_masm = radix16, .symbol_resolver = NULL
    };
    CstnError err  = CstnError_none();
    CstnEngine *cs = cstn_create(arch, opts, &err);

    if (err.value != CstnError_None) {
        printf("Error code: %d, Error message: %s\n", (int)err.value, err.message);
        if (err.message) {
            puts(err.message);
            CstnError_reset(&err);
        }
        return -1;
    }

    size_t size = 0;
    char *ret   = NULL;
    CstnInstr *insns = NULL;
    if ((ret = cstn_assemble(cs, assembly, 0, false, &size, &err))) {
        size_t count = cstn_disassemble(cs, ret, size, false, 0, &insns, &err);
        char *asm_text = cstn_format_insns(insns, count);
        puts(asm_text);
        free(asm_text);
        free(ret);
    } else {
        printf("Error code: %d, Error message: %s\n", (int)err.value, err.message);
        CstnError_reset(&err);
    }

    cstn_destroy(cs);

    puts("");
    return 0;
}

int main() {
    assemble(CstnArch_x86_64, CstnSyntax_Intel, true, LINUX_X64_SH);
    // check output with llvm-mc --triple=x86_64 --disassemble --output-asm-variant=1
    disassemble(CstnArch_x86_64, CstnSyntax_Intel, true, LINUX_X64_SH);
    return 0;
}