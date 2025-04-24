#include <stdio.h>
#include <string.h>

#include <cornerstone/cornerstone.h>

const char *LINUX_X64_SH = R"lit(push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push 0x3b /* SYS_execve */
    pop rax
    syscall)lit";

int assemble(CstnArch arch, CstnSyntax syntax, bool radix16, const char *assembly) {
    CstnOpts opts = {
        .arch = arch, .syntax = syntax, .lex_masm = radix16, .symbol_resolver = NULL
    };
    CstnError err  = CstnError_none();
    CstnEngine *cs = cstn_create(opts, &err);

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
    if ((ret = (unsigned char *)cstn_assemble(cs, assembly, 0, &size, &err))) {
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
        .arch = arch, .syntax = syntax, .lex_masm = radix16, .symbol_resolver = NULL
    };
    CstnError err  = CstnError_none();
    CstnEngine *cs = cstn_create(opts, &err);

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
    if ((ret = cstn_assemble(cs, assembly, 0, &size, &err))) {
        char *asm_text = cstn_disassemble(cs, ret, size, 0, &err);
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