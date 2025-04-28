#include <cstdio>
#include <iostream>

#include <cornerstone/cornerstone.hpp>

const char * const LINUX_X64_SH = R"lit(push 0x68
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

using namespace cstn;

int assemble(Arch arch, Syntax syntax, bool radix16, std::string_view assembly) {
    auto engine =
        Engine::create(Opts{.arch = arch, .syntax = syntax, .lex_masm = radix16}).unwrap();
    auto out = engine.assemble(assembly, 0).unwrap();
    for (auto i : out) {
        printf("0x%02x ", (unsigned char)i);
    }
    puts("");
    puts("");

    return 0;
}

int disassemble(Arch arch, Syntax syntax, bool radix16, std::string_view assembly) {
    auto engine =
        Engine::create(Opts{.arch = arch, .syntax = syntax, .lex_masm = radix16}).unwrap();
    auto out      = engine.assemble(assembly, 0).unwrap();
    auto asm_text = engine.disassemble(out, 0).unwrap().pretty_format();
    puts(asm_text.c_str());
    puts("");
    puts("");

    return 0;
}

int disassemble_insns(Arch arch, Syntax syntax, bool radix16, std::string_view assembly) {
    auto engine =
        Engine::create(Opts{.arch = arch, .syntax = syntax, .lex_masm = radix16}).unwrap();
    auto out      = engine.assemble(assembly, 0).unwrap();
    auto insns = engine.disassemble(out, 0).unwrap();
    std::cout << insns << std::endl;
    puts("");
    puts("");

    return 0;
}

int disassemble_twice(Arch arch, Syntax syntax, bool radix16, std::string_view assembly) {
    auto engine =
        Engine::create(Opts{.arch = arch, .syntax = syntax, .lex_masm = radix16}).unwrap();
    auto out      = engine.assemble(assembly, 0).unwrap();
    auto asm_text = engine.disassemble(out, 0).unwrap().pretty_format();
    out           = engine.assemble(asm_text, 0).unwrap();
    asm_text      = engine.disassemble(out, 0).unwrap().pretty_format();
    puts(asm_text.c_str());
    puts("");
    puts("");

    return 0;
}

int main() {
    assemble(Arch::x86_64, Syntax::Intel, true, LINUX_X64_SH);
    disassemble_insns(Arch::x86_64, Syntax::Intel, true, LINUX_X64_SH);
    disassemble(Arch::x86_64, Syntax::Intel, true, LINUX_X64_SH);
    disassemble_twice(Arch::x86_64, Syntax::Intel, true, LINUX_X64_SH);
}