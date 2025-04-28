#include <cornerstone/cornerstone.hpp>
#include <gtest/gtest.h>

using namespace cstn;

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

TEST(Test1, Output) {
    auto engine =
        Engine::create(Opts{.arch = Arch::x86_64, .syntax = Syntax::Intel, .lex_masm = true})
            .unwrap();
    auto a = engine.assemble(LINUX_X64_SH, 0).unwrap();
    auto d = engine.disassemble(a, 0).unwrap().pretty_format();
    auto t = engine.assemble(d, 0).unwrap();
    ASSERT_EQ(a, t);

    auto nop = engine.assemble("nop", 0).unwrap();
    ASSERT_EQ(nop.size(), 1);
    ASSERT_EQ(nop[0], '\x90');
}
