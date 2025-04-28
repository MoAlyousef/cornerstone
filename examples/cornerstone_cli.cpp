// Just a toy example file.
// echo "mov edx, 4" | ./bin/cornerstone_cli -a
// ./bin/cornerstone_cli -d out.o 
// 0x0000000000400000:     mov edx, 4

#include <cornerstone/cornerstone.hpp>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
static void make_binary(FILE *f) { _setmode(_fileno(f), _O_BINARY); }
#else
static void make_binary(FILE *) {}
#endif

static void usage(std::string_view argv0) {
    std::cerr << "Usage:\n"
              << "  " << argv0 << " [-a|-d] [-arch x86_64] [-intel|-att] infile [outfile]\n"
              << "Options:\n"
              << "  -a           Assemble (default)\n"
              << "  -d           Disassemble\n"
              << "  -arch <isa>  x86_64, x86, arm, aarch64, riscv64, ...\n"
              << "  -intel       Use Intel syntax (default for x86)\n"
              << "  -att         Use AT&T syntax\n";
    std::exit(1);
}

static cstn::Arch parse_arch(std::string_view s) {
    if (s == "x86_64")
        return cstn::Arch::x86_64;
    if (s == "x86")
        return cstn::Arch::x86;
    if (s == "arm")
        return cstn::Arch::arm;
    if (s == "aarch64")
        return cstn::Arch::aarch64;
    if (s == "riscv64")
        return cstn::Arch::riscv64;
    if (s == "riscv32")
        return cstn::Arch::riscv32;
    return cstn::Arch::UnknownArch;
}

int main(int argc, char **argv) try {
    bool do_asm      = true;
    cstn::Arch arch  = cstn::Arch::x86_64;
    cstn::Syntax syn = cstn::Syntax::Intel;

    std::vector<std::string_view> args(argv, argv + argc);
    const uint64_t addr = 0x400000;

    int idx = 1;
    while (idx < args.size() && args[idx][0] == '-') {
        std::string_view opt = args[idx++];
        if (opt == "-a")
            do_asm = true;
        else if (opt == "-d")
            do_asm = false;
        else if (opt == "-arch") {
            if (idx >= argc)
                usage(args[0]);
            arch = parse_arch(args[idx++]);
        } else if (opt == "-intel")
            syn = cstn::Syntax::Intel;
        else if (opt == "-att")
            syn = cstn::Syntax::ATT;
        else
            usage(args[0]);
    }

    std::string inFile  = (idx < argc ? std::string(args[idx]) : "-");
    std::string outFile = (idx + 1 < argc ? std::string(args[idx + 1]) : (do_asm ? "out.o" : "-"));

    std::ifstream ifs;
    std::istream *in = nullptr;

    if (inFile == "-") {
        if (!do_asm)
            make_binary(stdin);
        in = &std::cin;
    } else {
        ifs.open(inFile, std::ios::binary);
        if (!ifs) {
            std::cerr << "cannot open " << inFile << "\n";
            return 1;
        }
        in = &ifs;
    }
    std::string input((std::istreambuf_iterator<char>(*in)), std::istreambuf_iterator<char>());

    auto eng = cstn::Engine::create(arch, {syn}).unwrap();

    if (do_asm) {
        auto obj = eng.assemble(input, addr, true).unwrap();

        if (outFile == "-") {
            make_binary(stdout);
            std::cout.write(obj.data(), obj.size());
        } else {
            std::ofstream ofs(outFile, std::ios::binary);
            ofs.write(obj.data(), obj.size());
        }
    } else {
        auto dis = eng.disassemble(input, addr, true).unwrap();
        if (outFile == "-")
            std::cout << dis;
        else {
            std::ofstream ofs(outFile);
            ofs << dis;
        }
    }
    return 0;
} catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
}