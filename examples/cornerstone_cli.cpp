#include <cornerstone/cornerstone.hpp>

#include <fstream>
#include <iostream>
#include <iterator>

static void usage(const char *argv0) {
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

static cstn::Arch parseArch(const std::string &s) {
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
    bool doAsm       = true;
    cstn::Arch arch  = cstn::Arch::x86_64;
    cstn::Syntax syn = cstn::Syntax::Intel;

    int idx = 1;
    while (idx < argc && argv[idx][0] == '-') {
        std::string opt = argv[idx++];
        if (opt == "-a")
            doAsm = true;
        else if (opt == "-d")
            doAsm = false;
        else if (opt == "-arch") {
            if (idx >= argc)
                usage(argv[0]);
            arch = parseArch(argv[idx++]);
        } else if (opt == "-intel")
            syn = cstn::Syntax::Intel;
        else if (opt == "-att")
            syn = cstn::Syntax::ATT;
        else
            usage(argv[0]);
    }
    if (idx >= argc)
        usage(argv[0]);

    std::string inFile  = argv[idx++];
    std::string outFile = (idx < argc) ? argv[idx] : (doAsm ? "out.o" : "-");

    std::ifstream ifs(inFile, std::ios::binary);
    if (!ifs) {
        std::cerr << "cannot open " << inFile << "\n";
        return 1;
    }
    std::string input((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    auto eng = cstn::Engine::create({arch, syn}).unwrap();

    if (doAsm) {
        auto obj = eng.assemble(input, 0x400000, true).unwrap();

        std::ofstream ofs(outFile, std::ios::binary);
        ofs.write(obj.data(), obj.size());
    } else {
        auto dis = eng.disassemble(input, 0x400000, true).unwrap();
        if (outFile == "-")
            std::cout << dis;
        else {
            std::ofstream ofs(outFile);
            ofs << dis;
        }
    }
    return 0;
} catch (const std::exception &e) {
    std::cerr << e.what() << std::endl;
}
