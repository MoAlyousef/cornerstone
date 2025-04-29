#include <cornerstone/cornerstone.h>
#include <cornerstone/cornerstone.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>

#include <llvm/Config/llvm-config.h>
#include <llvm/MC/MCAsmBackend.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCObjectWriter.h>
#include <llvm/MC/MCParser/AsmLexer.h>
#include <llvm/MC/MCParser/MCTargetAsmParser.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCTargetOptionsCommandFlags.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>

namespace cstn {
using namespace llvm;

void init_llvm() {
    static std::once_flag init_flag;
    std::call_once(init_flag, []() {
#ifdef CORNERSTONE_ENABLE_ALL_ARCHS
        llvm::InitializeAllTargetInfos();
        llvm::InitializeAllTargetMCs();
        llvm::InitializeAllAsmParsers();
        llvm::InitializeAllDisassemblers();
        return;
#endif

#ifdef CORNERSTONE_ENABLE_ARCH_X86
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86AsmParser();
        LLVMInitializeX86AsmPrinter();
        LLVMInitializeX86Disassembler();
#endif

#ifdef CORNERSTONE_ENABLE_ARCH_AARCH64
        LLVMInitializeAArch64TargetInfo();
        LLVMInitializeAArch64TargetMC();
        LLVMInitializeAArch64AsmParser();
        LLVMInitializeAArch64AsmPrinter();
        LLVMInitializeAArch64Disassembler();
#endif

#ifdef CORNERSTONE_ENABLE_ARCH_ARM
        LLVMInitializeARMTargetInfo();
        LLVMInitializeARMTargetMC();
        LLVMInitializeARMAsmParser();
        LLVMInitializeARMAsmPrinter();
        LLVMInitializeARMDisassembler();
#endif

#ifdef CORNERSTONE_ENABLE_ARCH_RISCV
        LLVMInitializeRISCVTargetInfo();
        LLVMInitializeRISCVTargetMC();
        LLVMInitializeRISCVAsmParser();
        LLVMInitializeRISCVAsmPrinter();
        LLVMInitializeRISCVDisassembler();
#endif
    });
}

static Result<std::string> extract_text(llvm::StringRef objBuf) {
    auto mem      = llvm::MemoryBuffer::getMemBufferCopy(objBuf);
    auto objOrErr = llvm::object::ObjectFile::createObjectFile(mem->getMemBufferRef());
    if (!objOrErr)
        return Error(ErrorEnum::ReparseObjectError, "Reparse object error");

    for (const auto &sec : (*objOrErr)->sections())
        if (sec.isText()) {
            llvm::Expected<llvm::StringRef> data = sec.getContents();
            if (!data)
                continue;
            return std::string(data->bytes_begin(), data->bytes_end());
        }
    return Error(ErrorEnum::TextSectionMissing, "Text section missing");
}

struct Engine::Impl {
    Arch arch;
    Syntax syntax;
    bool lex_masm;
    SymbolResolver sym_resolver = nullptr;
    std::shared_ptr<Error> err  = std::make_shared<Error>(Error(ErrorEnum::None));
    Triple triple;
    MCObjectFileInfo mofi;
    MCTargetOptions mc_opts;
    std::string cpu;
    std::string features;
    // Need initialization in Impl::init
    const Target *target                 = nullptr;
    std::unique_ptr<MCRegisterInfo> mri  = nullptr;
    std::unique_ptr<MCAsmInfo> mai       = nullptr;
    std::unique_ptr<MCInstrInfo> mii     = nullptr;
    std::unique_ptr<MCSubtargetInfo> sti = nullptr;
    Impl(
        Arch arch_,
        Syntax syntax_,
        bool lex_masm_,
        SymbolResolver s,
        std::string cpu_,
        std::string features_
    )
        : arch(arch_), syntax(syntax_), lex_masm(lex_masm_), sym_resolver(s), cpu(std::move(cpu_)),
          features(std::move(features_)) {}

    Result<bool> init() {
        init_llvm();
        triple.setArch(static_cast<Triple::ArchType>(arch));
        std::string e;

        target = TargetRegistry::lookupTarget("", triple, e);
        if (!target || !e.empty()) {
            err->value   = ErrorEnum::TargetError;
            err->message = e;
            return *err;
        }
        mc_opts = mc::InitMCTargetOptionsFromFlags();
        mri     = std::unique_ptr<MCRegisterInfo>(target->createMCRegInfo(triple.str()));
        if (!mri)
            return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");

        mai = std::unique_ptr<MCAsmInfo>(target->createMCAsmInfo(*mri, triple.str(), mc_opts));
        if (!mai)
            return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");

        mii = std::unique_ptr<MCInstrInfo>(target->createMCInstrInfo());
        if (!mii)
            return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");

        sti = std::unique_ptr<MCSubtargetInfo>(
            target->createMCSubtargetInfo(triple.str(), cpu, features)
        );
        if (!sti)
            return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");
        return true;
    }
};
Engine::Engine(Arch arch, Opts opts)
    : impl(std::make_shared<Impl>(
          arch, opts.syntax, opts.lex_masm, opts.symbol_resolver, opts.cpu, opts.features
      )) {}

Result<Engine> Engine::create(Arch arch, Opts opts) {
    Engine engine(arch, opts);
    auto ret = engine.impl->init();
    if (ret.is_err()) {
        return ret.unwrap_err();
    } else {
        auto inited = ret.unwrap();
        if (inited)
            return engine;
        else
            return *engine.impl->err;
    }
}

Result<InstructionList> Engine::disassemble(
    std::string_view bytes_, uint64_t address, bool from_obj
) {
    std::string bytes;
    if (from_obj) {
        auto temp = extract_text(bytes_);
        if (temp.is_err())
            return temp.unwrap_err();
        bytes = temp.unwrap();
    } else {
        bytes = bytes_;
    }
    SourceMgr src_mgr;
    src_mgr.setDiagHandler(
        +[](const SMDiagnostic &Diag, void *ctx) {
            auto *err = static_cast<Error *>(ctx);
            if (err->value == ErrorEnum::None) {
                err->value     = ErrorEnum::DisasmError;
                err->message   = Diag.getMessage();
                err->line_no   = Diag.getLineNo();
                err->column_no = Diag.getColumnNo();
            }
        },
        impl->err.get()
    );
    MCContext ctx(
        impl->triple,
        impl->mai.get(),
        impl->mri.get(),
        impl->sti.get(),
        &src_mgr,
        &impl->mc_opts,
        false
    );
    impl->mofi.initMCObjectFileInfo(ctx, false, false);
    ctx.setObjectFileInfo(&impl->mofi);

    auto disasm =
        std::unique_ptr<MCDisassembler>(impl->target->createMCDisassembler(*impl->sti, ctx));
    if (!disasm)
        return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");

    unsigned dialect = !static_cast<unsigned>(impl->syntax);
    auto printer     = std::unique_ptr<MCInstPrinter>(
        impl->target->createMCInstPrinter(impl->triple, dialect, *impl->mai, *impl->mii, *impl->mri)
    );
    if (!printer)
        return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");
    uint64_t offset = 0;
    InstructionList out;

    while (offset < bytes.size()) {
        MCInst inst;
        uint64_t instSize = 0;

        auto status = disasm->getInstruction(
            inst,
            instSize,
            ArrayRef<uint8_t>(
                // NOLINTNEXTLINE
                reinterpret_cast<unsigned char *>(bytes.data()) + offset, bytes.size() - offset
            ),
            address + offset,
            llvm::nulls()
        );
        if (status != llvm::MCDisassembler::Success || instSize == 0) {
            impl->err->value = ErrorEnum::DisasmError;
            break;
        }

        Instruction ins;
        ins.address = address + offset;
        ins.size    = instSize;
        // NOLINTNEXTLINE
        std::memcpy(ins.bytes.data(), bytes.data() + offset, instSize);
        std::string line;
        llvm::raw_string_ostream rs(line);
        printer->printInst(&inst, ins.address, "", *impl->sti, rs);
        rs.flush();

        std::replace_if(
            line.begin(), line.end(), [](unsigned char c) { return std::isspace(c); }, ' '
        );

        auto l = line.find_first_not_of(' ');
        auto r = line.find_last_not_of(' ');
        line   = (l == std::string::npos) ? "" : line.substr(l, r - l + 1);

        auto sp      = line.find(' ');
        ins.mnemonic = (sp == std::string::npos) ? line : line.substr(0, sp);
        ins.op_str   = (sp == std::string::npos) ? "" : line.substr(sp + 1);

        out.insns.push_back(std::move(ins));
        offset += instSize;
    }

    if (impl->err->value != ErrorEnum::None)
        return *impl->err;
    else {
        return out;
    }
}

Result<std::string> Engine::assemble(std::string_view assembly, size_t address, bool create_obj) {
    // NOLINTNEXTLINE
    SmallString<1024> msg;
    raw_svector_ostream os(msg);
    SourceMgr src_mgr;
    src_mgr.setDiagHandler(
        +[](const SMDiagnostic &Diag, void *ctx) {
            auto *err = static_cast<Error *>(ctx);
            if (err->value == ErrorEnum::None) {
                err->value     = ErrorEnum::AsmError;
                err->message   = Diag.getMessage();
                err->line_no   = Diag.getLineNo();
                err->column_no = Diag.getColumnNo();
            }
        },
        impl->err.get()
    );
    MCContext ctx(impl->triple, impl->mai.get(), impl->mri.get(), impl->sti.get(), &src_mgr);
    impl->mofi.initMCObjectFileInfo(ctx, false, false);
    ctx.setObjectFileInfo(&impl->mofi);

    auto ce = std::unique_ptr<MCCodeEmitter>(impl->target->createMCCodeEmitter(*impl->mii, ctx));
    if (!ce) {
        return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");
    }

    auto mab = std::unique_ptr<MCAsmBackend>(
        impl->target->createMCAsmBackend(*impl->sti, *impl->mri, impl->mc_opts)
    );
    if (!mab)
        return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");
    auto ow = mab->createObjectWriter(os);

    auto streamer = std::unique_ptr<MCStreamer>(impl->target->createMCObjectStreamer(
        impl->triple,
        ctx,
        std::move(mab),
        std::move(ow),
        std::move(ce),
        *impl->sti,
        impl->mc_opts.MCRelaxAll,
        false,
        false
    ));

    if (!streamer) {
        return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");
    }

    auto buf = MemoryBuffer::getMemBuffer(assembly);

    src_mgr.AddNewSourceBuffer(std::move(buf), SMLoc());

    for (auto &entry : ctx.getSymbols()) {
        auto *sym = entry.second;
        if (sym->isUndefined()) {
            uint64_t val = 0;
            if (impl->sym_resolver(sym->getName().data(), &val)) {
                ctx.setSymbolValue(*streamer, sym->getName(), val);
            } else {
                impl->err->value   = ErrorEnum::MissingSymbol;
                impl->err->message = "Symbol Missing";
            }
        }
    }

    auto parser =
        std::unique_ptr<MCAsmParser>(createMCAsmParser(src_mgr, ctx, *streamer, *impl->mai));
    if (!parser) {
        return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");
    }
    auto tap = std::unique_ptr<MCTargetAsmParser>(
        impl->target->createMCAsmParser(*impl->sti, *parser, *impl->mii, impl->mc_opts)
    );
    if (!tap) {
        return Error(ErrorEnum::InsufficientMemory, "Insufficient memory");
    }

    parser->setAssemblerDialect(!static_cast<unsigned int>(impl->syntax));
    parser->setTargetParser(*tap);

    if (impl->syntax == Syntax::Intel && impl->lex_masm) {
        auto &lexer = parser->getLexer();
        lexer.setLexMasmIntegers(true);
        lexer.setLexMasmHexFloats(true);
        lexer.setLexMasmStrings(true);
    }

#if LLVM_VERSION_MAJOR > 15
    ctx.setSymbolValue(*streamer, Twine("."), address);
#else
    ctx.setSymbolValue(*streamer, ".", address);
#endif
    auto ret = parser->Run(false);
    if (impl->err->value != ErrorEnum::None)
        return *impl->err;
    else {
        if (ret) {
            impl->err->value = ErrorEnum::UnknownParserError;
            return *impl->err;
        }
        if (create_obj) {
            return std::string(msg.begin(), msg.end());
        } else {
            return extract_text(os.str());
        }
    }
}

Error::Error(ErrorEnum val) noexcept : value(val) {}

Error::Error(ErrorEnum val, std::string s) noexcept : value(val), message(std::move(s)) {}

std::string InstructionList::pretty_format() {
    std::string out;
    for (auto &i : insns) {
        // NOLINTBEGIN
        char buf[64];
        int len = std::snprintf(
            buf, sizeof(buf), "0x%016lx:\t%s %s\n", i.address, i.mnemonic.c_str(), i.op_str.c_str()
        );
        out.append(buf, len);
        // NOLINTEND
    }
    return out;
}

std::ostream &operator<<(std::ostream &os, InstructionList &i) {
    os << i.pretty_format();
    return os;
}
} // namespace cstn

static void cstn_copy_err(CstnError *err, const cstn::Error &error) {
    err->value     = static_cast<CstnErrorEnum>(error.value);
    err->message   = strdup(error.message.c_str());
    err->column_no = error.column_no;
    err->line_no   = error.line_no;
}

extern "C" CstnEngine *cstn_create(CstnArch arch, CstnOpts *opts, CstnError *err) {
    cstn::Opts opts0 = {};
    if (opts) {
        opts0.syntax          = static_cast<cstn::Syntax>(opts->syntax);
        opts0.lex_masm        = opts->lex_masm;
        opts0.symbol_resolver = opts->symbol_resolver;
        opts0.cpu             = opts->cpu ? opts->cpu : "";
        opts0.features        = opts->features ? opts->features : "";
    }
    auto ret = cstn::Engine::create(static_cast<cstn::Arch>(arch), opts0);
    if (ret.is_ok()) {
        // NOLINTNEXTLINE
        return new cstn::Engine(ret.unwrap());
    } else {
        auto &error  = ret.unwrap_err();
        err->value   = static_cast<CstnErrorEnum>(error.value);
        err->message = strdup(error.message.c_str());
        return nullptr;
    }
}

extern "C" void cstn_destroy(CstnEngine *cs) {
    // NOLINTNEXTLINE
    delete static_cast<cstn::Engine *>(cs);
}

extern "C" void CstnError_reset(CstnError *err) {
    err->value = CstnError_None;
    if (err->message) {
        // NOLINTNEXTLINE
        free(err->message);
        err->message = nullptr;
    }
    err->column_no = 0;
    err->line_no   = 0;
}

extern "C" char *cstn_assemble(
    CstnEngine *cs,
    const char *string,
    uint64_t address,
    bool create_obj,
    size_t *sz,
    CstnError *err
) {
    auto engine = static_cast<cstn::Engine *>(cs);
    auto ret    = engine->assemble(string, address, create_obj);
    CstnError_reset(err);
    char *temp = nullptr;
    if (ret.is_err()) {
        auto &error = ret.unwrap_err();
        cstn_copy_err(err, error);
    } else {
        auto &v = ret.unwrap();
        *sz     = v.size();
        temp    = strdup(v.c_str());
    }
    return temp;
}

extern "C" size_t cstn_disassemble(
    CstnEngine *cs,
    const char *code,
    size_t code_sz,
    uint64_t address,
    bool from_obj,
    CstnInstr **out,
    CstnError *err
) {
    auto eng = static_cast<cstn::Engine *>(cs);
    // NOLINTNEXTLINE
    std::string_view bytes(reinterpret_cast<const char *>(code), code_sz);

    auto ret = eng->disassemble(bytes, address, from_obj);
    CstnError_reset(err);

    if (ret.is_err()) {
        auto &e = ret.unwrap_err();
        cstn_copy_err(err, e);
        return 0;
    }
    auto &insns = ret.unwrap().insns;
    auto sz     = insns.size();
    // NOLINTBEGIN
    auto temp  = new CstnInstr[sz];
    size_t cnt = 0;
    for (auto &i : insns) {
        temp[cnt].address = i.address;
        temp[cnt].size    = i.size;
        std::memcpy(temp[cnt].bytes, i.bytes.data(), 24);
        temp[cnt].mnemonic = strdup(i.mnemonic.c_str());
        temp[cnt].op_str   = strdup(i.op_str.c_str());
        cnt += 1;
    }
    *out = temp;
    // NOLINTEND
    return sz;
}

extern "C" CstnError CstnError_none(void) {
    CstnError err = {};
    CstnError_reset(&err);
    return err;
}

extern "C" char *cstn_format_insns(CstnInstr *ins, size_t n) {
    std::string out;
    for (auto i = 0; i < n; i++) {
        // NOLINTBEGIN
        char buf[64];
        int len = std::snprintf(
            buf, sizeof(buf), "0x%016lx:\t%s %s\n", ins[i].address, ins[i].mnemonic, ins[i].op_str
        );
        out.append(buf, len);
        // NOLINTEND
    }
    return strdup(out.c_str());
}

extern "C" void cstn_free_insns(CstnInstr *ins, size_t n) {
    // NOLINTBEGIN
    for (size_t i = 0; i < n; i++) {
        free(ins[i].mnemonic);
        free(ins[i].op_str);
    }
    delete[] ins;
    // NOLINTEND
}

extern "C" CstnOpts CstnOpts_default() {
    CstnOpts opts = {
        .syntax          = CstnSyntax_Intel,
        .lex_masm        = true,
        .symbol_resolver = nullptr,
        .cpu             = "",
        .features        = ""
    };
    return opts;
}

extern "C" CstnOpts CstnOpts_new(
    CstnSyntax syntax,
    bool lex_masm,
    CstnSymbolResolver sym_resolver,
    const char *cpu,
    const char *features
) {
    CstnOpts opts = {
        .syntax          = syntax,
        .lex_masm        = lex_masm,
        .symbol_resolver = sym_resolver,
        .cpu             = cpu,
        .features        = features
    };
    return opts;
}