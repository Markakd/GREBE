/*
 * main function
 *
 * Copyright (C) 2012 Xi Wang, Haogang Chen, Nickolai Zeldovich
 * Copyright (C) 2015 Byoungyoung Lee
 * Copyright (C) 2015 - 2019 Chengyu Song 
 * Copyright (C) 2016 Kangjie Lu
 * Copyright (C) 2019 Yueqi Chen
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/SystemUtils.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/Path.h>

#include <fstream>
#include <memory>
#include <vector>
#include <sstream>
#include <sys/resource.h>

#include "GlobalCtx.h"
#include "CallGraph.h"
#include "StructFinder.h"
#include "CrashAnalyzer.h"
#include "PointerAnalysis.h"

using namespace llvm;

cl::list<std::string> InputFilenames(
    cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));

cl::opt<unsigned> VerboseLevel(
    "debug-verbose", cl::desc("Print information about actions taken"),
    cl::init(0));

cl::opt<std::string> DumpLocation(
    "dump-location", cl::desc("dump found structures"), cl::NotHidden, cl::init(""));

cl::opt<std::string> CrashReport(
    "crash-report", cl::desc("crash report"), cl::Required, cl::init(""));

// cl::opt<bool> AnalyzeLeakers(
//     "check-leakers", cl::desc("Analyze leakers"), cl::NotHidden, cl::init(false));

// cl::opt<bool> DumpAlias(
//     "dump-alias", cl::desc("Dump alias"), cl::NotHidden, cl::init(false));

// cl::opt<bool> DumpSimplified(
//     "dump-simple", cl::desc("Dump simplified leakers"), cl::NotHidden,
//     cl::init(false));

// cl::opt<bool> IgnoreReachable(
//     "ignore-reachable", cl::desc("Ignore whether the function is reachable from syscall"),
//     cl::NotHidden, cl::init(false));

cl::opt<std::string> CallGraph("call-graph", cl::desc("call graph from the report"),
    cl::Required, cl::init(""));

GlobalContext GlobalCtx;

void IterativeModulePass::run(ModuleList &modules) {

    ModuleList::iterator i, e;

    KA_LOGS(3, "[" << ID << "] Initializing " << modules.size() << " modules.");
    bool again = true;
    while (again) {
        again = false;
        for (i = modules.begin(), e = modules.end(); i != e; ++i) {
            KA_LOGS(3, "[" << i->second << "]");
            again |= doInitialization(i->first);
        }
    }

    KA_LOGS(3, "[" << ID << "] Processing " << modules.size() << " modules.");
    unsigned iter = 0, changed = 1;
    while (changed) {
        ++iter;
        changed = 0;
        for (i = modules.begin(), e = modules.end(); i != e; ++i) {
            KA_LOGS(3, "[" << ID << " / " << iter << "] ");
            // FIXME: Seems the module name is incorrect, and perhaps it's a bug.
            KA_LOGS(3, "[" << i->second << "]");
            
            bool ret = doModulePass(i->first);
            if (ret) {
                ++changed;
                KA_LOGS(3, "\t [CHANGED]");
            } else {
                KA_LOGS(3, " ");
            }
        }
        KA_LOGS(3, "[" << ID << "] Updated in " << changed << " modules.");
    }

    KA_LOGS(3, "[" << ID << "] Finalizing " << modules.size() << " modules.");
    again = true;
    while (again) {
        again = false;
        for (i = modules.begin(), e = modules.end(); i != e; ++i) {
            again |= doFinalization(i->first);
        }
    }

    KA_LOGS(3, "[" << ID << "] Done!\n");
    return;
}

void doBasicInitialization(Module *M) {

    // collect global object definitions
    for (GlobalVariable &G : M->globals()) {
        if (G.hasExternalLinkage())
            GlobalCtx.Gobjs[G.getName().str()] = &G;
    }

    // collect global function definitions
    for (Function &F : *M) {
        if (F.hasExternalLinkage() && !F.empty()) {
            // external linkage always ends up with the function name
            StringRef FNameRef = F.getName();
            std::string FName = "";
            if (FNameRef.startswith("__sys_"))
                FName = "sys_" + FNameRef.str().substr(6);
            else 
                FName = FNameRef.str();
            // fprintf(stderr, "FName: %s\n", FName.c_str());
            // assert(GlobalCtx.Funcs.count(FName) == 0); // force only one defintion
            GlobalCtx.Funcs[FName] = &F;
        }
    }

    return;
}

int main(int argc, char **argv) {

#ifdef SET_STACK_SIZE
    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
        rl.rlim_cur = SET_STACK_SIZE;
        setrlimit(RLIMIT_STACK, &rl);
    }
#endif

    // Print a stack trace if we signal out.
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 9
    sys::PrintStackTraceOnErrorSignal();
#else
    sys::PrintStackTraceOnErrorSignal(StringRef());
#endif
    PrettyStackTraceProgram X(argc, argv);

    // Call llvm_shutdown() on exit.
    llvm_shutdown_obj Y;  
    
    cl::ParseCommandLineOptions(argc, argv, "global analysis");
    SMDiagnostic Err;

    // Load modules
    KA_LOGS(0, "Total " << InputFilenames.size() << " file(s)");

    for (unsigned i = 0; i < InputFilenames.size(); ++i) {
        // Use separate LLVMContext to avoid type renaming
        KA_LOGS(1, "[" << i << "] " << InputFilenames[i] << "");
        LLVMContext *LLVMCtx = new LLVMContext();
        std::unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);

        if (M == NULL) {
            errs() << argv[0] << ": error loading file '" << InputFilenames[i] << "'\n";
            continue;
        }

        Module *Module = M.release();
        StringRef MName = StringRef(strdup(InputFilenames[i].data()));
        GlobalCtx.Modules.push_back(std::make_pair(Module, MName));
        GlobalCtx.ModuleMaps[Module] = InputFilenames[i];
        doBasicInitialization(Module);
    }

    std::ifstream report(CrashReport);

    // do we find explicit check expression
    bool explicity = false;

    if (report.is_open()) {

        std::string reportContent((std::istreambuf_iterator<char>(report)), 
                    std::istreambuf_iterator<char>());

        if (reportContent.find("WARNING") != string::npos
            && reportContent.find("invalid_op") != string::npos) {
                explicity = true;
            }

        if (reportContent.find("kernel BUG at") != string::npos) {
            explicity = true;
        }
        report.close();
    }

    std::ifstream file(CallGraph);
    std::string CrashLoc;
    bool kasan_check = false;

    if (file.is_open()) {
        std::string line, curFunc;
        std::string lastFunc = "";
        bool skipped = true;
        while (std::getline(file, line)) {
            StringRef readin = StringRef(line);
            curFunc = readin.split(" ").first.str();

            /* if previous function is in the skipped function list
               while current function is not, we set current function
               as the crash location */
            if (skipFunc.find(curFunc) != skipFunc.end()) {
                skipped = true;
            } else {
                if (skipped) 
                    CrashLoc = line;
                skipped = false;
            }

            if (curFunc.find("kasan_check_") != string::npos) {
                kasan_check = true;
            }

            if (lastFunc != "") {
                KA_LOGS(0, "inserting " << lastFunc << " " << curFunc);
                GlobalCtx.CallGraph[lastFunc] = curFunc;
            }
            lastFunc = curFunc;
        }
        file.close();
    }

    CallGraphPass CGPass(&GlobalCtx);
    CGPass.run(GlobalCtx.Modules);
    // CGPass.dumpCallers();
    // CGPass.dumpCallees();

    PointerAnalysisPass PAPass(&GlobalCtx);
    PAPass.run(GlobalCtx.Modules);

    KA_LOGS(0, "Here is the crash location "<<CrashLoc<<" explicit checking? "<<explicity);

    // CrashAnalyzer CA(&GlobalCtx, isExplicit, "refcount_inc_checked", "lib/refcount.c", 156);
    assert(CrashLoc != "");
    {
        CrashAnalyzer CA(&GlobalCtx, explicity, CrashLoc);
        CA.run(GlobalCtx.Modules);
        // test_bit include/asm-generic/bitops/instrumented-non-atomic.h:110
        if (DumpLocation != "")
            CA.dump(DumpLocation);
        else
            CA.dump();
    }


    // StructFinderPass SFPass(&GlobalCtx, "__le32_to_cpup", 58, 0);
    // SFPass.run(GlobalCtx.Modules);
    // SFPass.dump();

    outs() << "We got the crash location: " << CrashLoc << " explicit checking? " << explicity <<"\n";

    return 0;
}
