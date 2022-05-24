#ifndef ALIAS_ANALYZER_H
#define ALIAS_ANALYZER_H

#include "GlobalCtx.h"
#include "Common.h"

using namespace llvm;

class PointerAnalysisPass : public IterativeModulePass {

private:
    void detectAliasPointers(Function* F, AAResults &AAR, PointerAnalysisMap &aliasPtrs);

public:

    PointerAnalysisPass(GlobalContext *Ctx_)
        : IterativeModulePass(Ctx_, "PointerAnalysis") {}
    virtual bool doInitialization(Module*);
    virtual bool doFinalization(Module*);
    virtual bool doModulePass(Module*);

    void dumpAlias(){
        // dump alias
        for (auto const &alias : Ctx->FuncPAResults){
            KA_LOGS(0, "\n------ Function: " << alias.first->getName().str() << "-----\n");
            for( auto const &aliasMap : alias.second){
                KA_LOGS(0, "Start dumping alias of Pointer : " << *aliasMap.first << "\n");
                for( auto *pointer : aliasMap.second){
                    KA_LOGS(0, *pointer << "\n");
                }
                KA_LOGS(0, "End dumping\n");
            }
            KA_LOGS(0, "\nEnding Function----\n");
        }
    }
};

#endif