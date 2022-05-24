/*
 * Copyright (C) 2020 Zhenpeng Lin
 *
 * For licensing details see LICENSE
 */

#ifndef CA_H_
#define CA_H_

#include "GlobalCtx.h"
#include <set>


class CrashAnalyzer : public IterativeModulePass {
private:

    bool cond;
    bool analyzed;
    llvm::StringRef funcName;
    llvm::StringRef source;
    unsigned line;
    void runOnFunction(llvm::Function*);

public:
    CrashAnalyzer(GlobalContext *Ctx_, bool cond_,
            /*llvm::StringRef fn, 
            llvm::StringRef Sourcef_, unsigned l*/
            llvm::StringRef CrashLoc
    )
        : IterativeModulePass(Ctx_, "CrashAnalyzer") {
        cond = cond_;

        // KA_LOGS(0, "crash loc : " << CrashLoc << "\n");
        
        funcName = CrashLoc.split(" ").first;
        auto loc = CrashLoc.split(" ").second;
        source = loc.split(":").first;
        line = stoi(loc.split(":").second.str());

        // KA_LOGS(0, "parsed loc: " << funcName << "\n");
        // KA_LOGS(0, "source : " << source << "\n");
        // KA_LOGS(0, "Line: " << line << "\n");

        analyzed = false;
        Ctx->InstNum = 0;
    }

    void dump();
    void dump(StringRef outFile);

    virtual bool doInitialization(llvm::Module* );
    virtual bool doFinalization(llvm::Module* );
    virtual bool doModulePass(llvm::Module* );
};


#endif