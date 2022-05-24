/*
 * Copyright (C) 2020 Zhenpeng Lin
 *
 * For licensing details see LICENSE
 */

#ifndef SF_H_
#define SF_H_

#include "GlobalCtx.h"
#include <set>

typedef std::set<llvm::StringRef> StructSet;

class StructFinderPass : public IterativeModulePass {
private:

    void runOnFunction(llvm::Function*);
    llvm::StringRef handleType(Type *ty);
    void LogInst(Instruction *I);
    std::set<llvm::StringRef> taintAnalysis(llvm::Value *V, VSet &vs, bool found);
    std::set<llvm::StringRef> findParents(StringRef funcName);
    bool addToSet(std::set<llvm::StringRef> &stSet, StringRef st);

public:
    StructFinderPass(GlobalContext *Ctx_, /*llvm::StringRef moduleName,*/
            llvm::StringRef name, unsigned l, signed i)
        : IterativeModulePass(Ctx_, "StructFinder") {
        // moduleName = moduleName;
        funcName = name;
        line = l;
        idx = i;
        stop = false;
    }
        // : moduleName(moduleName),
        // : funcName(funcName),
        // : line(line),
        // : idx(idx)

    virtual bool doInitialization(llvm::Module* );
    virtual bool doFinalization(llvm::Module* );
    virtual bool doModulePass(llvm::Module* );


    bool started;
    bool stop;
    llvm::StringRef funcName;
    // llvm::StringRef moduleName;
    unsigned line;
    signed idx;

    void doAnalyze(llvm::Value *v);
    void dump();
    void dump(StringRef outFile);
};

#endif