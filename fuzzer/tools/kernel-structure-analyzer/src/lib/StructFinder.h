/*
 * Copyright (C) 2020 Zhenpeng Lin
 *
 * For licensing details see LICENSE
 */

#ifndef SF_H_
#define SF_H_

#include "Global.h"
#include <set>

typedef std::set<llvm::StringRef> StructSet;

class StructFinderPass : public IterativeModulePass {
private:

    void runOnFunction(llvm::Function*);
    Instruction* simpleBackward(Value *V, VSet &vs);
    void increaseRef(StringRef name);
    void handleStruct(StructType *st, set<StringRef> &stSet);
    StringRef getStType(Type *ty);


public:
    StructFinderPass(GlobalContext *Ctx_)
        : IterativeModulePass(Ctx_, "StructFinder") {}

    virtual bool doInitialization(llvm::Module* );
    virtual bool doFinalization(llvm::Module* );
    virtual bool doModulePass(llvm::Module* );

    // debug

    
    void dumpLoc();
    void geneGraph();
};

#endif