#include<llvm/IR/Instructions.h>
#include<llvm/IR/Function.h>
#include<llvm/IR/InstIterator.h>
#include<llvm/IR/LegacyPassManager.h>
#include <llvm/Analysis/AliasAnalysis.h>

#include "PointerAnalysis.h"

bool PointerAnalysisPass::doInitialization(Module *M) {
    return false;
}

bool PointerAnalysisPass::doFinalization(Module *M) {
    return false;
}

void PointerAnalysisPass::detectAliasPointers(Function* F, AAResults &AAR, 
        PointerAnalysisMap &aliasPtrs) {

    std::set<Value *> addr1Set;
    std::set<Value *> addr2Set;
    Value *Addr1, *Addr2;

    for (Argument &A : F->args())
        if (A.getType()->isPointerTy())
            addr1Set.insert(&A);

    for (Instruction &I : instructions(*F))
        if (I.getType()->isPointerTy())
            addr1Set.insert(&I);

    if (addr1Set.size() > 1000) {
        return;
    }

    for (auto Addr1 : addr1Set) {
        for (auto Addr2 : addr1Set) {
            if (Addr1 == Addr2)
                continue;
            AliasResult AResult = AAR.alias(Addr1, Addr2);

            bool notAlias = true;

            if (AResult == MustAlias || AResult == PartialAlias) {
                notAlias = false;
            } else if (AResult == MayAlias) {

            } 

            if (notAlias)
                continue;

            auto as = aliasPtrs.find(Addr1);
            if (as == aliasPtrs.end()) {
                SmallPtrSet<Value *, 16> sv;
                sv.insert(Addr2);
                aliasPtrs[Addr1] = sv;
            } else {
                as->second.insert(Addr2);
            }
        }
    }
}

bool PointerAnalysisPass::doModulePass(Module *M) {

    legacy::FunctionPassManager *FPasses = new legacy::FunctionPassManager(M);
    AAResultsWrapperPass *AARPass = new AAResultsWrapperPass();

    FPasses->add(AARPass);

    FPasses->doInitialization();

    for (Function &F : *M) {
        if (F.isDeclaration())
            continue;
        FPasses->run(F);
    }
    FPasses->doFinalization();

    AAResults &AAR = AARPass->getAAResults();

    for (Module::iterator f = M->begin(), fe = M->end();
            f != fe; ++f) {

        Function* F = &*f;
        PointerAnalysisMap aliasPtrs;

        if (F->empty())
            continue;
        detectAliasPointers(F, AAR, aliasPtrs);
        
        Ctx->FuncPAResults[F] = aliasPtrs;
        Ctx->FuncAAResults[F] = &AAR;
    }

    return false;
}
