/*
 * Copyright (C) 2020 Zhenpeng Lin
 *
 * For licensing details see LICENSE
 */

#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/TypeFinder.h>
#include <llvm/IR/Constants.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>

#include "StructFinder.h"


using namespace llvm;
using namespace std;

#define DEBUG

bool StructFinderPass::doInitialization(Module* M) {
    return false;
}

static void mergeSet(std::set<llvm::StringRef> &a, std::set<llvm::StringRef> b) {
    a.insert(b.begin(), b.end());
}

std::set<llvm::StringRef> StructFinderPass::findParents(StringRef fName) {
    // return its parent
    std::set<llvm::StringRef> parent;

    // for (auto kk : Ctx->CallGraph) {
    //     outs() << kk.first << " " << kk.second << "\n";
    // }

    if (Ctx->CallGraph.find(fName) != Ctx->CallGraph.end()) {
        outs() << "In table, found parent for "<<fName<<" : "<<Ctx->CallGraph[fName]<<"\n";
        parent.insert(Ctx->CallGraph[fName]);
    }
    return parent;
}

// TODO: heuristic for finding sock related structures.
bool StructFinderPass::addToSet(std::set<llvm::StringRef> &stSet, StringRef st) {
    if (st.startswith("struct.")) {
        Ctx->CandidateSt.insert(st);
    }

    if (st == "int")
        return true;

    if (st == "" || st == "int" || BlockSt.find(st) != BlockSt.end()) {
        // if (stSet.size() != 0) {
        //     return false;
        // } else {
            return true;
        // }
    }
    
    if (stop)
        return false;
    
    KA_LOGS(0, "Adding " << st);
    if (st == "int") {
        return true;
    }

    stSet.insert(st);
    return true;
}

std::set<llvm::StringRef> StructFinderPass::taintAnalysis(llvm::Value *V, VSet &vs, bool found) {

    std::set<llvm::StringRef> result;
    result.clear();

    if (!vs.insert(V).second) {
        return result;
    }

    // debuging!!! remove this when deploying blockset
    // found = false;
    KA_LOGV(0, V);

    // find the casting...
    for (auto *user : V->users()) {
        if (isa<BitCastInst>(user)) {
            BitCastInst *BCI = dyn_cast<BitCastInst>(user);
            Type *dst = BCI->getDestTy();
            auto name = handleType(dst);
            KA_LOGS(0, "Found "<<name<<" in casting");
            addToSet(result, name);
        }
    }

    if (auto *I = dyn_cast<Instruction>(V)) {

        switch (I->getOpcode())
        {
        case Instruction::Store:
            {
            
            StoreInst *SI = cast<StoreInst>(I);
            Type *SType = SI->getPointerOperandType();
            StringRef stName = handleType(SType);

            if (!addToSet(result, stName)) {
                break;
            }

            // would find a GetElementType
            if (!isa<GetElementPtrInst>(SI->getOperand(0))) {
                // assert(0 && "didn't find a GetElementPtrInst before StoreInst");
            }

            Value *GetV = SI->getOperand(1);

            // we skip these getElement since they are nested
            while (isa<GetElementPtrInst>(GetV)) {
                GetElementPtrInst *GEI = cast<GetElementPtrInst>(GetV);
                StringRef name = handleType(GEI->getSourceElementType());

                if (!addToSet(result, name)) {
                    break;
                }
    
                GetV = GEI->getOperand(0);
            }

            // the outside GetElementPtrInst
            mergeSet(result, taintAnalysis(GetV, vs, found));
            break;
            }
        
        case Instruction::Load:
            {
            // should pair with a GetElementPtr
            // remember to check if it is nested

            LoadInst *LI = cast<LoadInst>(I);
            Type *lType = LI->getPointerOperandType();
            StringRef stName = handleType(lType);

            if (!addToSet(result, stName)) {
                break;
            }

            if (stName == "struct.list_head" &&
                    isa<ConstantExpr>(LI->getOperand(0))) {
                // looking type info in list_head
                Value *bitcastV = nullptr;

                for (auto *user : V->users()) {
                    if (isa<PHINode>(user)) {
                        for (auto *uuser : user->users()) {
                            if (isa<BitCastInst>(uuser)) {
                                bitcastV = uuser;
                            }
                        }
                    }
                }

                if (bitcastV == nullptr) {
                    break;
                }

                for (auto *user : bitcastV->users()) {
                    if (isa<BitCastInst>(user)) {
                        BitCastInst *BCI = dyn_cast<BitCastInst>(user);
                        Type *src = BCI->getDestTy();
                        if (!addToSet(result, handleType(src))) {

                        }
                    }
                }
                break;
            }

            // would find a GetElementType
            if (!isa<GetElementPtrInst>(LI->getOperand(0))) {
                // it may not in some cases
                // outs() << "in " << LI->getFunction()->getName() << "\n";
                // assert(0 && "didn't find a GetElementPtrInst before LoadInst");
            }

            Value *GetV = LI->getOperand(0);

            // we skip these getElement since they are nested
            while (isa<GetElementPtrInst>(GetV)) {
                GetElementPtrInst *GEI = cast<GetElementPtrInst>(GetV);
                StringRef name = handleType(GEI->getSourceElementType());

                if (!addToSet(result, name)) {
                    break;
                }
    
                GetV = GEI->getOperand(0);
            }

            // the outside GetElementPtrInst
            mergeSet(result, taintAnalysis(GetV, vs, found));
            break;
            }

        case Instruction::Call:
            {

            CallInst *CI = cast<CallInst>(I);
            for (auto AI = CI->arg_begin(), E = CI->arg_end(); AI != E; AI++) {
                Value* arg = dyn_cast<Value>(&*AI);
                if (dyn_cast<Constant>(arg)) {
                    continue;
                }
                // if not &a->b
                if (!isa<GetElementPtrInst>(arg)) {
                    auto name = handleType(arg->getType());
                    addToSet(result, name);
                }
                // taint argument
                mergeSet(result, taintAnalysis(arg, vs, found));
            }
            break;
            }

        case Instruction::GetElementPtr:
            {
            // this is nested
            GetElementPtrInst *GEI = cast<GetElementPtrInst>(I);

            // while (isa<GetElementPtrInst>(GEI->getOperand(0))) {
            //     // nest struct
            //     Type *src = GEI->getSourceElementType();
            //     GEI = cast<GetElementPtrInst>(I);
            // }

            Type *src = GEI->getSourceElementType();
            // handle type
            auto name = handleType(src);
            if (!addToSet(result, name)) {
                break;
            }
            // addToSet(result, name);

            mergeSet(result, taintAnalysis(GEI->getOperand(0), vs, found));

            // handle GetElementPtr other operands
            for (unsigned i = 1, e = I->getNumOperands(); i != e; i++) {
                V = I->getOperand(i);
                if (dyn_cast<Constant>(V)) {
                    continue;
                }
                // taint value
                mergeSet(result, taintAnalysis(V, vs, found));
            }
            break;
            }
        case Instruction::PHI:
            {
            // check code coverage here to find the node
            PHINode *PN = cast<PHINode>(I);
            for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; i++) {
                Value* IV = PN->getIncomingValue(i);
                if (Instruction *II = dyn_cast<Instruction>(IV)) {
                    // if II not get covered
                    // continue
                }

                mergeSet(result, taintAnalysis(IV, vs, found));
            }
            break;
            }
        case Instruction::Alloca:
            // return
            // solve alias
            for (auto *user : V->users()) {
                if (isa<StoreInst>(user)) {
                    StoreInst *SI = cast<StoreInst>(user);
                    Value *next = SI->getOperand(0);
                    mergeSet(result, taintAnalysis(next, vs, found));
                }
            }
            break;

        
        case Instruction::BitCast:
            {
            // handle type info
            BitCastInst *BCI = dyn_cast<BitCastInst>(V);
            Type *src = BCI->getSrcTy();
            auto name = handleType(src);
            if (!addToSet(result, name)) {
                break;
            }

            mergeSet(result, taintAnalysis(BCI->getOperand(0), vs, found));
            break;
            }
        
        case Instruction::ICmp:
            // assert(0 && "This should not happen");
        case Instruction::FCmp:
            // assert(0 && "This should not happen");
        case Instruction::Add:
        case Instruction::FAdd:
        case Instruction::Sub:
        case Instruction::FSub:
        case Instruction::Mul:
        case Instruction::FMul:
        case Instruction::UDiv:
        case Instruction::SDiv:
        case Instruction::FDiv:
        case Instruction::URem:
        case Instruction::SRem:
        case Instruction::FRem:
        case Instruction::Shl:
        case Instruction::LShr:
        case Instruction::AShr:
        case Instruction::And:
        case Instruction::Or:
        case Instruction::Xor:
        case Instruction::Trunc:
        case Instruction::ZExt:
        case Instruction::SExt:
        case Instruction::FPToUI:
        case Instruction::FPToSI:
        case Instruction::UIToFP:
        case Instruction::SIToFP:
        case Instruction::FPTrunc:
        case Instruction::FPExt:
        case Instruction::PtrToInt:
        case Instruction::IntToPtr:
        case Instruction::AddrSpaceCast:
        case Instruction::Select:
            for (unsigned i = 0, e = I->getNumOperands(); i != e; i++) {
                V = I->getOperand(i);
                if (dyn_cast<Constant>(V)) {
                    continue;
                }
                // taint value
                mergeSet(result, taintAnalysis(V, vs, found));
            }
            break;

        default:
            KA_WARNS(0, "Unknown inst: "<<*I);
            break;
        }

    } else if (auto *Arg = dyn_cast<Argument>(V)) {
        // argument
        unsigned argNo = Arg->getArgNo();
        StringRef name = handleType(Arg->getType());

        if (!addToSet(result, name)) {
            return result;
        }
        // addToSet(result, name);
        
        Function* callee = Arg->getParent();
        
        auto parentName = findParents(callee->getName());
        bool matched = false;

        CallInstSet CISet;

        for (auto M : Ctx->Callers) {
            /* use endswith here because functions in the Callers
             * are like `filename`.functionName
             */ 
            if (M.first->getName().endswith(callee->getName()))
                CISet = M.second;

            for (CallInst *caller : CISet) {
                // TODO need pricise location check
                if (parentName.find(caller->getFunction()->getName())
                        != parentName.end()) {
                    matched = true;

                    auto parentFname = caller->getFunction()->getName();
                    if (parentFname.find("_sys_") != string::npos)
                        continue;
                    if (BlockFunc.find(parentFname) != BlockFunc.end())
                        continue;

                    KA_LOGS(2, "Taint to it's parent "<<caller->getFunction()->getName()<<" from "<<callee->getName());
                    mergeSet(result, taintAnalysis(caller->getArgOperand(argNo), vs, found));
                }
#if 0
                else {
                    KA_LOGS(0, "this is not the father: " << caller->getFunction()->getName());
                }
#endif
            }
        }

#ifdef DEBUG
        if (!matched) {
            KA_WARNS(0, "fails to find it's parent for function " << callee->getName());
            KA_LOGS(0, "function candidates:");
            for (CallInst* caller : CISet) {
                KA_LOGS(0, "this is " << caller->getFunction()->getName());
            }
        }
#endif
        return result;
    /* global variable */
    } else if (isa<GlobalVariable>(V)) {
        GlobalVariable *GV = cast<GlobalVariable>(V);
        StringRef name = handleType(GV->getType());

        if (!addToSet(result, name)) {
            return result;
        }
    }

#ifdef DEBUG
    else {
        outs() << "Unknow Value: " << *V << "\n";
    }
#endif

    return result;
}



bool StructFinderPass::doModulePass(Module* M) {

    // some functions are defined in headers
    // if (moduleName.str() != M->getSourceFileName()) 
    //     return false;

    for (Function &F : *M) 
        runOnFunction(&F);

    return false;
}

StringRef StructFinderPass::handleType(Type *ty) {
    
    if (ty == nullptr)
        return StringRef("");

    // debug type
#if 0
    std::string type_str;
    llvm::raw_string_ostream rso(type_str);
    ty->print(rso);
    KA_LOGS(0, "type :" << rso.str());
#endif

    if (ty->isStructTy()) {
        StructType *ST = dyn_cast<StructType>(ty);
        StringRef stname = ST->getName();

        if (stname.startswith("struct.")
                && !stname.startswith("struct.anon"))
            return stname;

    } else if (ty->isPointerTy()){
        ty = cast<PointerType>(ty)->getElementType();
        return handleType(ty);
    } else if (ty->isArrayTy()){
        ty = cast<ArrayType>(ty)->getElementType();
        return handleType(ty);
    } else if (ty->isIntegerTy()) {
        return StringRef("int");
    }

    return StringRef("");    
}


void StructFinderPass::doAnalyze(Value *v) {
    VSet vs;
    vs.clear();
    mergeSet(Ctx->CriticalSt, taintAnalysis(v, vs, false));
}

void StructFinderPass::dump() {
    outs() << "Found: \n";
    for (auto s : Ctx->CriticalSt) {
        outs() <<  s << " ";
    }
    outs() << "\n";
}

void StructFinderPass::dump(StringRef outFile) {
    outs() << "Found: \n";
    ofstream result;
    result.open(outFile);
    for (auto s : Ctx->CriticalSt) {
        outs() << s << " ";
        result << s.split(".").second.str() << "\n";
    }
    result.close();
    outs() << "\n";

    outs() << "All of the structures found:\n";
    for (auto s : Ctx->CandidateSt) {
        outs() << s << " ";
    }
    outs() << "\n";
}


void StructFinderPass::runOnFunction(Function *F) {

    if (funcName != F->getName() || started)
        return;

    KA_LOGS(0, "We found the target function: " << F->getName());

    unsigned current = 0;

    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
        Instruction* I = &*i;
        DILocation* Loc = I->getDebugLoc();
        if (line == Loc->getLine()) {
            if (isa<LoadInst>(I) || isa<StoreInst>(I)) {
                if (current == idx) {
                    VSet vs;
                    if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
                        // mergeSet(CriticalSt, taintAnalysis(LI->getOperand(0), false));
                        mergeSet(Ctx->CriticalSt, taintAnalysis(cast<Value>(LI), vs, false));
                    }

                    if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
                        // mergeSet(CriticalSt, taintAnalysis(SI->getOperand(1), false));
                        mergeSet(Ctx->CriticalSt, taintAnalysis(cast<Value>(SI), vs, false));
                    }
                    started = true;
                }
                current++;
            }
        }
    }
}


bool StructFinderPass::doFinalization(Module* M) {
    return false;
}
