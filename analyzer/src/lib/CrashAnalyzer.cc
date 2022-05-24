/*
 * Copyright (C) 2020 Zhenpeng Lin
 *
 * For licensing details see LICENSE
 */

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Debug.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/CFG.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>

#include "CrashAnalyzer.h"
#include "StructFinder.h"

void CrashAnalyzer::runOnFunction(Function *F) {
    if (funcName != F->getName() || analyzed)
        return;
    
    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
        Instruction* I = &*i;

        DILocation* Loc = I->getDebugLoc();

        // KA_LOGS(0, "File: "<<Loc->getScope()->getFilename()<<":"<<Loc->getLine()<<"\n");
        // KA_LOGS(0, "Source: "<<source<<"\n");

        if (Loc == nullptr) {
            continue;
        }

        /* remove "./" for header files */
        StringRef sourceF = Loc->getScope()->getFilename();
        if (sourceF.startswith("./")) {
            sourceF = sourceF.split("./").second;
        }

        if (line == Loc->getLine() && sourceF == source) {
            analyzed = true;

            KA_LOGS(0, "Analyzing: " << *I);

            Ctx->TmpTaintSrc.insert(I);

            if (!cond) {
                if (isa<LoadInst>(I) || isa<StoreInst>(I)) {
                    Ctx->TaintSrc.insert(I);
                    Ctx->InstNum ++;
                } else if (isa<CallInst>(I)) {
                    Function *F = cast<CallInst>(I)->getCalledFunction();

                    if (F == nullptr) {
                        KA_WARNS(0, "Fail to find Function from the CallInst "<<*I);
                        continue;
                    }

                    StringRef Fname = F->getName();
                    /* since we skip some debugging functions in the first step
                    let's taint starting from these functions' argument */
                    if (skipFunc.find(Fname) != skipFunc.end()) {
                        Ctx->TaintSrc.insert(I);
                    } else if (Fname.find("__write_once_size") != string::npos) {
                        Ctx->TaintSrc.insert(cast<CallInst>(I)->getArgOperand(0));
                    }else {
                        KA_WARNS(0, "Unknown call here "<<*I);
                    }
                } else {
                    KA_LOGS(1, "Unknown Inst here "<<*I);
                }
            } else {
                // Ctx->TaintSrc.insert(I);

                /* find explicit checkings
                 * let's find some critical functions causing panic to kernel,
                 * which generate reports. Functions include printk("INFO:")
                 * __warn_printk, asm sideeffect
                 */
                if (isa<CallInst>(I)) {
                    CallInst *CI = cast<CallInst>(I);
                    Function *F = CI->getCalledFunction();
                    StringRef Fname = ""; // if calling asm

                    if (F != nullptr) {
                        Fname = F->getName();
                    }

                    /* handle ODEBUG and DEBUG_OBJECTS_FREE.
                     * which generate warns using "implicit"
                     * checkings
                     */
                    if (Fname.find("init_work") != string::npos ||
                        Fname.find("print_unlock_imbalance_bug") != string::npos ||
                        Fname.find("debug_print_object") != string::npos ||
                        Fname.find("debug_object_init") != string::npos ||
                        Fname.find("debug_assert_init") != string::npos ||
                        /* DEBUG_OBJECTS_FREE */
                        Fname.find("debug_check_no_obj_freed") != string::npos) {
                            Ctx->TaintSrc.insert(I);
                        }

                    /* find printk */
                    if (Fname.find("printk") != string::npos || CI->isInlineAsm()) {
                        BasicBlock *BB = CI->getParent();
                        KA_LOGS(2, "Found BB : "<<*BB);
                        KA_LOGS(2, "terminator : "<<*BB->getTerminator());

                        Value *condV;
                        bool warnOnce = false;

                        /* find the outmost basic block*/
                        while (BB->getSinglePredecessor()) {
                            BasicBlock *newBB = BB->getSinglePredecessor();

                            /* heuristic: if sotring true to `refcount_inc_checked.__warned`
                             * exists in the skipped BB, there should exist an redundant
                             * checking for the `refcount_inc_checked.__warned` */
                            for (Instruction &BBInst : *BB) {
                                if (isa<StoreInst>(&BBInst)) {
                                    StoreInst *SI = cast<StoreInst>(&BBInst);
                                    if (isa<ConstantInt>(SI->getOperand(0))
                                        && isa<GlobalVariable>(SI->getOperand(1))) {
                                        StringRef GVName = cast<GlobalVariable>(SI->getOperand(1))->getName();
                                        KA_LOGS(0, "Found Global Value: "<<GVName);
                                        if (GVName.find("__warned") != string::npos &&
                                            F && F->getName().find("__warn_printk") != string::npos) {
                                            KA_LOGS(0, "Warn ONCE checking here....");
                                            warnOnce = true;
                                        }
                                    }
                                }
                            }


                            if (isa<BranchInst>(newBB->getTerminator())) {
                                BranchInst *BI = cast<BranchInst>(newBB->getTerminator());
                                if (BI->isConditional()) {
                                    KA_LOGS(0, "Found first condition : "<<*BI->getCondition());
                                    condV = BI->getCondition();
                                    break;
                                }
                            }
                            BB = newBB;
                            KA_LOGS(1, "Skipping BB: "<<*BB);
                        }

                        /*
                        * if we find a condition value and the logging is not WARN_ONCE,
                        * we mark the condition value as taint source and continue.
                        * */
                        if (condV && !warnOnce ) {
                            Ctx->TaintSrc.insert(condV);
                            continue;
                        }

                        // null the condition
                        Value *SecondCondV = nullptr;

                        /* breadth first search
                        * */
                        std::vector<BasicBlock *> BBVec;
                        std::set<BasicBlock *> BBSet;
                        BBVec.push_back(BB);
                        while (!BBVec.empty() && !SecondCondV) {
                            BB = BBVec.back();
                            BBVec.pop_back();

                            // cyclic basic block
                            if (!BBSet.insert(BB).second) {
                                continue;
                            }

                            if (!BB->hasNPredecessorsOrMore(1)) {
                                /* no predecessor, let's find
                                *  find its parents
                                * */
                               auto fName = BB->getParent()->getName();
                               if (Ctx->CallGraph.find(fName) != Ctx->CallGraph.end()) {
                                   auto callerName = Ctx->CallGraph[fName];
                                   for (auto M : Ctx->Callers) {
                                        if (M.first->getName().endswith(fName)) {
                                            auto CISet = M.second;
                                            for (CallInst *caller : CISet) {
                                                if (caller->getFunction()->getName()
                                                        == callerName) {
                                                    BB = caller->getParent();
                                                    KA_LOGS(0, "Backwarding to its parent "<<callerName);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            for (BasicBlock *Pred : predecessors(BB)) {
                                KA_LOGS(1, "Found pre : "<<*Pred);
                                BBVec.push_back(Pred);
                                if (isa<BranchInst>(Pred->getTerminator())) {
                                    BranchInst *BI = cast<BranchInst>(Pred->getTerminator());
                                    if (BI->isConditional()
                                        && condV != BI->getCondition()) {
                                            SecondCondV = BI->getCondition();
                                            assert(SecondCondV);
                                            KA_LOGS(0, "Found 1st condition : "<<*condV);
                                            KA_LOGS(0, "Found 2nd condition : "<<*SecondCondV);
                                            break;
                                    }
                                }
                            }
                        }

                        if (SecondCondV) {
                            Ctx->TaintSrc.insert(SecondCondV);
                            continue;
                        }

                        KA_WARNS(0, "Cannot find condition value");
                    }
                }
            }
        }
    }
}

void CrashAnalyzer::dump() {
    dump("/tmp/ca_result");
}

void CrashAnalyzer::dump(StringRef outFile) {
    for (auto *v : Ctx->TaintSrc) {
        outs() << "Found " << *v << "\n";
    }

    // outs() << "is condition? " << cond << "\n";
    // outs() << "number of load/store inst? " << Ctx->InstNum << "\n";

    if (!cond && Ctx->InstNum > 1) {
        KA_WARNS(0, "Please take a look at this case, find more than one load and store");
        sleep(2);
    }

    assert(Ctx->TaintSrc.size() > 0 || Ctx->TmpTaintSrc.size() > 0);
    if (Ctx->TaintSrc.size() == 0) {
        for (auto *src : Ctx->TmpTaintSrc) {
            Ctx->TaintSrc.insert(src);
        }
    }

    KA_LOGS(0, "Starting taint analysis");

    StructFinderPass SFPass(Ctx, "__le32_to_cpup", 58, 0);

    for (auto *v : Ctx->TaintSrc) {
        SFPass.doAnalyze(v);
    }

    SFPass.dump(outFile);
}


bool CrashAnalyzer::doInitialization(Module* M) {
    return false;
}

bool CrashAnalyzer::doModulePass(Module* M) {

    // some functions are defined in headers
    // if (moduleName.str() != M->getSourceFileName()) 
    //     return false;

    for (Function &F : *M) 
        runOnFunction(&F);

    return false;
}

bool CrashAnalyzer::doFinalization(Module* M) {
    return false;
}
