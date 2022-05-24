/*
 * Copyright (C) 2020 Zhenpeng Lin
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/TypeFinder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>

#include "StructFinder.h"
#include <algorithm>
#include <bits/stdc++.h>

#include <igraph/igraph.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>

using namespace llvm;
using namespace std;

void StructFinderPass::increaseRef(StringRef name) {
    if (!name.startswith("struct.") || name.startswith("struct.anon")) {
        return;
    }
    if (Ctx->structInfo.find(name.str()) == Ctx->structInfo.end()) {
            Ctx->structInfo[name.str()] = 1;
    } else {
        Ctx->structInfo[name.str()] ++; 
    }
    return;
}

void StructFinderPass::handleStruct(StructType *st, set<StringRef> &stSet) {
    for (auto subType : st->elements()) {

        // array
        while (const ArrayType* arrayType = dyn_cast<ArrayType>(subType)) {
			subType = arrayType->getElementType();
		}

        if (StructType *subST = dyn_cast<StructType>(subType)) {

            if (!subST->isOpaque() && !subST->isLiteral()) {
                StringRef subStName = subST->getStructName();
                /*if (!subStName.startswith("struct.") || subStName.startswith("struct.anon")) {
                    continue;
                }*/
                if (!stSet.insert(subStName).second) {
                    continue;
                }
            }

            // nested structures
            handleStruct(subST, stSet);
        }

        // pointer
        if (PointerType *ptrType = dyn_cast<PointerType>(subType)) {
            Type* baseType = ptrType->getElementType();
            if (StructType *ssubST = dyn_cast<StructType>(baseType)) {
                if (!ssubST->isOpaque() && !ssubST->isLiteral()) {
                    stSet.insert(ssubST->getStructName());
                }
            }
        }
    }
}

StringRef StructFinderPass::getStType(Type *ty) {
    
    if (ty == nullptr)
        return StringRef("");

    if (ty->isStructTy()) {
        StructType *ST = dyn_cast<StructType>(ty);
        StringRef stname = ST->getName();

        if (stname.startswith("struct.")
                && !stname.startswith("struct.anon"))
            return stname;

    } else if (ty->isPointerTy()){
        ty = cast<PointerType>(ty)->getElementType();
        return getStType(ty);
    } else if (ty->isArrayTy()){
        ty = cast<ArrayType>(ty)->getElementType();
        return getStType(ty);
    }

    return StringRef("");    
}

bool StructFinderPass::doInitialization(Module* M) {
    return false;
}


bool StructFinderPass::doModulePass(Module* M) {

    TypeFinder usedStructTypes;
    usedStructTypes.run(*M, false);

    bool doAnalysis = false;
    for (TypeFinder::iterator itr = usedStructTypes.begin(),
        ite = usedStructTypes.end(); itr != ite; itr++) {

        StructType* st = *itr;
        if (st->isOpaque() || st->isLiteral())
            continue;
        StringRef name = st->getStructName();

        if (Ctx->objects.find(name.str()) != Ctx->objects.end()) {
            continue;
        }

        Ctx->objects.insert(name.str());

        if (!name.startswith("struct.") || name.startswith("struct.anon")) {
            continue;
        }

        set<StringRef> stSet;
        stSet.clear();

        // find all outgoing structures
        // two structures only have on outgoing connection
        handleStruct(st, stSet);

        for (auto subStName : stSet) {
            increaseRef(subStName);
            Ctx->IncomingNode[subStName].insert(name);
            Ctx->OutgoingNode[name].insert(subStName);
        }
    }

    for (Function &F : *M) 
        runOnFunction(&F);

    return false;
}

Instruction* StructFinderPass::simpleBackward(Value *V, VSet &vs) {
    Value *ret = nullptr;

    if (V == nullptr) {
        return nullptr;
    }

    if (!vs.insert(V).second) {
        KA_LOGS(1, "Already found "<<*V<<"\n");
        return nullptr;
    }

    if (auto *I = dyn_cast<Instruction>(V)) {
        KA_LOGS(1, "Got "<<*I<<" "<<I->getFunction()->getName()<<"\n");

        switch (I->getOpcode()) {
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
            {
                break;
            }
            case Instruction::PHI:
            {
                // check code coverage here to find the node
                PHINode *PN = cast<PHINode>(I);
                for (unsigned i = 0, e = PN->getNumIncomingValues(); i < e; i++) {
                    Value* IV = PN->getIncomingValue(i);
                    if (Instruction *II = dyn_cast<Instruction>(IV)) {
                        // if II not get covered
                        // one imcoming value is enough
                        Instruction *RII = simpleBackward(II, vs);
                        if (RII != nullptr)
                            return RII;
                    }
                }
                break;
            }
            case Instruction::Call:
            {
                // find retinst
                Function *F = cast<CallInst>(I)->getCalledFunction();

                if (F == nullptr)
                    return nullptr;
                
                StringRef Fname = F->getName();

                if (Ctx->TypeMaps.find(Fname) != Ctx->TypeMaps.end()) {
                    KA_LOGS(1, "Found "<<Fname<<" in cache\n");
                    return Ctx->TypeMaps.find(Fname)->second;
                }

                for (auto M : Ctx->Callers) {
                    
                    if (M.first->getName()==Fname) {
                        F = M.first;
                        if (F->getInstructionCount() > 0) {
                            KA_LOGS(1, "Found the definition of " << Fname <<" @"<<F->getInstructionCount()<<"\n");
                            break;
                        }
                    }
                }
                
                KA_LOGS(1, "call in function: "<<F->getName()<<"; size : "<< F->getInstructionCount()<<"\n");
                for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
                    Instruction* II = &*i;
                    KA_LOGS(1, "Got inst in call "<<*II<<" in "<<F->getName()<<"\n");
                    if (isa<ReturnInst>(II)) {
                        Instruction *RII = simpleBackward(II, vs);
                        if (RII != nullptr) {
                            KA_LOGS(1, "Here : Adding Inst to cache "<<Fname<<"\n");
                            Ctx->TypeMaps[Fname] = RII;
                            return RII;
                        }
                    }
                }
                KA_LOGS(1, "Adding nullptr to cache "<<Fname<<"\n");
                Ctx->TypeMaps[Fname] = nullptr;
                break;
            }

            case Instruction::GetElementPtr:
            case Instruction::BitCast:
                return I;
            case Instruction::Ret:
                return simpleBackward(I->getOperand(0), vs);
        }
    }
    return nullptr;

}

// Function F may have been analyzed, so we only log once
void StructFinderPass::runOnFunction(Function *F) {
    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
        Instruction* I = &*i;

        if (isa<BitCastInst>(I)) {
            BitCastInst *BCI = cast<BitCastInst>(I);
            StringRef dstSt = getStType(BCI->getDestTy());
            StringRef srcSt = getStType(BCI->getSrcTy());

            if (dstSt == "")
                continue;

            // let's find the srcSt

            if (srcSt == "") {
                // update srcSt
                VSet vs;
                vs.clear();

                Instruction *II = simpleBackward(BCI->getOperand(0), vs);
                while (II != nullptr && srcSt == "") {
                    if (isa<GetElementPtrInst>(II)) {
                        GetElementPtrInst *GEP = cast<GetElementPtrInst>(II);
                        srcSt = getStType(GEP->getSourceElementType());
                        II = simpleBackward(GEP->getOperand(0), vs);
                    } else if (isa<BitCastInst>(II)) {
                        BitCastInst *BCI = cast<BitCastInst>(II);
                        srcSt = getStType(BCI->getSrcTy());
                        II = simpleBackward(BCI->getOperand(0), vs);
                    }
                }

                if (srcSt != "") {
                    KA_LOGS(1, "Find pair by backwarding: "<<dstSt<< " -> "<<srcSt<<" @ "<<I->getFunction()->getName()<<"\n");
                }

            }

            if (srcSt == dstSt) {
                continue;
            }

            if (srcSt != "") {
                // connect two structures
                // bitcast skb->data to struct lzp
                // link lzp -> skb
                //       dst    src
                KA_LOGS(1, "Find pair "<<dstSt<< " -> "<<srcSt<<" @ "<<I->getFunction()->getName()<<"\n");
                KA_LOGS(1, srcSt << " cast to " <<dstSt<<" @ "<<I->getFunction()->getName()<<"\n");
                bool firstTime = false;
                firstTime  = Ctx->IncomingNode[srcSt].insert(dstSt).second;
                firstTime |= Ctx->OutgoingNode[dstSt].insert(srcSt).second;
                if (firstTime) {
                    increaseRef(srcSt);
                }
            }

        }
    }
}

struct comp { 
    template <typename T> 
  
    // Comparator function 
    bool operator()(const T& l, 
                    const T& r) const
    { 
        if (l.second != r.second) { 
            return l.second < r.second; 
        } 
        return l.first < r.first; 
    } 
}; 
  
// Function to sort the map according 
// to value in a (key-value) pairs 
static void ssort(std::map<string, size_t>& M) 
{ 
  
    // Declare set of pairs and insert 
    // pairs according to the comparator 
    // function comp() 
    set<pair<string, size_t>, comp> S(M.begin(), 
                                   M.end()); 
  
    // Print the sorted value 
    for (auto& it : S) { 
        cout << it.first << ' '
             << it.second << endl; 
    } 
}

void StructFinderPass::dumpLoc(){
    // for(auto s : Ctx->structInfo){
    //     outs() << s.first << " " << s.second << "\n";
    // }

    // map<string, int
    ssort(Ctx->structInfo);

    geneGraph();
}

void StructFinderPass::geneGraph() {
    // size_t graph_size = Ctx->IncomingNode.size() > Ctx->OutgoingNode.size() ? Ctx->IncomingNode.size():Ctx->OutgoingNode.size();
    
    // build graph id map
    size_t current = 0;
    for (auto st : Ctx->IncomingNode) {
        if (Ctx->ObjMap.find(st.first) == Ctx->ObjMap.end()) {
            Ctx->ObjMap[st.first] = current;
            current ++;
        }
        for (auto sst : st.second) {
            if (Ctx->ObjMap.find(sst) == Ctx->ObjMap.end()) {
                Ctx->ObjMap[sst] = current;
                current ++;
            }   
        }
    }

    for (auto st : Ctx->OutgoingNode) {
        if (Ctx->ObjMap.find(st.first) == Ctx->ObjMap.end()) {
            Ctx->ObjMap[st.first] = current;
            current ++;
        }
        for (auto sst : st.second) {
            if (Ctx->ObjMap.find(sst) == Ctx->ObjMap.end()) {
                Ctx->ObjMap[sst] = current;
                current ++;
            }   
        }
    }
    // store the map
    ofstream stMap ("struct_map.txt");
    if (stMap.is_open()) {
        for (auto s : Ctx->ObjMap) {
            stMap << s.first.str() << " " << s.second << "\n";
        }
    } else {
        assert(false && "fail to open file\n");
    }

    igraph_t g;

    igraph_empty(&g, current, 1);
    // draw graph
    for (auto st : Ctx->IncomingNode) {
        if (Ctx->ObjMap.find(st.first) != Ctx->ObjMap.end()) {
            size_t ending = Ctx->ObjMap[st.first];
            for (auto endNode : st.second) {
                size_t starting = Ctx->ObjMap[endNode];
                igraph_add_edge(&g, starting, ending);
            }
        }
    }

    for (auto st : Ctx->OutgoingNode) {
        if (Ctx->ObjMap.find(st.first) != Ctx->ObjMap.end()) {
            size_t starting = Ctx->ObjMap[st.first];
            for (auto endNode : st.second) {
                size_t ending = Ctx->ObjMap[endNode];
                igraph_add_edge(&g, starting, ending);
            }
        }
    }

    outs() << "\ngot " << igraph_ecount(&g) << " of edges\n";
    // write graph
    FILE *f = fopen("structs.ncol", "w");
    int ret = igraph_write_graph_ncol(&g, f, 0, 0);
    fclose(f);
    igraph_destroy(&g);
}


bool StructFinderPass::doFinalization(Module* M) {
    return false;
}
