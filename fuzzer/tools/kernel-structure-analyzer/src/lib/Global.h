#ifndef _GLOBAL_H
#define _GLOBAL_H

#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>

#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "Common.h"

using namespace llvm;
using namespace std;

typedef std::vector< std::pair<llvm::Module*, llvm::StringRef> > ModuleList;
typedef std::unordered_map<llvm::Module*, llvm::StringRef> ModuleMap;
typedef std::set<llvm::Value *> VSet;


typedef std::unordered_map<std::string, llvm::Function*> FuncMap;
typedef std::unordered_map<std::string, llvm::GlobalVariable*> GObjMap;
typedef std::unordered_map<std::string, llvm::Instruction*> TypeMap;

/****************** Call Graph **************/
typedef unordered_map<string, llvm::Function*> NameFuncMap;
typedef llvm::SmallPtrSet<llvm::CallInst*, 8> CallInstSet;
typedef llvm::SmallPtrSet<llvm::Function*, 32> FuncSet;
typedef std::unordered_map<std::string, FuncSet> FuncPtrMap;
typedef llvm::DenseMap<llvm::Function*, CallInstSet> CallerMap;
typedef llvm::DenseMap<llvm::CallInst*, FuncSet> CalleeMap;
/****************** end Call Graph **************/


class GlobalContext {
private:
  // pass specific data
  std::map<std::string, void*> PassData;

public:
  bool add(std::string name, void* data) {
    if (PassData.find(name) != PassData.end())
      return false;

    PassData[name] = data;
    return true;
  }

  void* get(std::string name) {
    std::map<std::string, void*>::iterator itr;

    itr = PassData.find(name);
    if (itr != PassData.end())
      return itr->second;
    else
      return nullptr;
  }

  typedef std::set<llvm::StringRef> StrSet;
  StrSet CriticalObj;
  std::set<string> objects;
  std::map<string, size_t> structInfo;

  // Map global object name to object definition
  GObjMap Gobjs;

  // Map global function name to function defination
  FuncMap Funcs;

  // Map function pointers (IDs) to possible assignments
  FuncPtrMap FuncPtrs;

  // functions whose addresses are taken
  FuncSet AddressTakenFuncs;

  // Map a callsite to all potential callee functions.
  CalleeMap Callees;

  // Map a function to all potential caller instructions.
  CallerMap Callers;

  // Indirect call instructions
  std::vector<CallInst *>IndirectCallInsts;

  // Map function signature to functions
  DenseMap<size_t, FuncSet>sigFuncsMap;

  // Map global function name to function.
  NameFuncMap GlobalFuncs;

  // Unified functions -- no redundant inline functions
  DenseMap<size_t, Function *>UnifiedFuncMap;
  set<Function *>UnifiedFuncSet;

  // structs identified
  std::set<llvm::StringRef> CriticalSt;

  // type map for optimization
  TypeMap TypeMaps;

  // graph
  std::map<StringRef, set<StringRef>> IncomingNode;
  std::map<StringRef, set<StringRef>> OutgoingNode;
  std::map<StringRef, size_t> ObjMap;


  ModuleList Modules;
  ModuleMap ModuleMaps;
  std::set<std::string> InvolvedModules;
};

class IterativeModulePass {
protected:
  GlobalContext *Ctx;
  const char *ID;
public:
  IterativeModulePass(GlobalContext *Ctx_, const char *ID_)
    : Ctx(Ctx_), ID(ID_) { }

  // run on each module before iterative pass
  virtual bool doInitialization(llvm::Module *M)
    { return true; }

  // run on each module after iterative pass
  virtual bool doFinalization(llvm::Module *M)
    { return true; }

  // iterative pass
  virtual bool doModulePass(llvm::Module *M)
    { return false; }

  virtual void run(ModuleList &modules);
};

#endif
