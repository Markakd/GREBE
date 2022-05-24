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
#include <llvm/Analysis/AliasAnalysis.h>

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
typedef std::unordered_map<std::string, llvm::Function*> FuncMap;
typedef std::unordered_map<std::string, llvm::GlobalVariable*> GObjMap;

/****************** Call Graph **************/
typedef unordered_map<string, llvm::Function*> NameFuncMap;
typedef llvm::SmallPtrSet<llvm::CallInst*, 8> CallInstSet;
typedef llvm::SmallPtrSet<llvm::Function*, 32> FuncSet;
typedef std::unordered_map<std::string, FuncSet> FuncPtrMap;
typedef llvm::DenseMap<llvm::Function*, CallInstSet> CallerMap;
typedef llvm::DenseMap<llvm::CallInst*, FuncSet> CalleeMap;
/****************** end Call Graph **************/

/****************** Alias **************/
typedef DenseMap<Value *, SmallPtrSet<Value *, 16>> PointerAnalysisMap;
typedef unordered_map<Function *, PointerAnalysisMap> FuncPointerAnalysisMap;
typedef unordered_map<Function *, AAResults *> FuncAAResultsMap;
/****************** end Alias **************/

// StructFinder
typedef std::set<llvm::StringRef> StrSet;
typedef std::set<llvm::Value *> VSet;
typedef std::map<llvm::StringRef, llvm::StringRef> StrMap;

static StrSet skipFunc = {"debug_print_object",
     "debug_object_init", "debug_assert_init", /*ODEBUG*/
     "__dump_stack", "dump_stack", "print_address_description", 
     "kasan_report", "__kasan_report", "kasan_report_error",
     "kasan_report_double_free", "kasan_report_invalid_free",
     "__asan_report_load1_noabort", "__asan_report_store1_noabort",
     "__asan_report_load2_noabort", "__asan_report_store2_noabort",
     "__asan_report_load4_noabort", "__asan_report_store4_noabort",
     "__asan_report_load8_noabort", "__asan_report_store8_noabort",
     "__asan_report_load16_noabort", "__asan_report_store16_noabort",
     "__kasan_check_read", "__kasan_check_write",
     "kasan_check_read", "kasan_check_write",
     "check_memory_region_inline", "check_memory_region",
     "strlen", "__warn_printk", "printk",
     "print_unlock_imbalance_bug", "__init_work",
     "debug_check_no_obj_freed", "__asan_report_load_n_noabort",
     "__asan_report_store16_noabort", };

// Blocked structures
static StrSet BlockSt = {
  // "struct.llist_node", "struct.rhash_head", "struct.wait_queue_head",
  // "struct.net_device", "struct.timer_list", "struct.kref",
  // "struct.raw_spinlock", "struct.work_struct", "struct.sk_buff",
  // "struct.mutex", "struct.qspinlock", "struct.optimistic_spin_queue",
  // "struct.module", "struct.lockdep_subclass_key", "struct.resource",
  // "struct.notifier_block", "struct.refcount_struct", "struct.atomic64_t",
  // "struct.device", "struct.lockdep_map", "struct.spinlock",
  // "struct.lock_class", "struct.callback_head", "struct.lock_class_key",
  // "struct.trace_entry", "struct.atomic_t", "struct.rb_node",
  // "struct.hlist_node", "struct.list_head", "struct.worker",

  // "struct.debug_bucket", "struct.debug_obj",
  // "struct.inode",
  // // need to be added
  // // "struct.tun_file"
  // // "struct.proto_ops"
  // "struct.rcu_work",// need to handle this
  // // %work = getelementptr inbounds %struct.rcu_work, %struct.rcu_work* %rwork,
  // // call void @__init_work(%struct.work_struct* %work, i32 0)
  // // this is a bitcast

  // "struct.net",

  // "struct.nlattr", "struct.nlmsghdr", "struct.task_struct",
  // "struct.sock", "struct.socket", "struct.hlist_head",
  // "struct.kmem_cache", "struct.hrtimer", "struct.hrtimer_clock_base", "struct.hrtimer_cpu_base",
  // "struct.sockaddr", "struct.kobject", "struct.file",

  "struct.hrtimer_cpu_base", "struct.socket", "struct.sockaddr"

  "struct.nlo_configured_parameters", "struct.u64_stats_sync", "struct.ib_cq", "struct.address_space",
  "struct.attribute", "struct.be_mcc_wrb", "struct.ebitmap_node", "struct.mwifiex_adapter",
  "struct.i2c_client", "struct.rpc_clnt", "struct.hrtimer", "struct.bfa_cb_qe_s", "struct.pci_dev",
  "struct.sk_psock", "struct.wmi_tlv", "struct.rpc_task", "struct.closure", "struct.bdi_writeback",
  "struct.lowpan_peer", "struct.hrtimer_clock_base", "struct.timerqueue_node", "struct.host_cmd_ds_command",
  "struct.notifier_block", "struct.kuid_t", "struct.bpf_prog_aux", "struct.io_context", "struct.dio",
  "struct.z_erofs_decompressqueue", "struct.fsl_mc_command", "struct.rb_root", "struct.fddi_statistics",
  "struct.tboot_acpi_generic_address", "struct.tx_desc_cmd", "struct.device_node", "struct.bio",
  "struct.acpi_table_header", "struct.bdaddr_t", "struct.super_block", "struct.kmem_cache_node",
  "struct.kasan_cache", "struct.kmem_cache_cpu", "struct.kmem_cache_order_objects", "struct.sock",
  "struct.reciprocal_value", "struct.file", "struct.xarray", "struct.tx_desc", "struct.regpair",
  "struct.bnx2x_pending_mcast_cmd", "struct.writequeue_entry", "struct.ubifs_lprops", "struct.dm_writecache",
  "struct.in6_addr", "struct.csio_dma_buf", "struct.bfa_sgpg_wqe_s", "struct.bfa_lps_s", "struct.htc_packet",
  "struct.bfa_ioc_notify_s", "struct.dmxdev_filter", "struct.intel_engine_cs", "struct.dev_pm_ops",
  "struct.bfa_ioim_s", "struct.bfa_fcs_rport_s", "struct.bfa_fcxp_wqe_s", "struct.heap_fence",
  "struct.ib_mr", "struct.fwnode_handle", "struct.bfa_sgpg_s", "struct.fib6_info", "struct.bfa_fcxp_s",
  "struct.net_bridge_vlan", "struct.ext4_prealloc_space", "struct.nfs4_file", "struct.obj_cgroup",
  "struct.i915_gem_engines", "struct.efa_stats", "struct.gfar_extra_stats", "struct.mlx5e_ipsec_sw_stats",
  "struct.efa_com_stats_admin", "struct.smc_host_cdc_msg", "struct.mlx5e_tls_sw_stats",
  "struct.scsi_pointer", "struct.i40iw_puda_buf", "struct.tracing_map_field", "struct.bfa_itnim_s",
  "struct.bfa_s", "struct.bfa_timer_s", "struct.htab_elem", "struct.swait_queue_head", "struct.inode",
  "struct.hlist_head", "struct.sysfs_ops", "struct.bfa_rport_s", "struct.net", "struct.dma_fence",
  "struct.scatterlist", "struct.pnfs_block_extent", "struct.ubi_ainf_peb", "struct.sctp_chunk",
  "struct.dlm_rsb", "struct.ubi_wl_entry", "struct.nlmsghdr", "struct.rpc_rqst", "struct.allowedips_node",
  "struct.xfrm_state", "struct.crypto_instance", "struct.kobj_type", "struct.kset", "struct.tboot",
  "struct.ext4_super_block", "struct.otx2_drv_stats", "struct.smb_hdr", "struct.packet_fanout",
  "struct.key", "struct.ghes", "struct.kobject", "struct.external_name", "struct.mlx5_ib_mr",
  "struct.completion", "struct.xa_node", "struct.binder_node", "struct.lima_device", "struct.crypto_tfm",
  "struct.bfi_mbmsg_s", "struct.qrwlock", "struct.kernfs_node", "struct.net_device_stats", "struct.mount",
  "struct.crypto_alg", "struct.aligned_lock", "struct.lima_ip", "struct.wait_queue_head",
  "struct.delayed_work", "struct.bfi_mhdr_s", "struct.gpiochip_fwd", "struct.raw_spinlock",
  "struct.sock_common", "struct.nlattr", "struct.mutex", "struct.worker", "struct.task_struct",
  "struct.rhash_head", "struct.hlist_nulls_node", "struct.llist_node", "struct.optimistic_spin_queue",
  "struct.module", "struct.request", "struct.kref", "struct.io_cq", "struct.timer_list", "struct.net_device",
  "struct.device", "struct.lockdep_subclass_key", "struct.dentry", "struct.sk_buff", "struct.bpf_spin_lock",
  "struct.page", "struct.qspinlock", "struct.refcount_struct", "struct.callback_head", "struct.devres_node",
  "struct.rb_node", "struct.work_struct", "struct.spinlock", "struct.atomic64_t", "struct.trace_entry",
  "struct.lockdep_map", "struct.devres", "struct.lock_class", "struct.atomic_t", "struct.hlist_node",
  "struct.kmem_cache", "struct.lock_class_key", "struct.list_head"
};

static StrSet BlockFunc = {
  "process_one_work", "call_timer_fn", "task_work_run", "__do_softirq",
  "do_signal", //1aed58e
};

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

  /****** Alias Analysis *******/
  FuncPointerAnalysisMap FuncPAResults;
  FuncAAResultsMap FuncAAResults;

  // Map global function name to function.
  NameFuncMap GlobalFuncs;

  // Unified functions -- no redundant inline functions
  DenseMap<size_t, Function *>UnifiedFuncMap;
  set<Function *>UnifiedFuncSet;

  // taint source from the report
  VSet TaintSrc;

  // tmp src
  VSet TmpTaintSrc;

  // struct candidates result
  std::set<llvm::StringRef> CandidateSt;

  // number of Load/Store Instruction
  unsigned InstNum;

  // call graph from the report
  std::map<string, string> CallGraph;

  // structs identified
  std::set<llvm::StringRef> CriticalSt;

  // A factory object that knows how to manage AndersNodes
  // AndersNodeFactory nodeFactory;

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
