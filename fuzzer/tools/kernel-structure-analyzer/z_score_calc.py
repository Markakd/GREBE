import numpy as np
import sys
import json
from scipy import stats

st_list = {"struct.llist_node", "struct.rhash_head", "struct.wait_queue_head",
  "struct.net_device", "struct.timer_list", "struct.kref",
  "struct.raw_spinlock", "struct.work_struct", "struct.sk_buff",
  "struct.mutex", "struct.qspinlock", "struct.optimistic_spin_queue",
  "struct.module", "struct.lockdep_subclass_key",
  "struct.notifier_block", "struct.refcount_struct", "struct.atomic64_t",
  "struct.device", "struct.lockdep_map", "struct.spinlock",
  "struct.lock_class", "struct.callback_head", "struct.lock_class_key",
  "struct.trace_entry", "struct.atomic_t", "struct.rb_node",
  "struct.hlist_node", "struct.list_head", "struct.worker",

#   "struct.debug_bucket", "struct.debug_obj",
  "struct.inode",
#   "struct.hrtimer_cpu_base", #0.103839
#   // need to handle this
#   // %work = getelementptr inbounds %struct.rcu_work, %struct.rcu_work* %rwork,
#   // call void @__init_work(%struct.work_struct* %work, i32 0)
#   // this is a bitcast
# "struct.socket", 0.210472
# "struct.sockaddr", 1.069454
#  "struct.resource",1.205706

  "struct.net",
  "struct.nlattr", "struct.nlmsghdr", "struct.task_struct",
  "struct.sock",  "struct.hlist_head",
  "struct.kmem_cache", "struct.hrtimer", "struct.hrtimer_clock_base",
   "struct.kobject", "struct.file",}

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: %s page_rank.out"%(sys.argv[0]))
        exit(0)
    filename = sys.argv[1]

    sts = []
    rank_value = []

    data = open(filename).read()
    for info in data.split("\n"):
        if not info.strip():
            continue
        sts.append(info.split("=")[0].strip())
        rank_value.append(float(info.split("=")[1].strip()))
    
    rank_value = np.array(rank_value)
    zscores = stats.zscore(rank_value)

    stss = []

    for st, score in zip(sts, zscores):
        # we use 1.5 threshold, 97%??? confidence
        if score > 1.5:
            stss.append(st)
        print("%s\t=\t%lf"%(st, score))
    
    if len(sys.argv) == 3 and sys.argv[2] == "dump":
        open("block_st.txt",'w').write(json.dumps(stss))
    


    # for sss in st_list:
    #     if sss not in stss:
    #         print("Here: "+sss)