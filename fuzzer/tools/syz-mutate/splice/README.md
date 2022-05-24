## splice

#### Motivation

Fuzzing is one of the most practical approaches to finding bugs. However, utilizing fuzzing to find one bug's other manifestations in kernel is challenging.one potential approach is to minimize the search space of fuzzing. e.g. fuzzing specific syscalls related to the bug instead of fuzzing the whole kernel. However, there still exists a large searching space in syscall's argument if we specify the correct the syscall candidates, which reduces the probability of triggering the same bug.

To reduce the searching space of syscall argument, we propose a mutation method that splice the information in the PoC and the information in the seeds.

#### Approach

Based on the specification of syzkaller, one argument consists of several types:

PointerArg
   |
   |- - - - -
   |        |
   \/       \/
GroupArg   UnionArg
        |
        |
        \/
      Types


we parse the argument information in the syscall.
{ "sysName"+"baseArg": arg}
for each arg, we calcutate the complixity of them based on number of types.

replace inner of prog.UnionType and prog.StructType