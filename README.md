# GREBE

GREBE is an object-driven tool to identify **Multiple Error Behavior** of kernel bugs. GREBE consists of two components -- a static analysis tool to identify critical kernel objects of triggering the bug, and a fuzzing tool based [Syzkaller](https://github.com/google/syzkaller) to find its other error behavior. Refer to our [paper](https://zplin.me/papers/GREBE.pdf) for more details.

## Usage scenario

You find a low-severity bug in kernel, and would like to know the true effect of the bug. Examples: [CVE-2021-3715](https://zplin.me/talks/BHEU21_trash_kernel_bug.pdf)

You find a high-severity bug, and would like to know the bug's other memory corruption capability.

## How to use fuzzer

### Identify critical objects with the analyzer

see [here](./analyzer/README.md)

### Patch kernel to support object coverage feedback
```bash
patch [target_kernel_dir]/kernel/kcov.c -p1 < ./kernel.patch
```

### Build kernel with our gcc
```
export OBJ_FILE=[the_absolute_path_to_the_file_containing_critical_objects]
make CC=[path_to_our_gcc] -j`nproc`
```

### Run the fuzzer
The fuzzer works like [Syzkaller](https://github.com/google/syzkaller). It is noted that you should pass a POC to the `syz-manager` with `-auxiliary` flag.

## Acknowledge

```
@INPROCEEDINGS{9833683,
author={Lin, Zhenpeng and Chen, Yueqi and Wu, Yuhang and Mu, Dongliang and Yu, Chensheng and Xing, Xinyu and Li, Kang},
booktitle={2022 IEEE Symposium on Security and Privacy (SP)},
title={GREBE: Unveiling Exploitation Potential for Linux Kernel Bugs},
year={2022},
pages={2078-2095},
doi={10.1109/SP46214.2022.9833683}
}
```

