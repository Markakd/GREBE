# GREBE

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
The fuzzer works like [Syzkaller](https://github.com/google/syzkaller).
