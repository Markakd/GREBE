# Step 1: build kernel bitcode

Download llvm-10.0.1 [source code](https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/llvm-project-10.0.1.tar.xz) and build it with this [patch](https://github.com/Markakd/LLVM-O0-BitcodeWriter/blob/master/WriteBitcode.patch) applied to get a customized clang, then build kernel with our custimized clang to get unoptimized bitcode.

# Step 2: build the analyzer
The analyzer depends on llvm-10, so make sure llvm-10 is installed. Follow [here](https://apt.llvm.org/) to install llvm-10.

`sudo apt install libstdc++-10-dev` to solve the issue of not finding lstdc++

Then run `make` to build the analyzer.

# Step 3: Analyzing the kernel

Get call graph of crash report
```bash
python get_cg.py report
```
You will see a file named report_cg.txt 

Then,
```bash
python run_analyze.py .
```
to generate objects identified in file `sts.txt`
