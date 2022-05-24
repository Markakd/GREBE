# Step 1: build kernel bitcode
Follow [here](https://github.com/Markakd/LLVM-O0-BitcodeWriter) to build a clang to would generate bitcode for you, then build kernel as usual but make sure you are building with our custimized clang.


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
