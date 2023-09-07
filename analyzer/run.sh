#!/bin/bash
### run.sh - 
###   Provided the following environment variables as inputs, 
###   run the GREBE/analyzer workflow to produce the 
###   object report 'sts.txt':
###    - WORKDIR=/path/to/GREBE/analyzer/
###    - KERNEL_SRC=/path/to/linux/src/
###    - KASAN_LOG=/path/to/kasan_report.log
set -ex

WORKDIR=${WORKDIR}
KERNEL_SRC=${KERNEL_SRC}
KASAN_LOG=${KASAN_LOG}

DEFAULT_WORKDIR=/workspace
if [ -z ${WORKDIR} ]; then
    echo "[-] Environment var WORKDIR not set! Defaulting to ${DEFAULT_WORKDIR}..."
    WORKDIR=${DEFAULT_WORKDIR}
fi

if [ -z ${KERNEL_SRC} ]; then
    echo "[-] Environment var KERNEL_SRC not set!"
    exit 1
fi

if [ -z ${KASAN_LOG} ]; then
    echo "[-] Environment var KASAN_LOG not set!"
    exit 1
fi

if [[ ! -d ${WORKDIR} ]]; then
    echo "[-] Could not find WORKDIR=${WORKDIR}!"
    exit 2
fi

if [[ ! -d ${KERNEL_SRC} ]]; then
    echo "[-] Could not find KERNEL_SRC=${KERNEL_SRC}!"
    exit 2
fi

if [[ ! -f ${KASAN_LOG} ]]; then
    echo "[-] Could not find KASAN_LOG=${KASAN_LOG}!"
    exit 2
fi

EXPECTED_KASAN=$(realpath ${WORKDIR}/report)
# GREBE/analyzer/run_analyze.py expects the KASAN log to be named
#  @ GREBE/analyzer/report
cp ${KASAN_LOG} ${EXPECTED_KASAN}
echo "[+] Copied ${KASAN_LOG} -> ${EXPECTED_KASAN}"

ANALYZER_BUILD=$(realpath ${WORKDIR}/build)
EXPECTED_BUILD=~/kernel_bugs/Github/syzObjkaller/tools/analyzer
# GREBE/analyzer/run_analyze.py expects GREBE/analyzer/build
#  @ ~/kernel_bugs/Github/syzObjkaller/tools/analyzer
mkdir -p ${EXPECTED_BUILD}
cp -r ${ANALYZER_BUILD} ${EXPECTED_BUILD}
echo "[+] Copied ${ANALYZER_BUILD} -> ${EXPECTED_BUILD}"

EXPECTED_KERNEL=$(realpath ${WORKDIR}/linux-bitcode)
# GREBE/analyzer/run_analyze.py expects the Linux kernel source repo
#  @ GREBE/analyzer/linux-bitcode
rm -rf ${EXPECTED_KERNEL}
cp -r ${KERNEL_SRC} ${EXPECTED_KERNEL}
echo "[+] Copied ${KERNEL_SRC} -> ${EXPECTED_KERNEL}"

#### GREBE/analyzer WORKFLOW BEGIN ####
## 1. Build Kernel bitcode
# Build Linux kernel with custom clang and emit unoptimized LLVM bitcode
echo "[*] Building Linux kernel with custom clang..."
cd ${EXPECTED_KERNEL} && make CC=clang CFLAGS="-O0 -emit-llvm -flto -save-temps"
echo "[+] Output unoptimized LLVM bitcode for Linux kernel."

## 2. Parse call graph from KASAN report
echo "[*] Processing KASAN report..."
cd ${WORKDIR} && python3 get_cg.py ${EXPECTED_KASAN}
echo "[+] Finished processing KASAN log."
EXPECTED_CG=$(realpath ${WORKDIR}/report_cg.txt)
# Expected output is 'report_cg.txt'
if [[ ! -f ${EXPECTED_CG} ]]; then
    echo "[-] get_cg.py failed to produce report_cg.txt from ${EXPECTED_KASAN}!"
    exit 2
fi

## 3. Run GREBE/analyzer providing the kernel bitcode, KASAN log, and call graph
echo "[*] Analyzing kernel bit-code, KASAN log, and call graph..."
cd ${WORKDIR} && python3 run_analyze.py .
echo "[+] Finished analysis."
EXPECTED_OUT=$(realpath ${WORKDIR}/sts.txt)
# Expected output is 'sts.txt'
if [[ ! -f ${EXPECTED_OUT} ]]; then
    echo "[-] run_analyze.py failed to produce ${EXPECTED_OUT}!"
    exit 2
fi
