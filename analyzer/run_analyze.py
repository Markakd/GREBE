import sys
import re
import os
import shutil

pattern1 = "BUG: KASAN: global-out-of-bounds in ([\s\S]*?)\n"
pattern2 = "BUG: KASAN: slab-out-of-bounds in ([\s\S]*?)\n"
pattern3 = "BUG: KASAN: use-after-free in ([\s\S]*?)\n"

patterns = [pattern1, pattern2, pattern3]

pattern_kasan = "BUG: KASAN:([\s\S]*?)in ([\s\S]*?)\n"
pattern_general = "RIP:([\s\S]*?):([\s\S]*?)\n"

def main():
    if len(sys.argv) == 1:
        print("%s report"%sys.argv[0])
    
    report = open(sys.argv[1]).read()

    explicity = True

    if ("WARNING" in report and "do_invalid_op" in report) or "kernel BUG at" in report:
        explicity = False

    # find crash location

    if "BUG: KASAN" not in report:
        p = re.compile(pattern_general)
        m = p.search(report)

    else:
        # for pp in patterns:
        #     p = re.compile(pp)
        #     m = p.search(report)
        #     if m: break
        p = re.compile(pattern_kasan)
        m = p.search(report)
    assert(m and "Did not find crash location")
    print("explicity? "+str(explicity))
    print(m.group(2))

def run_case(case_path):
    # get source file
    cgs = open(case_path+"/report_cg.txt", "r").read()
    sources = ""
    for cc in cgs.split("\n"):
        if not cc.strip(): continue
        source = cc.split(" ")[1].split(":")[0]
        if source.endswith(".h"): continue
        sources += case_path+"/linux-bitcode/"+source+".bc "

    cmd = "~/kernel_bugs/Github/syzObjkaller/tools/analyzer/build/lib/analyzer "
    cmd += "--crash-report="+case_path+"/report "
    cmd += "--call-graph="+case_path+"/report_cg.txt "
    if len(sys.argv) == 4:
        cmd += "`find "+case_path+"/linux-bitcode -name \"*.bc\"`"
    else:
        cmd += sources
    if len(sys.argv) > 2:
        cmd += "--debug-verbose=3"
    print("executing %s\n"%(cmd))

    os.system(cmd)
    shutil.copyfile("/tmp/ca_result", case_path+"/sts.txt")

if __name__ == "__main__":
    run_case(sys.argv[1])
