import re
import sys

# kasan, kmasn, info hang
kasan_pattern = "Call Trace:\n([\s\S]*?)\n(RIP: 00|Allocated by task|===)" # group 0
kasan_pattern2 = "Call Trace:\n([\s\S]*?)\nAllocated by task" # uaf
kasan_pattern3 = "Call Trace:\n([\s\S]*?)\n===" # kasan_null_ptr

# group 0 and 1
kernel_bug = "RIP: 0010:([\s\S]*?)Code[\s\S]*R13:[\s\S]*Call Trace:\n([\s\S]*?)\nModules linked in"

#warn
warn  = "RIP: 0010:([\s\S]*?)RSP[\s\S]*?Call Trace:\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
warn2 = "RIP: 0010:([\s\S]*?)Code[\s\S]*?Call Trace:\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
warn3 = "RIP: 0010:([\s\S]*?)Code[\s\S]*?R13:.*?\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
warn4 = "RIP: 0010:([\s\S]*?)RSP[\s\S]*?R13:.*?\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"

pattern2 = "R13:.*\n([\s\S]*?)Kernel Offset"
pattern3 = "Call Trace:\n([\s\S]*?)\n(Modules linked in| ret_from_fork)"


pattern4 = "RIP: 0010:([\s\S]*)Code[\s\S]*?Call Trace:\n([\s\S]*?)(Kernel Offset|entry_SYSCALL)"

DEBUG=False

def dprint(s):
    if DEBUG:
        print(s)

def get_call_trace(pattern, report):
    p = re.compile(pattern)
    m = p.search(report)
    if not m:
        return None
    trace = m.group(1)
    if "invalid_op" in trace: return None
    if "Code: " in trace: return None
    return m

def get_call_trace2(report):
    p = re.compile(pattern2)
    m = p.search(report)
    if not m:
        return ""
    trace = m.group(1)
    return trace

def get_calls():
    if len(sys.argv) == 1:
        print("%s report"%sys.argv[0])
    report = open(sys.argv[1]).read()
    # print(report)
    # print("Matched....")
    
        
    if "WARNING" in report or "GPF" in report or "kernel BUG at" in report \
            or "BUG: unable to handle" in report:
        found = get_call_trace(warn, report)
        if found:
            # print(found.group(1)+found.group(2))
            return found.group(1)+found.group(2)
        found = get_call_trace(warn2, report)
        if found:
            # print(found.group(1)+found.group(2))
            return found.group(1)+found.group(2)
        found = get_call_trace(warn3, report)
        if found:
            # print(found.group(1)+found.group(2))
            return found.group(1)+found.group(2)
        found = get_call_trace(warn4, report)
        if found:
            # print(found.group(1)+found.group(2))
            return found.group(1)+found.group(2)
    elif "kasan" in report:
        found = get_call_trace(kasan_pattern, report)
        if found:
            # print(found.group(1))
            return found.group(1)
        found = get_call_trace(kasan_pattern2, report)
        if found:
            # print(found.group(1))
            return found.group(1)
        found = get_call_trace(kasan_pattern3, report)
        
    # else:
        # print("not a kasan report and a WARNING")
        # return ""
    found = get_call_trace(pattern3, report)
    if found:
        return found.group(1)
    found = get_call_trace(pattern4, report)
    if found:
        return found.group(1) + found.group(2)
    return ""

def get_cg():
    cgs = ""
    calls = get_calls()

    dprint(calls)

    for call in calls.split("\n"):
        if call.startswith("RIP"):
            call = call.split("RIP: 0010:")[1]
        cc = call.strip().split(" ")
        if len(cc) < 2:
            dprint("skipping "+str(cc))
            continue
        function = cc[0].split("+")[0].split(".")[0]
        source = cc[1]

        if ":" not in source:
            continue

        assert(function != "")
        assert(source != "")
        cgs += function+" "+source+"\n"
    return cgs

if __name__ == "__main__":
    outs = get_cg()
    print(outs)
    open(sys.argv[1]+"_cg.txt", "w").write(outs)