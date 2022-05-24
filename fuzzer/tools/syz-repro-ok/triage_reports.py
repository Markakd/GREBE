import json
import os
import sys

fixed_bugs_db = "fixed_bugs.db"
invalid_bugs_db = "invalid_bugs.db"

def get_crash_descs(workdir):
    descs = []
    crashes = os.path.join(workdir, "crashes")
    for crash in os.listdir(crashes):
        cc = os.path.join(crashes, crash)
        desc = open(os.path.join(cc, "description")).read().strip()
        if desc in ["panic: no result", "panic: disabled syscall",
                    "lost connection to test machine"]:
            continue
        if "panic: runtime error: index" in desc:
            continue
        descs.append((crash,desc))
    return descs

def is_fixed(desc, fixed_bugs):
    for bug_id in fixed_bugs:
        if desc in fixed_bugs[bug_id]['title']:
            return fixed_bugs[bug_id]
    return None

def is_invalid_bug(desc, invalids):
    for title in invalids:
        if desc in title:
            return True
    return False

if __name__ == "__main__":

    show_path = True

    if len(sys.argv) == 1:
        print("Usage: %s workdir"%(sys.argv[0]))
        exit(0)
    
    if len(sys.argv) == 3 and sys.argv[2] == "hide-path":
        show_path = False
    
    workdir = sys.argv[1]
    descs = get_crash_descs(workdir)

    fixed_bugs = json.loads(open(fixed_bugs_db).read())
    invalids   = json.loads(open(invalid_bugs_db).read())

    unknown = []
    fixed   = []
    invalid = []


    for i in descs:
        desc = i[1]
        patch = is_fixed(desc, fixed_bugs)
        if patch:
            fixed.append(i)
        elif is_invalid_bug(desc, invalids):
            invalid.append(i)
        else:
            unknown.append(i)
    
    if show_path:
        print(workdir)

    if len(fixed) != 0:
        print("Fixed:")
    for i in fixed:
        patch_info = is_fixed(i[1], fixed_bugs)
        if patch_info['patch_id'] in workdir:
            print(i[0]+", "+i[1]+", same bug here!!!,"+patch_info['patch'])
        else:
            print(i[0]+", "+i[1]+",,"+patch_info['patch'])
        

    if len(invalid) != 0:
        print("\nInvalid:")
    for i in invalid:
        print(i[0]+", "+i[1])

    if len(unknown) != 0:
        print("\nUnknown:")
    for i in unknown:
        print(i[0]+", "+i[1])

    print("\n\n")



