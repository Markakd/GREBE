import sys

def build_map(files):
    content = ""
    with open(files) as f:
        content = f.read()

    keys = {}
    data = content.split("\n")
    for i in data:
        if not i: continue
        # print(i)
        a, b = i.split(" ")
        # print(a)
        # print(b)
        keys[int(b)] = a

    return keys

def process_ranks(files):
    content = ""
    with open(files) as f:
        content = f.read()
    
    keys = {}
    data = content.split("\n")
    for i in data:
        # print(i)
        if "s" in i or not i: continue
        a, b = i.split(" = ")
        keys[int(a)] = float(b)
    return keys

if __name__ == "__main__":
    keys = build_map(sys.argv[1])
    ranks = process_ranks(sys.argv[2])

    # sorted_rank = {k: v }
    for k, v in sorted(ranks.items(), key=lambda item: item[1]):
        print(str(keys[k]) + " = " + str(v))

    #print
    # for k, v in sorted_rank.items():
    #     print(str(keys[k]) + " = " + str(v))
