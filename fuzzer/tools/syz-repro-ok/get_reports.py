#!/usr/bin/env python3
import sys
import urllib2
import os
from bs4 import BeautifulSoup
import json

# bug_id = sys.argv[1]
# WRITE  = sys.argv[2] if len(sys.argv) > 2 else ''
# target = 'https://syzkaller.appspot.com/bug?id='+str(bug_id)
syzbot_fix = "https://syzkaller.appspot.com/upstream/fixed"
syzbot_invaild = "https://syzkaller.appspot.com/upstream/invalid"

content = urllib2.urlopen(syzbot_fix).read()
content_invaild = urllib2.urlopen(syzbot_invaild).read()

soup = BeautifulSoup(content, 'html.parser')

list_tables = soup.find_all(class_='list_table')

bugs = {}

for table in list_tables:
    trs = table.find_all('tr')
    for tr in trs:
        info = tr
        # print(info)
        # import ipdb; ipdb.set_trace()
        title = info.find(class_='title')
        if not title:
            continue
        bugID = title.a['href'].split("id=")[1]
        title = title.text.strip()
        patch = info.find(class_="mono")
        # print(patch)
        if not patch:
            continue
        patchID = patch.text.strip().split(" ")
        if len(patchID) == 0:
            continue
        patchID = patchID[0]
        if not patch.a:
            continue
        patchMsg = patch.a.contents[0]
        patch = patch.a['href']
        key_info = {
            "title" : title,
            "patch" : patch,
            "patch_id" : patchID,
            "patch_msg" : patchMsg,
        }
        bugs[bugID] = key_info

if len(sys.argv) > 1:
    open(sys.argv[1], 'w').write(json.dumps(bugs))
else:
    open("fixed_bugs.db",'w').write(json.dumps(bugs))

soup = BeautifulSoup(content_invaild, 'html.parser')
list_tables = soup.find_all(class_='list_table')

invalids = []
for table in list_tables:
    trs = table.find_all('tr')
    for tr in trs:
        title = tr.find(class_='title')
        if not title:
            continue
        title = title.text.strip()
        invalids.append(title)
open("invalid_bugs.db", 'w').write(json.dumps(invalids))

