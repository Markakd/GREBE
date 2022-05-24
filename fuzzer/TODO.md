## TODOs
[x] mutation algo for mutating poc
[x] collect object coverage and filter necessary input during triaging
[x] collect syscalls that have the same object coverage as others, but are new to corpus
[x] generate proc using the syscalls from the corpus
[ ] design a new mutation algo for mutating poc. e.g. vary the resource use and resource generating syscall, letting the triage process find out the system calls that cover the objects.

original syzkaller commit : 196277c4035b5442b7a259953677543566c9b9a9
