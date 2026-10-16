import sys
path = r"d:\Agent44\src\agent44\eval_runner.py"
with open(path, "r", encoding="utf-8") as fh:
    lines = fh.readlines()
for idx in range(983, 998):
    print(idx + 1, repr(lines[idx]))