import sys

path = r"d:\Agent44\src\agent44\eval_runner.py"
with open(path, encoding="utf-8") as fh:
    lines = fh.readlines()

for idx in range(1472, 1490):
    print(idx + 1, repr(lines[idx]))