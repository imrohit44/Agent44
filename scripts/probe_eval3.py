import sys

path = r"d:\Agent44\src\agent44\eval_runner.py"
with open(path, encoding="utf-8") as fh:
    lines = fh.readlines()

chunk = "".join(lines[987:992])
print("CHUNK REPR:")
print(repr(chunk))
print()
r1_old = """    ``select_ids`` further bounds the run to an explicit scenario-id subset
    (a bounded pilot). Every id must exist and belong to ``partition`` or the
    run fails closed through :func:`select_cases` before any subprocess,
    proxy, or model call; the resolved ids are recorded in the report under
    ``partition_selection.explicit_selection``.
"""
print("SCRIPT OLD REPR:")
print(repr(r1_old))
print()
print("EQUAL:", chunk == r1_old)