import sys
path = r"d:\Agent44\src\agent44\eval_runner.py"
with open(path, "r", encoding="utf-8") as fh:
    src = fh.read()

old = """    ``select_ids`` further bounds the run to an explicit scenario-id subset
    (a bounded pilot). Every id must exist and belong to ``partition`` or the
    run fails closed through :func:`select_cases` before any subprocess,
    proxy, or model call; the resolved ids are recorded in the report under
    ``partition_selection.explicit_selection``.
    """
print("found:", old in src)
if old in src:
    idx = src.index(old)
    print(repr(src[idx - 60:idx + len(old) + 40]))