import io
import sys

sys.path.insert(0, "src")

from agent44 import corpus  # noqa: E402

# Read the default selection ids from the benchmark module (source-level dump).
src = io.open("src/agent44/benchmark.py", encoding="utf-8").read()
start = src.find("def _default_selection()")
end = src.find("def main(", start)
body = src[start:end]
# Extract the tuple literal of ids.
tu = body[src.find("ids = ("):]
tu = tu[: tu.rfind(")") + 1]
import ast as _ast

ids = [e.value for e in _ast.parse(tu).body[0].value.elts]
print("default_selection_count =", len(ids))
assigned = corpus.partition_map()
for sid in ids:
    if sid not in assigned:
        print("MISSING from development partition:", sid)
print("all_selected_in_development =", all(s in assigned for s in ids))
