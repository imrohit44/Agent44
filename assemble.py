import io


def rd(name):
    return io.open(name, encoding="utf-8").read().splitlines(keepends=True)


def rw(name, text):
    io.open(name, "w", encoding="utf-8").write(text)


# bench_S3a: drop the premature tuple-closing ')' (bench_S3b continues the tuple).
s3a = rd("bench_S3a.py")
assert s3a[-1].strip() == ")", s3a[-1]
s3a = s3a[:-1]

# bench_S5: drop the dead 'resolve_extension_case' dispatcher (lines 79-86).
s5 = rd("bench_S5.py")
out_s5 = []
skip = False
for i, line in enumerate(s5, 1):
    if i == 79:
        skip = True
    if skip and i == 86:
        skip = False
        continue
    if not skip:
        out_s5.append(line)

parts = [
    rd("bench_S1.py"),
    rd("bench_S2.py"),
    s3a,
    rd("bench_S3b.py"),
    rd("bench_S4.py"),
    out_s5,
    rd("bench_S6a.py"),
    rd("bench_S6b.py"),
    rd("bench_S7a.py"),
    rd("bench_S7b.py"),
    rd("bench_S8.py"),
    rd("bench_S9a.py"),
    rd("bench_S9b.py"),
]
out = "".join(x for p in parts for x in p)
rw("src/agent44/benchmark.py", out)
print("written", out.count("\n") + 1, "lines")
