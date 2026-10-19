import io

def rd(name):
    return io.open(name, encoding="utf-8").read().splitlines(keepends=True)

def rw(name, text):
    io.open(name, "w", encoding="utf-8").write(text)

s3a = rd("tmp_bench_S3a.py")
assert s3a[-1].strip() == ")", "unexpected S3a tail"
s3a = s3a[:-1]

s5 = rd("tmp_bench_S5.py")
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

parts = [rd("tmp_bench_S1.py"), rd("tmp_bench_S2.py"), s3a, rd("tmp_bench_S3b.py"), rd("tmp_bench_S4.py"), out_s5, rd("tmp_bench_S6a.py"), rd("tmp_bench_S6b.py"), rd("tmp_bench_S7.py"), rd("tmp_bench_S8.py"), rd("tmp_bench_S9a.py"), rd("tmp_bench_S9b.py"), rd("tmp_bench_S9c.py")]
out = "".join(x for p in parts for x in p)
rw("src/agent44/benchmark.py", out)
print("written", out.count("\n") + 1, "lines")
