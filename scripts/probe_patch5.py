p1 = r'd:\Agent44\scripts\apply_eval_runner_edits.py'
p2 = r'd:\Agent44\src\agent44\eval_runner.py'
s1 = open(p1, encoding='utf-8').read()
s2 = open(p2, encoding='utf-8').read()
i = s1.find('r6_old = """')
k = s1.find('"""', i + len('r6_old = """'))
r6_old = s1[i + len('r6_old = """'):k]
m = s2.find('            evaluate(')
n = s2.find('adapter_replay=args.adapter_replay,', m)
o = s2.find('bootstrap_seed=args.seed,', n)
p = s2.find('\n', o)
print('SCRIPT R6_OLD LEN:', len(r6_old))
print('FILE CALL LEN:', p - m)
for cnt in range(min(len(r6_old), p - m)):
    if r6_old[cnt] != s2[m + cnt]:
        print('FIRST DIFF at', cnt)
        print('  script:', repr(r6_old[max(0, cnt - 20):cnt + 40]))
        print('  file :', repr(s2[m + cnt - 20:p - 20 + 40]))
        break
else:
    print('NO DIFF until min length')
    print('script len:', len(r6_old), 'file len:', p - m)
    if len(r6_old) != p - m:
        print('script tail repr:', repr(r6_old[min(len(r6_old), p - m):]))
        print('file tail repr:', repr(s2[p - 12:p + 20]))
