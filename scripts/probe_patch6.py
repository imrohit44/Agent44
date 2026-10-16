p1 = r'd:\Agent44\scripts\apply_eval_runner_edits.py'
p2 = r'd:\Agent44\src\agent44\eval_runner.py'
s1 = open(p1, encoding='utf-8').read()
s2 = open(p2, encoding='utf-8').read()
i = s1.find('r6_old = """')
k = s1.find('"""', i + 1)
r6_old = s1[i + len('r6_old = """'):k]
m = s2.find('            evaluate(')
n = s2.find('adapter_replay=args.adapter_replay,', m)
o = s2.find('bootstrap_seed=args.seed,', n)
p = s2.find('\n', o)
print('SCRIPT R6_OLD (first 200 chars):')
print(repr(r6_old[:200]))
print()
print('FILE CALL (first 200 chars):')
print(repr(s2[m:m + 200]))
