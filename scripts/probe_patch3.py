p1 = r'd:\Agent44\scripts\apply_eval_runner_edits.py'
p2 = r'd:\Agent44\src\agent44\eval_runner.py'
s1 = open(p1, encoding='utf-8').read()
s2 = open(p2, encoding='utf-8').read()
i = s1.find('r6_old')
j = s1.find('r6_new')
r6_old = s1[i:j].split('r6_new')[0].rsplit('"""', 1)[1]
print('SCRIPT R6_OLD REPR:')
print(repr(r6_old))
print('COUNT IN FILE:', s2.count(r6_old))
