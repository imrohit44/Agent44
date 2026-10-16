p1 = r'd:\Agent44\scripts\apply_eval_runner_edits.py'
p2 = r'd:\Agent44\scripts\patch_apply_script.py'
s1 = open(p1, encoding='utf-8').read()
s2 = open(p2, encoding='utf-8').read()
i = s1.find('r6_old')
j = s2.find('old =')
k = s2.find('new =')
old = s2[j + 5:k]
print('PATTERN REPR:', repr(old))
print('COUNT IN TARGET:', s1.count(old))
