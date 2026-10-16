p = r'd:\Agent44\scripts\apply_eval_runner_edits.py'
s = open(p, encoding='utf-8').read()
old = '''        )
"""
'''

new = '''            )
        )
"""
'''
assert s.count(old) == 1
s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
print('fixed r6 closing')