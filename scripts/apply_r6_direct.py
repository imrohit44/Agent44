p = r'd:\Agent44\src\agent44\eval_runner.py'
with open(p, encoding='utf-8') as fh:
    src = fh.read()

anchor_start = 'evaluate(\n'
anchor_end = 'bootstrap_seed=args.seed,\n'
i = src.find(anchor_start)
j = src.find(anchor_end, i)
assert i != -1 and j != -1, 'evaluate call anchors not found'
k = src.find('\n', j)
block = src[i:k]
print('CURRENT BLOCK:')
print(repr(block))
print()
new_block = block.replace(
    anchor_end,
    anchor_end + '            adapter_deadline=args.adapter_deadline,\n',
    1,
)
print('NEW BLOCK:')
print(repr(new_block))
print()
src2 = src.replace(block, new_block, 1)
assert src2.count(new_block) == 1
with open(p, 'w', encoding='utf-8') as fh:
    fh.write(src2)
print('R6 APPLIED')
