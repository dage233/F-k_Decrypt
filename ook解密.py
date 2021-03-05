global cs
global ip

global ss
# global sp

global ds
global bp

global tab
global out

lookup = {
    '.?': '>',
    '?.': '<',
    '..': '+',
    '!!': '-',
    '!.': '.',
    '.!': ',',
    '!?': '[',
    '?!': ']',
}

str = '''..... ..... ..... ..... !?!!. ?.... ..... ..... ..... .?.?! .?... .!...
..... ..... !.?.. ..... !?!!. ?!!!! !!?.? !.?!! !!!.. ..... ..... .!.?.
..... ...!? !!.?. ..... ..?.? !.?.. ..... .!.?. ..... ..... !?!!. ?!!!!
!!!!! !?.?! .?!.? ..... ....! ?!!.? ..... ...?. ?!.?. ..... !.?.. .....
!?!!. ?!!!! !!?.? !.?!! !!!!! !!!!. ..... ...!. ?.... ...!? !!.?. .....
?.?!. ?..!. ?.... ..... !?!!. ?!!!! !!!!? .?!.? !!!!! !!!!! !!!.? .....
..!?! !.?.. ....? .?!.? ....! .!!!. !!!!! !!!!! !!!!! !!.?. ..... .!?!!
.?... ...?. ?!.?. ..... !.!!! !!!!! !.?.. ..... ..!?! !.?.. ..... .?.?!
.?... ..... !.?.'''

str2 = str.replace('\n', '').replace('Ook','').replace(' ','')
lenth = len(str2)
cs=''
for i in range(0,lenth,2):
    cs+=lookup[str2[i]+str2[i+1]]
print(str2)

ip = 0

ss = []
# sp = 0

ds = []
bp = 0

tab = 0
out = []


def tab_():
    i = tab
    stab = ''
    while i > 0:
        stab += '\t'
        i -= 1
    return stab


def push(var):
    global ss
    ss.append(var)


def pop():
    global ss
    return ss.pop()


def op_inc_val():
    global ip
    count = 0
    while True:
        op = cs[ip]
        ip = ip + 1
        if op == '+':
            count = count + 1
        else:
            break
    l = len(ds)
    if l <= bp:
        ds.append(0)
    old = ds[bp]
    old += count
    ds[bp] = old
    print(tab_() + 'ds[%d] += %d                  (%d)' % (bp, count, old))


def op_dec_val():
    global ip
    count = 0
    while True:
        op = cs[ip]
        ip = ip + 1
        if op == '-':
            count = count + 1
        else:
            break
    old = ds[bp]
    old -= count
    ds[bp] = old
    print(tab_() + 'ds[%d] -= %d                  (%d)' % (bp, count, old))


def op_inc_dp():
    global bp
    bp = bp + 1


def op_dec_dp():
    global bp
    bp = bp - 1


def op_jmp_fwd():
    global tab
    global ip
    print(tab_() + 'while ds[%d]=%d:' % (bp, ds[bp]))
    tab = tab + 1
    if ds[bp] != 0:
        curip = ip - 1
        push(curip)
    else:
        c = 1;
        while c > 0:
            op = cs[ip]
            if op == '[':
                c += 1
            elif op == ']':
                c -= 1
            ip += 1


def op_jmp_bck():
    global tab
    global ip
    tab = tab - 1
    if ds[bp] != 0:
        ip = pop()


def op_out():
    print(tab_() + 'putchar(ds[%d])                  (%d)' % (bp, ds[bp]))
    out.append(ds[bp])


def op_in():
    print(tab_() + 'getchar')


end = len(cs)
while ip < end:
    op = cs[ip]
    ip = ip + 1
    if op == '+':
        ip = ip - 1
        op_inc_val()
        ip = ip - 1
    elif op == '-':
        ip = ip - 1
        op_dec_val()
        ip = ip - 1
    elif op == '>':
        op_inc_dp()
    elif op == '<':
        op_dec_dp()
    elif op == '[':
        op_jmp_fwd()
    elif op == ']':
        op_jmp_bck()
    elif op == '.':
        op_out()
    elif op == ',':
        op_in()
    else:
        print('invalid opcode')
        break

print(out)
str = ''
for c in out:
    str += '%c' % (c)
print(str)
