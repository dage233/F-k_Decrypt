import math


def ex_gcd(a, b):
    """
    扩展欧几里得
    """
    if b == 0:
        return 1, 0
    else:
        k = a // b
        remainder = a % b
        x1, y1 = ex_gcd(b, remainder)
        x, y = y1, x1 - k * y1
    return x, y


def fast_expmod(b, e, m):
    """
    快速幂
    """
    result = 1
    while e != 0:
        if (e & 1) == 1:
            # ei = 1, then mul
            result = (result * b) % m
        e >>= 1
        # b, b^2, b^4, b^8, ... , b^(2^n)
        b = (b * b) % m
    return result


def make_key(p, q, e):
    """
    生成公钥和密钥
    """
    n = p * q
    fin = (p - 1) * (q - 1)
    if math.gcd(e, fin) != 1:
        print("math.gcd(e, fin)==", math.gcd(e, fin), "!=1,需要选择其他e")
    d = ex_gcd(e, fin)[0]
    while d < 0:
        d = (d + fin) % fin
    print("###密钥制作###")
    print("p,q,n,fin,d:", p, q, n, fin, d)
    return [[n, e], [n, d]]


def encryption(key, data):
    """
    加密
    """
    n, e = key
    data = list(data)
    out = []
    for i in data:
        out.append(fast_expmod(ord(i), e, n))
    return out


def decrypt(key, data):
    """
    解密
    """
    n, d = key
    data = data
    out = ''
    for i in data:
        out += (chr(fast_expmod(i, d, n)))
    return out


# p=33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489
# q=36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917
# e=65537

p = 17
q = 3599
e = 31

public_key, private_key = make_key(p, q, e)

Plaintext = chr(88)
print('公钥:', public_key)
print('公钥:', private_key)
print('明文:', Plaintext)
ciphertext = encryption(public_key, Plaintext)
print('密文:', ciphertext)
Plaintext2 = decrypt(private_key, ciphertext)
print('解密明文:', Plaintext2)

exit(0)
