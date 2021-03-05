### RSA算法
#
没啥大用,以前学习RSA时的代码,懒得删了

这个代码主要分六块

## 1

```python
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
```
## 2
这个是扩展欧几里得的代码 输入a,b 得到一组x,y使得ax+by=gcd(a,b)
```python
def make_key(p,q,e):
    """
    生成公钥和密钥
    """
    n=p*q
    fin=(p-1)*(q-1)
    d=ex_gcd(e,fin)[0]
    while d<0:
        d=(d+fin)%fin
    return [[n,e],[n,d]]

```
## 3
这个是获得公钥和密钥的代码,输入p,q,e 返回两个两个列表 形式为[[n,e],[n,d]]
```python
def make_key(p,q,e):
    """
    生成公钥和密钥
    """
    n=p*q
    fin=(p-1)*(q-1)
    d=ex_gcd(e,fin)[0]
    while d<0:
        d=(d+fin)%fin
    return [[n,e],[n,d]]

```
## 4
加密算法 输入字符串 返回一个密文密钥的列表
```python
def encryption(key,data):
    """
    加密
    """
    n,e=key
    data=list(data)
    out=[]
    for i in data:
        out.append(fastExpMod(ord(i),e,n))
    return out

```
## 5
解密算法 输入一个密文密钥列表(4的输出) 输出对应的明文
```python
def Decrypt(key,data):
    """
    解密
    """
    n,d=key
    data=data
    out=''
    for i in data:
        out+=(chr(fastExpMod(i,d,n)))
    return out

```
## 6
测试代码 其中p,q,e可以任意修改
```python
p=33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489
q=36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917
e=65537

public_key,private_key=make_key(p,q,e)

Plaintext='Hello World!'
print('明文:',Plaintext)
ciphertext=encryption(public_key,Plaintext)
print('密文:',ciphertext)
Plaintext2=Decrypt(private_key,ciphertext)
print('解密明文:',Plaintext2)

exit(0)
```