---
title: hgame2020 week2 wp
date: 2020-07-15 10:36:53
tags: hgame
---

# web

本来打算往web方向做，但是，这周的web题我一题都没做出来。。。





# pwn

别问，问就是菜

# re

## babypyc

这里的pyc不能直接用uncompyle6等工具反编译，但可以用marshal读取字节码。一开始不会用marshal，感谢Lurkrul大佬。
根据字节码写出来源码大概长这样

```python
O0o = '/KDq6pvN/LLq6tzM/KXq59Oh/MTqxtOTxdrqs8OoR3V1X09J'
O0o = b'QreZoJSeWr2ioJN4cXhvvNO8f4mfqKDtrrftpI/JZ1JvRV9Q'
flag = getflag()

raw_flag = flag[6:-1]
if len(flag) -7 != 36:
    print('Wrong length')
else:   
    raw_flag = raw_flag[::-1]
    ciphers = [[raw_flag[6*row+col] for row in range(6)] for col in range(6)]#第6，12。。   7，14.。。。 8，16.。。
    for row in range(5):
        for col in range(6):
                ciphers[row][col] += ciphers[row+1][col]
                ciphers[row][col] %= 256
    cipher = ''
    for row in range(6):
        col = 0
        while col < 6:
            cipher += bytes([ciphers[row][col]])
            col += 1

b64encode(cipher)
```

exp:

```python
import base64

O0o = b'QreZoJSeWr2ioJN4cXhvvNO8f4mfqKDtrrftpI/JZ1JvRV9Q'
a = base64.b64decode(O0o)
x = [[a[i + 6 *j] for i in range(6)] for j in range(6)]

for i in range(1, 6):
    for j in range(6):
        x[5 - i][j] = x[5 - i][j] - x[6 - i][j]
        if x[5 - i][j] < 0:
            x[5 - i][j] += 256
s = []
for i in range(6):
    for j in range(6):
        s.append(x[j][i])

s = bytes(s).decode()
print('hgame{' + s[::-1] + '}')
```

>hgame{PytH0n_0pc0dE_Is-so~!NTERe$TiNgG89!!}




## crackme

好像是用c#写的东西，用jetbrains的dotpeek反编译。发现是关于aes加密的
主要就是CBC模式的特点。

```python
import base64
from Crypto.Cipher import AES

r = AES.new(base64.b64decode('SGc0bTNfMm8yMF9XZWVLMg=='), AES.MODE_CBC, base64.b64decode('MFB1T2g5SWxYMDU0SWN0cw=='))
t = AES.new(base64.b64decode('SGc0bTNfMm8yMF9XZWVLMg=='), AES.MODE_ECB)
a1 = base64.b64decode('mjdRqH4d1O8nbUYJk+wVu3AeE7ZtE9rtT/8BA8J897I=')
a2 = 'MFB1T2g5SWxYMDU0SWN0cw=='
a3 = 'dJntSWSPWbWocAq4yjBP5Q=='#密文分组2
def xor(s1, s2):
    #assert len(s1)==len(s2)
    return bytes( map( (lambda x: x[0]^x[1]), zip(s1, s2) ) )

s1 = a1[:16]
s2 = a1[16:]
s2 = t.decrypt(s2)
s1 = t.decrypt(s1)

s3 = b'Same_ciphertext_'
text1 = base64.b64encode(xor(s1, s3)).decode()

s4 = r.encrypt(s3)#密文分组1
s5 = t.decrypt(base64.b64decode(a3))
text2 = xor(s5, s4).decode()

print('hgame{' + text1+text2 + '}')

```

>hgame{L1R5WFl6UG5ZOyQpXHdlXw==DiFfer3Nt_w0r1d}



## babyPy

python字节码
翻译过来大概长这样

```python
import dis

def foo(flag):
    O0O = flag[::-1]
    O0o = list(O0O)
    for O0 in range(1, len(O0o)):
        Oo = O0o[O0 - 1] ^ O0o[O0]
        O0o[O0] = Oo
    O = bytes(O0o)
    O.hex()
dis.dis(foo)
```

```python
s = '7d037d045717722d62114e6a5b044f2c184c3f44214c2d4a22'
s = [0x7d, 0x03, 0x7d, 0x04, 0x57, 0x17, 0x72, 0x2d, 0x62, 0x11, 0x4e]
s += [0x6a, 0x5b, 0x04, 0x4f, 0x2c, 0x18, 0x4c, 0x3f, 0x44, 0x21, 0x4c]
s += [0x2d, 0x4a, 0x22]
b = '}'
for i in range(1, len(s)):
    a = s[i - 1] ^ s[i]
    b += chr(a)

print(b[::-1])
```

>hgame{sT4cK_1$_sO_e@Sy~~}




## unpack

按照群里的资料脱壳
再用ida打开

```python
s = [0x68 ,0x68, 0x63, 0x70, 0x69, 0x80, 0x5b, 0x75, 0x78, 0x49, 0x6d]
s += [0x76, 0x75, 0x7b, 0x75, 0x6e, 0x41, 0x84, 0x71, 0x65, 0x44]
s += [0x82, 0x4a, 0x85, 0x8c, 0x82, 0x7d, 0x7a, 0x82, 0x4d, 0x90]
s += [0x7e, 0x92, 0x54, 0x98, 0x88, 0x96, 0x98, 0x57, 0x95, 0x8f, 0xa6]
for i in range(42):
    print(chr(s[i] - i), end='')
```

>hgame{Unp@cking_1s_R0m4ntic_f0r_r3vers1ng}


# crypto

## Remainder

中国剩余定理在rsa方面的应用 (啥也不懂，套公式公式就完事儿了)

```python
from Crypto.Util import number
import gmpy2

x = 78430786011650521224561924814843614294806974988599591058915520397518526296422791089692107488534157589856611229978068659970976374971658909987299759719533519358232180721480719635602515525942678988896727128884803638257227848176298172896155463813264206982505797613067215182849559356336015634543181806296355552543
y = 49576356423474222188205187306884167620746479677590121213791093908977295803476203510001060180959190917276817541142411523867555147201992480220531431019627681572335103200586388519695931348304970651875582413052411224818844160945410884130575771617919149619341762325633301313732947264125576866033934018462843559419
z = 48131077962649497833189292637861442767562147447040134411078884485513840553188185954383330236190253388937785530658279768620213062244053151614962893628946343595642513870766877810534480536737200302699539396810545420021054225204683428522820350356470883574463849146422150244304147618195613796399010492125383322922
e = 65537
p = 94598296305713376652540411631949434301396235111673372738276754654188267010805522542068004453137678598891335408170277601381944584279339362056579262308427544671688614923839794522671378559276784734758727213070403838632286280473450086762286706863922968723202830398266220533885129175502142533600559292388005914561
q = 150088216417404963893679242888992998793257903343994792697939121738029477790454833496600101388493792476973514786401036309378542808470513073408894727406158296404360452232777491992630316999043165374635001806841520490997788796152678742544032835808854339130676283497122770901196468323977265095016407164510827505883
r = 145897736096689096151704740327665176308625097484116713780050311198775607465862066406830851710261868913835866335107146242979359964945125214420821146670919741118254402096944139483988745450480989706524191669371208210272907563936516990473246615375022630708213486725809819360033470468293100926616729742277729705727

M = p*q*r
Mp = q*r
Mq = p*r
Mr = p*q
tp = gmpy2.invert(Mp, p)
tq = gmpy2.invert(Mq, q)
tr = gmpy2.invert(Mr, r)
c = x*tp*Mp + y*tq*Mq + z*tr*Mr #c=pow(m,e,M)

phin = (p-1)*(q-1)*(r-1)
d = gmpy2.invert(e, phin)
print(number.long_to_bytes(pow(c,d,M)).decode())
```

运行结果为

>1hAyuFoOUCamGW9BP7pGKCG81iSEnwAOM8x
>********** DO NOT GUESS ME ********
>hg In number theory, 
>am the Chinese 
>e{ remainder theorem 
>Cr states that if one
>T_  knows the 
>w0 remainders of the 
>Nt Euclidean division
>+6  of an integer n 
>Ot by several 
>h3 integers, then 
>R_ YOU CAN FIND THE 
>mE FLAG, ;D
>!! 
>!} 
>********** USE YOUR BRAIN *********
>cbl8KukOPUvpoe1LCpBchXHJTgmDknbFE2z

>hgame{CrT_w0Nt+6Oth3R_mE!!!}




## Verification_code

sha256
签到题，暴力穷举即可

```python
import os, sys, signal
import string, random
from hashlib import sha256

a = 'H3VPl1mQutHB3NZG'
res = 'e9872a762c9c35c32efc4a1bc935fa8cd0e48e7b70ca27ea50392a546e892f59'
s = string.ascii_letters + string.digits
for i in s:
    for j in s:
        for k in s:
            for l in s:
                cmp = i + j + k + l + a
                if sha256(cmp.encode()).hexdigest() == res:
                    print(cmp)
```

![](https://r3n0.top/wp-content/uploads/2020/04/week2-1.png)



# misc

## 所见即为假

下载得到一个压缩文件，双击就解压了（mac上直接就解压了，后来在Windows上打开发现需要密码，是伪加密），解压后是一张图片，名字是flag in picture
用010editor打开压缩包
![](https://r3n0.top/wp-content/uploads/2020/04/week2-2.png)
发现这么一串东西

百度一通，发现有个叫f5隐写的东西
下载使用工具
![](https://r3n0.top/wp-content/uploads/2020/04/week2-3.png)

![](https://r3n0.top/wp-content/uploads/2020/04/week2-4.png)
得到一串字符，看起来像是16进制
![](https://r3n0.top/wp-content/uploads/2020/04/week2-5.png)



## 地球上最后的夜晚

打开压缩包，里面是一个加密的压缩包和一个pdf，pdf名字是no password
这里是pdf隐写，用wbs43open提取内容，no password的意思是提取的时候不用密码
得到压缩文件的密码
![](https://r3n0.top/wp-content/uploads/2020/04/week2-6.png)
解压后是一个word
这里可以改成zip格式，打开看到很多文件，在其中一个文件里找到flag
![](https://r3n0.top/wp-content/uploads/2020/04/week2-7.png)


## Cosmos的午餐

又是wireshark，这次又多了个log文件
打开发现都是tcp，只有一个http并且里面只能看到一个crt文件
百度一番发现要导入log文件
多出了很多http，导出
找到那个最大的文件，改格式解压，根据题目提示找到详细信息

> Key: gUNrbbdR9XhRBDGpzz

然后看到图片名字，使用outguess解密得到一个网址
打开后下载了一个文件，是个二维码，扫码即得flag

>hgame{ls#z^$7j%yL9wmObZ#MKZKM7!nGnDvTC}

## 玩玩条码

视频隐写，用MSU StegoVideo提取到7z密码
打开是一个条形码，扫码得flag

>hgame{9h7epp1fIwIL3fOtsOAenDiPDzp7aH!7}

- 那么那个JPNPostCode是干嘛的？？？