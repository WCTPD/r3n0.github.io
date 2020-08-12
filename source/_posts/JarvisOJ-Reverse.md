---
title: JarvisOJ Reverse
date: 2020-07-25 13:32:56
tags: JarvisOJ
categories: Reverse
---

# Smali

[smali语法学习](https://wiki.x10sec.org/android/basic_operating_mechanism/java_layer/smali/smali/)

将smali翻译成Java

```java
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.spi.DirStateFactory.Result;

public class Crackme extends Object {

    private String str2;

    public Crackme () {
        super();
        String v0 = "cGhyYWNrICBjdGYgMjAxNg==";
        this.str2 = v0;
        v0 = "sSNnx1UKbYrA1+MOrdtDTA==";
        this.GetFlag(v0);
    }

    private String GetFlag(String str) {
        int v3 = 0; //Base64.DEFAULT
        byte[] v2 = str.getBytes();
        byte[] content = Base64.decode(v2, v3); //v0
        v2 = this.str2.getBytes();
        v2 = Base64.decode(v2, v3);
        kk = new String(v2); //v1
        String v3_0 = this.decrypt(content, kk);
      	System.out.println(v3_0)
        return 0;
    }

    private String decrypt(byte[] content, String password) {
        int m = 0; //v4
        try {
            String keyStr = password.getBytes(); //v3
            //String v7 = "AES";
            SecretKeySpec key = new SecretKeySpec(keyStr, "AES"); //v2
            //v7 = AES/ECB/NoPadding
            Cipher cipher = Cipher.getInstance("NoPadding"); //v0
            int v7 = 2;
            cipher.init(v7, key);
            byte[] result = cipher.doFinal(content);
            return new String(result);
        } catch {
            //.......
        }
    }
}
```

有些地方类型不对，能看大致逻辑就行

> PCTF{Sm4liRiver}

# CrackMe2

.Net逆向

![](http://img.gaochenyang.com/uPic/Jarvis-2.png)

这题有混淆，可以用de4dot还原符号

![](http://img.gaochenyang.com/uPic/Jarvis1.png)

这里是程序的主逻辑

![](http://img.gaochenyang.com/uPic/Jarvis-4.png)

可以看到用了AES加密

用dnspy直接动调可以得到bytes和text2要比较的值,然后解密就行

```python
#!/usr/local/bin/python3
import base64
from Crypto.Cipher import AES

_bytes = [0x70, 0x63, 0x74, 0x66, 0x32, 0x30, 0x31, 0x36, 0x70, 0x63, 0x74]
_bytes += [0x66, 0x32, 0x30, 0x31, 0x36, 0x70, 0x63, 0x74, 0x66, 0x32, 0x30]
_bytes += [0x31, 0x36, 0x70, 0x63, 0x74, 0x66, 0x32, 0x30, 0x31, 0x36]
_bytes = ''.join([chr(_) for _ in _bytes]).encode()
text2 = base64.b64decode(b"x/nzolo0TTIyrEISd4AP1spCzlhSWJXeNbY81SjPgmk=")
key = _bytes
cipher = AES.new(key, AES.MODE_ECB)

print(cipher.decrypt(text2).decode())
```

# Fibonacci

用jar2exe打包成exe，~~但不知道为什么没法运行，找不到jre。~~

我windows虚拟机上的jre是32位的，得装64位

成功运行后

![](http://img.gaochenyang.com/uPic/Jarvis-5.png)

[jar2exe提取源码](https://blog.csdn.net/qq_35078631/article/details/79050341)(这个方法只能提取加载过的类，所以提取的jar不完整)

提取完整的jar可以用OD [方法](https://www.wtfplus.com/357.html)

先找到RCDATA的偏移

![](http://img.gaochenyang.com/uPic/Jarvis-6.png)

RVA是77398，内存基址是400000

在这个地方下硬件断点后等程序断下，然后在最外层循环处下断

![](http://img.gaochenyang.com/rR6Yuo.png)

经过调试发现解密的jar数据存在这个位置

![](http://img.gaochenyang.com/9ptaLu.png)

然后R11存的应该是长度

![](http://img.gaochenyang.com/Ywm34l.png)

把这片数据dump下来，解压

![](http://img.gaochenyang.com/AnkcoS.png)

这就是完整的jar了，然后丢进jeb里分析就行

代码没有判断的逻辑，输入什么都会提示错误，需要自己运行那段解密的代码

> PCTF{1ts_not_5c2ipt_Chall3nge}

# FindPass

判断flag的逻辑很简单

![](http://img.gaochenyang.com/8Dxdqv.png)

用jeb调试一下，下个断点看下变量就可以得到flag了

# DD-Hello

![](http://img.gaochenyang.com/I9qhzL.png)

只要把`start`里面的`call`的地址改成另一个函数的地址就能直接输出flag了

>要CALL的地址 - 下一条指令地址 = E8 后面的硬编码
>
>E8 后面的硬编码 + 下一条指令地址 = CALL的地址

# 软件密码破解3

MFC逆向

![](http://img.gaochenyang.com/FcNZaI.png)

首先要找到处理输入的的地方(这个地方找了很久)，最后在找API函数下断点的时候看到了这个

![](/Users/r3n0/Library/Application Support/typora-user-images/image-20200729160410709.png)

挺像加密后的flag,通过交叉引用来到了这里,跑到函数开头下断点

![](http://img.gaochenyang.com/97HOHT.png)

猜测程序的流程是输入密码，输入到一定长度后判断是否正确，如果正确~~就弹出flag~~弹的是flag就是你的口令

经过调试后发现这个函数的作用是将输入转成HEX(只能输入0123456789ABCDE)，然后判断生成的hex长度是否为8,8返回0，否则返回1.但我在后续的调试中没有发现有什么比较flag的逻辑。

----

![](http://img.gaochenyang.com/9GrgBU.png)

看了下交叉引用发现还有其他地方引用了。不过不知道为什么我当时下的硬件断点没有断下来.

```
int sub_BA1970()
{
  signed int v0; // esi
  unsigned __int8 v1; // bl
  char v2; // cl
  char v3; // al
  char v4; // cl
  char v5; // al
  unsigned __int8 v6; // dl
  unsigned __int8 v7; // bl
  char v8; // cl
  char v9; // al
  unsigned __int8 v10; // dl
  unsigned __int8 v11; // bl
  char v12; // cl
  char v13; // al
  unsigned __int8 v14; // dl
  unsigned __int8 v15; // bl
  int v16; // edi
  unsigned __int8 v17; // cl
  unsigned __int8 v18; // dl
  char v19; // dl
  int result; // eax
  char v21; // cl

  v0 = 64;
  do
  {
    v1 = byte_D0B0D0[(unsigned __int8)byte_D1145B];
    v2 = byte_D0B0D0[(unsigned __int8)byte_D0B0D0[(unsigned __int8)byte_D0B0D0[(unsigned __int8)byte_D11459]]];
    v3 = byte_D0B0D0[(unsigned __int8)byte_D0B0D0[(unsigned __int8)byte_D0B0D0[(unsigned __int8)byte_D0B0D0[LOBYTE(byte_D11458[0])]]]];
    byte_D1145A = byte_D0B0D0[(unsigned __int8)byte_D0B0D0[(unsigned __int8)byte_D1145A]];
    byte_D11459 = v2;
    v4 = byte_D0B0D0[(unsigned __int8)byte_D1145A];
    LOBYTE(byte_D11458[0]) = v3;
    v5 = byte_D0B0D0[(unsigned __int8)byte_D11459];
    byte_D1145B = v1;
    v6 = byte_D0B0D0[v1];
    v7 = byte_D0B0D0[(unsigned __int8)byte_D1145C];
    byte_D1145B = v6;
    byte_D1145A = v4;
    v8 = byte_D0B0D0[v6];
    byte_D11459 = v5;
    v9 = byte_D0B0D0[(unsigned __int8)byte_D1145A];
    byte_D1145C = v7;
    v10 = byte_D0B0D0[v7];
    v11 = byte_D0B0D0[(unsigned __int8)byte_D1145D];
    byte_D1145C = v10;
    byte_D1145B = v8;
    v12 = byte_D0B0D0[v10];
    byte_D1145A = v9;
    v13 = byte_D0B0D0[(unsigned __int8)byte_D1145B];
    byte_D1145D = v11;
    v14 = byte_D0B0D0[v11];
    v15 = byte_D0B0D0[(unsigned __int8)byte_D1145E];
    v16 = (unsigned __int8)byte_D0B0D0[(unsigned __int8)byte_D0B0D0[(unsigned __int8)byte_D1145F]];
    byte_D1145D = v14;
    byte_D1145C = v12;
    v17 = byte_D0B0D0[v14];
    byte_D1145B = v13;
    v18 = byte_D0B0D0[(unsigned __int8)byte_D0B0D0[v15]];
    byte_D1145C = byte_D0B0D0[(unsigned __int8)byte_D1145C];
    v19 = byte_D0B0D0[v18];
    byte_D1145D = byte_D0B0D0[v17];
    result = (unsigned __int8)byte_D0B0D0[v16];
    v21 = byte_D0B0D0[result];
    byte_D1145E = v19;
    byte_D1145F = v21;
    --v0;
  }
  while ( v0 );
  byte_D11460 = 1;
  return result;
}
```

```
int __stdcall sub_BA1B80(int a1)
{
  sub_BA1970();
  if ( (unsigned __int8)(byte_D1145B + byte_D1145A + byte_D11459 + LOBYTE(byte_D11458[0])) == 71
    && (unsigned __int8)(byte_D1145F + byte_D1145E + byte_D1145D) == 3
    && LOBYTE(byte_D11458[0]) == (unsigned __int8)byte_D11459 + 68
    && (unsigned __int8)byte_D11459 == (unsigned __int8)byte_D1145A + 2
    && (unsigned __int8)byte_D1145A == (unsigned __int8)byte_D1145B - 59
    && (unsigned __int8)byte_D1145E == (unsigned __int8)byte_D1145C + 10
    && (unsigned __int8)byte_D1145E == (unsigned __int8)byte_D1145F + 9
    && (unsigned __int8)byte_D1145C == (unsigned __int8)byte_D1145D + 52 )
  {
    JUMPOUT(__CS__, 0x1947 + 12189696);
  }
  return 0;
}
```

这两个函数很可疑, `sub_BA1B80`这个函数应该是解方程，然鹅程序好像并不会在这两个函数断下来orz，去看wp了。

https://www.52pojie.cn/thread-674056-1-1.html

需要很多windows知识，得找个时候补一下，先爬了.