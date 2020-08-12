---
title: hgame2020 week4 wp
date: 2020-07-15 10:37:04
tags: hgame
---

# RE

## easyVM

调试的时候发现是将输入经过变换后和一串字符进行比较，并且后面的输入不会影响前面的结果，于是就。。。。
根据flag的格式套路把flag凑出来了
![](https://r3n0.top/wp-content/uploads/2020/04/week4-1.png)
..............

## Secret
ida打开找到main函数
![](https://r3n0.top/wp-content/uploads/2020/04/week4-2.png)
发现使用了soket，用nc连接
![](https://r3n0.top/wp-content/uploads/2020/04/week4-3.png)

是一串乱码
用python算了一下这串乱码的长度，是0x1E6，正好和read函数读取的长度一样
然后看了下这个文件的hex，在401bfc的位置发现了一串0
![](https://r3n0.top/wp-content/uploads/2020/04/week4-4.png)
长度是0x1E6
程序原本是不完整的，要通过soket读取一串字符后把它写到相应的地方，再把这块内存修改为7
填上这块0之后发现最后一句变成了这样
![](https://r3n0.top/wp-content/uploads/2020/04/week4-5.png)
进去之后
![](https://r3n0.top/wp-content/uploads/2020/04/week4-6.png)
看到了一串不认识的函数
经百度后发现这是用来发送信号的，又再函数列表里找到了接受信号的函数
![](https://r3n0.top/wp-content/uploads/2020/04/week4-7.png)
整了很久才高明白程序的流程（诡异的程序调试的时候信号乱发rip乱跳）
大致就是执行到main的时候fork处一个子进程，主进程进入死循环，子进程进行执行,
等子进程执行到401BFC的时候就会按照流程向主进程发送信号，主进程接受信号就会执行相应的函数
所以根据信号流程，这个加密算法应该是这样的：

```
#include <stdio.h>

unsigned int arry[4] = {0x42655f29, 0x9e822efc, 0x0da278c92, 0x4e355a62};
unsigned b = 0x9e3779b9;
int count = 0;
unsigned int c[14];
int main()
{
    unsigned int c1, c2;
    int count1 = 0, v3 = 0;
    char ch[100] = "hgame{No11112121212121212121212121212121212121212121212";
    for (int i = 0; i < 7; i++)
    {
        count1 = 0;
        v3 = count++;
        c1 = *(unsigned int *)(ch + 4 * v3);
        v3 = count++;
        c2 = *(unsigned int *)(ch + 4 * v3);
        for (int j = 0; j < 32; j++)
        {
            c1 += (arry[count1 & 3] + count1) ^ (((c2 >> 5) ^ 16 * c2) + c2);
            count1 += b;
            c2 += (arry[(count1 >> 11) & 3] + count1) ^ (((c1 >> 5) ^ 16 * c1) + c1); 
        }
        c[count - 2] = c1;
        c[count - 1] = c2;
    }
    for (int i = 0; i < 14; i++)
        printf("%X ", c[i]);
}
```

经过查找发现这是xtea加密
解密如下：

```
#include <stdio.h>

int main()
{
    unsigned int array[4] = {0x42655f29, 0x9e822efc, 0x0da278c92, 0x4e355a62};
    unsigned d = 0x9e3779b9;
    unsigned int cipher[14] = {0x27A9C8E9, 0x0BAA973B4, 0x0AAC072F9, 0x0A3FA8000, 0x0D9F4C2D3, 0x0FB3F6BC5, 0x0D3D3D95E,
                               0x86961D77, 0x0E600C53F, 0x98BC27B9, 0x9AAC3AC, 0x6ADC2424, 0x605E304, 0x65E78C77};
    
    for (int j = 0; j < 14; j+=2)
    {
        int count1 = d << 5;
        for (int i = 0; i < 32; i++)
        {
            cipher[j+1] -= (array[(count1 >> 11) & 3] + count1) ^ (((cipher[j] >> 5) ^ 16 * cipher[j]) + cipher[j]);
            count1 -= d;
            cipher[j] -= (array[count1 & 3] + count1) ^ (((cipher[j+1] >> 5) ^ 16 * cipher[j+1]) + cipher[j+1]);
        }
    }
    for (int i = 0; i < 14; i++)
        printf("%X ", cipher[i]);
    return 0;
}
```

得到一串16进制
![](https://r3n0.top/wp-content/uploads/2020/04/week4-8.png)
再把每一串16进制倒过来转成字符串就是flag了