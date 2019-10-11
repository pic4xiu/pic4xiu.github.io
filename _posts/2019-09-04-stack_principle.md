---
layout:     post   			        # 使用的布局（不需要改）
title:      pwn的栈利用   			# 标题 
subtitle:   原理篇 			#副标题
date:       2019-09-04 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

这篇文章只是起到抛砖引玉的效果，尽量使用最简洁的介绍让大家明白一些知识点，简化做题环境

## 栈溢出

所谓栈溢出就是告诉我们函数调用过程时会把ret即函数执行完的地址放入栈中,我们利用缓冲区的溢出将其覆盖后即可跳转到我们自己的shellcode

## shellcode编写

本篇在shellcode的变形让我受益匪浅比如一些很恶心的题会将我们的输入进行解码在写到栈中,所以我们必须先逆向出来算法,当然一般这种题的知识点点到为止,不会在算法上太难为我们,而shellcode变形这块就更恶心了.

例如我们在栈中写入了shellcode,我们到eip时跳到shellcode开始处,这时我们的shellcode含有一些push操作,这时如果我们的shellcode结尾布置到了紧靠esp的位置,那就要考虑是否有覆盖的问题,所以这时的解决方法就是将shellcode进行拆分,中间有一个`jump $当前指令+偏移量`进行拼接,即可完成起shell

## 溢出点进阶

我们之前知道了栈的ret可以受我们控制,那么我们是否可以将某些敏感函数写入ret呢,答案是肯定的,同时要在32位程序中函数的参数是布置在栈中的


(示意图,待画)

所以我们完全可以这样布置`padding(到达溢出点)+function_we_want+ret+parameter`

## rop

这篇我们要深入理解ret的含义,要知道ret在汇编中代表这`pop eip`,暂且这么理解,这就像我们在栈中布置了一个地址,例如是
```
0x123   push eax
0x134   ret
```
例如我们的程序溢出点是20个,我们就可以这么构造

```
aaaa
aaaa
aaaa
aaaa
aaaa
0x123<-原ret
```

我们把0x123写入栈的ret,那么我们的程序在会跳转到`push eax`中,之后又执行ret,但是我们的栈顶指向eax,所以我们就会跳转到eax的指向中,大家可以好好理解一下

## vsdo

这个的点就比较骚了，我们知道只要程序开启了pie，我们就很难确定libc中的函数，所以我们这时候看到vsdo在内存中的位置是不变的,这时我们根据调用函数的返回值.可以利用他来起shell,比如说我们通过one_gagede找到了一个片段,其中的限制条件是eax为0,我们就可以根据他来起

这几天做题发现没有什么会做的,还是要夯实基础,于是在**i春秋**上找了篇教程也算是重新学习一遍吧,环境搭建不谈了,还有做题环境(ida,pwntools),没有gdb可能觉得对新手不太友好,我也不算新手了,算是个老菜鸡了,还是做吧

## 溢出点寻找

这个作者写的栈溢出基础,关键就是溢出点的判断,**hello**和**csaw ctf 2016 quals-warmup**不谈了,直接无脑`cyclic`就行,从之后开始就开始学新东西了

### doubly_dangerous

这题没有找到很好的思路,溢出点的思路行不通,只能通过让`if`的语句成立,`s`和`v5`相差**0x40**个字节,直接修改`v5`即可,修改后的exp如下

```
#!/usr/bin/python
#coding:utf-8

from pwn import *

io =process('doubly_dangerous')
payload = 'A'*64
payload += "\x00\x80\x34\x41"

print io.recv()					
io.sendline(payload)			
print io.recv()					
```

### sCTF 2016 q1-pwn1

这题思路很请奇,`fget`只接收32个字节,我们可以知道到栈底有0x3c个字节,加上ebp足足有0x40个字节,也就是64个字节,但是我们使用ida分析的时候会发现他进行了个替换,把所有`I`替换成了`you`,这样我们只需要写`I*(63/3)+x+ret`即可完成

### Tokyo West CTF 3rd 2017-just_do_it

本题也并不是修改ret,而是要将**v6**的值进行改写因为会最后`put(v6)`,而且我们之前的flag文件已经打开存到了bss中

 - 直接到ret前看stack前4字节
