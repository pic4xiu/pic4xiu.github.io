---
layout:     post   			        # 使用的布局（不需要改）
title:      从0开始学pwn   			# 标题 
subtitle:   (1)  			#副标题
date:       2019-08-16 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

今天从零开始学**stack**,也算是记录一下吧,在这里记录一下特别细的知识点

## 准备环境

使用`gcc -g -fno-stack-protector -z execstack -o test test.c`依次关掉**Canary**和**NX**

`echo 0 > /proc/sys/kernel/randomize_va_space`关闭**PIE**

` ulimit -c unlimited`表示自己程序只要错误就生成dump文件,之后`echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern`表示存到tmp目录下,之后我们就可以`gdb $文件名 core.%t`调试了

## ASLR和PIE的各种事

其实我第一遍学的时候以为,emm,这不是一样的东西吗,甚至以为效果是它俩求并就行,靠发现完全不是,[这个](https://blog.csdn.net/Plus_RE/article/details/79199772)写的很棒了,谢谢师傅,在这里简单记录一下技巧吧(表格中提到的是被随机化的,堆另外再提)

\ |aslr=0 | aslr=1 | aslr=2
:-: | :-: | :-: | :-:
开启PIE | null | code\data\stack | libc\code\data\stack
关闭PIE | null | stack | libc\stack

**brk()** 在aslr为1时地址静止,**mmap()** 地址随机

如果你想,emm,那我直接关闭本地aslr不完事了吗,hah,年轻了亚还是,远程服务器可是开着的,掩耳盗铃还行,所以一般情况下我们只能找漏洞点让数据泄漏出来

## 所有保护全关->跳转执行shellcode
在栈上写shellcode后ret直接指向shellcode就行,最简单的一种利用,但是我们要注意到底要覆盖多少字节,同时我们应该注意这种类型的漏洞关键便是理解好堆栈,我们以下方程序举例,一起分析一下堆栈
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void hello(int x) {
    printf("hello %d\n",x);
}

int main(int argc, char** argv) {
    hello(3);
}
```
然后直接`gcc -m32 test`进行编译运行,之后直接到gdb中进行调试
首先`b main`断到main函数,之后一步一步看
```
   0x8048435 <main+14>    sub    esp, 4
   0x8048438 <main+17>    sub    esp, 0xc
 ► 0x804843b <main+20>    push   3
   0x804843d <main+22>    call   hello <0x804840b>
```
这是hello函数前的准备,我们只需要注意`push 3`这步操作,执行完后esp-4,同时指向3
```
───────────────────────────────────[ DISASM ]───────────────────────────────────
   0x8048435 <main+14>    sub    esp, 4
   0x8048438 <main+17>    sub    esp, 0xc
   0x804843b <main+20>    push   3
 ► 0x804843d <main+22>    call   hello <0x804840b>
        arg[0]: 0x3
        arg[1]: 0xffffd0b4 —▸ 0xffffd293 ◂— 0x6d6f682f ('/hom')
        arg[2]: 0xffffd0bc —▸ 0xffffd2af ◂— 'XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat0'
        arg[3]: 0x8048481 (__libc_csu_init+33) ◂— lea    eax, [ebx - 0xf8]
 
   0x8048442 <main+27>    add    esp, 0x10
   0x8048445 <main+30>    mov    eax, 0
   0x804844a <main+35>    mov    ecx, dword ptr [ebp - 4]
   0x804844d <main+38>    leave  
   0x804844e <main+39>    lea    esp, [ecx - 4]
   0x8048451 <main+42>    ret    
 
   0x8048452              nop    
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ esp  0xffffcff0 ◂— 0x3
01:0004│      0xffffcff4 —▸ 0xffffd0b4 —▸ 0xffffd293 ◂— 0x6d6f682f ('/hom')
02:0008│      0xffffcff8 —▸ 0xffffd0bc —▸ 0xffffd2af ◂— 'XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat0'
03:000c│      0xffffcffc —▸ 0x8048481 (__libc_csu_init+33) ◂— lea    eax, [ebx - 0xf8]
04:0010│      0xffffd000 —▸ 0xf7fb03dc (__exit_funcs) —▸ 0xf7fb11e0 (initial) ◂— 0x0
05:0014│      0xffffd004 —▸ 0xffffd020 ◂— 0x1
06:0018│ ebp  0xffffd008 ◂— 0x0
07:001c│      0xffffd00c —▸ 0xf7e16637 (__libc_start_main+247) ◂— add    esp, 0x10
```
之后call指令,我们把下一个地址即`0x8048442`入栈,我们`s`跟进,函数开始了经典的提升栈操作
```
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x804840b <hello>       push   ebp
   0x804840c <hello+1>     mov    ebp, esp
   0x804840e <hello+3>     sub    esp, 8
   0x8048411 <hello+6>     sub    esp, 8
   0x8048414 <hello+9>     push   dword ptr [ebp + 8]
   0x8048417 <hello+12>    push   0x80484e0
   0x804841c <hello+17>    call   printf@plt <0x80482e0>
 
   0x8048421 <hello+22>    add    esp, 0x10
   0x8048424 <hello+25>    nop    
   0x8048425 <hello+26>    leave  
   0x8048426 <hello+27>    ret    
```
看到执行到`hello+6`的操作应该是栈被抬高了
```
pwndbg> stack 8
00:0000│ esp  0xffffcfd8 ◂— 0x0
01:0004│      0xffffcfdc —▸ 0xf7e1632a (init_cacheinfo+666) ◂— mov    dword ptr [esp + 0xc], 2
02:0008│      0xffffcfe0 ◂— 0x1
... ↓
04:0010│ ebp  0xffffcfe8 —▸ 0xffffd008 ◂— 0x0
05:0014│      0xffffcfec —▸ 0x8048442 (main+27) ◂— add    esp, 0x10
06:0018│      0xffffcff0 ◂— 0x3
07:001c│      0xffffcff4 —▸ 0xffffd0b4 —▸ 0xffffd293 ◂— 0x6d6f682f ('/hom')
```
之后的` ► 0x8048414 <hello+9>     push   dword ptr [ebp + 8]`我们应该知道了,这个是参数,目前具体的堆栈图如下
指针 |内存
:-: | :-: 
esp | sth 
esp+4 | sth
esp+8 | sth
esp+c | sth
ebp | sth
ebp+4 | ret
ebp+8 | 3
