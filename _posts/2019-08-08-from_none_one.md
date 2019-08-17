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

`echo 0 > /proc/sys/kernel/randomize_va_space`关闭`PIE`

` ulimit -c unlimited`表示自己程序只要错误就生成dump文件,之后`echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern`表示存到tmp目录下,之后我们就可以`gdb $文件名 core.%t`调试了

## ASLR和PIE的各种事

其实我第一遍学的时候以为,emm,这不是一样的东西吗,甚至以为效果是它俩求并就行,靠发现完全不是,[这个](https://blog.csdn.net/Plus_RE/article/details/79199772)写的很棒了,谢谢师傅,在这里简单记录一下诀窍吧(表格中提到的是被随机化的,堆另外再提)

\ |aslr=0 | aslr=1 | aslr=2
:-: | :-: | :-: | :-:
开启PIE | null | code\data\stack | libc\code\data\stack
关闭PIE | null | stack | libc\stack

**brk()** 在aslr为1时地址静止,**mmap()** 地址随机

如果你想,emm,那我直接关闭本地aslr不完事了吗,hah,年轻了亚还是,远程服务器可是开着的,掩耳盗铃还行,所以一般情况下我们只能找漏洞点让数据泄漏出来

## 所有保护全关->跳转执行shellcode
在栈上写shellcode后ret直接指向shellcode就行,最简单的一种利用,但是我们要注意到底要覆盖多少字节,同时我们应该注意这种类型的漏洞关键便是理解好堆栈
