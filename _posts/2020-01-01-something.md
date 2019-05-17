---
layout:     post   			        # 使用的布局（不需要改）
title:      整理一些小命令   			# 标题 
subtitle:   随时更新😀  			#副标题
date:       2020-01-01 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

## Recent

最近一直很迷茫，看看pwn看看Re，很懵逼，不过现在找回状态了，还是好好看pwn吧，老是想一口气吃成胖子，现在还不是老老实实看文章，（难受

这篇就更新一下pwn相关的常用的小命令

```
ROPgadget --binary pwnme --only "call|ret"
#找gadget贼6，但是有时候不太好用

echo 0 > /proc/sys/kernel/randomize_va_space
#关掉linux系统的pie保护

x/32gx addr
x/10s  addr
find addr,offset,string
print function
#gdb显示一些addr存放的值🤣，炒鸡好用

ulimit -c unlimited
#开启core dump，防止地址受gdb影响

objdump -d -j .plt file_name
#显示plt表
objdump -R file_name
#显示got表
```

> got plt

这里记一下got、plt表，好不容易差不多明了了，网上有很多解释，这里通俗说一下，调用plt_func可以直接使用函数，如我们吧ret_addr改为plt_func函数后，后边跟参数（32位）或者是之前已经pop_reg的话（64位），即可直接使用，而got_func中保存着真实地址，当然如果直接是`call addr`的时候就要直接使用got_func了

> Thought

下边说一下根据`checksec`结果解常规栈溢出pwn题的思路

#全关
直接在栈上写shellcode，然后ret写成shellcode地址

#只开NX
找`system`和`/bin/sh`地址，当然静态链接没有的话可以直接写入

#开NX和PIE
利用`write`泄露地址，然后根据偏移找到`system`和`/bin/sh`，也可以使用`DynELF`来泄露`system`地址
