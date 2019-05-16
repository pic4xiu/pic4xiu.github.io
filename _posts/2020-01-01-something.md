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
find addr offset string
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

这里记一下got、plt表，好不容易差不多明了了，网上有很多解释，这里通俗说一下，调用got_func可以直接使用函数，而plt_func中保存着真实地址
