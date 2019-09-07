---
layout:     post  			            # 使用的布局（不需要改）
title:      萌新之   			          # 标题 
subtitle:   pwn与Re入门                  # 副标题
date:       2019-09-07 		    		# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		# 这篇文章标题背景图片
catalog: true 		        			# 是否归档
tags:	            					# 标签
    - misc
---

考虑到看到本篇的各位学弟学妹的水平应该不尽相同,所以大家可以根据自己跳到相应段落

下面简单总结一下2年来的一些**pwn**和**Re**(逆向)经历,给刚入坑或已入坑的萌新,半萌新们提供一份经验

## 何为逆向

逆向笼统的来讲就是给一个程序,然后我们根据程序去分析这个程序的流程走向,听上去也许挺不可思议,但是事实上市面上早已出现各种工具去辅助我们去分析,例如`windows`平台下的`ida pro`,可以有效的将程序反汇编成伪代码

![](https://github.com/pic4xiu/pic4xiu.github.io/blob/master/img/9-7-1.png)

同时还可以把汇编层面的流程图清晰的列出来

![](https://github.com/pic4xiu/pic4xiu.github.io/blob/master/img/9-7-2.png)

## 用处
> 可以用来干什么

大家对外挂应该十分熟悉,事实上通过反汇编等等逆向手段,我们可以半知半解甚至十分清晰的把我们的游戏数据改成我们需要的,这其中如金钱,经验等等.同时伴随而来的便是混淆,反调试等等

## 逆向学习路线

先说大一和大二上的Re学习路线,这段学习经历关键即打好基础,关键就是研究到了**加解密算法**,**工具使用**(如windows平台的ida,ollydbg,linux平台的gdb),

 - [reversing.kr](http://reversing.kr/)
 - [i春秋个人成长的ctf大本营](https://www.ichunqiu.com/competition)
 - 大比赛的各种题,百度都有