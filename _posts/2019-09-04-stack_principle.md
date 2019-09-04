---
layout:     post   			        # 使用的布局（不需要改）
title:      pwn的栈利用   			# 标题 
subtitle:   原理篇 			#副标题
date:       2019-09-04 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

这几天把**i春秋**的教程粗粗的看完了,知道了好多之前不太清楚或模棱两可的知识,下面总结一下

## 栈溢出

本篇就是告诉我们函数调用过程时会把ret即函数执行完的地址放入栈中,我们利用缓冲区的溢出将其覆盖后即可跳转到我们自己的shellcode

## shellcode编写

本篇在shellcode的变形让我受益匪浅比如一些很恶心的题会将我们的输入进行解码在写到栈中,所以我们必须先逆向出来算法,当然一般这种题的知识点点到为止,不会在算法上太难为我们,而shellcode变形这块就更恶心了.

例如我们在栈中写入了shellcode,我们到eip时跳到shellcode开始处,这时我们的shellcode含有一些push操作,这时如果我们的shellcode结尾布置到了紧靠esp的位置,那就要考虑是否有覆盖的问题,所以这时的解决方法就是将shellcode进行拆分,中间有一个`jump $当前指令+偏移量`进行拼接,即可完成起shell

## 溢出点进阶

我们之前知道了栈的ret可以受我们控制,那么我们是否可以将某些敏感函数写入ret呢,答案是肯定的,同时要在32位程序中函数的参数是布置在栈中的


(示意图,待画)

所以我们完全可以这样布置`padding(到达溢出点)+function_we_want+ret+parameter`

## rop

这篇我们要深入理解ret的含义,要知道ret在汇编中代表这`pop eip`,暂且这么理解,这就像我们在栈中布置了一个地址,例如是
```
0x123   push eax
0x134   ret
```
例如我们的程序溢出点是20个,我们就可以这么构造

```
aaaa
aaaa
aaaa
aaaa
aaaa
0x123<-原ret
```

我们把0x123写入栈的ret,那么我们的程序在会跳转到`push eax`中,之后又执行ret,但是我们的栈顶指向eax,所以我们就会跳转到eax的指向中,大家可以好好理解一下

## 
