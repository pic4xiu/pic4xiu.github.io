---
layout:     post   			        # 使用的布局（不需要改）
title:      Sort out some commands   			# 标题 
subtitle:   and some nauseous bug  			#副标题
date:       2020-01-01 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - pwn
---

## 洞

> 栈溢出

```
    gets(&v2);
```

> 格式化字符串

```
    printf(s2, &v1);
```

## small orders

这篇就更新一下pwn相关的常用的小命令

```
od

Ctrl+F9
#od跑到最近ret处
Alt+F9
#调用dll时快速回到用户代码中

nm -D some.so
objdump -tT  some.so
#dump出so各函数地址
ROPgadget --binary pwnme --only "call|ret"
#找gadget贼6，但是有时候不太好用
echo 0 > /proc/sys/kernel/randomize_va_space
#关掉linux系统的pie保护
ulimit -c unlimited
#开启core dump，防止地址受gdb影响
objdump -d -j .plt file_name
#显示plt表
objdump -R file_name
#显示got表

gdb

x/wx addr
find addr,offset,string
print function
#gdb显示一些addr存放的值🤣，炒鸡好用
 - w可换位b/h/g，分别取1/2/8字节
 - /后可以接数字，表示显示多少
 - 第二个x可以换成u（unsinged int）/d（10进制数）/s（字符串）/i（指令）
set *addr=value
 - 设置addr值，默认为4字节
 - 也可以将*换位{char/short/long}分别设置1/2/8字节
 
p *((struct _IO_FILE_plus*)0x602400)
 - 按照 ** 结构体显示

gdb-peda

elfsymbol
vmmap
readelf
find string
record

```

> got plt

这里记一下got、plt表，好不容易差不多明了了，网上有很多解释，这里通俗说一下，调用plt_func可以直接使用函数，如我们吧ret_addr改为plt_func函数后，后边跟参数（32位）或者是之前已经pop_reg的话（64位），即可直接使用，而got_func中保存着真实地址，当然如果直接是`call addr`的时候就要直接使用got_func了

> Thought

#只开NX
找`system`和`/bin/sh`地址，当然静态链接没有的话可以直接写入

#开NX和PIE
利用`write`泄露地址，然后根据偏移找到`system`和`/bin/sh`，也可以使用`DynELF`来泄露`system`地址



## bugs which make the head big

> gdb插件冲突

我们在安装peda和pwngdb这两个各有特点(pwngdb调试堆一绝)的插件时,可能会遇到这样的问题,一般起因是因为先装了peda,之后装pwngdb,在`.gdbinit`文件中未及时注释掉,也即这样
```
source ~/peda/peda.py
source /home/pic/pwndbg/gdbinit.py
```
造成如下问题
```
Traceback (most recent call last):
  File "/home/pic/pwndbg/gdbinit.py", line 36, in <module>
    import pwndbg # isort:skip
  File "/home/pic/pwndbg/pwndbg/__init__.py", line 19, in <module>
    import pwndbg.commands.aslr
  File "/home/pic/pwndbg/pwndbg/commands/aslr.py", line 24, in <module>
    def aslr(state=None):
  File "/home/pic/pwndbg/pwndbg/commands/__init__.py", line 298, in __call__
    return _ArgparsedCommand(self.parser, function)
  File "/home/pic/pwndbg/pwndbg/commands/__init__.py", line 267, in __init__
    super(_ArgparsedCommand, self).__init__(function, command_name=command_name, *a, **kw)
  File "/home/pic/pwndbg/pwndbg/commands/__init__.py", line 61, in __init__
    raise Exception('Cannot override non-whitelisted built-in command "%s"' % command_name)
Exception: Cannot override non-whitelisted built-in command "aslr"
```
看到大意是想把aslr重写但是失败了,解决方法便是将`.gdbinit`文件第一行注释掉
```
source ~/peda/peda.py
source /home/pic/pwndbg/gdbinit.py
```

> pwngdb 安装死活不成功

今天学习 tcache ，结果在 18.04 里边死活装不上 pwngdb ，在 `sudo ./setup.sh` 报错中发现是 pip 源的问题，就用[这个](https://blog.csdn.net/yucicheung/article/details/79095742)大佬的方法把 pip 默认源改成了 豆瓣的，立马见效
