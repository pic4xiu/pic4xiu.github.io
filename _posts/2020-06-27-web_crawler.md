---
layout:     post   			        # 使用的布局（不需要改）
title:      Simple gadgets  			# 标题 
subtitle:   written by Python 			#副标题
date:       2020-06-27 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - python
---

这个是完成了一个获取长理官网新闻文字和图片的小爬虫，完成的功能及其简陋。写完想笑哈哈哈哈哈

## 6.27

```
import requests
import re
import urllib.request
count=1
jpg_count=1
url='https://www.cust.edu.cn/'
response = requests.get(url)
response.encoding = 'utf-8'
html = response.text
easy = re.findall(r'<ul class="list01">(.*?)</ul>',html,re.S)
people = re.findall(r'href="(.*?)"',str(easy),re.S)
for i in people:
    i='https://www.cust.edu.cn/'+i
    file = "E:/new/新闻" + str(count) + '.html'
    r = requests.get(i)
    r.encoding = 'utf-8'
    with open(file, "wb") as code:
        code.write(r.content)
    count=count+1
    jpg = re.findall(r'window.open(.*?).jpg',r.text,re.S)
    for j in jpg:
        print(j[4:])
        rsp=urllib.request.urlopen("https://www.cust.edu.cn/"+j[4:]+".jpg")
        img=rsp.read()
        file = "E:/new/图片" + str(jpg_count) + '.jpg'
        with open(file,'wb') as f:
            f.write(img)
        jpg_count=jpg_count+1
```

5月份参加了个作品赛，完成了一套linux平台的源代码漏洞加固程序，整合的py脚本如下，然后里边用到的东西在自己github里，也没啥特别有技术含量的东西，就不献丑了

```
import re

def Findhf(text):
    Headerfile=[]
    x=text.split("\n")
    #print(x)
    for i in x:
        if('#include' in i):
            Headerfile.append(i)
    #print(Headerfile)
    return Headerfile

def Findo(text):
    others=[]

    x=text.split("\n")
    #print(x)
    for i in x:
        if('#include' not in i):
                if('main' not in i):
                    others.append(i)
                else:
                    break
    #print(others)
    return others

def Findm(text):
    real=[]
    rep=[]
    count=1
    x=text.split("\n")
    for i in x:
        if(count==1):
            if('main' in i):
                #print(i)
                count=count-1
        else:
                if('}' != i):
                    real.append(i)
                else:
                    print('found finish')
    for a in real:
        if('write' in a):
            te=a.split(',')
            del te[0]
            te.pop()
            place=','.join(te)
            place='    mywrite('+place+');'
            rep.append(place)
        else:
            rep.append(a)
    #print(rep)
    return rep

def antidebug(text):
    head=Findhf(text)
    oth=Findo(text)
    main_real=Findm(text)
    fp = open('head.c', "r", encoding='UTF-8')
    head0 = fp.read()
    fp = open('ot.c', "r", encoding='UTF-8')
    oth0 = fp.read()
    head1='\n'.join(head)+head0+'\n'.join(oth)
    print(head1)
    fp = open('mai.c', "r", encoding='UTF-8')
    main0 = fp.read()
    main1=main0+'\n'.join(main_real)
    print(main1)
    text=head1+main1+oth0
    return text

def start():
    filename = input("请输入文件名字：")
    try:
        fp = open(filename, "r", encoding='UTF-8')
        print("%s 文件打开成功" % filename)
        text = fp.read()
        text = antidebug(text)
        outputFileName = "antidebug_"+filename
        f2 = open(outputFileName, "w+")
        f2.write(text)
    except IOError:
        print("文件打开失败,%s 文件不存在" % filename)
        start()

if __name__ == '__main__':
    message=''
    while message != "exit":
        start()
        message = input("输入exit结束程序 或 输入任意键继续\n")
```
