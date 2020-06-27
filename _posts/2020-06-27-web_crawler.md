---
layout:     post   			        # 使用的布局（不需要改）
title:      Simple web crawlers   			# 标题 
subtitle:   written by Python 			#副标题
date:       2020-06-27 				# 时间
author:     pic4xiu 		    		# 作者
header-img: img/post-bg-debug.png 		#这篇文章标题背景图片
catalog: true 					# 是否归档
tags:						#标签
    - python
---

就拿这个记录自己学习 python 爬虫的日常吧

##6.27

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

最近一直没碰 python 和二进制，最近一次敲代码就是作品赛~~~

这个是完成了一个获取学校官网新闻文字和图片的菜鸡爬虫，完成的功能及其简陋。虽然技术不过关但我觉得代码还是写的比较精简的
