### 介绍
我们公司前段时间需要自助修改svn密码的功能，运维在网上找过很多的svn修改密码工具，有的用php实现的，有的用python实现的。但是都不尽如人意，其实原理很简单，就是针对svn的秘钥文件进行增删改查，于是就用java实现了一个web服务。有需要拿去直用～

### 部署方法

#### 1.maven编译
---
  maven clean install
---
编译出可执行的jar包，本项目是基于spring-boot的很简单
#### 2.把生产的jar包拷贝到svn的秘钥文件同级目录，执行jar文件 
---
 nohup java -jar reset-svn-pass.jar &
--- 
#### 3.访问 http:your-ip:10086即可
