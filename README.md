### 一、介绍
​      	前段时间公司需要员工能够自助修改自己的svn密码，运维在网上找过很多的svn修改密码工具，有的用php实现的，有的用python实现的。但是都不尽如人意，最后决定自己手动实现，于是就用java实现了一个web服务。供用户和运护使用、分享给有需要的～

![首页](https://github.com/swalikh/SVN-password-reset-tools/src/main/resources/static/img/error.png)

![修改错误](https://github.com/swalikh/SVN-password-reset-tools/src/main/resources/static/img/success.png)

### 二、部署方法

#### 1.进入工程，在pom.xml同目录执行maven编译

```
maven clean install
```

#### 2.把target文件夹下的jar包拷贝到服务器svn的秘钥文件同级目录并运行jar文件

```
nohup java -jar reset-svn-pass.jar &
```

#### 3.访问 http:your-ip:10086即可
