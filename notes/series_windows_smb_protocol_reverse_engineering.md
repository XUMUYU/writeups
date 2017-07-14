## windows smb协议逆向之旅


* 目录
  * MS17-010永恒之蓝漏洞详细分析与利用
  * Windows对SMB协议的实现
  * 历年来Windows SMB出现的那些漏洞
  * SMB协议的fuzzing测试



有趣的Windows SMB协议

1. 有哪些功能的数据包
2. 数据包格式是怎样的
3. windows服务端如何接收这些数据包（接收buffer、处理过程） srv.sys srvnet.sys
4. 有哪些特殊的数据包交互过程（UDP的、非客户端驱动的、已经丢弃的）
5. 这些年微软对smb功能的变化


-----------------------------

SMB_FEA_LIST出的漏洞，能否检索一下SMB协议中用到的所有相关LIST的处理过程，看是否同样出现将DWORD大小设置为WORD的情况。
-----------------------------

Freebuf有篇很好的文章：·`BlackHat议题： SMB不只是共享你的文件`

### windows smb协议


### windows对smb的实现

讲述一下smb如何处理smb数据包的过程

能否用一句话或一张图，简单明了地解释SMB协议的作用。哪些数据包和哪些sys中的函数相互关联，彻底搞清楚每个数据包在服务端都干了什么。从github/google搜索有关Windows SMB逆向的资料。对Windows SMB协议做到烂熟于心。

### 逆向srv.sys和.sys

数据包接收过程

数据包存储在哪里

数据包都是由哪些sys的哪些函数处理

每个数据包的处理过程



### linux smb源码阅读

通过上述，看Linux的实现，深入理解Linux与Windows的不同。

### 补丁对比

分析历年来srv.sys和.sys的改动

### 相关漏洞分析

将08年以来SMB协议的可用漏洞研究一番。

### smb协议fuzzing

能否研究基于函数的fuzzing方法（提取出来srv.sys或srvnet.sys的函数，对某个函数的输入参数进行fuzzing），或者基于数据包的fuzz ing方法。
从github/google 上寻找相关项目。可以fuzzing windows/Linux/Mac。





