# 读《有趣的二进制》有感

* 目录
  * [0x00_写在前面](#0x00_写在前面)
  * [0x01_何为逆向工程？](#0x01_何为逆向工程？)
  * [0x02_逆向工程能干什么？](#0x02_逆向工程能干什么？)
    * 游戏外挂
    * 异常分析
    * 加壳和脱壳
    * 漏洞利用
  * [0x03_与逆向有关的一些技术](#0x03_与逆向有关的一些技术)
    * 调试器原理
    * 代码注入
    * 何为API钩子
  * [0x04_与逆向有关的一些工具](#0x04_与逆向有关的一些工具)
  * [0x05_总结](#0x05_总结)

## 0x00_写在前面

这是一本不需要太多专业知识就能读懂的书，很适合作为逆向工程领域的入门资料。书中主要讲了一些有关逆向的基础知识，涉及范围较为零散。总体来看，这本书脉络性不是很强，知识点讲解粗枝大叶。读后说没入门吧，自己也懂了一些知识，说入门了吧，但却向别人说不出来个逆向的一二三，有种高不成低不就的感觉。

当然，被选进了图灵教育丛书，说明它还是有很多可以学习的地方，先摘录一些有趣的知识吧。

> 冯诺依曼结构的精髓在于，处理器按照顺序执行指令和操作数据，而无论指令还是数据，它们的本质并没有区别，都是一串二进制数字的序列。

如果用一句话简要地概括何为冯诺依曼结构，那这个描述再适合不过了。如果能从冯诺依曼为起点，写一篇叙事形式的计算机安全领域相关理论的进化史，名字暂且定为`漏洞简史`，将前后攻防技术的发展串联在一起，比如Bug的出现、缓冲区溢出的利用，还有后面防止缓冲区溢出的DEP和绕过DEP而产生的ROP等等之间的历史渊源，应该很有趣吧，先在这里留个想法，希望以后能抽时间完成。

> 我也曾经用SoftICE玩过一点逆向工程，找到判断是否注册激活的逻辑，然后用一个无条件跳转替换它，或者跳过序列号的校验逻辑，不管输入什么序列号都能激活。

译者讲述了逆向工程领域中软件破解的常规思路。从理论上来看，一款需要注册激活的软件，它总会采用判断语句来确认当前的激活状态，我们只要逆向阅读程序，搞清楚注册激活部分的逻辑，然后将其绕过就可以了，这就是软件破解的本质吧。至于后面怎么使用Ollydbg或者Windbg，这些都是具体的工具，唯熟能生巧耳。


## 0x01_何为逆向工程？

何为逆向工程？这个问题恐怕是初学者遇到最迷茫的问题了。作者先让我们分析了一些简单的可执行程序，通过二进制编辑器静态查看程序包含的字符串，采用Process Monitor动态监控目标程序对文件的读写、注册表的修改，利用Ollydbg洞察程序的详细逻辑等，以窥探其行为。

像这样对软件进行分析并搞清楚其行为的工作就是“逆向工程”。

以前自己误认为逆向工程必须去看程序的二进制代码，其实不然。采用Process Monitor监控也是一种对目标程序的逆向。这样就教导我们，思维不能太狭隘。

二进制编辑器、计算器、反汇编器和调试器可谓是逆向工程的四大法宝。而它们的目标，自然是汇编代码。无论如何，阅读反汇编或者动态调试目标程序总是逆向工程的基础性工作，初学者只有认真学习汇编语言，才能尽快入门。

## 0x02_逆向工程能干什么？

逆向工程理论的实际领域，包括软件破解、游戏外挂、软件漏洞分析、恶意软件分析、木马病毒专杀等等。在讲述什么是逆向工程之后，作者通过对一款射击游戏逆向实现修改玩家分数的作弊，或许能够激发大家学习逆向工程的兴趣。

### 游戏外挂

游戏外挂的基本思想是，通过进程内存编辑器，找到目标游戏进程内存中当前分值所在内存地址，然后将其修改为需要的分值即可实现最简单的外挂功能。这得益于微软提供了一种进程之间的修改机制——ReadProcessMemory和WriteProcessMemory。

那为什么一个进程能够访问并修改另一个进程的内存空间呢？

这里拓展一下知识面，进程内存独立的只是低2G的用户态空间，高2G的内核态空间是所有进程共享的。因此一段执行中的线程进入内核态后，它可以拿到其它进程的CR3寄存器，用该CR3替换自己的CR3从而完成地址空间的转换，然后即可对目标进程的用户态空间进行读取或修改。

`备注`：业余时间可以写一款进程内存修改器练手。当然，现代游戏外挂的制作早已不是修改内存这么简单的事情了，深入学习可以参考《游戏外挂攻防艺术》。

### 异常分析

讲述游戏外挂基本原理之后，作者又讲解了如何利用进程异常时产生的内存转储文件分析崩溃原因，其中涉及了系统实时调试方面的设置，算是逆向工程另一个应用领域吧。

### 加壳和脱壳

既然软件这么容易被分析破解，又有哪些防止软件被别人分析的方法呢？本书介绍了IsDebuggerPresent或CheckRemoteDebuggerPresent等反调试技术。

加壳：但正如最简单的激活破解逻辑一样，这种检测调试器的逻辑通过静态分析也很容易被识破，所以就有了比如EB FF实现的代码混淆等防分析方法。另外还可以通过UPX、ASPack进行打包实现反调试。

脱壳：打包后的可执行程序一定会在某个时间点完成解压缩，然后切换到真正的程序。因此，理论上只要用调试器跟踪可执行文件解压缩的逻辑，将位于内存中解压缩后的可执行代码导出，即可完成脱壳。

### 漏洞利用

漏洞利用是逆向工程中关注度比较高的方向之一。书中通过一个Linux下简单的缓冲区溢出漏洞程序，向我们展示了如何通过栈溢出实现系统提权的利用过程。通过覆盖栈上的返回地址，让其指向一段采用exec函数启动/bin/sh的shellcode，从而完成了系统提权。

俗话说，魔高一尺，道高一丈。为了应对类似缓冲区溢出漏洞的利用，人们提出了地址空间布局随机化ASLR、除存放可执行代码的内存空间.text节外的其余内存空间尽量禁用执行权限的Exec-Shield机制、编译时在各函数入口和出口插入用于检测栈数据完整性的StackGuard机制等，这些都大大提高了系统的安全性。

总有那么些聪明的白帽子喜欢研究如何绕过这些安全机制，于是乎就出现了下面的智慧火花：

* 针对Exec-Shield机制的Return-into-libc方法：通过调整参数和栈的配置，使得程序能够跳转到libc.so中的System函数以及exec函数，借此来运行/bin/sh程序。
* 利用未随机化的模块内部汇编代码进行攻击的ROP。

## 0x03_与逆向有关的一些技术

这一部分应该是全书中技术含量最高的一部分了，主要讲了调试器、进程注入和API钩子等，初学者应该按照书中的例子，付诸于亲自实践，加深理解。

###　调试器原理

这得益于操作系统给开发者提供了一系列API来实现调试功能。通过调用设置了DEBUG_PROCESS或DEBUG_ONLY_THIS_PROCESS标志的CreateProcess函数启动目标进程，调试器可以捕获进程中所有产生的异常。我们只要调用WaitForDebugEvent函数就可以获取各种调试事件信息，处理后再调用ContinueDebugEvent函数即可让被调试对象恢复运行。

在Windows中，即使我们的程序不是作为调试器挂载到目标进程上，只要能够获取目标进程的句柄，就可以随意读写该进程的内存空间。

通过OpenProcess得到进程句柄后，可以调用ReadProcessMemory和WriteProcessMemory读写进程内存；用OpenThread打开线程后，可通过GetThreadContext和SetThreadContext来读写寄存器。

### 代码注入

在其他进程中运行任意代码的手法，统称为代码注入。在使用DLL的情况下，一般叫做DLL注入。

Windows提供SetWindowsHookEx、CallNextHookEx、UnhookWindowsHookEx函数来劫持系统消息。
SetWindowsHookEx的功能是，指定劫持的消息类型和回调函数，在系统消息传递给目标线程原有的窗口过程之前，将传递给窗口过程的消息劫持下来，交给回调函数进行处理。

那如何在其他进程实现注入呢？可以用CreateRemoteThread函数在其他进程中创建线程，这个函数可以在新线程中运行LoadLibrary，从而使得其他进程可以强制加载某个DLL实现DLL注入。

### 何为API钩子

在进程中插入额外的的逻辑称之为“钩子”，其中对API插入额外的逻辑称为“API钩子”。钩子的原理是，将函数开头的几个字节替换成jmp指令，强制跳转到另外一个函数。比如将MessageBoxA替换为HookedMessageBoxA，修改消息框的标题栏。微软研究院开发了一款Detours的API钩子库来实现这一功能。

## 0x04_与逆向有关的一些工具

书中最后介绍了Metasploit这款漏洞利用框架，我们可以使用msfpayload生成想要的各种shellcode，然后采用该框架对漏洞进行利用。Metasploit是集漏洞利用、免杀、扫描渗透、木马控守为一体的大成，适合专门搞渗透的人员研究。

EMET是微软发布的一款免费的漏洞缓解工具，它增加了一些有趣的反ROP机制。微软在2012年的蓝猫奖中收获了一种反ROP机制——ROPGuard。简单来说，就是一种检查“RETN所返回的目标有没有相对应的CALL”，即CALL-RETN匹配性的机制。这种方案能够有效地检测出Return-into-libc和ROP攻击。

当然也可以根据栈永远向低位方向增长的这一特性，那么正常情况下EBP必然大于ESP，也可以对这一个逻辑进行检查来判断是否遭到溢出攻击。

## 0x05_总结

这是自己第一本从头到尾看的专业书，收获自然颇丰。书中介绍了逆向工程领域最基本的一些东西，适合初学者琢磨。正如书名所说，整体来看，这本书是有趣的。