# 读《C++反汇编与逆向分析技术揭秘》有感

强烈推荐学习逆向的童鞋仔细阅读这本书。

## 0x04 观察各种表达式的求值过程

算数运算与其他传递计算结果的代码组合后才能被视为一条有效的语句。

### 1. 加法

在编译过程中，编译器常常会采用“常量传播”和“常量折叠”这样的方案对代码中的变量与常量进行优化。

```
int nVarOne = 0;
int nVarTwo = 0;
nVarOne = nVarOne +1;
nVarOne = 1 +2;
nVarOne = nVarOne + nVarTwo;
printf("nVarOne = %d\r\n", nVarOne);
```
优化：
```
push 3
push offset Format
call printf
```

### 2. 减法

负数的补码可以简化为取反+1.

原码：0001 1001 --> 1010 --> -2 正负相加不为0，+0和-0不一致。

反码：0001 1110 --> 1111 --> -0 正负相加为-0，+0和-0不一致。

补码：0001 1111 --> 10000 --> 0000 --> 正负相加为0

负数在内存中都是以补码存在的。

### 3. 乘法

乘法运算对应的汇编指令包括有符号imul、无符号mul两种。由于乘法指令的执行周期较长，在编译过程中，编译器会先尝试将乘法转换成加法，或使用移位等周期较短的指令。当它们都不可转换时，才会使用乘法指令。

Debug版：
```
mov edx, dword ptr[ebp-4]
nVarOne * 15
imul edx, edx, 0Fh
nVarOne * 16
shl eax, 4
nVarOne * nVarTwo
mov ecx, dword ptr[ebp-4]
imul ecx, dword ptr[ebp-8]
nVarTwo *4 +5
lea edx, [ecx*4+5]
```
Release版：
```
nVarOne * 15
lea eax, [esi+esi*2]
lea eax, [eax+eax*4]
eax = eax *4+eax = 5*eax = 5*(3*esi) = esi*15
nVarTwo * 4 +5
lea edx, ds:5[esi*4]
nVarTwo * 9 +5
lea [esi+esi*8+5]
```

LEA指令如何理解？？？？？？？？？？？？？？？？？？？

### 4. 除法

有符号idiv、无符号div。

在C++中，除法运算不保留余数，有专门求取余数的运算%，即取模运算。

有符号和无符号混除，其结果则是无符号的，有符号数的最高位（符号位）被作为数据位对待，然后作为无符号数参与计算。

计算机取整：

向下取整：c语言floor函数

向下取整的除法，当除数为2的幂时，可以直接用带符号右移指令sar来完成。

向上取整：c语言ceil函数

向下取整和向上取整存在的问题：[-a/b] != -[a/b]

向零取整：

满足[-a/b] = [a/-b] = -[a/b]

在c语言和其它多数高级语言中，对整数除法规定为向零取整，也称之为截断除法。



8 % -3 = 2

-8 % -3 = -2

-8 % 3 = -2

被除数a 除数b 商为q 余数为r
```c
b*q+r = a
q = (a-r)/b
r = a - b*q
q = (8-r)/(-3) = -(2-r/3) = -2
r = 8 - (-3) * (-2) = 2
```

x86系列的CPU对于位运 算、加、减等基本指令都能在1个CPU周期内完成；乘法1个 CPU周期左右，或者是需要两/三个周期，但每个周期能启动一个新的乘指令。但作为基本指令的除法却超出预料，它是一条很慢的操作，整数和浮点 的除法都慢。

英特尔P5赛扬CPU浮点数除法差不多是37个CPU周期，整数除法是80个CPU周期，AMD2200+浮点数的除法差不多是 21个CPU周期，整数的除法是40个CPU周期。 

编译器对除法的优化：如果除数时变量，则只能使用除法指令，如果除数为常量，就有了优化的余地。

```
nVarOne / nVarTwo
mov eax, dword ptr[ebp-4]
cdq; 扩展高位
idiv eax, dword ptr[ebp-8]
```

cdq的作用是将一个32位有符号数扩展为64位有符号数，数据能表示的数不变。

具体实现：比如eax=fffffffb（值为-5），然后cdq把eax的最高位bit，也就是二进制1，全部复制到edx的每一个bit位，edx变成 FFFFFFFF，这时eax与edx连起来就是一个64位数，FFFFFFFF FFFFFFFB ，它是一个 64 bit 的大型数字，数值依旧是 -5 。

为什么idiv之前会存在cdq指令？据说，很久以前，指令集规定除数必须是被除数的一半长，因此就一直沿用下来。

 无符号除法

xor edx, edx

除数为2的幂、非2的幂、负数等各种情况：

除数为2的幂：

![](../../images/div_math.png)

将向零取整的除法操作转化为向下取整的sar指令。

nVarOne / 2

```
mov eax, dword ptr[ebp-4]
cdq
sub eax, edx
sar eax, 1
```


nVarOne / 8
```
mov eax, dword ptr[ebp-4]
cdq
and edx, 7
add eax, edx
sar eax, 3
```
and edx, 7保证了当nVarOne为负数时edx内容为2^n-1，当nVarOne为正数时edx为0，满足了上述公式。

nVarOne / -8  -->  -(nVarOne / 8)

```
mov eax, dword ptr[ebp-4]
cdq
and edx, 7
add eax, edx
sar eax, 3
neg eax; 取反加1 求相反数
```

非2的幂：
nVarTwo / 7的Debug版：

```
mov eax, dword ptr[ebp-8]
cdq
mov ecx, 7
idiv eax, ecx
```
Release版优化：

![](./../div_math_not_2.png)

最终得到优化后的除法： x * c >> n

第1种情形MagicNumber <= 0x7FFFFFFF：


```assembly
mov esi , dword ptr[ebp-8]
mov eax, 38E38E39h
imul ecx
sar edx, 1
mov eax, edx
shr eax, 1Fh
add edx, eax
push edx
```

在乘法指令中，edx存放乘积数据的高4字节，因此直接使用edx，就等价于乘积右移了32位。sar又右移了1位，因此共右移了33位。

2^33 / 38E38E39h = 8.99999

因此上述汇编的c语言为：nVarTwo / 9

第2种情形MagicNumber >= 0x80000000：

编译器在计算MagicNumber时是作为无符号处理的，而imul指令是作为有符号处理的。所以当魔数≥0x80000000时，实际参与乘法运算的是个负数，导致魔数与数学公式上的那个“大常数”意义不一致。 因此情形1的优化不适用于这种情况，重新推导公式：

![](../../div_math_not_2_big.png)



```
mov eax, 92492493h
imul esi
add edx, esi
sar edx, 2
mov eax, edx
shr eax, 1Fh
add edx, eax
push edx
```

上述计算过程：

![](../../div_math_not_2_big_2.png)

计算2^34 / 92492493h = 6.999999

因此上述除法为：nVarTwo / 7

另外还有其它情况的优化，推导过程太复杂，暂且到这里。

第三种情形MagicNumber超出了2^32：

![](../../div_math_not_2_too_big.png)

推导：
```
mov ecx, [esp+arg_0]
mov eax, 24924925h
mul ecx
sub ecx, edx
shr ecx, 1
add ecx, edx
shr ecx, 2
push ecx
```

上述过程：

![](../../div_math_not_2_too_big_2.png)

根据魔术公式，计算即可。

除数为负数时，也有两个推导公式。

取模运算。

### 5. 算数结果溢出


```c
for(int i = 1; i > 0; i++)
{
  printf("%d\r\n", i);
}
```

进位：无符号数超出存储范围叫做进位。不会破坏数据，进位后的1位数据存储在CF标志位中。

溢出：有符号数超出存储范围叫做溢出。破坏了符号位，溢出标志位OF。

OF的判定：参与加法运算的数值符号一致，而计算结果符号不同，则判定OF成立，其它都不成立。

### 6.自增自减
讨论：
```
nVarOne = 1
nVarOne = 5 + (nVarOne++);
```
结果是多少？

INC  DEC

VC编译器先将自增自减运算进行分离，然后根据运算符的位置来决定执行顺序。

### 7. 条件跳转

特殊：JZ JNZ JE JNE JS JNS JP JNP JO JNO JC JNC

无符号数：JB JNB JAE JBE JNA JNBE JNAE JA

有符号数：JL JNL JNGE JGE JLE JNG JNLE JG

跳转指令本质上检查的时标记位是否符号要求，通常与修改标记位的CMP或TEST指令匹配出现，当然，也可以自定义汇编语言修改标志位。

表达式短路：

通过逻辑与和逻辑或运算使得语句根据条件在执行时发生中断，从而不予执行后面的语句。如何利用表达式短路来实现语句中断呢？

与运算：当运算符左边的语句为假值时，直接返回假值，不执行右边语句。

或运算：当运算符左边的语句为真值时，直接返回真值，不执行右边语句。

```c
int Accumulation(int number)
{
  number && (number += Accumulation(nubmer - 1));
  // (number == 0) || (number += Accumulation(nubmer - 1));
  return number;
}
```
汇编语言（逻辑与和逻辑或汇编代码完全一样）：

```
cmp dword ptr[ebp+8], 0
je Accumulation+35h
mov eax, dword ptr[ebp+8]
sub eax, 1
push eax
call Accumulation
add esp, 4
mov ecx, dword ptr[ebp+8]
add ecx, eax
mov dword ptr[ebp+8], ecx
mov eax, dword ptr[ebp+8]
ret
```

### 8.条件表达式

三目运算：表达式？表达式2：表达式3

return arc == 5 ? 5 : 6;
```
xor eax, eax
cmp dword ptr[ebp+8], 5
setne al
add eax, 5
```

setne检查ZF标志位，当ZF==1时，赋值AL为0，反之赋值AL为1.

按照字面意思理解setne即可。

return argc == 5 ? 4 : 10;

```
mov eax, dword ptr[ebp+8]
sub eax, 5
neg eax
sbb eax, eax
and eax, 6
add eax, 4
```

只要eax不为5，则sub后，eax不为0，neg取反后，eax的符号位必定变化，CF标志位修改为1。接下来执行借位减法：

sbb eax, eax   -->  eax = eax -eax - CF

当CF为1时，eax为0xFFFFFFFF，否则为0，and 6后再add完成优化。

return argc <= 8 ? 4 : 10;

```
xor eax, eax
cmp dword ptr[ebp+8], 8
setg al
dec eax; 此时eax为0或0xFFFFFFFF
and eax, FAh
add eax, 0Ah
```

优点：编译器这样做是为了避免产生分支语句。

上述流程的关键在于setg指令。

return argc ? 8 : n表达式中有未知数时，无优化。

### 9. 位运算

<< >> | & ^ ~

异或：相同时为0，不同时为1.

位运算再程序算法中被大量使用，如不可逆算法md5。如何使得一个数不可逆转呢？如x&0=0，而根据结果是无法推导出x的值的。

在算数运算中，编译器会将各种运算转换成位运算，因此掌握位运算对学会算法识别是一件非常重要的事。

shl、sar、or、and、xor、not

有符号数的右移：sar，保留符号位；无符号数的右移shr，最高位补零。

### 10. 编译器使用的优化技巧

代码优化：执行速度优化、内存存储空间优化、磁盘存储空间优化、编译时间优化

预处理-->词法分析-->语法分析-->语义分析-->**中间代码生成**-->目标代码生成

在中间代码生成阶段所做的优化，不具备设备相关性，在不同的硬件环境中都能通用，因此编译器设计者广泛采用这类方法。

中间代码生成阶段：

常量折叠、常量传播、减少变量、公共表达式、复写传播、 剪去不可达分支、顺序语句替代分支、强度削弱、数学变换、代码外提

目标代码生成阶段：

（1）流水线优化

指令工作流程：取指令、指令译码、寻址确定操作数、取操作数、执行、存放结果

在A流水线处理的过程中，B流水线就可以提前对下一条指令做处理。

对于流水线的设计，不同厂商有不同的设计理念。

Intel的长流水线设计：把每条指令划分出很多阶段，使得每个步骤的工作内容都很简单，从而容易设计电路，加快工作频率，因此Intel处理器的主频较高。但也有缺点：

```
00401063 jmp [00401000h]
00401069 add esp, 8
```

按长流水线设计的处理器使A流水线先取得00401063指令，然后开始译码，此时B流水线开始工作，按部就班去取00401069处的指令，也开始译码。当A流水线完成，知道这是个jmp指令，意识到B流水线取指令错误，需要立刻停止B流水线的工作，定位新地址，从取指令重新开始工作。

有些时候甚至需要回滚操作，清除掉B流水线执行错误带来的影响（流水线冲洗）。由于长流水线设计步骤较多，会导致发生错误后损失较大。

AMD的设计理念是多流水线设计：位每条指令划分的工作阶段少，但流水线数量较多。这样一来，并行的成都更高了，而且由于流水线的工作步骤少，弥补错误会更及时，错误的影响也较少。当然也有缺点，同样的指令，由于划分的工作阶段少，每个阶段做的事情多，电路设计也较为复杂，主频也会受到限制，同时由于流水线数量较多，处理器对流水线的管理成本也增大了。

流水线工作的禁忌：

指令相关性、地址相关性

```
call printf
add esp, 8
mov eax, 92492493h
imul esi
;编译器O2选项生成的优化代码
call printf
mov eax, 92492493h
add esp, 8
imul esi
```

（2）分支优化

为配合流水线工作，处理器增加了一个分支目标缓冲器Branch Target Buffer。在流水线工作模式下，如果遇到分支结构，就可以利用分支目标缓冲器预测并读取指令的目标地址。

如果分支目标缓冲器中记录的目标地址等于实际目标地址，则并行成功；如果记录地址不等于实际目标地址，则流水线被冲洗。同一个分支，多次预测失败，则更新记录的目标地址。

分支预测属于“经验主义”或“机会主义”，会存在一定的误测。

```c
for(int i = 0; i < 10; i++)
{
  //预测成功9999次，退出循环时预测失败1次，该过程重复10次
  for(int j = 0; j < 10000; j++)
  	a[i][j]++;
}
//比较
for(int j = 0; j < 10000; j++)
{
  //预测成功9次，退出循环时预测失败1次，该过程重复10000次
  for(int i = 0; i < 10; i++)
  	a[i][j]++;
}
```

在编写多重循环时，应该把大循环放在内层，增加分支预测的准确度。

乱序就是指CPU不按照程序严格规定的先后顺序执行，预测就是CPU基于先有经验预先执行了后续可能执行的代码。

传统观念认为，由于CPU在运行过程中会丢弃乱序执行和预测执行所导致的不正确的运算结果，所以乱序执行和预测执行不会对程序的正确性和安全性造成任何影响。

然而，最新的发现表明攻击者完全可以利用这两种CPU特性进行侧信道攻击。 

本质：乱序和预测执行导致了CPU缓存被修改，然后利用后续的侧信道攻击使用CPU缓存达到越权读取的目的。

Meltdown攻击

Meltdown攻击的本质是利用CPU进行的安全检查和乱序执行之间的race condition，给攻击者创造一个很短的攻击窗口。 

```
; rcx = kernel address
; rbx = probe array
mov al, byte [rcx]
shl rax, 0xc
mov rbx, qword [rbx + rax]
```

乱序指令1  + 乱序指令2  -->  指令退休（安全检查）  -->  回滚。 

由于乱序执行的指令对缓存的操作在这些指令被丢弃时不会被重置，攻击者就可以通过缓存侧信道的方式来获取这些乱序执行的信息，从而导致了Meltdown攻击。 本质上，Spectre攻击的原理也是一样的。 

攻击的关键在于：

乱序执行的这两条指令必须在读取内核内存的指令退休之前（也就是权限审核之前）执行完毕。 

Spectre攻击



疑问：有无可能，在独立的无虚拟环境的服务器，通过socket来利用这个漏洞？ 

最新：研究人员又发现了8个类似于Spectre方式的CPU漏洞。

（3）高速缓存优化

内存访问效率大大低于处理器。处理器准备了片上高速缓存cache来存放经常访问的数据和代码。

VA --> cache  --> 内存 --> TLB  --> 缺页中断  --> 磁盘

cache不仅会读取指令需要的数据，还会把这个地址附近的数据都读进来。

数据对齐、数据集中、减少体积。
```
; int main(int argc, const char **argv, const char **envp)
; ret address
; argc
; argv
; envp
sub esp, 10h
mov ecx, [esp+10h+argv]

```

### 0x11. 一次算法逆向之旅

后续补充

## 0x05 流程控制语句

### 1. if语句

if语句转换的条件跳转指令与if语句的判断结果是相反的。

```assembly
if(argc ==0)
  argc = 5;
else
  argc = 6;
; debug
cmp dword ptr[ebp+8], 0
jne main+2fh
argc =5
jmp xxxx
main+2fh: argc = 6
xxx:......
; release
mov edx, [esp+4]
xor eax, eax;  --> 这里的优化技巧知道吗？
test edx, edx; 修改ZF标志位
setnz al
add eax, 5
```

c语言是根据代码行的位置来决定编译后的二进制代码的地址高低的。

在没有高级源码的情况下，分析者需要先定位语句块的边界，然后根据跳转目标和逻辑依赖慢慢反推处高级代码。

if else if else

在各分支插入return语句，这样既没有破坏程序流程，又可以省略掉else语句，可以减少一次JMP跳转，使程序执行效率得到提高。

```c
if(argc > 0)
  argc = 5;
else if (argc == 0)
  argc = 6;
else
  argc = 10;
```

### 2. switch

switch本质上是多分支结构，效率上高于if else if多分支结构。

在switch分支小于4的情况下，vc编译器采用模拟if else if的方法（switch是将所有条件跳转都放置在一起，if else则分开）；当分支数大于3，并且case的判定值存在明显线性关系组合时，则为case语句制作与一份case地址数组：

```
switch(index){
  case 1: ...;break;
  case 2: ...;break;
  case 3: ...;break;
  case 4: ...;break;
  case 5: ...;break;
  case 6: ...;break;
  case 7: ...;break;
}
mov edx, dword ptr[ebp-4]
sub edx, 1
mov dword ptr[ebp-4], edx
cmp dword ptr[ebp-4], 6
ja 00401187
mov eax, dword ptr[ebp-4]
jmp dword ptr[eax*4+00401198h]
```

当case的最小值为0时，不需要调整下标。

如果不存在case 4呢？dword ptr[eax*4+00401198] = [004011AB]将被填充为switch的结束地址或default语句块的首地址，从而达到地址表的线性有序。

如果每两个case值之间的差值小于等于6，并且case语句数大于等于4，编译器就会采用上述线性结构的地址表。

如果case的顺序为3、2、1、4、5，在case线性地址表中，也会重新排序。

当两个case值的间隔较大时，仍然使用switch的结尾地址或default语句块的首地址来代替地址表中缺少的case地址，就会造成极大的空间浪费。

因此对于这种非线性的switch结构，采用索引表的方式优化。

两张表：case语句块的地址表，case语句块的索引表。

索引表-->地址表

case语句索引表每一项的大小为1个字节，保存了地址表中的下标值，因此最多可以存储256项。

```
switch(index){
  case 1: ...;break;
  case 2: ...;break;
  case 3: ...;break;
  case 4: ...;break;
  case 256: ...;break;
}
```

4*256=1024

地址表：0-->case1，1-->case2，2-->case3，3-->case4，4-->case256，5-->default

索引表256，0-3存储的是0、1、2、3，4-254存储的是5（不存在的case），255存储的是4.

4*6+256=280字节。

```
mov edx, dword ptr[ebp-8]
sub edx, 1
mov dword ptr[ebp-8], edx
cmp dword ptr[ebp-8], FFh
ja 0040e002
mov ecx, dword ptr[ebp-8]
xor eax, eax
mov al, byte ptr(0040e02f)[ecx]
jmp dword ptr[eax*4+40E013h]
```

case差值超过255的采用判定树来优化。
```
switch(index){
  case 1: ...;break;
  case 2: ...;break;
  case 3: ...;break;
  case 4: ...;break;
  case 256: ...;break;
  case 10000: ...;break;
}
```

判定树的基本流程  -->  降低判定树的高度

在树的优化过程中，采用if else优化、有序线性优化、非线性索引优化，来降低树的高度。根据效率选择。

### 3. do/while/for

for循环更符合人类的思维方式，在循环结构中被使用的频率也最高。

do循环的效率最高。

while先比较再循环，使用了2个跳转指令。

while优化：先if再do while。
```
mov edx, [esp+4]
xor eax, eax
xor ecx, ecx
test edx, edx
jl 004010013
0040100c:
	add eax, ecx
	inc ecx
	cmp ecx, edx
	jle 0040100c
00401013:
	ret
; 逆向
if(edx > 0)
{
  do{
    eax += ecx;
    ecx ++;
  }while(ecx <= edx);
}
; 还原
ecx = 0;
while(ecx <= edx)
{
  eax += ecx;
  ecx ++;
}	
```

for优化：它需要三个跳转指令才能够完成循环。

for循环赋初值不属于循环体，其它与while循环一致，因此也可以优化为if+do while。

从结构上优化循环后，还需要从细节上再次优化。

循环结构优化：代码外提

do()while(index < count -1)

循环强度降低优化：乘法转为加法
```c
int t,i = 0;
while(t < argc)
{
  t = i * 99;
  i++;
}
//优化
while(t < argc)
{
  t = i;
  i += 99;
}
```

## 0x06 函数的工作原理



## 0x07 变量在内存中的位置和访问方式



## 0x08 数组和指针的寻址



## 0x09 结构体和类



## 0x10 关于构造函数和析构函数



## 0x11 关于虚函数



## 0x12 从内存角度看继承和多重继承



## 0x13 异常处理














## 0x99 参考

1. 原码、反码、补码的产生 https://www.zhihu.com/question/20159860
2. 除法运算逆向分析  https://blog.csdn.net/devenlau/article/details/54798769
3. CPU乱序执行和预测执行导致的安全问题 https://zhuanlan.zhihu.com/p/32654221