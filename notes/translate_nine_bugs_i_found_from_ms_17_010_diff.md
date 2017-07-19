# 【翻译】利用MS17-010补丁对比发现的九个漏洞

文章已首发在Freebuf.COM，转载请注明来源：

[FB - 利用MS17-010补丁对比发现的九个漏洞](http://www.freebuf.com/system/139481.html)

`译者注` MS17-010的硝烟已经过去两个月了，每个关注它的安全爱好者都学到了不同的东西。这篇翻译是原作者结合NSA泄露的武器库，通过补丁对比从MS17-010中发现的九个漏洞。作者从微软对SMB协议的实现缺陷方面向我们讲述了MS17-010涉及的方方面面，堪称鞭辟入里之作。可以毫不夸张地说，只有理解这篇文章，才算真正了解MS17-010。看过之后，越来越觉得不敢独享，故将其细细翻译并作了标注，希望能对寻找相关资料的童鞋有所帮助。

目录

* [0x00 SMB Transaction概述](#0x00-smb-transaction概述)
  * [1 消息格式](#1.-消息格式)
  * [2 实现细节](#2.-实现细节)
* [Bug1：Transaction InParameters和InData缓冲区未初始化漏洞](#bug1transaction-inparameters和indata缓冲区未初始化漏洞)
* [Bug2: TRANS_PEEK_NMPIPE子命令始终期望MaxParameterCount为16](#bug2-trans_peek_nmpipe子命令始终期望maxparametercount为16)
* [Bug3: 允许Transaction响应数据长度大于申请的缓冲区长度](#bug3-允许transaction响应数据长度大于申请的缓冲区长度)
* [Bug4: 允许ParameterCount/DataCount之和大于TotalParameterCount/TotalDataCount](#bug4-允许parametercountdatacount之和大于totalparametercounttotaldatacount)
* [Bug5: 允许Transaction secondary请求在服务端开始处理transaction后才被接收和处理](#bug5-允许transaction-secondary请求在服务端开始处理transaction后才被接收和处理)
  * [1 利用该漏洞的第一种场景](#1-利用该漏洞的第一种场景)
  * [2 利用该漏洞的第二种场景](#2-利用该漏洞的第二种场景)
* [Bug6: 允许Transaction secondary请求设置为任意transaction类型](#bug6-允许transaction-secondary请求设置为任意transaction类型)
* [Bug7: SrvOs2FeaListSizeToNt中的类型分配错误](#bug7-srvos2fealistsizetont中的类型分配错误)
* [Bug8: SrvOs2GeaListSizeToNt中的类型分配错误](#bug8-srvos2gealistsizetont中的类型分配错误)
* [Bug9: SESSION_SETUP_AND_X请求格式混淆漏洞](#bug9-session_setup_and_x请求格式混淆漏洞)
* [补充：永恒之蓝到底是如何实现利用的](#补充永恒之蓝到底是如何实现利用的)
  * [1. Srvnet缓冲区简述](#1-srvnet缓冲区简述)
  * [2. 永恒之蓝利用细节](#2-永恒之蓝利用细节)
* [参考资料](#参考资料)

## 0x00 smb transaction概述

### 1. 消息格式

为了能更好地理解后面的漏洞，有必要先了解一下SMB Transaction的相关知识，大多数MS17-010中的漏洞都与transaction有关。当然，我尽可能简短地介绍。

`译者注` SMB协议是一个通过网络在共享文件、打印设备、命名管道、邮槽之间操作数据的协议。利用该协议，客户端就可以去访问服务器上的共享文件和目录（增删改查）、打印队列和进程间通信服务等，还可以实现客户端和服务器之间的远程过程子协议的认证传输。这些功能落实到实现上，就变成了符合下述SMB消息格式的数据包。

SMB消息格式分为三部分：

|格式     |  长度  |
|--------|--------|
|SMB_header|a fixed 32-bytes|
|SMB_Parameters|a variable length parameter block |
|SMB_Data|a variable length data block|

根据微软官方文档，SMB消息根据功能可大致分为如下类别：

* Session management
* Transaction subprotocol
* File/directory access methods
* Read/write/lock methods
* Query directory information
* Query/set attributes methods
* Printing methods
* Other
* Obsolete
* Reserved but not implemented

目前SMB协议共包含75种命令，不同命令通过SMB_Header中1字节大小的Command字段来区别定义。其中SMB Transaction子协议包括以下6种命令：

* SMB_COM_TRANSACTION
* SMB_COM_TRANSACTION_SECONDARY
* SMB_COM_TRANSACTION2
* SMB_COM_TRANSACTION2_SECONDARY
* SMB_COM_NT_TRANSACT
* SMB_COM_NT_TRANSACT_SECONDARY

`译者注` 其中SMB_COM_TRANSACTION命令用于和邮槽、命名管道进行通信。SMB_COM_TRANSACTION2命令用于打开或创建一个共享文件或文件夹，设置它们的扩展属性。SMB_COM_NT_TRANSACT命令用于打开或创建一个文件或文件夹，并应用扩展属性EA或安全描述符SD。

SMB\_COM\_\*TRANSACT\*\_SECONDARY的作用就是，当一个需要发送的transaction消息的实际长度超过SMB\_Parameters中MaxBufferSize字段能够定义的最大长度时，客户端必须通过一个或多个SMB\_COM\_\*TRANSACT\*\_SECONDARY命令来发送剩余的消息内容。SMB\_COM\_\*TRANSACT\*\_SECONDARY必须保证和SMB\_COM\_\*TRANSACT\*命令具有相同的TID、UID、PID和MID。

微软官方文档列举了上述SMB Transaction命令相关的三组子命令码（SMB_COM_*TRANSACT*_SECONDARY只是被用来发送对应较大size的transaction消息），部分摘录如下：

* SMB_COM_TRANSACTION
  * TRANS_MAILSLOT_WRITE 0x0001
  * TRANS_SET_NMPIPE_STATE 0x0001
  * TRANS_RAW_READ_NMPIPE 0x0036
* SMB_COM_TRANSACTION2
  * TRANS2_OPEN2 0x0000
  * TRANS2_FIND_NEXT2 0x0002
  * TRANS2_QUERY_FILE_INFORMATION 0x0007
* SMB_COM_NT_TRANSACT
  * NT_TRANSACT_CREATE 0x0001
  * NT_TRANSACT_SET_SECURITY_DESC 0x0003

`译者注` 这些子命令码分别通过2字节的SMB_Parameters.Words.Setup.Subcommand、SMB_Parameters.Words.Setup、SMB_Parameters.Words.Function字段来区分定义。比较有趣的是，SMB_COM_TRANSACTION中的TRANS_MAILSLOT_WRITE、TRANS_SET_NMPIPE_STATE子命令码完全一致，不知在处理流程上有什么相似的地方，后续可以着重研究一番。

### 2. 实现细节

`译者注` 前面已经介绍过，一个完整的SMB消息包含SMB_Header、SMB_Parameters和SMB_Data三部分。

SMB_Header主要定义了各种SMB命令的命令码、TID、PID、UID、MID等字段：
```c
SMB_Header
{
    UCHAR  Protocol[4];
    UCHAR  Command;  //命令码
    SMB_ERROR Status;
    UCHAR  Flags;
    USHORT Flags2;
    USHORT PIDHigh;
    UCHAR  SecurityFeatures[8];
    USHORT Reserved;
    USHORT TID;
    USHORT PIDLow;
    USHORT UID;
    USHORT MID;
}
```

同一Transaction消息序列中的SMB数据包的TID、PID、UID、MID必须保持一致。

SMB_Parameters主要包含用于管理Transaction消息的一些标志和设置信息，为服务端处理提供必要的上下文环境。以SMB_COM_TRANSACTION命令为例，其SMB_Parameters格式如下：
```c
SMB_Parameters
{
   UCHAR  WordCount;
   Words
   {
     USHORT TotalParameterCount;
     USHORT TotalDataCount;
     USHORT MaxParameterCount;
     USHORT MaxDataCount;
     UCHAR  MaxSetupCount;
     UCHAR  Reserved1;
     USHORT Flags;
     ULONG  Timeout;
     USHORT Reserved2;
     USHORT ParameterCount;
     USHORT ParameterOffset;
     USHORT DataCount;
     USHORT DataOffset;
     UCHAR  SetupCount;
     UCHAR  Reserved3;
     USHORT Setup[SetupCount];  //3种Transaction子命令的该字段略有不同
   }
}
```
SMB_COM_TRANSACTION命令的Setup结构定义了其下属的子命令码、FID等设置信息：
```c
Setup
{
   USHORT Subcommand;
   USHORT FID;
}
```
在SMB_COM_TRANSACTION2命令中，Setup字段只存放2字节的子命令码，无其它设置信息。与前两种Transaction命令不同的是，SMB_COM_NT_TRANSACT中的SMB_Parameters部分将子命令码单独定义在Function字段，根据子命令码的不同定义不同的Setup内容：
```c
SMB_Parameters
{
   ......
   UCHAR  SetupCount;
   USHORT Function;
   USHORT Setup[SetupCount];
   ......
}
```
SMB_Data主要包含了用于服务端操作的参数和数据：
```c
SMB_Data
{
   USHORT ByteCount;
   Bytes
   {
     SMB_STRING Name;
     UCHAR      Pad1[];
     UCHAR      Trans_Parameters[ParameterCount];
     UCHAR      Pad2[];
     UCHAR      Trans_Data[DataCount];
   }
}
```
根据这些对SMB消息格式的描述可知，Transaction消息中包含Setup、Trans_Parameters和Trans_Data等可变大小的内容，分别提供客户端与服务端之间进行Transaction交互期间的配置、参数和数据。无论客户端发送给服务端的SMB请求，还是服务端发送给客户端的SMB响应，都包含这些可变内容。在SMB请求中，被称之为InSetup、InParameters和InData；在SMB响应中，被称之为OutSetup、OutParameters和OutData。这些缓冲区在当前数据包中的长度、在整个Transaction消息的总长度以及允许的最大长度，都在SMB_Prameters的部分字段体现：

| 缓冲区 | 关联字段	 |
|--------|--------|
|SMB_Prameters.Setup       |SetupCount、MaxSetupCount        |
|SMB_Data.Trans_Parameters |ParameterCount 、TotalParameterCount、MaxParameterCount|
|SMB_Data.Trans_Data       |DataCount、TotalDataCount、MaxDataCount|

服务端会将从客户端接收的InSetup、InParameters和InData，同后续需要响应给客户端的OutSetup、OutParameters和OutData等内容存放在同一个缓冲区中，称之为Transaction data buffer。需要注意的是，这些数据之间不是单纯的前后顺序排列，很多都是重叠的。

同时，服务端还会定义一个TRANSACTION结构体，用于存放指向Transaction data buffer缓冲区中上述6种数据的指针，与之相关的*Count、Total*Count、Max*Count等字段，以及TID、PID、UID标识符等配置信息。

接下来介绍一下Windows SMB transaction的实现细节。

`01` TRANSACTION结构体和Transaction data buffer总是分配在同一个缓冲区，在内存中它们是相邻的：
```bash
+-----------------+--------------------------------------------+
|   TRANSACTION   |   transaction data buffer                  |
+-----------------+--------------------------------------------+
```
`译者注` TRANSACTION和Transaction data buffer共同组成了的缓冲区称之为Transaction buffer。

`02` Transaction buffer位于分页内存池缓冲区中。

`03` 对于Size小于等于0x5000的Transaction buffer，Windows采用快表为其分配缓冲区，并且整个缓冲区的size将被设置为0x5000，即使起初申请的大小只有0x100；对于Size大于0x5000的Transaction buffer，Windows直接从分页内存池中为其分配缓冲区。如果SMB_COM_TRANSACTION命令的SetupCount字段被置为0，无论Size大小是多少，都会直接从分页内存池中分配。

`04` TRANSACTION结构体中一些重要的成员变量：

* InSetup：指向transaction data buffer中接收的Setup的指针
* OutSetup：指向transaction data buffer中响应的setup的指针（当接收完所有Transaction数据且还未存入transaction data buffer时设置该指针）
* InParameters：指向transaction data buffer中接收的trans_parameters的指针
* OutParameters：指向transaction data buffer中响应的trans_parameters的指针
* InData：指向transaction data buffer中接收的trans_data的指针
* OutData：指向transaction data buffer中响应的trans_data的指针
* SetupCount：Transaction请求中包含的setup元素的个数（每个元素占2字节），它决定了InSetup缓冲区的大小
* MaxSetupCount：Transaction响应中客户端能接收的setup的最大字节数，它决定了OutSetup缓冲区的大小
* ParameterCount：当前请求数据包中接收的trans_parameter的字节数，或响应数据包中trans_parameter的大小
* TotalParameterCount：同一transaction请求序列中所有SMB数据包trans_parameter全部字节数，它决定了InParameters缓冲区的大小
* MaxParameterCount：Transaction响应中客户端能接收的trans_parameter的最大字节数，它决定了OutParameters缓冲区的大小
* DataCount：当前请求数据包中接收的trans_data的字节数，或响应数据包中trans_data的大小
* TotalDataCount：同一transaction请求序列所有SMB数据包trans_data的全部字节数，它决定了InData缓冲区的大小
* MaxDataCount：Transaction响应中客户端能接收的trans_data的最大字节数，它决定了OutData缓冲区的大小
* Function：定义NT transaction下属子命令码
* Tid：Tree标识符
* Pid：进程标识符
* Uid：用户标识符
* Mid/Fid：Multiplex标识符
* AllDataReceived：当ParameterCount等于TotalParamterCount && DataCount等于TotalDataCount时，该字段被设置为1

`05` 在transaction data buffer中，InParameters、OutParameters、InData、OutData缓冲区有三种布局：

`第一种：` 除TRANS\_MAILSLOT\_WRITE和SetupCount字段置为0的”TRANS“数据包外，其它SMB\_COM\_TRANSACTION数据包的内存布局如下所述，In*和 Out*缓冲区是重叠的：
```bash
+---------------+------------------------------------------------------+
|  TRANSACTION  |             transaction data buffer                  |
+---------------+------------------------------------------------------+
                | InSetup |   InParameters   |      InData       |     |
                +------------------------------------------------------+
                |  OutParameters  |            OutData                 |
                +------------------------------------------------------+
```
`译者注` 重叠的含义是指，InSetup、InParameters、InData所在内存位置，就是OutParameters、OutData所在内存位置。上图中InSetup和OutParameters的起始位置相同。简单来说，上述情况的内存布局可以具体表示为：
```bash
+---------------+------------------------------------------------------+
|  TRANSACTION  | InSetup |   InParameters   |      InData       |     |
+---------------+------------------------------------------------------+
```
或
```bash
+---------------+------------------------------------------------------+
|  TRANSACTION  |  OutParameters  |            OutData                 |
+---------------+------------------------------------------------------+
```
TRANSACTION结构体中的InSetup指针和OutParameters指针在内存中指向的都是同一个内存地址。
`第二种：` 除第一种情况外的其它SMB_COM_TRANSACTION数据包和所有SMB_COM_TRANSACTION2数据包的内存布局如下所述，所有缓冲区都不重叠：
```bash
+---------------+-------------------------------------------------------------------+
|  TRANSACTION  |                  transaction data buffer                          |
+---------------+-------------------------------------------------------------------+
                | InSetup | InParameters |   InData   |  OutParameters  |  OutData  |
                +-------------------------------------------------------------------+
```

`第三种：` SMB_COM_NT_TRANS数据包的内存布局如下所述，InParameters和OutParameters之间、InData和OutData之间的缓冲区都是重叠的：
```bash
+---------------+-----------------------------------------------------------+
|  TRANSACTION  |               transaction data buffer                     |
+---------------+-----------------------------------------------------------+
                | InSetup |      InParameters    |     InData      |        |
                +---------+----------------------+--------------------------+
                |         |  OutParameters  |    |        OutData           |
                +-----------------------------------------------------------+
```

`06` 当ParameterCount等于TotalParamterCount且DataCount等于TotalDataCount时，本次Transaction请求就会被服务端处理。

`07` 当处理transaction请求时，InParameters和InData指针有可能会被修改。

`08` 处理完Transaction请求后，ParameterCount和DataCount字段（通常在被调用的transaction处理函数中设置）被分别用于决定响应数据包中OutParameters和OutData缓冲区的大小。

`09` SMB\_COM\_\*\_SECONDARY请求可以被用来覆盖之前SMB数据包发送的trans\_parameters和trans\_data的内容。无论覆盖的偏移是多少，ParameterCount和DataCount字段都会相应增加。

假设TotalParameterCount为0，TotalDataCount为16。第一个transaction请求中包含8字节的trans_data。如果第二个transaction请求中包含偏移为0的8字节数据（正常情况下偏移应该为8），就会导致第一个transaction请求的8字节数据全部被覆盖，并且接下来的8字节trans_data没有被覆盖。

`译者注` 在SMB\_COM\_\*\_SECONDARY请求中包含ParameterDisplacement和DataDisplacement两个偏移字段，用来定义当前SMB数据包中的trans_parameters和trans_data在InParameters缓冲区和InData缓冲区的偏移。正如上述举例所示，将第二个请求的DataDisplacement偏移设置为0，则第二个请求的Data内容就会覆盖第一个请求的Data内容。

`10` 对于复杂的transaction请求（指的是那些采用secondary才能完成传输过程的Transaction）而言，服务端根据最后一个SMB_COM_*_SECONDARY命令来确定transaction的类型。

如果最后一个命令是SMB_COM_TRANSACTION_SECONDARY，服务端后续会按照TRANS_*处理子命令；如果最后一个命令是SMB_COM_TRANSACTION2_SECONDARY，服务端后续会按照TRANS2_*处理子命令；如果最后一个命令是SMB_COM_NT_TRANSACT_SECONDARY，服务端后续会按照NT_TRANSACT_*处理子命令。

`11` WriteMode字段被设置为RAW_MODE的SMB_COM_WRITE_ANDX命令，也采用Transaction方式在客户端与服务端之间进行数据交互。期间Transaction采用SMB_Parameters.FID代替SMB_Header.MID来实现前后transaction数据包的匹配。

上述关于SMB Transaction的知识已经足够了，下面赶紧开始漏洞细节吧。这些都是通过MS17-010补丁对比发现的。

## Bug1：Transaction InParameters和InData缓冲区未初始化漏洞

`译者注` 通常来说，申请一块内存后的第一件事，就是将这块内存的所有字节初始化为0x00或其它内容。遗憾的是，Transaction data buffer这一点做的并不完善。

微软在SMB协议的实现上，申请Transaction data buffer后并没有将其初始化。如果我们发送多个ParameterDisplacement和DataDisplacement偏移为0的transaction请求，由于ParameterCount和DataCount字段无论偏移是多少都会相应增加（参见实现细节09），因此服务端会将未初始化的trans_parameter和trans_data缓冲区的内容作为后续处理函数的输入数据。

一般情况下，服务端进程会将输入的trans_parameter和trans_data作为不可信数据进行处理（使用前会进行验证），因此未初始化的输入通常并没有什么用处。但是，如果我们能够找到一个可以将输入数据作为输出返回给客户端的transaction命令，就可以利用这个bug来泄露输入中未初始化的数据内容。

这个能够完美利用该bug的transaction子命令就是NT_TRANSACT_RENAME。微软相关文档中将该命令标记为“未实现”，但实际上srv.sys中处理该命令的SrvSmbNtRename函数是有具体实现代码的，其大致伪代码如下所示：
```c
SrvSmbNtRename()
{
    // ParameterCount must be >= 4
    // first 2 bytes of InParameters is fid
    // verify fid
    // if verification failed, return error without data
    // if verification success, return success without modifying OutParameters, ParameterCount, OutData, DataCount
}
```
`译者注` 该函数首先要求ParameterCount字段必须大于等于4，并且InParameters的前两个字节定义为FID字段。然后判断FID是否合法。如果FID不合法，会返回一个错误；如果FID合法，则会返回不作任何修改的OutParameters、ParameterCount、OutData、DataCount等内存数据。

前面实现细节05中已经提到，transaction的InData和OutData的内存区域是重叠的。因此，如果transaction的*Parameter*和*Data*区域不作任何改动，SrvSmbNtRename函数验证FID成功后，实际上返回的是InData缓冲区的内容（类似于echo回显命令）。

要想成功实现回显，对NT_TRANSACT_RENAME命令唯一的要求就是提供一个合法的FID。因此我们首先需要通过打开一个命名管道或共享来从服务端得到一个合法的FID。

由于泄露的信息来自于已经释放了的缓冲区，因此这个bug对漏洞利用并没有太大帮助。并且transaction的长度始终不小于0x5000字节，也很难从中筛选出有效信息。

该bug可能的用途：

* 通过泄露的指针检测目标系统架构是32位还是64位；
* 泄露的内存中可能包含某些重要的数据。

备注：

* 该漏洞并没有被用在NSA武器库中；
* 微软起初推出的补丁只是将InParameters和InData缓冲区初始化为0，由于In*和Out*不完全重叠，因此还是有可能从OutParameters和 OutData缓冲区造成信息泄露。后续5月17号的安全补丁就修复了srv.sys中多个有可能造成OutParameters和OutData缓冲区信息泄露的函数漏洞。未修复前，这些函数都没有将OutParameters和OutData缓冲区初始化为0；
* 5月17号的安全补丁修改了SrvSmbNtRename函数，使其只返回一个错误信息。

## Bug2: TRANS_PEEK_NMPIPE子命令始终期望MaxParameterCount为16

SrvPeekNamedPipe函数用于处理TRANS_PEEK_NMPIPE子命令。它会将命名管道数据trans_data存在OutParameters缓冲区中，具体位于OutParameters+16的内存位置。

`译者注` OutParameters和OutData的内存位置是相邻的，正常情况下命名管道数据存储的内存位置就是OutData缓冲区的起始位置，也就是说OutData Pointer = OutParameters+16。
```c
+------------------------------------------------------+
|  OutParameters  |            OutData                 |
+------------------------------------------------------+
```
如果MaxParameterCount字段等于16，那么OutData正好会指向正确的命名管道数据的内存位置。但如果故意设置MaxParameterCount的值大于16，OutData Pointer = OutParameters + MaxParameterCount，就有可能泄露未初始化的OutData缓冲区。结合后面的bug3，会达到更好的利用效果。

值得注意的是，网上很多扫描器利用这个bug来判断MS17-010是否已经被修补。

SrvAllocationTransaction函数用于申请transaction结构和transaction data缓冲区。如果申请的transaction data缓冲区长度大于0x10400字节，该函数就将指向transaction的指针设置为NULL，然后向客户端返回一个STATUS_INSUFF_SERVER_RESOURCES/0xC0000205错误码。

按照上述逻辑，如果客户端发送一个MaxParameterCount、MaxDataCount二者之和大于0x10400的请求时，理论上应该得到一个0xC0000205的错误码。

不过为了修复上面这个内存泄露漏洞，在调用SrvAllocationTransaction函数之前，MS17-010补丁会将TRANS_PEEK_NMPIPE命令的MaxParameterCount字段强制修改为16。这样就会导致，即使原本MaxParameterCount、MaxDataCount二者之和大于0x10400，如果MaxParameterCount被修改后，二者之和很没有超过0x10400，SrvAllocationTransaction函数就不会返回错误码，反而继续调用SrvPeekNamedPipe函数。而SrvPeekNamedPipe响应给客户端的内容由InSetup的内容决定。

`译者注` 在实际环境中，可以构造TRANS_PEEK_NMPIPE命令请求数据包，保证MaxParameterCount、MaxDataCount满足二者之和大于0x10400，MaxDataCount+16小于0x10400。如果目标主机没有安装MS17-010补丁，则会返回一个0xC0000205错误码；如果目标主机已经修复了这个漏洞，则响应给客户端的内容就不是0xC0000205错误码，而是由InSetup决定。因此可以通过检查TRANS_PEEK_NMPIPE命令响应回来的数据包是否为0xC0000205错误码来判断漏洞是否被修补。

## Bug3: 允许Transaction响应数据长度大于申请的缓冲区长度

SrvCompleteExecuteTransaction函数用于向客户端发送transaction响应，但期间并没有检查ParameterCount/DataCount是否大于MaxParameterCount/MaxDataCount。因此SrvCompleteExecuteTransaction有可能将缓冲区外的内存数据返回给客户端，从而会导致信息泄露。

要想利用这个bug，可以构造一个满足bug2的TRANS_PEEK_NMPIPE子命令，将MaxParameterCount设置为一个很大的数值，MaxDataCount只设置为1。如果transaction响应数据的长度（DataCount）大于MaxDataCount，SrvCompleteExecuteTransaction函数就会将OutData缓冲区及其之后的数据返回给客户端。

`译者注` bug2允许返回给客户端的OutData指针可以指向OutData缓冲区起始地址之后的内存位置，bug3允许返回的缓冲区大小可以超过MaxDataCount规定的长度。这两个bug，一个控制返回数据的起始地址，一个控制返回数据的长度。

此时transaction缓冲区如下所示：
```c
+---------------+-----------------------------------------------------+
|  TRANSACTION  |            transaction data buffer                  |
+---------------+-----------------------------------------------------+
                | InSetup |  InParameters  |       InData       |     |
                +-----------------------------------------------------+------------+
                |           OutParameters                     |OutData|  OOB read  |
                +-----------------------------------------------------+------------+
```
NSA武器库中的Eternalromance就采用bug2和bug3实现了信息泄露。有趣的是，自从win8发布伊始，这个bug就已经在win8及其之后的系统中被修复了。用于win8之前系统的MS17-010补丁，修复这个bug所采用的代码和win8中的代码就是一样的。

`译者注` 为何微软之前已经知道该漏洞的存在，却没有修复？细思甚恐。

由于NSA Eternalromance需要利用这个bug来泄露TRANSACTION结构体的地址，因而它无法在win8之后系统中实现利用。

### Bug4: 允许ParameterCount/DataCount之和大于TotalParameterCount/TotalDataCount

当发送SMB_COM_*_SECONDARY命令时，服务端通过检查displacement的值和trans_data的长度，以确保写入内存的数据不会超出申请的缓冲区大小。但期间并没有检查所有接收的ParameterCount/DataCount之和是否大于TotalParameterCount/TotalDataCount。

举例说明：假设一个transaction的TotalDataCount等于0x20。第一个请求发送0x18字节的数据，DataCount为0x18；第二个请求发送0x10字节的数据，DataCount就变成了0x28。

通常情况下，这个bug没有什么价值，但结合下面的bug5就能实现漏洞利用。

### Bug5: 允许Transaction secondary请求在服务端开始处理transaction后才被接收和处理

如果发送一个设置AllDataReceived字段的transaction secondary请求，服务端默认不作任何处理，直接返回一个错误。

对于需要多个数据包才能完成传输的transaction请求而言，服务端会在处理transaction之前设置好AllDataReceived字段，具体会在SrvSmbTransactionSecondary或SrvSmbNtTransactionSecondary函数中完成。但如果transaction在一个SMB消息中就能完成传输，服务端并不会去设置AllDataReceived。这就可能存在下述漏洞：

在服务端正在处理transaction或正在发送响应数据给客户端期间，可以通过发送一个transaction secondary请求来修改InParamter/InData缓冲区和ParameterCount/DataCount字段的内容。

`译者注` 没有设置AllDataReceived的话，表示服务端还可以继续接收Transaction请求，并将参数和数据存入InParameters和InData缓冲区中，ParameterCount/DataCount字段依旧会相应增加。

### 1. 利用该漏洞的第一种场景

在服务端发送响应数据给客户端期间，向其发送特定的transaction secondary请求（将DataCount修改为超出OutData缓冲区的长度）。结果就会导致，服务端将OutData缓冲区外的内存数据作为响应发送给客户端（类似于bug3）。

但这种利用方法所需条件非常苛刻，必须保证服务端在发送响应数据之前，接收并完成对transaction secondary请求的处理。因此这种场景下看起来很难成功实现利用。

不过NSA武器库中的Eternalchampion和Eternalsynergy却采用了一种非常巧妙的方法来满足上述利用条件。

为了实现SMB登录，客户端会向服务端发送一个SMB_COM_SESSION_SETUP_ANDX请求。请求中包含了用于定义客户端能够接收消息最大字节数的MaxBufferSize字段。

如果transaction响应消息的大小超过了MaxBufferSize字段，服务端就会将整个响应消息分片为多个数据包发送给客户端。为了保证能够连续发送这些数据包，服务端会增加调用RestartTransactionResponse函数的任务队列。另外，该函数并没有检查MaxParameterCount和MaxDataCount是否合法。

根据以上描述，NSA采用了如下利用方式：

先向服务端发送一个携带特定MaxBufferSize字段的SMB_COM_SESSION_SETUP_ANDX登录请求，然后构造两个请求：一个完整的NT_TRANS_RENAME请求（其响应数据长度大于MaxBufferSize）；一个NT_TRANS_RENAME secondary请求（其中的trans_data长度就是要泄露的字节数）。最后，将这两个请求通过一个TCP数据包发送给服务端。

由于服务端同时接收了位于同一个数据包的NT_TRANS_RENAME和NT_TRANS_RENAME secondary请求，因此服务端在发送完NT_TRANS_RENAME响应的第一部分数据之后，服务端队列会先处理NT_TRANS_RENAME secondary请求，再调用RestartTransactionResponse函数发送NT_TRANS_RENAME响应的剩余数据。由于Bug4的存在，在处理NT_TRANS_RENAME secondary请求时，DataCount数值会相应增加（而不会去检查其是否大于TotalDataCount）。这就导致后续服务端发送的transaction响应的剩余内容会携带OutData缓冲区外的内存数据。

Eternalchampion和Eternalsynergy都利用该bug实现信息的泄露。但不知何种原因，二者使用了不同的参数。

### 2. 利用该漏洞的第二种场景

在服务端处理transaction期间，向其发送一个transaction secondary请求。不过很难在服务端处理transaction期间找到能够一种同时处理transaction secondary请求的利用途径。也很难满足“保证先处理完transaction secondary请求，再将上个transaction请求的响应数据返回给客户端”这一苛刻条件。
NSA武器库中的Eternalchampion采用设置SMB_INFO_IS_NAME_VALID查询级别的TRANS2_QUERY_PATH_INFORMATION子命令来实现该漏洞的利用。

`译者注` TRANS2_QUERY_PATH_INFORMATION子命令用于查询指定文件或文件夹中包含的信息，可以通过设置SMB_Data.Trans2_Parameters.InformationLevel字段来指定查询信息的级别。

如果信息级别设置为SMB_INFO_IS_NAME_VALID，SrvSmbQueryPathInformation处理函数就会修改InData指针，使其指向在栈中申请的UNICODE_STRING结构体。如果此时服务端能够在Transaction处理完成之前，转去处理transaction secondary请求，那么保存着EIP/RIP的栈内存就会被transaction secondary请求中包含特定偏移的trans_data和dataDisplacement所覆盖。（也就是说，我们可以控制栈中包含函数返回地址。）

由于栈中的偏移总是固定的，因此NSA Eternalchampion这种利用方式并不会导致目标主机出现崩溃。

`备注：` 在SrvSmbWriteAndX函数中也发现了针对该bug的修复补丁。

## Bug6: 允许Transaction secondary请求设置为任意transaction类型

通常情况下，如果第一个SMB数据包没有完成transaction数据的传输，后续数据包必须满足如下条件：

* SMB_COM_TRANSACTION后必须跟着SMB_COM_TRANSACTION_SECONDARY
* SMB_COM_TRANSACTION2后必须跟着SMB_COM_TRANSACTION2_SECONDARY
* SMB_COM_NT_TRANS后必须跟着SMB_COM_NT_TRANS_SECONDARY

但实际上，服务端并没有对Secondary数据包的类型进行检查。因此，可以通过发送任意类型的transaction secondary命令来完成transaction数据的传输，只需保证TID、UID、PID和MID匹配即可。

别忘了，服务端根据最后一个SMB_COM_*_SECONDARY数据包判断transaction命令的类型，因此通过最后一个Secondary请求，我们可以将任意transaction类型转变为SMB_COM_TRANSACTION或SMB_COM_TRANSACTION2类型。由于SMB_COM_NT_TRANS需要通过Function字段确定子命令类型（另外两个命令没有Function字段），故无法将非SMB_COM_NT_TRANS类型转换为SMB_COM_NT_TRANS类型。

NSA武器库中的Eternalblue利用该bug，使得TRANS2_OPEN2命令可以传输大于0x10000字节的transaction数据。由于只有SMB_COM_NT_TRANS请求的TotalDataCount为4个字节，其它类型请求的TotalDataCount都为2个字节。因此漏洞利用需要先发送一个SMB_COM_NT_TRANS请求将TotalDataCount定义为大于0xFFFF字节，然后再发送SMB_COM_TRANSACTION2_SECONDARY请求，完成TRANS2_OPEN2命令中所有transaction数据的传输。

在前面的介绍（实现细节11）中已经提及，当WriteMode字段被设置为RAW_MODE时，SMB_COM_WRITE_ANDX命令也会采用transaction方式传递数据。这是一种非常有趣的情况，因为SrvSmbWriteAndX函数会利用下述代码向transacation中写入数据：
```c
memmove(transaction->Indata, request->data, request->dataLength);
transaction->InData += request->dataLength; //移动InData指针
transaction->DataCount += request->dataLength;
```
需要注意的是，SrvSmbWriteAndX在向缓冲区中写入数据时，会移动InData的指针；而transaction secondary请求使用dataDisplacement字段设置在InData缓存区中写入数据的位置（而不移动InData指针）。

假设我们首先创建一个TotalDataSize设置为0x2000的transaction传输过程，MID与打开命名管道的FID保持一致。此时的内存布局如下所示（省略了无关的OutParameters和OutData）：
```bash
+---------------+-----------------------------------------------------+
|  TRANSACTION  |            transaction data buffer                  |
+---------------+-----------------------------------------------------+
                | InSetup |   InParameters   |        InData          |
                +-----------------------------------------------------+
```
然后发送一个WriteMode设置为RAW_MODE、trans_data大小为0x100字节的SMB_COM_WRITE_ANDX命令。如果我们再向服务端发送dataDisplacement等于0x1f??的transaction secondary数据包，显而易见：

> 0x1f?? + 0x100 > 0x2000

Trans_data大小为0x100字节SMB_COM_WRITE_ANDX命令会将InData指针向后移动0x100字节，写入的数据也会超出原本申请的transaction data缓冲区的范围。如下所示：
```bash
+---------------+-----------------------------------------------------+
|  TRANSACTION  |            transaction data buffer                  |
+---------------+-----------------------------------------------------+
                | InSetup |   InParameters   |    |        InData             |
                +-----------------------------------------------------+
```
这种越界写漏洞可以实现非常好的漏洞利用效果，但需要提前为上述SMB_COM_WRITE_ANDX命令提供一个有效的命名管道FID。而Vista之后系统，默认的Windows配置已经不允许匿名登陆（NULL）访问任何命名管道。

`备注：`NSA武器库中的Eternalromance和Eternalsynergy都利用这个bug实现了越界写的效果。另外，Eternalromance还利用Bug3来泄露transaction结构体的地址（只在win8之前系统有效）。而Eternalsynergy利用的是Bug5，并采用了一些技巧在Win8和Win2012中寻找具有NonPagedPoolExecute属性的内存页。两个工具还采用一种增大内存页的方式向我们展示了另外一种堆喷射的方法。

### Bug7: SrvOs2FeaListSizeToNt中的类型分配错误

SMB_COM_TRANSACTION2命令用于对文件或文件夹的`拓展属性EA的名称/数值对`进行编码，客户端的请求中使用了SMB_FEA数据结构：

```c
SMB_FEA
{
  UCHAR      ExtendedAttributeFlag;
  UCHAR      AttributeNameLengthInBytes;
  USHORT     AttributeValueLengthInBytes;
  UCHAR      AttributeName[AttributeNameLengthInBytes + 1];
  UCHAR      AttributeValue[AttributeValueLengthInBytes];
}
```

通常在发送的SMB_COM_TRANSACTION2子命令请求中，含有承载多个SMB_FEA数据结构的FEA_LIST列表：

```c
SMB_FEA_LIST
{
  ULONG SizeOfListInBytes;
  UCHAR FEAList[];
}
```
当服务端处理这些含有FEA_LIST的SMB_COM_TRANSACTION2子命令请求时，会将其转换为FILE_FULL_EA_INFORMATION数据结构的列表：

```c
typedef struct _FILE_FULL_EA_INFORMATION {
  ULONG  NextEntryOffset;
  UCHAR  Flags;
  UCHAR  EaNameLength;
  USHORT EaValueLength;
  CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;
```

SrvOs2FeaListToNt函数会通过如下伪代码完成转换：
```c
SrvOs2FeaListToNt()
{
    outputLen = SrvOs2FeaListSizeToNt(feaList);
    output = SrvAllocateNonPagedPool(outputLen);
    // start copy all FEA data to output in a list of FILE_FULL_EA_INFORMATION format
}
```
SrvOs2FeaListToNt先调用SrvOs2FeaListSizeToNt，根据原始FEA_LIST计算出FILE_FULL_EA_INFORMATION列表缓冲区长度，然后调用SrvAllocateNonPagedPool申请新的缓冲区，最后将所有SMB_FEA数据以FILE_FULL_EA_INFORMATION格式拷贝到新的缓冲区。漏洞出现在用于计算新缓冲区长度的SrvOs2FeaListSizeToNt函数：
```c
SrvOs2FeaListSizeToNt(feaList)
{
  outputLen = 0;
  foreach (fea in feaList) {
    if (IsFeaDataOutOfBound(fea, feaList)) {
      // 缩小FEAfeaList.SizeOfListInBytes的范围只在合法的FEA中，因此拷贝步骤不会再检查其合法性
      // feaList.SizeOfListInBytes定义为DWORD但却以WORD类型设置，因此HIDWORD永远不会被修改
      (WORD) feaList.SizeOfListInBytes = Pos(fea) - Pos(feaList);
      return outputLen;
    }
    outputLen += GetNtLengthForFea(fea);
  }
  return outputLen;
}
```

根据上面伪代码的描述，如果发送一个feaList.SizeOfListInBytes为0x10000字节，但有效的FEA条目却小于0x10000字节（假设为0x4000）的请求。经过上述错误类型的长度计算，feaList.SizeOfListInBytes就变成了0×14000（因为HIDWORD没有被修改而Pos(fea) – Pos(feaList)得到的结果为0×4000）。后续拷贝SMB_FEA数据到输出区域时，就会导致缓冲区溢出。

要想成功实现利用，需要发送一个大于0×10000字节的transaction data，但FEA_LIST结构只在SMB_COM_TRANSACTION2命令中存在，TotalDataCount字段类型是USHORT（最大值为0xFFFF），因此我们需要利用Bug6（借助SMB_COM_NT_TRANS命令）来发送一个大于0×10000字节的FEA_LIST。

所需条件最少的漏洞利用途径是采用TRANS2_OPEN2子命令。处理该命令的SrvSmbOpen2函数，在权限检查之前会调用SrvOs2FeaListToNt函数转换FEA_LIST列表。因此，客户端只需访问服务端任意一个共享（IPC$是最好的选择），然后发送符合上述要求的transaction命令即可。

需要注意的是，Win8以上操作系统默认不允许匿名连接访问IPC$（IPC$可以连接上，但大部分transaction命令都无法使用）。

## Bug8: SrvOs2GeaListSizeToNt中的类型分配错误

该bug和bug7类似，只是出现在与上述不同的SrvOs2GeaListSizeToNt函数。要想利用，必须提供有效的FID才行。

## Bug9: SESSION_SETUP_AND_X请求格式混淆漏洞

该bug在MS17-010补丁中并没有被修复，将它放在这，是因为NSA武器库借助了该bug来实现漏洞的利用。该Bug本身只能欺骗服务端，来申请一个大的非分页内存池（小于0×20000字节），来存储客户端信息。

在NT LM 0.12中，包含两种格式的SMB_COM_SESSION_SETUP_ANDX请求。第一种格式：
```c
SMB_Parameters
{
   UCHAR  WordCount;  //13
   Words
   {
     UCHAR  AndXCommand;
     UCHAR  AndXReserved;
     USHORT AndXOffset;
     USHORT MaxBufferSize;
     USHORT MaxMpxCount;
     USHORT VcNumber;
     ULONG  SessionKey;
     USHORT OEMPasswordLen;
     USHORT UnicodePasswordLen;
     ULONG  Reserved;
     ULONG  Capabilities;
   }
}
SMB_Data
{
   USHORT ByteCount;
   Bytes
   {
     UCHAR      OEMPassword[];
     UCHAR      UnicodePassword[];
     UCHAR      Pad[];
     SMB_STRING AccountName[];
     SMB_STRING PrimaryDomain[];
     SMB_STRING NativeOS[];
     SMB_STRING NativeLanMan[];
   }
}
```
该请求用于LM和NTLM的身份认证。

另外一种格式：
```c
SMB_Parameters
{
   UCHAR  WordCount;  //12
   Words
   {
     UCHAR  AndXCommand;
     UCHAR  AndXReserved;
     USHORT AndXOffset;
     USHORT MaxBufferSize;
     USHORT MaxMpxCount;
     USHORT VcNumber;
     ULONG  SessionKey;
     USHORT SecurityBlobLength;
     ULONG  Reserved;
     ULONG  Capabilities;
   }
}
SMB_Data
{
   USHORT ByteCount;
   Bytes
   {
     UCHAR      SecurityBlob[SecurityBlobLength];
     SMB_STRING NativeOS[];
     SMB_STRING NativeLanMan[];
   }
}
```
该请求用于NTLMv2（NTLM SSP）的身份认证。

需要注意的是，两种格式的WordCount是不同的（第一种格式为13，第二个格式为12）。

BlockingSessionSetupAndX函数用于处理上述两种格式的SMB_COM_SESSION_SETUP_ANDX请求，其伪代码如下所述：
```c
BlockingSessionSetupAndX()
{
    // ...
    // check word count
    if (! (request->WordCount == 13 || (request->WordCount == 12 && (request->Capablilities & CAP_EXTENDED_SECURITY))) ) {
        // error and return
    }
    // ...
    if ((request->Capablilities & CAP_EXTENDED_SECURITY) && (smbHeader->Flags2 & FLAGS2_EXTENDED_SECURITY)) {
        // this request is Extend Security request
        GetExtendSecurityParameters();  // extract parameters and data to variables
        SrvValidateSecurityBuffer();  // do authentication
    }
    else {
        // this request is NT Security request
        GetNtSecurityParameters();  // extract parameters and data to variables
        SrvValidateUser();  // do authentication
    }
    // ...
}
```
由上可知，如果发送Extended Security的SMB_COM_SESSION_SETUP_ANDX请求（WordCount为12）。数据包中含有CAP_EXTENDED_SECURITY，但没有FLAGS2_EXTENDED_SECURITY。服务端会将其当作NT Security请求来处理（WordCount为13）。

我们也能修改请求数据包，使服务端将其当作包含CAP_EXTENDED_SECURITY和FLAGS2_EXTENDED_SECURITY的NT Security请求（WordCount为13）。

但后一种情况没有什么用处，因为在GetExtendSecurityParameters函数中针对ByteCount数值又做了额外的检查。

通常，服务端会在调用不同命令的处理函数之前，通过SrvValidateSmb函数验证WordCount和ByteCount字段的合法性。WordCount*2和ByteCount不能超过实际接收的data大小。

利用上述混淆漏洞（将WordCount为12的Extended Security请求，当作WordCount为13的NT Security请求来处理），当服务端从数据包中提取parameters和data时，可以实现从错误的位置读取ByteCount的数值。

由于ByteCount数值只是用来计算缓冲区的大小，以便存储NativeOS和NativeLanMan的unicode字符串（UTF16），因此这个bug并不会引起任何内存崩溃或信息泄露。NativeOS和NativeLanMan的大小根据“ByteCount – other_data_size”计算，并且它们使用的缓冲区从分页内存池中申请。

NSA武器库中的Eternalchampion利用这个漏洞，将UNICODE_STRING.MaximumLength设置为0x15ff，并将shellcode载荷存放在这个缓冲区中。由于非分页内存池在win8之前系统是可以被执行的，因此只要后续能调用该缓冲区（利用上面的越界写漏洞），就能实现shellcode载荷的执行。

NSA武器库中的Eternalblue也利用这个bug在服务端内存中创建一个可控的缓冲区，攻击者可以控制该缓冲区的申请或释放。

`备注：` 当NTLM身份认证被禁止时，就无法利用该bug了。


## 补充：永恒之蓝到底是如何实现利用的

`译者注` 大部分童鞋看过上述漏洞原理，应该对MS17-010有了更清晰的认识。但只根据上面的信息，却不一定能完全理解针对这些漏洞的实际利用方法。如果非要让某个童鞋解释一下永恒之蓝到底是如何实现利用的，很可能还是说不出个所以然来。因此，根据原作者在Github上提供的POC等相关提示，下面以最经典的永恒之蓝为例，详细描述一下实现漏洞利用的具体细节。不当之处，敬请指正。

### 1. Srvnet缓冲区简述

在讲解漏洞利用细节之前，还需要了解一些有关srvnet缓冲区的内容。

在服务端的SMB服务进程中，除了第一部分讲述的用来存储客户端SMB消息的Transaction缓冲区外，还有与SMB处理有关的srvnet缓冲区。

Srvnet缓冲区共包含两部分内容：一个指向特定结构体的指针和一个接收缓冲区的内存描述列表MDL。

由于MDL中描述了虚拟内存和物理内存页之间的关系，控制MDL的值就能实现任意地址写入；而上述指针指向的结构体中，包含着指向SMB命令处理函数的指针。因此如果能够控制该指针，将其指向我们构造的假结构体。后续调用SMB命令处理函数时，就能实现shellcode代码的执行。

目标主机创建并使用Srvnet缓冲区的步骤：

（1）服务端接收前4个字节后，就会在内存中创建一个Srvnet缓冲区。Srvnet缓冲区可能的长度为“...、0x9000、0x11000、0x21000、...”。服务端会根据前4个字节中包含的SMB消息长度，从中选择一个足够大的长度。

（2）在接收整个SMB消息或连接丢失后，服务端会调用SrvNetWskReceiveComplete函数处理SMB消息。该函数首先检查并设置某些参数后，就将SMB消息传递给SrvNetCommonReceiveHandler函数。

（3）SrvNetCommonReceiveHandler函数根据Srvnet缓冲区中的结构体指针，从里面找到SMB命令处理函数的内存地址，最终将SMB消息传递给对应的SMB命令处理函数进行处理。

`译者注` 前面九个Bug都是在SMB命令处理函数处理过程中出现的。

如果srvnet缓冲区中的结构体指针被修改指向了假的结构体，而假结构体中SMB命令处理函数指针指向了我们的Shellcode载荷，那么就能使SrvNetCommonReceiveHandler函数去调用Shellcode载荷，而非SMB命令处理函数。

需要注意的是，通常SMB命令处理函数在处理完SMB消息时，会释放掉申请的Srvnet缓冲区，但Shellcode却没有该功能。Srvnet缓冲区不被释放的话，就会造成内存泄露。不过这个问题并不会造成太大影响，因此可以忽略不记。

### 2. 永恒之蓝利用细节

首先要明确的是，永恒之蓝共使用了前面提及的3个漏洞：

* Bug7：SrvOs2FeaListSizeToNt中的类型分配错误，利用该bug的缓冲区溢出实现“越界写”的效果；
* Bug6: 允许Transaction secondary请求设置为任意transaction类型，利用该bug实现“以SMB_COM_NT_TRANSACT传输较大长度（大于0xFFFF）的transaction消息，而后续以SMB_COM_TRANSACTION2类型进行处理”的效果；
* Bug9: SESSION_SETUP_AND_X请求格式混淆漏洞，通过发送一个特殊的session setup命令来申请一个非分页内存池（用来创建一个可控的缓冲区）。

具体实现细节如下：

永恒之蓝首先通过申请多个Srvnet缓冲区，利用HAL堆喷射，在特定内存位置（x64系统中为0xffffffffffd00010）存放一个假的结构体和Shellcode载荷。

借助上述漏洞，申请一个位于非分页内存池（Bug9），用于存放后续转换FEA_LIST需要的新缓冲区。然后通过一定的技巧，在该缓冲区之后申请一个Srvnet缓冲区。

利用Secondary请求，再向服务端发送一个长度较大、且包含特定FEA_LIST的TRANS2_OPEN2命令（Bug6）。服务端在转换FEA_LIST时就会导致缓冲区溢出（Bug7），将后续Srvnet缓冲区覆盖掉，修改其中的结构体指针，使其指向已经构造好的假结构体，假结构体中的SMB命令处理函数指针指向了Shellcode载荷。

当SrvNetCommonReceiveHandler函数调用SMB命令处理函数指针时，实际上就执行了Shellcode。

## 参考资料

原文：
* https://github.com/worawit/MS17-010/blob/master/BUG.txt

补充：
* https://github.com/worawit/MS17-010/blob/master/eternalblue_exploit7.py
* https://github.com/worawit/MS17-010/blob/master/eternalblue_exploit8.py