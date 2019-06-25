实验二 网络层实验—Ping程序的设计与实现
2.1 课程设计目的
本实验目的是使学生掌握网络层协议的原理及实现方法。
2.2 课程设计内容
本实验为ICMP实验。实验内容：Ping命令实现的扩充，在给定的Ping程序的基础上做如下功能扩充：
	-h	显示帮助信息
	-b	允许ping一个广播地址，只用于IPv4
	-t  设置ttl值，只用于IPv4
	-q	安静模式。不显示每个收到的包的分析结果，只在结束时，显示汇总结果

Ping命令的基本描述
Ping的操作是向某些IP地址发送一个ICMP Echo消息，接着该节点返回一个ICMP Echo replay消息。
ICMP消息使用IP头作为基本控制。IP头的格式如下
0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
   Version=4
   IHL   Internet头长
   Type of Service = 0
   Total Length IP包的总长度
   Identification, Flags, Fragment Offset 用于IP包分段
   Time to Live IP包的存活时长
   Protocol  ICMP = 1
   Addresses  发送Echo消息的源地址是发送Echo reply消息的目的地址,相反,发送Echo 消息的目的地址是发送Echo reply消息的源地址。




Ping实际上是使用ICMP中的ECHO报文来实现的。Echo 或 Echo Reply 消息格式如下:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-
Type
echo消息的类型为8
    echo reply 的消息类型为0。
Code=0
Checksum
为从TYPE开始到IP包结束的校验和
Identifier
    如果 code = 0, identifier用来匹配echo和echo reply消息
Sequence Number
    如果 code = 0, identifier用来匹配echo和echo reply消息
功能描述:
    收到echo 消息必须回应 echo reply 消息。
    identifier 和 sequence number 可能被发送echo的主机用来匹配返回的
    echo reply消息。例如:  identifier 可能用于类似于TCP或UDP的 port
    用来标示一个会话, 而sequence number 会在每次发送echo请求后递增。
    收到echo的主机或路由器返回同一个值与之匹配
1、	数据结构的描述
1) IP包格式
struct ip {
    	BYTE Ver_ihl;    //版本号与包头长度
		BYTE TOS;        //服务类型
		WORD Leng;       //IP包长度
		WORD Id;         //IP包标示,用于辅助IP包的拆装,本实验不用,置零
		WORD Flg_offset; //偏移量,也是用于IP包的拆装,本实验不用,置零
		BYTE TTL;        //IP包的存活时间
		BYTE Protocol;   //上一层协议,本实验置ICMP
		WORD Checksum; //包头校验和,最初置零,等所有包头都填写正确后,计算并替换。
		BYTE Saddr[4];   //源端IP地址
		BYTE Daddr[4];   //目的端IP地址
		BYTE Data[1];    //IP包数据
};

2）ICMP包格式
struct icmp {
		BYTE Type;		 //ICMP类型,本实验用 8: ECHO  0:ECHO  REPLY
		BYTE Code;       //本实验置零
		WORD Checksum;   //ICMP包校验和,从TYPE开始,直到最后一位用户数据,如果为
字节数为奇数则补充一位
		WORD ID;         //用于匹配ECHO和ECHO REPLY包
		WORD Seq;        //用于标记ECHO报文顺序
		BYTE Data[1];    //用户数据
};
2.3 课程设计分析
1、	总体设计
程序分为两大部分：一部分读取收到的所有消息，并输出ICMP Echo replay消息，另一部分每个一秒钟发送一个Echo消息。另一部分由SIGALARM信号每秒驱动一次。
2、	详细设计
 ping程序函数概貌






1）main函数
 

2）readloop函数
 
3）proc函数
 
4）send函数
  

