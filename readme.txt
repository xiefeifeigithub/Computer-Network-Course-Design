实验二 网络层实验—Ping程序的设计与实现

本实验为ICMP实验。实验内容：Ping命令实现的扩充，在给定的Ping程序的基础上做如下功能扩充：
	-h	显示帮助信息  ./ping_2 -h
	-b	允许ping一个广播地址，只用于IPv4  ./ping_2 -b <所在网络广播地址>
	-t  设置ttl值，只用于IPv4   ./ping_2 -t 10 www.baidu.com
	-q	安静模式。不显示每个收到的包的分析结果，只在结束时，显示汇总结果  ./ping_2 -q www.baidu.com
    -c  发送指定个数的数据包   ./ping_2 -c 10 www.baidu.com
	-r  接收指定个数的数据包   ./ping_2 -r 10 www.baidu.com
    -s  发送指定大小的数据包   ./ping_2 -s 60 www.baidu.com
	-c  设置发送包的个数       ./ping_2 -c 5 www.baidu.com
    -r  设置收到包的个数       ./ping_2 -r 5 www.baidu.com
    -i  设置发送包的时间间隔   ./ping_2 -i 5 www.baidu.com
    -t  设置包的初始序列号     ./ping_2 -n 1 www.baidu.com

注意：
1. 某些特定局域网可能会应为防火墙的原因无法ping，建议连接手机热点。
1. 在Linux命令行中输入 sudo -s -H 切换到root权限,目的是为了创建raw stock（原始套接字）。
2. 编译命令：gcc ping_2.c -lpthread -o ping_2  
3. 执行可执行文件  ./ping_2  [-v] [-h] [-b] [-t ttl] [-q] [-c number] [-r number] [-i times] [-n seq_num] <hostname>\n"