#ifndef PING_2_H_
#define PING_2_H_
#include 	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/icmp6.h>
#include	<netinet/ip6.h>
#include	<sys/types.h>	/* basic system data types */
#include	<sys/socket.h>	/* basic socket definitions */
#include	<sys/time.h>	/* timeval{} for select() */
#include	<time.h>		/* timespec{} for pselect() */
#include	<netinet/in.h>	/* sockaddr_in{} and other Internet defns */
#include	<arpa/inet.h>	/* inet(3) functions */
#include	<netdb.h>
#include	<signal.h>

#include <math.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include 	<pwd.h>
#include	<unistd.h>
#include	<sys/un.h>		/* for Unix domain sockets */
#include	<sys/ioctl.h>
#include	<net/if.h>
#include <stdarg.h>
#include <syslog.h>
#ifdef  HAVE_SOCKADDR_DL_STRUCT
# include       <net/if_dl.h>
#endif

#define BUFSIZE		1500
#define MAXLINE         4096




/* globals */
char	 recvbuf[BUFSIZE];
char	 sendbuf[BUFSIZE];
int ttl_signal;
int ttl_value;
char *ttl_val;
int    datalen;	/* #bytes of data, following ICMP header */
char	*host;
int   broad_sign=0;
int	 nsent;			/* add 1 for each sendto() */
pid_t pid;			/* our PID */
int	 sockfd;
int	 verbose;
int    daemon_proc;            /* set nonzero by daemon_init() */

/* function prototypes */
void	 proc_v4(char *, ssize_t, struct timeval *);
void	 proc_v6(char *, ssize_t, struct timeval *);
void	 send_v4(void);
void	 send_v6(void);
void	 readloop(void);
void	 sig_alrm(int);
void     sig_int(int signo);
void	 tv_sub(struct timeval *, struct timeval *);

char * Sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
struct addrinfo* host_serv(const char *host, const char *serv, int family, int socktype);
void err_quit(const char *fmt,...);
void err_sys(const char *fmt,...);
static void err_doit(int errnoflag, int level, const char *fmt, va_list ap);

struct proto {
  void	 (*fproc)(char *, ssize_t, struct timeval *);  //fproc 是指向用于处理接收到ICMP包的函数的指针,
  void	 (*fsend)(void);  //fsend 是指向用于发送ICMP数据包的函数的指针
  struct sockaddr  *sasend;	/* sockaddr{} for send, from getaddrinfo */  //sasend 是指向目标主机的地址信息的指针
  struct sockaddr  *sarecv;	/* sockaddr{} for receiving */   //sarecv 指示从哪接收ICMP数据包
  socklen_t	    salen;		/* length of sockaddr{}s */  //salen 以上两个地址结构的大小
  int	   	    icmpproto;	/* IPPROTO_xxx value for ICMP */  //icmpproto 指示使用的ICMP协议值, IPPROTO_ICMP 或 IPPROTO_ICMPV6
} *pr;


#endif /* PING_2_H_ */





