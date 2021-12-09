//HRH Prince Sven Olaf of CyberBunker-Kamphuis
//CB3ROB TACTICAL SYSTEMS
//One CyberBunker Avenue
//Republic CyberBunker

//DEFAULT KISS-TCP PORTS:

// Fldigi   7342
// AGWPE    8001
// CB3ROB   8001
// Direwolf 8001
// UZ7HO    8100

//COMPILE WITH gcc -O3 -o cb3rob-kiss-tcp-attach cb3rob-kiss-tcp-attach.c -lutil
//openpty() REQUIRES -lutil

//TO BRING UP AN AX.25 KISS INTERFACE (ax0,ax1,etc) TO A KISS TNC OR KISS CONCENTRATOR SERVER:

// ./cb3rob-kiss-tcp-attach NOCALL 208.109.9.123 8001 &

#include<arpa/inet.h>
#include<fcntl.h>
#include<linux/ax25.h>
#include<linux/if.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
#include<linux/if_slip.h>
#include<linux/tcp.h>
#include<netdb.h>
#include<netinet/in.h>
#include<pty.h>//COMPILE WITH -lutil
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<sys/stat.h>
#include<sys/time.h>
#include<sys/types.h>
#include<syslog.h>
#include<termios.h>
#include<time.h>
#include<unistd.h>

struct sockaddr_in saddr;
struct sockaddr_ll saddrll;
struct termios trm;
struct timeval tv;
struct hostent*he;
int sock;
int disc;
char dev[IFNAMSIZ];
int slave;
int master;
int true;
int nfds;
struct ifreq ifr;
int fdx;
int encap;
unsigned char pbfr[2048];
ssize_t bytes;
fd_set readfds;
fd_set writefds;
fd_set exceptfds;
ax25_address call;

char*srcbtime(time_t t){
static char rcbt[22];
struct tm*ts;
if(!t)t=time(NULL);
ts=gmtime(&t);
memset(&rcbt,0,sizeof(rcbt));
snprintf(rcbt,sizeof(rcbt)-1,"%04d-%02d-%02dT%02d:%02d:%02dZ",ts->tm_year+1900,ts->tm_mon+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
return(rcbt);
};//SRCBTIME

int calltobin(char*ascii,ax25_address*bin){
int n;
if(ascii==NULL)return(-1);
if(bin==NULL)return(-1);
for(n=0;n<6;n++)bin->ax25_call[n]=0x40;
for(n=0;(n<6)&&(((ascii[n]>=0x30)&&(ascii[n]<=0x39))||(((ascii[n]&0xDF)>=0x41)&&((ascii[n]&0xDF)<=0x5A)));n++){
if((ascii[n]>=0x30)&&(ascii[n]<=0x39))bin->ax25_call[n]=ascii[n]<<1;
if(((ascii[n]&0xDF)>=0x41)&&((ascii[n]&0xDF)<=0x5A))bin->ax25_call[n]=(ascii[n]&0xDF)<<1;
};//FOR
if(n<1)return(-1);
if(ascii[n]==0){bin->ax25_call[6]=0;return(n);};
if(ascii[n]!=0x2D)return(-1);
if((ascii[n+1]>=0x30)&&(ascii[n+1]<=0x39))if(ascii[n+2]==0){bin->ax25_call[6]=(ascii[n+1]-0x30)<<1;return(6);};
if(ascii[n+1]==0x31)if((ascii[n+2]>=0x30)&&(ascii[n+2]<=0x35))if(ascii[n+3]==0){bin->ax25_call[6]=(10+(ascii[n+2]-0x30))<<1;return(6);};
return(-1);
};//CALLTOBIN

void tcpconnect(char*host,char*port){
//(RE-)CONNECT TCP
if(sock!=-1)close(sock);
sock=-1;
while(sock==-1){
//ALWAYS LOOK UP THE HOST AGAIN
he=gethostbyname(host);
if((he==NULL)||(he->h_addrtype!=AF_INET)||(he->h_length!=4)){printf("%s INVALID SERVER: %s\n",srcbtime(0),host);sleep(1);continue;};
saddr.sin_family=AF_INET;
bcopy(he->h_addr_list[0],&saddr.sin_addr.s_addr,sizeof(saddr.sin_addr.s_addr));
saddr.sin_port=htons(atoi(port));
sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
if(sock==-1){printf("%s SOCKET SETUP ERROR\n",srcbtime(0));sleep(1);continue;};
true=1;
setsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,(char*)&true,sizeof(int));
true=1;
setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,(char*)&true,sizeof(int));
if(master!=-1)while((bytes=read(master,&pbfr,sizeof(pbfr)))>0)printf("%s FLUSHED: %ld BYTES FROM MASTER\n",srcbtime(0),bytes);//IF MASTER
printf("%s CONNECTING: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));
if(connect(sock,(struct sockaddr*)&saddr,sizeof(saddr))!=0){close(sock);sock=-1;printf("%s CONNECT ERROR: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));sleep(1);continue;};
printf("%s CONNECTED: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));
};//WHILE SOCK -1
//GET RID OF OLD PACKETS COLLECTED IN PTY BEFORE COMPLETING TCP(RE-)CONNECT
if(master!=-1)while((bytes=read(master,&pbfr,sizeof(pbfr)))>0)printf("%s FLUSHED: %ld BYTES FROM MASTER\n",srcbtime(0),bytes);//IF MASTER
memset(&pbfr,0,sizeof(pbfr));
bytes=0;
};//TCPCONNECT

int main(int argc,char**argv){

if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

if(argc<4){printf("USAGE: %s <CALLSIGN[-SSID]> <KISS-TCP-SERVER-OR-TNC> <PORT>\n",argv[0]);exit(EXIT_FAILURE);};

if(calltobin(argv[1],&call)<1){printf("INVALID DEVICE CALLSIGN: %s\n",argv[1]);exit(EXIT_FAILURE);};

//CREATE PSEUDO TTY
master=-1;
slave=-1;

memset(&trm,0,sizeof(struct termios));
cfmakeraw(&trm);
trm.c_cflag|=CREAD;
if(openpty(&master,&slave,NULL,&trm,NULL)){printf("%s UNABLE TO CREATE PTY PAIR\n",srcbtime(0));exit(EXIT_FAILURE);};
printf("%s TTYNAME MASTER: %s\n",srcbtime(0),ttyname(master));
printf("%s TTYNAME SLAVE: %s\n",srcbtime(0),ttyname(slave));

//MAKE SLAVE PTY AX.25 NETWORK DEVICE
fdx=socket(PF_PACKET,SOCK_DGRAM,htons(ETH_P_AX25));//JUST GET THE RAW SOCKET NEEDED TO FORCE THE CRC MODE ANYWAY RIGHT AWAY AND ALSO USE IT FOR THE IOCTLS
if(fdx==-1){printf("%s PACKET SOCKET NEEDED TO SETUP PTY %s NOT SUPPORTED\n",srcbtime(0),ttyname(slave));exit(EXIT_FAILURE);};
disc=N_AX25;
if(ioctl(slave,TIOCSETD,&disc)){printf("%s UNABLE TO SET LINE DICIPLINE N_AX25 ON PTY %s\n",srcbtime(0),ttyname(slave));exit(EXIT_FAILURE);};
if(ioctl(slave,SIOCGIFNAME,&dev)){printf("%s UNABLE TO GET NETWORK DEVICE NAME FOR PTY %s\n",srcbtime(0),ttyname(slave));exit(EXIT_FAILURE);};
if(ioctl(slave,SIOCSIFHWADDR,&call)){printf("%s UNABLE TO SET CALLSIGN ON PTY %s NETWORK DEVICE %s\n",srcbtime(0),ttyname(slave),dev);exit(EXIT_FAILURE);};
encap=SL_MODE_KISS;
if(ioctl(slave,SIOCSIFENCAP,&encap)){printf("%s UNABLE TO SET ENCAPSULATION SLIP MODE KISS ON PTY %s NETWORK DEVICE %s\n",srcbtime(0),ttyname(slave),dev);exit(EXIT_FAILURE);};

//SET AX.25 NETWORK DEVICE FLAGS
memset(&ifr,0,sizeof(struct ifreq));
strncpy(ifr.ifr_name,dev,sizeof(ifr.ifr_name)-1);
ifr.ifr_mtu=AX25_MTU;
if(ioctl(fdx,SIOCSIFMTU,&ifr)){printf("%s UNABLE TO SET MTU %d ON NETWORK DEVICE %s\n",srcbtime(0),AX25_MTU,dev);exit(EXIT_FAILURE);};
ifr.ifr_flags=IFF_UP|IFF_RUNNING;
if(ioctl(fdx,SIOCSIFFLAGS,&ifr)){printf("%s UNABLE TO BRING UP NETWORK DEVICE %s\n",srcbtime(0),dev);exit(EXIT_FAILURE);};
//LINUX SEEMS TO HAVE A BUG IN THE ax0 N_KISS DRIVER THAT CAUSES THE FIRST 2 PACKETS TO HAVE TRANSMIT KISS CHANNEL 8 AND 2 RESPECTIVELY
//REST OF THE PACKETS IS FINE.. CAN'T HELP THAT. NOT OUR FAULT. 1ST PACKET AFTER BRINGING UP INTERFACE: $C0 $80 2ND PACKET: $C0 $20
//NOTE THAT WE CAN'T (EASILY) SET THE BYTE TO $00 OURSELVES AS THERE IS NO GUARANTEE OR NEED FOR ONE READ() TO CONTAIN ONE FRAMED PACKET
//PROBLEM TURNED OUT TO BE SOME PACKET BANGING TEST FOR THE CRC METHOD BY THE KERNEL (USING USER SENT PACKETS TO DO IT WITH)
//WE'LL SWITCH IT OFF THE SAME WAY KISSPARAMS DOES HERE: SO NOW THE FIRST 2 PACKETS COMING FROM THE KISS DEVICE ARE FINE TOO.
//THE INTERFACE MUST ALREADY BE UP TO DO THIS. NOT TO WORRY. WE'LL FLUSH ANYTHING THAT CAME IN BEFORE FINISHING SETTING UP THE TCP SOCKET ANYWAY.
if(ioctl(fdx,SIOCGIFINDEX,&ifr)){printf("%s UNABLE TO GET INTERFACE INDEX FOR NETWORK DEVICE %s\n",srcbtime(0),dev);exit(EXIT_FAILURE);};
memset(&saddrll,0,sizeof(struct sockaddr_ll));
saddrll.sll_family=AF_PACKET;
saddrll.sll_protocol=htons(ETH_P_AX25);
saddrll.sll_ifindex=ifr.ifr_ifindex;
if(sendto(fdx,"\x85\x01",2,MSG_DONTWAIT,(struct sockaddr*)&saddrll,sizeof(struct sockaddr_ll))!=2){printf("%s UNABLE TO SEND SET CRC MODE COMMAND TO INTERFACE %s\n",srcbtime(0),dev);exit(EXIT_FAILURE);};
close(fdx);

//SET THE TTY TO NONBLOCK!
fcntl(master,F_SETFL,fcntl(master,F_GETFL,0)|O_NONBLOCK);
fcntl(slave,F_SETFL,fcntl(slave,F_GETFL,0)|O_NONBLOCK);

sock=-1;tcpconnect(argv[2],argv[3]);

printf("%s AX.25 BOUND TO DEVICE %s\n",srcbtime(0),dev);

//LOOP DATA
ssize_t n;

FD_ZERO(&readfds);
FD_ZERO(&writefds);
FD_ZERO(&exceptfds);

while(1){
FD_ZERO(&readfds);
FD_SET(master,&readfds);
FD_SET(sock,&readfds);
nfds=sock;if(master>sock)nfds=master;
tv.tv_sec=30;
tv.tv_usec=0;
select(nfds+1,&readfds,&writefds,&exceptfds,&tv);

if(FD_ISSET(sock,&readfds)){
bytes=recv(sock,&pbfr,sizeof(pbfr),MSG_DONTWAIT);
if(bytes==0){printf("%s DISCONNECTED\n",srcbtime(0));sleep(1);tcpconnect(argv[2],argv[3]);continue;};
if(bytes>0){
printf("%s SOCKET RECV: %ld BYTES:",srcbtime(0),bytes);for(n=0;n<bytes;n++)printf(" %02X",pbfr[n]);printf("\n");
if(write(master,&pbfr,bytes)<1)printf("%s ERROR WRITING TO INTERFACE: %s\n",srcbtime(0),dev);
};//BYTES>0
};//FDSET

if(FD_ISSET(master,&readfds)){
bytes=read(master,&pbfr,sizeof(pbfr));
if(bytes>0){
printf("%s MASTER READ: %ld BYTES:",srcbtime(0),bytes);for(n=0;n<bytes;n++)printf(" %02X",pbfr[n]);printf("\n");
if(send(sock,&pbfr,bytes,MSG_DONTWAIT)<1){printf("%s DISCONNECTED\n",srcbtime(0));sleep(1);tcpconnect(argv[2],argv[3]);continue;};
};//BYTES>0
};//FDSET

};//WHILE 1
};//MAIN
