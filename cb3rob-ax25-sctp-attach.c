//HRH Prince Sven Olaf of CyberBunker-Kamphuis
//CB3ROB TACTICAL SYSTEMS
//One CyberBunker Avenue
//Republic CyberBunker

//COMPILE WITH gcc -O3 -o cb3rob-ax25-sctp-attach cb3rob-ax25-sctp-attach.c

//TO BRING UP AN AX.25 AX25-OVER-SCTP INTERFACE (bpq0,bpq1,etc) TO AN AX25-OVER-SCTP CONCENTRATOR SERVER:

// ./cb3rob-ax25-sctp-attach NOCALL-15 208.109.9.123 8001 &

#include<arpa/inet.h>
#include<fcntl.h>
#include<linux/ax25.h>
#include<linux/if.h>
#include<linux/if_arp.h>
#include<linux/if_tun.h>
#include<linux/if_slip.h>
#include<linux/sctp.h>
#include<netdb.h>
#include<netinet/in.h>
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
struct sockaddr_in baddr;
struct timeval tv;
struct hostent*he;
int sock;
int tap;
char dev[IFNAMSIZ];
int nfds;
struct ifreq ifr;
int fdx;
int encap;
fd_set readfds;
fd_set writefds;
fd_set exceptfds;
ax25_address call;
char systemline[256];

struct bpqethhdr{
uint8_t ethdst[6];
uint8_t ethsrc[6];
uint16_t ptype;
uint8_t lenlsb;//DON'T ASK... IT'S ACTUALLY THE LENGTH OF THE PAYLOAD MINUS THE KISS BYTE PLUS +4 (ETHERNET CHECKSUM)
uint8_t lenmsb;//IN LITTLE ENDIAN FORMAT OF ALL THINGS... (SO PAYLOAD LENGTH +5, IN 'REVERSE ORDER') $14 $00 (1+15+4=20=$0014)
unsigned char payload[2048];
};

struct bpqethhdr sockpacket;
struct bpqethhdr tappacket;

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

void sctpconnect(char*host,char*port){
//(RE-)CONNECT SCTP
if(sock!=-1)close(sock);
sock=-1;
while(sock==-1){
//ALWAYS LOOK UP THE HOST AGAIN
he=gethostbyname(host);
if((he==NULL)||(he->h_addrtype!=AF_INET)||(he->h_length!=4)){printf("%s INVALID SERVER: %s\n",srcbtime(0),host);sleep(1);continue;};
saddr.sin_family=AF_INET;
bcopy(he->h_addr_list[0],&saddr.sin_addr.s_addr,sizeof(saddr.sin_addr.s_addr));
saddr.sin_port=htons(atoi(port));
sock=socket(PF_INET,SOCK_STREAM,IPPROTO_SCTP);
if(sock==-1){printf("%s SOCKET SETUP ERROR\n",srcbtime(0));sleep(1);continue;};
printf("%s CONNECTING: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));
if(connect(sock,(struct sockaddr*)&saddr,sizeof(saddr))!=0){close(sock);sock=-1;printf("%s CONNECT ERROR: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));sleep(1);continue;};
printf("%s CONNECTED: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));
};//WHILE SOCK -1
};//SCTPCONNECT

int main(int argc,char**argv){
int n;
char bdev[IFNAMSIZ];
char tdev[IFNAMSIZ];
char fbuf[256];
struct ifreq ifr;
FILE *bp;

if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

if(argc<4){printf("USAGE: %s <CALLSIGN[-SSID]> <AX25-OVER-SCTP-SERVER> <PORT>\n",argv[0]);exit(EXIT_FAILURE);};

if(calltobin(argv[1],&call)<1){printf("INVALID DEVICE CALLSIGN: %s\n",argv[1]);exit(EXIT_FAILURE);};

sock=-1;sctpconnect(argv[2],argv[3]);

tap=open("/dev/net/tun",O_RDWR);
if(tap==-1){printf("COULD NOT CREATE TAP DEVICE PAIR\n");exit(EXIT_FAILURE);};
fdx=socket(PF_AX25,SOCK_DGRAM,0);
if(fdx==-1){printf("COULD NOT OPEN CONFIGURATION SOCKET\n");exit(EXIT_FAILURE);};
memset(&ifr,0,sizeof(ifr));
//FIND FREE DEVICE NUMBER AND CREATE THE TAP MASTER DEVICE
ifr.ifr_flags=IFF_TAP|IFF_NO_PI;
if(ioctl(tap,TUNSETIFF,(void*)&ifr)){printf("COULD NOT SET TAP DEVICE INTERFACE FLAGS\n");exit(EXIT_FAILURE);};
if(ioctl(tap,TUNGETIFF,(void*)&ifr)){printf("COULD NOT GET TAP DEVICE NAME\n");exit(EXIT_FAILURE);};
printf("%s NETWORK MASTER DEVICE %s CREATED\n",srcbtime(0),ifr.ifr_name);
ifr.ifr_flags=IFF_UP|IFF_RUNNING;
if(ioctl(fdx,SIOCSIFFLAGS,&ifr)){printf("COULD NOT BRING UP TAP DEVICE\n");exit(EXIT_FAILURE);};
//FIND CORRESPONDING BPQ DEVICE FOR TAP MASTER DEVICE
bp=fopen("/proc/net/bpqether","r");
if(bp==NULL){printf("COULD NOT OPEN BPQETHER PROC FILE\n");exit(EXIT_FAILURE);}
memset(&bdev,0,sizeof(bdev));
if(fgets(fbuf,sizeof(fbuf),bp)==NULL){printf("COULD NOT READ BPQETHER PROC FILE HEADER LINE\n");exit(EXIT_FAILURE);};//SKIP HEADER
while(fgets(fbuf,sizeof(fbuf),bp)!=NULL){
sscanf(fbuf,"%s %s ",bdev,tdev);
if(!strncmp(tdev,ifr.ifr_name,IFNAMSIZ))break;
memset(&bdev,0,sizeof(bdev));
};//FOREACH PROCFILE LINE
fclose(bp);
if(!bdev[0]){printf("COULD NOT FIND BPQ DEVICE FOR %s\n",tdev);exit(EXIT_FAILURE);};
printf("%s BPQ-ETHER SLAVE DEVICE %s FOR %s\n",srcbtime(0),bdev,tdev);
//GET BPQ ETHERNET II FRAME SOURCE FROM TAP DEV
if(ioctl(fdx,SIOCGIFHWADDR,&ifr)<0){printf("COULD NOT RETREIVE TAP MAC ADDRESS\n");exit(EXIT_FAILURE);}
bcopy(ifr.ifr_hwaddr.sa_data,sockpacket.ethsrc,sizeof(sockpacket.ethsrc));
//BRING UP BQP DEV
memset(&ifr,0,sizeof(struct ifreq));
strncpy(ifr.ifr_name,bdev,IFNAMSIZ-1);
ifr.ifr_mtu=AX25_MTU;
if(ioctl(fdx,SIOCSIFMTU,&ifr)){printf("COULD NOT SET BPQ DEVICE MTU\n");exit(EXIT_FAILURE);}
ifr.ifr_hwaddr.sa_family=ARPHRD_AX25;
memset(ifr.ifr_hwaddr.sa_data,0,sizeof(ifr.ifr_hwaddr.sa_data));
bcopy(&call,ifr.ifr_hwaddr.sa_data,7);
if(ioctl(fdx,SIOCSIFHWADDR,&ifr)){printf("COULD NOT SET BPQ DEVICE CALLSIGN\n");exit(EXIT_FAILURE);};
ifr.ifr_flags=IFF_UP|IFF_RUNNING;
if(ioctl(fdx,SIOCSIFFLAGS,&ifr)){printf("COULD NOT BRING UP BPQ DEVICE\n");exit(EXIT_FAILURE);}
close(fdx);

fcntl(sock,F_SETFL,fcntl(sock,F_GETFL,0)|O_NONBLOCK);
fcntl(tap,F_SETFL,fcntl(tap,F_GETFL,0)|O_NONBLOCK);

printf("%s AX.25 BOUND TO DEVICE %s\n",srcbtime(0),dev);

//LOOP DATA
ssize_t bytes;

FD_ZERO(&readfds);
FD_ZERO(&writefds);
FD_ZERO(&exceptfds);

sockpacket.ethdst[0]=0xFF;
sockpacket.ethdst[1]=0xFF;
sockpacket.ethdst[2]=0xFF;
sockpacket.ethdst[3]=0xFF;
sockpacket.ethdst[4]=0xFF;
sockpacket.ethdst[5]=0xFF;
sockpacket.ptype=htons(ETH_P_BPQ);
sockpacket.lenlsb=0;
sockpacket.lenmsb=0;

while(1){
FD_ZERO(&readfds);
FD_SET(tap,&readfds);
FD_SET(sock,&readfds);
nfds=sock;if(tap>sock)nfds=tap;
tv.tv_sec=30;
tv.tv_usec=0;
printf("%s EXITED SELECT WITH %d FILEDESCRIPTORS\n",srcbtime(0),select(nfds+1,&readfds,&writefds,&exceptfds,&tv));

//PACKETS THAT ARRIVE FROM AX25-OVER-SCTP SERVER
if(FD_ISSET(sock,&readfds)){
bytes=recv(sock,&sockpacket.payload,sizeof(sockpacket.payload),MSG_DONTWAIT);
if(bytes<=1){printf("%s DISCONNECTED\n",srcbtime(0));sleep(1);sctpconnect(argv[2],argv[3]);};
if(bytes>=15){//2 7 BYTE ADDRESSES, 1 CONTROL BYTE
sockpacket.lenlsb=((bytes+5)&0x00FF);
sockpacket.lenmsb=(((bytes+5)&0xFF00)>>8);
printf("%s INCOMING PACKET: %ld BYTES:",srcbtime(0),bytes);for(n=0;n<bytes;n++)printf(" %02X",sockpacket.payload[n]);printf("\n");
if(write(tap,&sockpacket,bytes+16)<1)printf("%s ERROR WRITING TO INTERFACE: %s\n",srcbtime(0),dev);
};//BYTES>=17
};//FDSET

//PACKETS THAT GO TO AX25-OVER-SCTP SERVER
if(FD_ISSET(tap,&readfds)){
bytes=read(tap,&tappacket,sizeof(struct bpqethhdr));
if(bytes>=(31)){//16 BYTE ETHBPQ HEADER + 15 BYTE AX25 PAYLOAD
if(tappacket.ptype==ntohs(ETH_P_BPQ)){
printf("%s OUTGOING PACKET: %ld BYTES:",srcbtime(0),bytes-16);for(n=0;n<bytes-16;n++)printf(" %02X",tappacket.payload[n]);printf("\n");
if(send(sock,&tappacket.payload,bytes-16,MSG_DONTWAIT)<1){printf("%s DISCONNECTED\n",srcbtime(0));sleep(1);sctpconnect(argv[2],argv[3]);};
}else{printf("%s TAP DEVICE IGNORED NON BPQ PROTOCOL FAMILY: %04X PACKET\n",srcbtime(0),ntohs(tappacket.ptype));};//BPQ FRAME
};//BYTES>0
};//FDSET

};//WHILE 1
};//MAIN
