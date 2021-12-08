//HRH Prince Sven Olaf of CyberBunker-Kamphuis
//CB3ROB TACTICAL SYSTEMS
//One CyberBunker Avenue
//Republic CyberBunker

//COMPILE WITH gcc -O3 -o cb3rob-axudp-attach cb3rob-axudp-attach.c

//TO BRING UP AN AX.25 AXUDP INTERFACE (bpq0,bpq1,etc) TO AN AXUDP CONCENTRATOR SERVER:

// ./cb3rob-axudp-attach NOCALL-15 hu1nod.packetradio.at 93 &

#include<arpa/inet.h>
#include<fcntl.h>
#include<linux/ax25.h>
#include<linux/if.h>
#include<linux/if_tun.h>
#include<linux/if_slip.h>
#include<linux/tcp.h>
#include<net/if.h>
#include<net/if_arp.h>
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
uint16_t len;
unsigned char payload[2048];
};

uint16_t fcs16;

struct bpqethhdr sockpacket;
struct bpqethhdr tappacket;

//SOME RIPPED STUFF TO GET THE CRC TO WORK. DON'T ASK.

//crc.c Computations involving CRCs

//The following code was taken from Appendix B of RFC 1171
//(Point-to-Point Protocol)
//The RFC credits the following sources for this implementation:
//Perez, "Byte-wise CRC Calculations", IEEE Micro, June, 1983.
//Morse, G., "Calculating CRC's by Bits and Bytes", Byte,
//September 1986.
//LeVan, J., "A Fast CRC", Byte, November 1987.
//The HDLC polynomial: x**0 + x**5 + x**12 + x**16

//FCS lookup table as calculated by the table generator in section 2.

static uint16_t fcstab[256]={
0x0000,0x1189,0x2312,0x329B,0x4624,0x57AD,0x6536,0x74BF,
0x8C48,0x9DC1,0xAF5A,0xBED3,0xCA6C,0xDBE5,0xE97E,0xF8F7,
0x1081,0x0108,0x3393,0x221A,0x56A5,0x472C,0x75B7,0x643E,
0x9CC9,0x8D40,0xBFDB,0xAE52,0xDAED,0xCB64,0xF9FF,0xE876,
0x2102,0x308B,0x0210,0x1399,0x6726,0x76AF,0x4434,0x55BD,
0xAD4A,0xBCC3,0x8E58,0x9FD1,0xEB6E,0xFAE7,0xC87C,0xD9F5,
0x3183,0x200A,0x1291,0x0318,0x77A7,0x662E,0x54B5,0x453C,
0xBDCB,0xAC42,0x9ED9,0x8F50,0xFBEF,0xEA66,0xD8FD,0xC974,
0x4204,0x538D,0x6116,0x709F,0x0420,0x15A9,0x2732,0x36BB,
0xCE4C,0xDFC5,0xED5E,0xFCD7,0x8868,0x99E1,0xAB7A,0xBAF3,
0x5285,0x430C,0x7197,0x601E,0x14A1,0x0528,0x37B3,0x263A,
0xDECD,0xCF44,0xFDDF,0xEC56,0x98E9,0x8960,0xBBFB,0xAA72,
0x6306,0x728F,0x4014,0x519D,0x2522,0x34AB,0x0630,0x17B9,
0xEF4E,0xFEC7,0xCC5C,0xDDD5,0xA96A,0xB8E3,0x8A78,0x9BF1,
0x7387,0x620E,0x5095,0x411C,0x35A3,0x242A,0x16B1,0x0738,
0xFFCF,0xEE46,0xDCDD,0xCD54,0xB9EB,0xA862,0x9AF9,0x8B70,
0x8408,0x9581,0xA71A,0xB693,0xC22C,0xD3A5,0xE13E,0xF0B7,
0x0840,0x19C9,0x2B52,0x3ADB,0x4E64,0x5FED,0x6D76,0x7CFF,
0x9489,0x8500,0xB79B,0xA612,0xD2AD,0xC324,0xF1BF,0xE036,
0x18C1,0x0948,0x3BD3,0x2A5A,0x5EE5,0x4F6C,0x7DF7,0x6C7E,
0xA50A,0xB483,0x8618,0x9791,0xE32E,0xF2A7,0xC03C,0xD1B5,
0x2942,0x38CB,0x0A50,0x1BD9,0x6F66,0x7EEF,0x4C74,0x5DFD,
0xB58B,0xA402,0x9699,0x8710,0xF3AF,0xE226,0xD0BD,0xC134,
0x39C3,0x284A,0x1AD1,0x0B58,0x7FE7,0x6E6E,0x5CF5,0x4D7C,
0xC60C,0xD785,0xE51E,0xF497,0x8028,0x91A1,0xA33A,0xB2B3,
0x4A44,0x5BCD,0x6956,0x78DF,0x0C60,0x1DE9,0x2F72,0x3EFB,
0xD68D,0xC704,0xF59F,0xE416,0x90A9,0x8120,0xB3BB,0xA232,
0x5AC5,0x4B4C,0x79D7,0x685E,0x1CE1,0x0D68,0x3FF3,0x2E7A,
0xE70E,0xF687,0xC41C,0xD595,0xA12A,0xB0A3,0x8238,0x93B1,
0x6B46,0x7ACF,0x4854,0x59DD,0x2D62,0x3CEB,0x0E70,0x1FF9,
0xF78F,0xE606,0xD49D,0xC514,0xB1AB,0xA022,0x92B9,0x8330,
0x7BC7,0x6A4E,0x58D5,0x495C,0x3DE3,0x2C6A,0x1EF1,0x0F78};

#define PPPINITFCS 0xFFFF //Initial FCS value
#define PPPGOODFCS 0xF0B8 //Good final FCS value

//Calculate a new fcs given the current fcs and the new data.

uint16_t pppfcs(uint16_t fcs,unsigned char*cp,int len)
{
//ASSERT(sizeof (uint16_t) == 2);
//ASSERT(((uint16_t) -1) > 0);
while(len--)fcs=(fcs >> 8)^fcstab[(fcs^*cp++)&0xFF];
return fcs;
};

//End code from Appendix B of RFC 1171

//The following routines are simply convenience routines...
//I'll merge them into the mainline code when suitably debugged

//Return the computed CRC
unsigned short int compute_crc(unsigned char*buf,int l){
int fcs;
fcs=PPPINITFCS;
fcs=pppfcs(fcs,buf,l);
fcs^=0xFFFF;
return fcs;
};

//Return true if the CRC is correct
int ok_crc(unsigned char*buf,int l){
int fcs;
fcs=PPPINITFCS;
fcs=pppfcs(fcs,buf,l);
return fcs==PPPGOODFCS;
};

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

void udpconnect(char*host,char*port){
//(RE-)CONNECT UDP
if(sock!=-1)close(sock);
sock=-1;
while(sock==-1){
//ALWAYS LOOK UP THE HOST AGAIN
he=gethostbyname(host);
if((he==NULL)||(he->h_addrtype!=AF_INET)||(he->h_length!=4)){printf("%s INVALID SERVER: %s\n",srcbtime(0),host);sleep(1);continue;};
saddr.sin_family=AF_INET;
bcopy(he->h_addr_list[0],&saddr.sin_addr.s_addr,sizeof(saddr.sin_addr.s_addr));
saddr.sin_port=htons(atoi(port));
sock=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
if(sock==-1){printf("%s SOCKET SETUP ERROR\n",srcbtime(0));sleep(1);continue;};
baddr.sin_family=AF_INET;
baddr.sin_addr.s_addr=INADDR_ANY;
baddr.sin_port=htons(atoi(port));
bind(sock,(struct sockaddr*)&baddr,sizeof(baddr));
//ACTUALLY WE DON'T REALLY CARE IF BINDING TO THE SOURCE UDP PORT WORKED AS IT'S ONLY THERE TO CATER TO AXIPD'S NASTYNESS.
//IF THE DESIRED SOURCEPORT=DESTINATION PORT IS TAKEN THE WORLD WILL JUST HAVE TO LIVE WITH IT BEING ANOTHER PORT AND ADAPT.
//IT'LL BE ANOTHER PORT ONCE IT PASSES THROUGH MOST NAT ROUTERS ANYWAY. IT'S MORE OF A PREFERENCE REALLY THAN AN ACTUAL DEMAND.
printf("%s CONNECTING: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));
if(connect(sock,(struct sockaddr*)&saddr,sizeof(saddr))!=0){close(sock);sock=-1;printf("%s CONNECT ERROR: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));sleep(1);continue;};
printf("%s CONNECTED: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));
};//WHILE SOCK -1
};//UDPCONNECT

int main(int argc,char**argv){
int n;
char bdev[IFNAMSIZ];
char tdev[IFNAMSIZ];
char fbuf[256];
struct ifreq ifr;
FILE *bp;

if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

if(argc<4){printf("USAGE: %s <CALLSIGN[-SSID]> <AXUDP-SERVER> <PORT>\n",argv[0]);exit(EXIT_FAILURE);};

if(calltobin(argv[1],&call)<1){printf("INVALID DEVICE CALLSIGN: %s\n",argv[1]);exit(EXIT_FAILURE);};

sock=-1;udpconnect(argv[2],argv[3]);

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
sockpacket.len=0;

while(1){
FD_ZERO(&readfds);
FD_SET(tap,&readfds);
FD_SET(sock,&readfds);
nfds=sock;if(tap>sock)nfds=tap;
tv.tv_sec=30;
tv.tv_usec=0;
printf("%s EXITED SELECT WITH %d FILEDESCRIPTORS\n",srcbtime(0),select(nfds+1,&readfds,&writefds,&exceptfds,&tv));

//PACKETS THAT ARRIVE FROM AXUDP SERVER

if(FD_ISSET(sock,&readfds)){
bytes=recv(sock,&sockpacket.payload,sizeof(sockpacket.payload),MSG_DONTWAIT);
if(bytes<=1){printf("%s DISCONNECTED\n",srcbtime(0));sleep(1);udpconnect(argv[2],argv[3]);};
if(bytes>=17){//2 7 BYTE ADDRESSES, 1 CONTROL BYTE, 2 BYTE FCS
sockpacket.len=htons(bytes+3);//+5=INCLUDE FCS +3= STRIP THE FCS ON BPQETHER, ALSO BELOW
fcs16=ntohs(compute_crc(sockpacket.payload,bytes-2));
printf("%s INCOMING FCS: %04X MSB: %02X LSB: %02X %ld BYTES:",srcbtime(0),fcs16,sockpacket.payload[bytes-2],sockpacket.payload[bytes-1],bytes-2);for(n=0;n<bytes;n++)printf(" %02X",sockpacket.payload[n]);printf("\n");
if((sockpacket.payload[(bytes-2)]!=(fcs16>>8))||(sockpacket.payload[(bytes-1)]!=(fcs16&0x00FF))){printf("%s INCOMING FCS FAILED\n",srcbtime(0));continue;};
if(write(tap,&sockpacket,bytes+14)<1)printf("%s ERROR WRITING TO INTERFACE: %s\n",srcbtime(0),dev);
};//BYTES>=17
};//FDSET

//PACKETS THAT GO TO AXUDP SERVER

if(FD_ISSET(tap,&readfds)){
bytes=read(tap,&tappacket,sizeof(struct bpqethhdr)-2);//LEAVE 2 BYTES SPACE TO ADD THE FCS
if(bytes>=(31)){//16 BYTE ETHBPQ HEADER + 15 BYTE AX25 PAYLOAD
if(tappacket.ptype==ntohs(ETH_P_BPQ)){
fcs16=ntohs(compute_crc(tappacket.payload,bytes-16));
tappacket.payload[bytes-16]=(fcs16>>8);//FCS MSB
tappacket.payload[bytes-15]=(fcs16&0x00FF);//FCS LSB
printf("%s OUTGOING FCS: %04X MSB: %02X LSB: %02X %ld BYTES:",srcbtime(0),fcs16,tappacket.payload[bytes-16],tappacket.payload[bytes-15],bytes-14);for(n=0;n<bytes-14;n++)printf(" %02X",tappacket.payload[n]);printf("\n");
if(send(sock,&tappacket.payload,bytes-14,MSG_DONTWAIT)<1){printf("%s DISCONNECTED\n",srcbtime(0));sleep(1);udpconnect(argv[2],argv[3]);};
};//BPQ FRAME
};//BYTES>0
};//FDSET

};//WHILE 1
};//MAIN
