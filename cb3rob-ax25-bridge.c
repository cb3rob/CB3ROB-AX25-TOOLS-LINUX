// CB3ROB Tactical Systems AX.25 Bridge for Linux. (APRS/Packet Radio)
// 2016 HRH Prince Sven Olaf of CyberBunker-Kamphuis (CB3ROB / RCB1AA)
// VERSION 2.0 RELEASE

// [client] [client] [client] [bbs] [digipeater] (each with their own callsign or ssid)
//    |        |         |      |     |
//    +--------+---------+------+-----+          (ethernet switch/vlan/etc)
//                |
//          [bridging box]                       (can NOT reliably run AX.25 terminal/servers at the same time)
//                |
//              [tnc]        \~/                 (callsign of interfaces is irrelevant)
//                |           |
//            [tranceiver]----+                  (callsigns on interfaces on the bridge do not show up in the path)

// Warning: when connecting multiple tnc/tranceivers or soundmodems packets between them are also bridged
// This can be used to bridge different frequencies together but would usually be undesired.

// Packets will appear on the radio with the callsign of the ethernet connected clients.
// Packets from the radio(s) will appear at all ethernet connected clients.
// Packets from and between all clients will be broadcast on the radio(s)

// Traffic between multiple bpq enabled ethernet interfaces or vlans is also bridged for internal communication.

// This is NOT a DIGIPEATER - traffic within the same radio frequency is NOT repeated to extend range

// No additional hops appear in the path
// It works as-if the client callsign would be directly connected to the tnc/radio

#include<arpa/inet.h>
#include<fcntl.h>
#include<ifaddrs.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<net/if.h>
#include<net/if_arp.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<sys/time.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<signal.h>
#include<stdint.h>
#include<time.h>

#define MAX_PORTS 32
#define PACKET_SIZE 1500
#define AXALEN 7

struct sockaddr_ll ssockaddrll;
struct sockaddr_ll dsockaddrll;
struct sigaction sigact;

socklen_t clen;

int portcount;
int needreload;

int sock;

struct interfaces{
int ifindex;
char ifname[IFNAMSIZ];
char netcall[AXALEN];
unsigned short status;
char asciicall[10];
};

struct interfaces myinterfaces[MAX_PORTS];

char*srcbtime(time_t t){
static char rcbt[22];
struct tm*ts;
if(!t)t=time(NULL);
ts=gmtime(&t);
memset(&rcbt,0,sizeof(rcbt));
snprintf(rcbt,sizeof(rcbt)-1,"%04d-%02d-%02dT%02d:%02d:%02dZ",ts->tm_year+1900,ts->tm_mon+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
return(rcbt);
};//SRCBTIME

char*displaycall(uint8_t*c){
static char a[10];
int n;
for(n=0;(n<6)&&(c[n]!=0x40);n++)a[n]=(c[n]>>1);
snprintf(&a[n],4,"-%d",(c[6]>>1)&0x0F);
return(a);
};//DISPLAYCALL

//SIGNALHANDLER HUP
void requestreload(int signum){needreload=1;};

void getinterfaces(){
portcount=0;
struct ifaddrs*ifaddr,*ifa;
struct ifreq ifr;
memset(&myinterfaces,0,sizeof(myinterfaces));
printf("%s SCANNING AX.25 INTERFACES\n",srcbtime(0));
//GETIFADDRS WORKS WITHOUT IP
if(getifaddrs(&ifaddr)==-1){perror("GETIFADDRS");exit(EXIT_FAILURE);};
for(ifa=ifaddr;(ifa!=NULL&&portcount<MAX_PORTS);ifa=ifa->ifa_next){
if(ifa->ifa_addr==NULL)continue;
//CHECK FOR AF_PACKET - WE NEED IT - THEY ALL HAVE IT - IT DOES AVOID DOUBLE NAMES ON OTHER FAMILIES
if(ifa->ifa_addr->sa_family!=AF_PACKET)continue;
//ONLY HAVE TO SET THE NAME ONCE
strncpy(ifr.ifr_name,ifa->ifa_name,IFNAMSIZ-1);
if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){perror("IOCTL");exit(EXIT_FAILURE);};
if(ifr.ifr_hwaddr.sa_family==AF_AX25){
bcopy(ifr.ifr_hwaddr.sa_data,myinterfaces[portcount].netcall,7);
strncpy(myinterfaces[portcount].ifname,ifr.ifr_name,sizeof(myinterfaces[portcount].ifname));
strncpy(myinterfaces[portcount].asciicall,displaycall((uint8_t*)myinterfaces[portcount].netcall),sizeof(myinterfaces[portcount].asciicall)-1);
if(ioctl(sock,SIOCGIFFLAGS,&ifr)<0){perror("IOCTL");exit(EXIT_FAILURE);};
myinterfaces[portcount].status=ifr.ifr_flags;
if(ioctl(sock,SIOCGIFINDEX,&ifr)<0){perror("IOCTL");exit(EXIT_FAILURE);};
myinterfaces[portcount].ifindex=ifr.ifr_ifindex;
printf("%s FOUND AX.25 PORT %d: %d %s %s STATUS: %s\n",srcbtime(0),portcount,myinterfaces[portcount].ifindex,myinterfaces[portcount].ifname,myinterfaces[portcount].asciicall,((myinterfaces[portcount].status&(IFF_UP|IFF_RUNNING))?"UP":"DOWN"));
portcount++;
};//IF AX.25
};//FOR INTERFACES
freeifaddrs(ifaddr);
needreload=0;
printf("%s DONE SCANNING INTERFACES\n",srcbtime(0));
if(portcount<2){printf("%s INSUFFICIENT (%d) AX.25 PORTS FOR BRIDGING\n",srcbtime(0),portcount);needreload=1;sleep(5);};//INSUFFICIENT
};//GETINTERFACES

int main(void){
ssize_t bytes;
int po;

uint8_t*pctr;
uint8_t buf[PACKET_SIZE];

fd_set readfds;
struct timeval tv;
if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

if((sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_AX25)))==-1){perror("SOCKET");exit(EXIT_FAILURE);};

//THIS DOESN'T WORK WITH THE CURRENT VERSION OF THE KERNEL.
//THEREFORE PACKETS ORIGINATING FROM TERMINAL SOFTWARE RUNNING ON THE MACHINE THAT RUNS THE BRIDGE NEVER GET BRIDGED.
//THEREFORE IT IS INADVISABLE TO RUN THE BRIDGE ON THE SAME MACHINES AS CLIENT OR SERVERS
//THEY'LL ONLY WORK ON THE INTERFACE THEY'RE BOUND TO AND NOT GET BRIDGED TO THE REST OF THE NETWORK
//true=1;
//setsockopt(sock,SOL_PACKET,PACKET_RECV_OUTPUT,(char*)&true,sizeof(int));

memset(&sigact,0,sizeof(struct sigaction));
sigact.sa_handler=requestreload;
sigaction(SIGHUP,&sigact,NULL);

//FORCE RELOAD FOR STARTUP
needreload=1;

fcntl(sock,F_SETFL,fcntl(sock,F_GETFL,0)|O_NONBLOCK);

memset(&dsockaddrll,0,sizeof(struct sockaddr_ll));

FD_ZERO(&readfds);
while(1){
while(needreload==1)getinterfaces();
if(portcount<2)needreload=1;

memset(&buf,0,sizeof(buf));
memset(&ssockaddrll,0,sizeof(struct sockaddr_ll));

tv.tv_sec=10;
tv.tv_usec=0;
FD_SET(sock,&readfds);
select(sock+1,&readfds,NULL,NULL,&tv);
clen=sizeof(struct sockaddr_ll);
bytes=recvfrom(sock,&buf,sizeof(buf),0,(struct sockaddr*)&ssockaddrll,&clen);

//DEBUG PACKET
if(bytes<16)continue;
pctr=buf;
//KISS byte
if(pctr[0]!=0)continue;
pctr++;
if(ssockaddrll.sll_protocol!=htons(ETH_P_AX25))continue;
if(ssockaddrll.sll_family!=AF_PACKET)continue;
if(ssockaddrll.sll_hatype!=ARPHRD_AX25)continue;

printf("====================\n");
printf("%s INPUT DEVICE: %d FAMILY: %04X PROTOCOL: %04X TO: %s ",srcbtime(0),ssockaddrll.sll_ifindex,ssockaddrll.sll_hatype,ntohs(ssockaddrll.sll_protocol),displaycall(pctr));
pctr+=AXALEN;
//SRC ADDR
printf("FROM: %s SIZE: %ld\n",displaycall(pctr),bytes);

dsockaddrll.sll_family=ssockaddrll.sll_family;
dsockaddrll.sll_protocol=ssockaddrll.sll_protocol;
dsockaddrll.sll_hatype=ssockaddrll.sll_hatype;

for(po=0;po<portcount;po++){
//NOT BRIDGING TO SOURCE INTERFACE
if(myinterfaces[po].ifindex==ssockaddrll.sll_ifindex)continue;
//NOT BRIDGING TO INTERFACES THAT ARE NOT UP
if(!(myinterfaces[po].status&(IFF_UP|IFF_RUNNING))){needreload=1;continue;};
//ALL FINE, FORWARD PACKET
printf("%s FORWARDING PACKET OVER INTERFACE %s (%d) TO %s\n",srcbtime(0),myinterfaces[po].ifname,myinterfaces[po].ifindex,displaycall(buf+1));

dsockaddrll.sll_ifindex=myinterfaces[po].ifindex;

if(sendto(sock,&buf,bytes,0,(struct sockaddr*)&dsockaddrll,sizeof(struct sockaddr_ll))==-1){perror("SENDTO");needreload=1;continue;};
};//FOR FORWARD PACKET TO EACH INTERFACE THAT WAS UP AT PROGRAM START IT DID NOT ORIGINATE FROM

};//WHILE 1
};//MAIN

