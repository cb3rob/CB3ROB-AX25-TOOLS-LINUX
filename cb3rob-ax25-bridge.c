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
#include<ifaddrs.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<net/if.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<signal.h>
#include<stdint.h>

#define MAX_PORTS 32
#define AXALEN 7
#define PACKET_SIZE 1500

struct sockaddr_pkt ssockaddrpkt;
struct sockaddr_pkt dsockaddrpkt;

int portcount;
int needreload;

int true;

struct interfaces{
int ifindex;
unsigned char ifname[IFNAMSIZ];
uint8_t netcall[AXALEN];
unsigned short status;
uint8_t asciicall[10];
};

struct interfaces myinterfaces[MAX_PORTS];

uint8_t *displaycall(uint8_t *c){
//2021-11-14 HRH PRINCE SVEN OLAF OF CYBERBUNKER-KAMPHUIS
//PARAMETERS
//uint8_t *c[6] - BINARY ADDRESS FIELD IN AX.25 PACKET
//RETURNS VALUES:
//uint8_t *c[10] - ZERO TERMINATED ASCII CALL-SSID
static uint8_t a[10];
int n;
for(n=0;(n<6)&&(c[n]!=0x40);n++)a[n]=(c[n]>>1);
a[n++]='-';
snprintf((unsigned char*)&a[n],3,"%d",(c[6]>>1)&0x0F);
return(a);
};//DISPLAYCALL

//SIGNALHANDLER HUP
void requestreload(){needreload=1;};

void getinterfaces(){
portcount=0;
int socktemp;
struct ifaddrs *ifaddr, *ifa;
struct ifreq ifr;
if((socktemp=socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_AX25)))==-1){perror("SOCKET - THIS PROGRAM MUST BE RUN AS ROOT");exit(1);};
bzero(&myinterfaces,sizeof(myinterfaces));
printf("SCANNING AX.25 INTERFACES\n");
//GETIFADDRS WORKS WITHOUT IP
if(getifaddrs(&ifaddr)==-1){perror("getifaddrs");exit(EXIT_FAILURE);};
for(ifa=ifaddr;(ifa!=NULL&&portcount<MAX_PORTS);ifa=ifa->ifa_next){
if(ifa->ifa_addr==NULL)continue;
//CHECK FOR AF_PACKET - WE NEED IT - THEY ALL HAVE IT - IT DOES AVOID DOUBLE NAMES ON OTHER FAMILIES
if(ifa->ifa_addr->sa_family!=AF_PACKET)continue;
//ONLY HAVE TO SET THE NAME ONCE
strncpy(ifr.ifr_name,ifa->ifa_name,IFNAMSIZ-1);
if(ioctl(socktemp,SIOCGIFFLAGS,&ifr)<0){perror("ioctl");exit(1);};
myinterfaces[portcount].status=ifr.ifr_flags;
if(ioctl(socktemp,SIOCGIFHWADDR,&ifr)<0){perror("ioctl");exit(1);};
if(ifr.ifr_hwaddr.sa_family==AF_AX25){
bcopy(ifr.ifr_hwaddr.sa_data,myinterfaces[portcount].netcall,7);
strncpy(myinterfaces[portcount].ifname,ifr.ifr_name,sizeof(myinterfaces[portcount].ifname));
strncpy(myinterfaces[portcount].asciicall,displaycall(myinterfaces[portcount].netcall),sizeof(myinterfaces[portcount].asciicall));
if(ioctl(socktemp,SIOCGIFINDEX,&ifr)<0){perror("ioctl");exit(1);};
myinterfaces[portcount].ifindex=ifr.ifr_ifindex;
printf("FOUND AX.25 PORT %d: %d %s %s STATUS: %s\n",portcount,myinterfaces[portcount].ifindex,myinterfaces[portcount].ifname,myinterfaces[portcount].asciicall,((myinterfaces[portcount].status&(IFF_UP|IFF_RUNNING))?"UP":"DOWN"));
portcount++;
};//IF AX.25
};//FOR INTERFACES
freeifaddrs(ifaddr);
close(socktemp);
needreload=0;
printf("DONE SCANNING INTERFACES\n");
if(portcount<2){printf("INSUFFICIENT (%d) AX.25 PORTS FOR BRIDGING\n",portcount);needreload=1;sleep(5);};//INSUFFICIENT
};//getinterfaces

int main(void){
socklen_t clen;
int sock;
ssize_t bytes;
int po;
uint8_t *pctr;
uint8_t buf[PACKET_SIZE];
if((sock=socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_AX25)))==-1){perror("SOCKET - THIS PROGRAM MUST BE RUN AS ROOT");exit(1);};

//THIS DOESN'T WORK WITH THE CURRENT VERSION OF THE KERNEL.
//THEREFORE PACKETS ORIGINATING FROM TERMINAL SOFTWARE RUNNING ON THE MACHINE THAT RUNS THE BRIDGE NEVER GET BRIDGED.
//THEREFORE IT IS INADVISABLE TO RUN THE BRIDGE ON THE SAME MACHINES AS CLIENT OR SERVERS
//THEY'LL ONLY WORK ON THE INTERFACE THEY'RE BOUND TO AND NOT GET BRIDGED TO THE REST OF THE NETWORK
//true=1;
//setsockopt(sock,SOL_PACKET,PACKET_RECV_OUTPUT,(char*)&true,sizeof(int));

signal(SIGHUP,requestreload);

//FORCE RELOAD FOR STARTUP
needreload=1;

while(1){
while(needreload==1)getinterfaces();
if(portcount<2)needreload=1;

bzero(&buf,sizeof(buf));
bzero(&ssockaddrpkt,sizeof(struct sockaddr_pkt));

clen=sizeof(struct sockaddr_pkt);
bytes=recvfrom(sock,&buf,sizeof(buf),0,(struct sockaddr*)&ssockaddrpkt,&clen);
//DEBUG PACKET
if(bytes<16)continue;
pctr=buf;
//KISS byte
if(pctr[0]!=0)continue;
pctr++;
if(ssockaddrpkt.spkt_protocol!=htons(ETH_P_AX25))continue;
if(ssockaddrpkt.spkt_family!=PF_AX25)continue;

//int n;printf("RECEIVED %ld BYTES:",bytes);for(n=0;n<bytes;n++)printf(" %02X",buf[n]);printf("\n");
printf("============================================\n");
printf("INPUT DEVICE: %s FAMILY: %04X PROTOCOL: %04X TO: %s ",ssockaddrpkt.spkt_device,ssockaddrpkt.spkt_family,ntohs(ssockaddrpkt.spkt_protocol),displaycall(pctr));
pctr+=AXALEN;
//SRC ADDR
printf("FROM: %s SIZE: %ld\n",displaycall(pctr),bytes);

for(po=0;po<portcount;po++){
//NOT BRIDGING TO SOURCE INTERFACE
if(strncmp(myinterfaces[po].ifname,ssockaddrpkt.spkt_device,sizeof(ssockaddrpkt.spkt_device))==0)continue;
//NOT BRIDGING TO INTERFACES THAT ARE NOT UP
if(!(myinterfaces[po].status&(IFF_UP|IFF_RUNNING))){needreload=1;continue;};
//ALL FINE, FORWARD PACKET
printf("FORWARDING PACKET OVER INTERFACE %s (%d) TO %s\n",myinterfaces[po].ifname,myinterfaces[po].ifindex,displaycall(buf+1));
bzero(&dsockaddrpkt,sizeof(struct sockaddr_pkt));
dsockaddrpkt.spkt_family=ssockaddrpkt.spkt_family;
strncpy(dsockaddrpkt.spkt_device,myinterfaces[po].ifname,sizeof(ssockaddrpkt.spkt_device));
dsockaddrpkt.spkt_protocol=ssockaddrpkt.spkt_protocol;
clen=sizeof(struct sockaddr_pkt);
if(sendto(sock,&buf,bytes,0,(struct sockaddr*)&dsockaddrpkt,clen)==-1){perror("sendto");needreload=1;continue;};
};//FOR FORWARD PACKET TO EACH INTERFACE THAT WAS UP AT PROGRAM START IT DID NOT ORIGINATE FROM

};//while1
};//main

