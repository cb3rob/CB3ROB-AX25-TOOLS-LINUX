// CB3ROB Tactical Systems AX.25 Switch for Linux. (APRS/Packet Radio)
// 2021 HRH Prince Sven Olaf of CyberBunker-Kamphuis (CB3ROB / RCB1AA)
// VERSION 1.0 RELEASE

// [client] [client] [client] [bbs] [digipeater] (each with their own callsign or ssid)
//    |        |         |      |     |
//    +--------+---------+------+-----+          (ethernet switch/vlan/etc)
//                |
//          [switching box]                      (can NOT reliably run AX.25 terminal/servers at the same time)
//                |
//              [tnc]        \~/                 (callsign of interfaces is irrelevant)
//                |           |
//            [tranceiver]----+                  (callsigns on interfaces on the switch do not show up in the path)

// When connecting multiple tnc/tranceivers or soundmodems packets between them are also switched
// This can be used to bridge different frequencies and make transparent interconnects possible.
// as this is the switch version, (unlike the bridge version) it won't flood the other frequency.

// Interface routes to the source destinations will be learned whenever they send a packet (SABM, etc)
// As soon as a specific route to a specific address is known (After the first packet sent by it) traffic to it
// will no longer be sent to all the ports but just to the port it's connected to.
// This prevents one network flooding another network as it, at most, lets initial connect requests and beacons
// spread over all connected network segments, established sessions will always only affect the needed networks
// Traffic between nodes on the same network segment will not affect other networks after the initial packets.

// The route cache is based on SOURCE callsign-ssid entries and has a default expiry time of 90 seconds,
// it's destination port is updated on every received packet and it's expiry time is set back to 90 seconds.

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
#include<linux/if.h>
#include<linux/if_arp.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
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
#define ROUTEEXPIRY 90
#define AXALEN 7
#define MAXDIGIS 7

struct sockaddr_ll ssockaddrll;
struct sockaddr_ll dsockaddrll;
struct sigaction sigact;

socklen_t clen;

int portcount;
int needreload;
time_t lastreload;

int sock;

int po;

struct route{
union{
uint64_t intcall;
uint8_t bincall[8];
};
int port;
time_t lastseen;
void*next;
};//STRUCT ROUTE

struct route*startrte;
struct route*findrte;

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

int checkbincall(uint8_t*c){
if(c==NULL)return(-1);
if(                                   (c[0]&1) || (c[0]<0x60) || (c[0]>0xB4) || ((c[0]>0x72)&&(c[0]<0x82))   )return(-1);
if( (c[1]!=0x40) && (                 (c[1]&1) || (c[1]<0x60) || (c[1]>0xB4) || ((c[1]>0x72)&&(c[1]<0x82)) ) )return(-1);
if( (c[2]!=0x40) && ( (c[1]==0x40) || (c[2]&1) || (c[2]<0x60) || (c[2]>0xB4) || ((c[2]>0x72)&&(c[2]<0x82)) ) )return(-1);
if( (c[3]!=0x40) && ( (c[2]==0x40) || (c[3]&1) || (c[3]<0x60) || (c[3]>0xB4) || ((c[3]>0x72)&&(c[3]<0x82)) ) )return(-1);
if( (c[4]!=0x40) && ( (c[3]==0x40) || (c[4]&1) || (c[4]<0x60) || (c[4]>0xB4) || ((c[4]>0x72)&&(c[4]<0x82)) ) )return(-1);
if( (c[5]!=0x40) && ( (c[4]==0x40) || (c[5]&1) || (c[5]<0x60) || (c[5]>0xB4) || ((c[5]>0x72)&&(c[5]<0x82)) ) )return(-1);
return(0);
};//CHECKBINCALL

int bincalllast(uint8_t*c){
return(c[6]&1);
};//BINCALLLAST

int digifwd(uint8_t*c){
return(c[6]&0x80);
};//DIGIFWD

int checkbinpath(uint8_t*c,ssize_t l){
int n;
if(c==NULL)return(-1);
if(l<15)return(-1);//SHORT PACKET
if(checkbincall(c))return(-1);
if(bincalllast(c))return(-1);
if(checkbincall(c+7))return(-1);
if(bincalllast(c+7))return(0);//DONE
for(n=2;n<MAXDIGIS+2;n++){
if((n*7)>(l-1))return(-1);//ADDRESS+CONTROL LONGER THAN PACKET
if(checkbincall(c+(n*7)))return(-1);
if(bincalllast(c+(n*7)))return(0);//DONE
};//FOREACH DIGIPEATER
return(-1);//MAXDIGIS RAN OUT
};//CHECKBINPATH

//WE'RE ONLY INTERESTED IN SETTING ROUTES -TO- NODES WE RECEIVED PACKETS FROM..
//MEANING EITHER THE SOURCE ADDRESS OR THE LAST DIGIPEATER IN THE PATH THAT HAS THE FORWARDED FLAG ON

uint8_t*getlasthop(uint8_t*c){
int n;
static uint8_t *r;
r=c+7;//INITIALIZE LASTHOP=SRC
if(!bincalllast(c+7))for(n=2;n<MAXDIGIS+2;n++){
if(digifwd(c+(n*7)))r=c+(n*7);
if(bincalllast(c+(n*7)))return(r);//DONE
};//FOREACH DIGIPEATER
return(r);//MAXDIGIS RAN OUT PATH IS WHATEVER REPEATER WAS LAST HEARD OR THE ACTUAL DST
};//GETLASTHOP

//SAME THING, OTHER WAY AROUND... FIND (ROUTE TO) DEST CALL OR FIRST DIGIPEATER THAT DID NOT FORWARD THE FRAME

uint8_t*getnexthop(uint8_t*c){
int n;
if(bincalllast(c+7))return(c+0);//NEXTHOP=DST,DONE
for(n=2;n<MAXDIGIS+2;n++){
if(!digifwd(c+(n*7)))return(c+(n*7));
if(bincalllast(c+(n*7)))break;
};
return(c);//MAXDIGIS RAN OUT PATH IS JUST DST... WE'LL RETURN SOMETHING TO TRY...
};//GETNEXTHOP

char*bincalltoascii(uint8_t*c){
static char a[10];
int n;
if(c==NULL)return(NULL);
for(n=0;(n<6)&&(c[n]!=0x40);n++)a[n]=(c[n]>>1);
if((c[6]>>1)&0x0F){
a[n++]='-';
if(((c[6]>>1)&0x0F)>=10){
a[n++]=0x31;a[n++]=((c[6]>>1)&0x0F)+0x26;
}else a[n++]=0x30+((c[6]>>1)&0x0F);
};//IF SSID
for(;n<sizeof(a);n++)a[n]=0;
return(a);
};//BINCALLTOASCII

void printbinpath(uint8_t*c){
int n;
if(c==NULL)return;
printf("%s FROM: %s",srcbtime(0),bincalltoascii(c+7));
if(!bincalllast(c+7))for(n=2;n<MAXDIGIS+2;n++){
printf(" -> %s",bincalltoascii(c+(n*7)));
if(digifwd(c+(n*7)))printf("*");
if(bincalllast(c+(n*7)))break;
};//FOR DIGIPEATER
printf(" TO: %s\n",bincalltoascii(c));
};//PRINTBINPATH

struct route*addroute(uint8_t*bincall,int port){
struct route*thisrte;
struct route*prevrte;
if(bincall==NULL)return(NULL);
union{
uint64_t tmpcall64;
uint8_t tmpcall[8];
}tmp;
tmp.tmpcall64=0;
bcopy(bincall,tmp.tmpcall,6);tmp.tmpcall[6]=bincall[6]&0x1E;
prevrte=NULL;
printf("%s ROUTER UPDATE PATH TO: %s VIA DEVICE: %d\n",srcbtime(0),bincalltoascii(bincall),port);
for(thisrte=startrte;thisrte!=NULL;thisrte=thisrte->next)if(tmp.tmpcall64==thisrte->intcall)break;else prevrte=thisrte;
if(thisrte==NULL){
thisrte=malloc(sizeof(struct route));
if(thisrte==NULL)return(NULL);
memset(thisrte,0,sizeof(struct route));
thisrte->intcall=tmp.tmpcall64;
thisrte->next=NULL;
if(startrte==NULL)startrte=thisrte;
if(prevrte!=NULL)prevrte->next=thisrte;
};
thisrte->lastseen=time(NULL);
thisrte->port=port;
return(thisrte);
};//ADDROUTE

struct route*delroute(uint8_t*bincall){
struct route*thisrte;
struct route*prevrte;
if(bincall==NULL)return(NULL);
union{
uint64_t tmpcall64;
uint8_t tmpcall[8];
}tmp;
tmp.tmpcall64=0;
bcopy(bincall,tmp.tmpcall,6);tmp.tmpcall[6]=bincall[6]&0x1E;
prevrte=NULL;
printf("%s ROUTER DELETE CALLSIGN: %s\n",srcbtime(0),bincalltoascii(bincall));
for(thisrte=startrte;thisrte!=NULL;thisrte=thisrte->next)if(thisrte->intcall==tmp.tmpcall64)break;else prevrte=thisrte;
if(thisrte!=NULL){
if(startrte==thisrte)startrte=thisrte->next;
if(prevrte!=NULL)prevrte->next=thisrte->next;
memset(thisrte,0,sizeof(struct route));
free(thisrte);
};//FOUND
return(thisrte);
};//DELROUTE

struct route*getroute(uint8_t*bincall){
struct route*thisrte;
if(bincall==NULL)return(NULL);
union{
uint64_t tmpcall64;
uint8_t tmpcall[8];
}tmp;
tmp.tmpcall64=0;
bcopy(bincall,tmp.tmpcall,6);tmp.tmpcall[6]=bincall[6]&0x1E;
for(thisrte=startrte;thisrte!=NULL;thisrte=thisrte->next)if(thisrte->intcall==tmp.tmpcall64)break;
if(thisrte!=NULL)printf("%s ROUTER FOUND PATH TO CALLSIGN: %s VIA DEVICE: %d\n",srcbtime(0),bincalltoascii(bincall),thisrte->port);
return(thisrte);
};//DELROUTE

struct route*delport(int port,int live){
struct route*thisrte;
struct route*prevrte;
struct route*delrte;
time_t nowtime;
time_t purgetime;
nowtime=time(NULL);
purgetime=nowtime-live;
prevrte=NULL;
delrte=NULL;
printf("%s ROUTER DELETE PORT: %d\n",srcbtime(nowtime),port);
for(thisrte=startrte;thisrte!=NULL;thisrte=thisrte->next){
if(delrte!=NULL){memset(delrte,0,sizeof(struct route));free(delrte);delrte=NULL;};
if((thisrte->port==port)||(thisrte->lastseen<purgetime)){
printf("%s ROUTER PURGED ROUTE TO: %s OVER DEVICE: %d LIVETIME: %ld SECONDS\n",srcbtime(nowtime),bincalltoascii(thisrte->bincall),thisrte->port,nowtime-thisrte->lastseen);
if(startrte==thisrte)startrte=thisrte->next;
if(prevrte!=NULL)prevrte->next=thisrte->next;
delrte=thisrte;
}else prevrte=thisrte;//PREVRTE ONLY UPDATED IF WE DO NOT DELETE THE CURRENT ENTRY
};//FOR ALL
if(delrte!=NULL){memset(delrte,0,sizeof(struct route));free(delrte);delrte=NULL;};//CLEAR LAST
return(thisrte);
};//DELROUTE

struct route*expireroute(time_t live){
struct route*thisrte;
struct route*prevrte;
struct route*delrte;
time_t nowtime;
time_t purgetime;
nowtime=time(NULL);
purgetime=nowtime-live;
prevrte=NULL;
delrte=NULL;
printf("%s ROUTER EXPIRY CHECK: %lu SECONDS\n",srcbtime(nowtime),live);
for(thisrte=startrte;thisrte!=NULL;thisrte=thisrte->next){
if(delrte!=NULL){memset(delrte,0,sizeof(struct route));free(delrte);delrte=NULL;};
//CHECK IF WE HAVE A myinterfaces TABLE ENTRY FOR THAT IFINDEX
for(po=0;po<portcount;po++)if(thisrte->port==myinterfaces[po].ifindex)break;
//IF EXPIRED OR INTERFACE IS GONE, DELETE
if((thisrte->lastseen<purgetime)||(po==portcount)){
printf("%s ROUTER PURGED ROUTE TO: %s OVER DEVICE: %d LIVETIME: %ld SECONDS\n",srcbtime(nowtime),bincalltoascii(thisrte->bincall),thisrte->port,nowtime-thisrte->lastseen);
if(startrte==thisrte)startrte=thisrte->next;
if(prevrte!=NULL)prevrte->next=thisrte->next;
delrte=thisrte;
}else prevrte=thisrte;//PREVRTE ONLY UPDATED IF WE DO NOT DELETE THE CURRENT ENTRY
};//FOR ALL
if(delrte!=NULL){memset(delrte,0,sizeof(struct route));free(delrte);delrte=NULL;};//CLEAR LAST
return(thisrte);
};//EXPIREROUTE

void printroutes(){
time_t purgetime;
purgetime=time(NULL);
struct route*thisrte;
for(thisrte=startrte;thisrte!=NULL;thisrte=thisrte->next)printf("CALLSIGN: %-12s PORT: %10d LIVETIME; %10ld SECONDS\n",bincalltoascii(thisrte->bincall),thisrte->port,purgetime-thisrte->lastseen);
};//PRINTROUTE

//SIGNALHANDLER HUP
void requestreload(int signum){needreload=1;};

void getinterfaces(){
portcount=0;
struct ifaddrs*ifaddr,*ifa;
struct ifreq ifr;
memset(&myinterfaces,0,sizeof(myinterfaces));
printf("====================\n");
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
if(ifr.ifr_hwaddr.sa_family!=AF_AX25)continue;
bcopy(ifr.ifr_hwaddr.sa_data,myinterfaces[portcount].netcall,7);
strncpy(myinterfaces[portcount].ifname,ifr.ifr_name,sizeof(myinterfaces[portcount].ifname));
strncpy(myinterfaces[portcount].asciicall,bincalltoascii((uint8_t*)myinterfaces[portcount].netcall),sizeof(myinterfaces[portcount].asciicall)-1);
if(ioctl(sock,SIOCGIFFLAGS,&ifr)<0){perror("IOCTL");exit(EXIT_FAILURE);};
myinterfaces[portcount].status=ifr.ifr_flags;
if(ioctl(sock,SIOCGIFINDEX,&ifr)<0){perror("IOCTL");exit(EXIT_FAILURE);};
myinterfaces[portcount].ifindex=ifr.ifr_ifindex;
printf("%s FOUND AX.25 PORT: %d DEVICE: %d NAME: %s CALLSIGN: %s STATUS: %s\n",srcbtime(0),portcount,myinterfaces[portcount].ifindex,myinterfaces[portcount].ifname,myinterfaces[portcount].asciicall,((myinterfaces[portcount].status&(IFF_UP|IFF_RUNNING))?"UP":"DOWN"));
portcount++;
};//FOR INTERFACES
freeifaddrs(ifaddr);
needreload=0;
printf("%s DONE SCANNING INTERFACES\n",srcbtime(0));
lastreload=time(NULL);
expireroute(ROUTEEXPIRY);
printroutes();
if(portcount<2){printf("%s INSUFFICIENT (%d) AX.25 PORTS FOR BRIDGING\n",srcbtime(0),portcount);needreload=1;sleep(5);};//INSUFFICIENT
};//GETINTERFACES

int main(int argc,char**argv){
ssize_t bytes;

uint8_t buf[PACKET_SIZE];

uint8_t*nexthopbin;
char*nexthopascii;

fd_set readfds;
struct timeval tv;

if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

if((sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_AX25)))==-1){perror("SOCKET");exit(EXIT_FAILURE);};

startrte=NULL;

//THIS DOESN'T WORK WITH THE CURRENT VERSION OF THE KERNEL.
//THEREFORE PACKETS ORIGINATING FROM TERMINAL SOFTWARE RUNNING ON THE MACHINE THAT RUNS THE BRIDGE NEVER GET BRIDGED.
//THEREFORE IT IS INADVISABLE TO RUN THE BRIDGE ON THE SAME MACHINES AS CLIENT OR SERVERS
//THEY'LL ONLY WORK ON THE INTERFACE THEY'RE BOUND TO AND NOT GET BRIDGED TO THE REST OF THE NETWORK

//true=1;
//setsockopt(sock,SOL_PACKET,PACKET_RECV_OUTPUT,(char*)&true,sizeof(int)); (RETURNS SOME PROTOCOL NOT SUPPORTED ERROR)

//THIS DOESN'T WORK EITHER.
//true=0;
//setsockopt(sock,SOL_PACKET,PACKET_IGNORE_OUTGOING,(char*)&true,sizeof(int)); (RETURNS 0 BUT DOESN'T DO ANYTHING ;)

//THERE ARE 2 PROBLEMS ACTUALLY... 1: INTERCEPTING PACKETS SENT FROM LOCAL INTERFACES BY PROGRAMS AND 2: GETTING PACKETS TO GO BACK IN TO THOSE PROGRAMS (THEY ONLY GO OUT ONTO THE LINE)
//AND DOING SO WITHOUT REPEATING THE PACKET THE SWITCH JUST BROADCASTED -ITSELF- :P (TIMES THE NUMBER OF INTERFACES)

//THE SOLUTION WILL BE TO JUST HOOK A TAP+BPQ INTERFACE TO THIS PROGRAM TO WHICH ALL LOCAL PROGRAMS CAN BIND INSTEAD WHICH WILL NOT BE INCLUDED
//IN THE LIST OF INTERCEPTED INTERFACES FOR ALL LOCAL PROGRAMS TO USE AS THEIR BIND INTERFACE INSTEAD OF ANY OF THE 'WIRE' INTERFACES. HOOKING THE PROGRAMS DIRECTLY INTO THE SWITCH ITSELF.

//FOR NOW IT WORKS FINE FOR US.. JUST SEPERATE BOX FOR THE SWITCHING. NO PROBLEM. OPTIONAL EXTRAS... RUNNING SERVERS AND TERMINALS ON THE SWITCH BOX.

memset(&sigact,0,sizeof(struct sigaction));
sigemptyset(&sigact.sa_mask);
sigact.sa_flags=SA_NODEFER|SA_RESTART;
sigact.sa_handler=requestreload;
sigaction(SIGHUP,&sigact,NULL);

//FORCE RELOAD FOR STARTUP
needreload=1;
//INITIALIZE LASTRELOAD
lastreload=time(NULL);

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
//ACTUALLY NEED THE FD_ISSET BECAUSE SELECT WILL FALL THROUGH AFTER THE TIMER,
//SOCK IS IN BLOCKING MODE AND READ WILL OTHERWISE NEVER FALL THROUGH TO CHECK
//THE RELOAD TIMER AND CALL GETINTERFACES AGAIN IN LONG TIMES OF INACTIVITY
if(FD_ISSET(sock,&readfds)){
bytes=recvfrom(sock,&buf,sizeof(buf),0,(struct sockaddr*)&ssockaddrll,&clen);
//SHORT PACKET (NOT AX.25)
if(bytes<16)continue;
//KISS byte
if(buf[0]!=0)continue;
if(ssockaddrll.sll_protocol!=htons(ETH_P_AX25))continue;
if(ssockaddrll.sll_family!=AF_PACKET)continue;
if(ssockaddrll.sll_hatype!=ARPHRD_AX25)continue;
if(checkbinpath((uint8_t*)buf+1,bytes-1))continue;
printf("====================\n");
printf("%s INPUT DEVICE: %d FAMILY: %04X PROTOCOL: %04X\n",srcbtime(0),ssockaddrll.sll_ifindex,ssockaddrll.sll_hatype,ntohs(ssockaddrll.sll_protocol));
printbinpath((uint8_t*)buf+1);
addroute(getlasthop((uint8_t*)buf+1),ssockaddrll.sll_ifindex);//SET ROUTE TO SOURCE ADDRESS ON PORT WE HEARD IT FROM
nexthopbin=getnexthop((uint8_t*)buf+1);
findrte=getroute(nexthopbin);
nexthopascii=bincalltoascii(nexthopbin);
dsockaddrll.sll_family=ssockaddrll.sll_family;
dsockaddrll.sll_protocol=ssockaddrll.sll_protocol;
dsockaddrll.sll_hatype=ssockaddrll.sll_hatype;
for(po=0;po<portcount;po++){
//ONLY SEND TO SPECIFIC PORT IF WE HAVE ONE (REBUILD STRUCTURE TO USE PORT NUMBERS LATER)
if(findrte!=NULL)if(findrte->port!=myinterfaces[po].ifindex)continue;
//NOT BRIDGING TO SOURCE INTERFACE
if(myinterfaces[po].ifindex==ssockaddrll.sll_ifindex){
printf("%s NOT RETURNING PACKET OVER INPUT DEVICE: %d (%s) %s: %s\n",srcbtime(0),myinterfaces[po].ifindex,myinterfaces[po].ifname,nexthopbin==(buf+1)?"TO":"VIA",nexthopascii);
continue;};
//NOT BRIDGING TO INTERFACES THAT ARE NOT UP
if(!(myinterfaces[po].status&(IFF_UP|IFF_RUNNING))){needreload=1;continue;};
//ALL FINE, FORWARD PACKET
printf("%s FORWARDING PACKET OVER DEVICE: %d (%s) %s: %s\n",srcbtime(0),myinterfaces[po].ifindex,myinterfaces[po].ifname,nexthopbin==(buf+1)?"TO":"VIA",nexthopascii);
dsockaddrll.sll_ifindex=myinterfaces[po].ifindex;
if(sendto(sock,&buf,bytes,0,(struct sockaddr*)&dsockaddrll,sizeof(struct sockaddr_ll))==-1){perror("SENDTO");delport(dsockaddrll.sll_ifindex,ROUTEEXPIRY);needreload=1;continue;};
};//FOR FORWARD PACKET TO EACH INTERFACE THAT WAS UP AT PROGRAM START IT DID NOT ORIGINATE FROM
};//FD_SET
//RELOAD EVERY 2 MINUTES ANYWAY
if(lastreload<(time(NULL)-120))needreload=1;
expireroute(ROUTEEXPIRY);
};//WHILE 1
};//MAIN
