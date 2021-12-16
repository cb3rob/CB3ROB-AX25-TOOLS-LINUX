//HRH Prince Sven Olaf of CyberBunker-Kamphuis
//CB3ROB TACTICAL SYSTEMS
//One CyberBunker Avenue
//Republic CyberBunker

#include<arpa/inet.h>
#include<fcntl.h>
#include<linux/sctp.h>
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<time.h>
#include<unistd.h>

#define MAXPACKETLENGTH 3000
#define MAXCLIENTS 100
#define MAXBACKLOG 16
#define MAXDIGIS 7

struct timeval tv;

int sock;
int true;
struct sockaddr_in saddr;

int nfds;
int wnfds;
int rnfds;
fd_set readfds;
fd_set writefds;

struct packet{
size_t offset;
uint8_t data[MAXPACKETLENGTH];
};

struct clients{
int fd;
time_t lastvalid;
struct packet ax25frame;
}cl[MAXCLIENTS];

unsigned char sctppacket[1500];

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
if(                 (                 (c[0]&1) || (c[0]<0x60) || (c[0]>0xB4) || ((c[0]>0x72)&&(c[0]<0x82)) ) )return(-1);
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

int checkbinpath(uint8_t*c,ssize_t l){
int n;
if(c==NULL)return(-1);
if(l<15)return(-1);//SHORT PACKET
if(checkbincall((uint8_t*)c))return(-1);
if(bincalllast((uint8_t*)c))return(-1);
if(checkbincall((uint8_t*)c+7))return(-1);
if(bincalllast((uint8_t*)c+7))return(0);//DONE
for(n=2;n<MAXDIGIS+2;n++){
if((n*7)>(l-1))return(-1);//ADDRESS+CONTROL LONGER THAN PACKET
if(checkbincall((uint8_t*)c+(n*7)))return(-1);
if(bincalllast((uint8_t*)c+(n*7)))return(0);//DONE
};//FOREACH DIGIPEATER
return(-1);//MAXDIGIS RAN OUT
};//CHECKBINPATH

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

void printpacket(uint64_t slot){
int n;
printf("%s SOURCE: %s ",srcbtime(cl[slot].lastvalid),bincalltoascii((uint8_t*)cl[slot].ax25frame.data+7));
printf("DESTINATION: %s SLOT: %d - %lu BYTES:",bincalltoascii((uint8_t*)cl[slot].ax25frame.data),cl[slot].fd,cl[slot].ax25frame.offset);
if(!cl[slot].ax25frame.offset)printf(" SIZE-ZERO"); else for(n=0;n<cl[slot].ax25frame.offset;n++)printf(" %02X",cl[slot].ax25frame.data[n]);
printf("\n");
};//PRINTPACKET

void wipe(uint64_t slot){
memset(&cl[slot].ax25frame,0,sizeof(struct packet));
};//WIPE

void disconnect(uint64_t slot){
printf("%s DISCONNECTED SLOT: %lu SOURCE: %d\n",srcbtime(0),slot,cl[slot].fd);
close(cl[slot].fd);
memset(&cl[slot],0,sizeof(struct clients));
FD_CLR(cl[slot].fd,&readfds);
FD_CLR(cl[slot].fd,&writefds);
cl[slot].fd=-1;
};//DISCONNECT

void broadcast(uint64_t slot){
uint64_t dest;
ssize_t bytes;
tv.tv_sec=0;
tv.tv_usec=100000;
if(select(wnfds+1,NULL,&writefds,NULL,&tv)>0){
printf("%s SENT PACKET FROM: %d TO:",srcbtime(0),cl[slot].fd);
//IF NOT READY TO SEND DATA TO RIGHT NOW WE SIMPLY SKIP THEM. CAN'T HAVE SLOW LINKS HOLD THE REST DOWN.
for(dest=0;dest<MAXCLIENTS;dest++)if((cl[dest].fd!=-1)&&(cl[dest].fd!=cl[slot].fd)&&(FD_ISSET(cl[slot].fd,&writefds))){
bytes=send(cl[dest].fd,&cl[slot].ax25frame.data,cl[slot].ax25frame.offset,MSG_NOSIGNAL);
printf(" %d",cl[dest].fd);
if(bytes<1)disconnect(dest);
};//FOREACH CLIENT
};//ANYONE AT ALL READY TO RECEIVE?
printf("\n");
};//BROADCAST

void setuplistener(){
while(1){
sock=socket(PF_INET,SOCK_STREAM|SOCK_NONBLOCK,IPPROTO_SCTP);
if(sock==-1){printf("%s SOCKET CREATION FAILED\n",srcbtime(0));sleep(1);continue;};
true=1;
setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char*)&true,sizeof(int));
true=1;
setsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,(char*)&true,sizeof(int));
saddr.sin_family=AF_INET;
saddr.sin_port=htons(8001);
saddr.sin_addr.s_addr=INADDR_ANY;
if(bind(sock,(struct sockaddr*)&saddr,sizeof(saddr))!=0){printf("%s SOCKET BIND FAILED\n",srcbtime(0));close(sock);sleep(1);continue;};
if(listen(sock,MAXBACKLOG)!=0){printf("%s SOCKET LISTEN FAILED\n",srcbtime(0));close(sock);sleep(1);continue;};
printf("%s SOCKET LISTEN SUCCESS\n",srcbtime(0));
break;
};//WHILE 1
};//SETUPLISTENER

int main(int argc,char**argv){
setuplistener();
ssize_t bytes;
uint64_t slot;
int active;
//ZERO CLIENTS TABLE
memset(&cl,0,sizeof(cl));
//SET ALL FILEDESCRIPTORS TO -1
for(slot=0;slot<MAXCLIENTS;slot++)cl[slot].fd=-1;
FD_ZERO(&readfds);
FD_ZERO(&writefds);
FD_SET(sock,&readfds);

while(1){
//REBUILD SELECT DATA ON EACH LOOP
FD_ZERO(&readfds);
FD_ZERO(&writefds);
FD_SET(sock,&readfds);
tv.tv_sec=30;
tv.tv_usec=0;
nfds=0;
for(slot=0;slot<MAXCLIENTS;slot++)if(cl[slot].fd!=-1){FD_SET(cl[slot].fd,&readfds);FD_SET(cl[slot].fd,&writefds);if(nfds<cl[slot].fd)nfds=cl[slot].fd;};
wnfds=nfds;//FOR BROADCAST - WITHOUT SOCK
rnfds=nfds;//FOR RECEIVE - WITH SOCK TO ACCEPT NEW CLIENTS
if(sock>rnfds)rnfds=sock;
printf("%s ENTERING SELECT\n",srcbtime(0));
active=select(rnfds+1,&readfds,NULL,NULL,&tv);
printf("%s EXITED SELECT WITH %d FILEDESCRIPTORS\n",srcbtime(0),active);
if(active>0){

for(slot=0;slot<MAXCLIENTS;slot++)if((cl[slot].fd!=-1)&&(FD_ISSET(cl[slot].fd,&readfds))){
bytes=recv(cl[slot].fd,&sctppacket,sizeof(sctppacket),MSG_DONTWAIT);
if(bytes<1){disconnect(slot);continue;};
cl[slot].ax25frame.offset=bytes;
bcopy(sctppacket,cl[slot].ax25frame.data,bytes);
//CHECK AX-25 FRAME VALIDITY HERE LATER ON
if(checkbinpath((uint8_t*)&cl[slot].ax25frame.data,cl[slot].ax25frame.offset)){printf("INVALID ADDRESS IN PATH\n");printpacket(slot);wipe(slot);continue;};
printf("COMPLETE!\n");cl[slot].lastvalid=time(NULL);printpacket(slot);broadcast(slot);wipe(slot);
};//FOR CLIENTS LOOP

//HANDLE NEW CLIENTS AFTER FORWARDING ANY TRAFFIC AS WE CAN'T ADD THEM TO THE SELECT ANYMORE ANYWAY
if(FD_ISSET(sock,&readfds)){
//FIND FIRST FREE SLOT
for(slot=0;(slot<MAXCLIENTS)&&(cl[slot].fd!=-1);slot++);
//ACCEPT 1 CLIENT PER LOOP
cl[slot].fd=accept(sock,NULL,0);//NON BLOCK
//DON'T OVERFLOW MAXCLIENTS TABLE
if(cl[slot].fd!=-1){
//HAVE CLIENT
if(slot<(MAXCLIENTS-1)){
cl[slot].lastvalid=0;
wipe(slot);
//FORCE NONBLOCK
fcntl(cl[slot].fd,F_SETFL,fcntl(cl[slot].fd,F_GETFL,0)|O_NONBLOCK);
//true=1;//DISABLE NAGLE - PROBABLY NOT FOR SCTP
//setsockopt(cl[slot].fd,IPPROTO_SCTP,SCTP_NODELAY,(char*)&true,sizeof(int));
printf("%s ACCEPTED SOURCE %d INTO SLOT %lu\n",srcbtime(0),cl[slot].fd,slot);
}else{
printf("%s REJECTED SOURCE %d\n",srcbtime(0),cl[slot].fd);
disconnect(slot);
};//MAXCLIENTS CHECK
};//HAVE CLIENT
};//FDISSET SOCK

};//IF SELECT > 0
};//WHILE 1
};//MAIN

