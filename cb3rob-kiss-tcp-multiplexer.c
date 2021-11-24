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

#include<arpa/inet.h>
#include<fcntl.h>
#include<linux/tcp.h>
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

struct timeval tv;

int sockfd;
int true;
struct sockaddr_in saddr;

int nfds;
fd_set readfds;
fd_set writefds;
fd_set exceptfds;

struct packet{
size_t offset;
uint8_t data[MAXPACKETLENGTH];
};

struct clients{
int fd;
time_t lastvalid;
struct packet kiss;
}cl[MAXCLIENTS];

unsigned char tcppacket[1500];

char *srcbtime(time_t t){
static char rcbt[22];
struct tm *ts;
if(!t)t=time(NULL);
ts=gmtime(&t);
bzero(&rcbt,sizeof(rcbt));
snprintf(rcbt,sizeof(rcbt)-1,"%04d-%02d-%02dT%02d:%02d:%02dZ",ts->tm_year+1900,(ts->tm_mon)+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
return(rcbt);
};//SRCBTIME

void printpacket(uint64_t slot){
int n;
printf("%s PACKET FROM: %d - %lu BYTES:",srcbtime(cl[slot].lastvalid),cl[slot].fd,cl[slot].kiss.offset);
if(!cl[slot].kiss.offset)printf(" SIZE-ZERO"); else for(n=0;n<cl[slot].kiss.offset;n++)printf(" %02X",cl[slot].kiss.data[n]);
printf("\n");
};//PRINTPACKET

void wipe(uint64_t slot){
bzero(&cl[slot].kiss,sizeof(struct packet));
};//WIPE

void disconnect(uint64_t slot){
printf("%s DISCONNECTED SLOT: %lu SOURCE: %d\n",srcbtime(0),slot,cl[slot].fd);
close(cl[slot].fd);
bzero(&cl[slot],sizeof(struct clients));
cl[slot].fd=-1;
};//DISCONNECT

void broadcast(uint64_t slot){
uint64_t dest;
ssize_t bytes;
printf("%s SENT PACKET FROM: %d TO:",srcbtime(0),cl[slot].fd);
for(dest=0;dest<MAXCLIENTS;dest++)if((cl[dest].fd!=-1)&&(cl[dest].fd!=cl[slot].fd)){
bytes=send(cl[dest].fd,&cl[slot].kiss.data,cl[slot].kiss.offset,MSG_NOSIGNAL);
printf(" %d",cl[dest].fd);
if(bytes<1)disconnect(dest);
};//FOREACH CLIENT
printf("\n");
};//BROADCAST

void setuplistener(){
while(1){
sockfd=socket(PF_INET,SOCK_STREAM|SOCK_NONBLOCK,IPPROTO_TCP);
if(sockfd==-1){printf("%s SOCKET CREATION FAILED\n",srcbtime(0));sleep(1);continue;};
true=1;
setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(char*)&true,sizeof(int));
true=1;
setsockopt(sockfd,SOL_SOCKET,SO_KEEPALIVE,(char*)&true,sizeof(int));
saddr.sin_family=AF_INET;
saddr.sin_port=htons(8001);
saddr.sin_addr.s_addr=INADDR_ANY;
if(bind(sockfd,(struct sockaddr*)&saddr,sizeof(saddr))!=0){printf("%s SOCKET BIND FAILED\n",srcbtime(0));close(sockfd);sleep(1);continue;};
if(listen(sockfd,1024)!=0){printf("%s SOCKET LISTEN FAILED\n",srcbtime(0));close(sockfd);sleep(1);continue;};
printf("%s SOCKET LISTEN SUCCESS\n",srcbtime(0));
break;
};//WHILE 1
};//SETUPLISTENER

int main(){
setuplistener();
ssize_t bytes;
size_t n;
uint64_t slot;
int active;
//ZERO CLIENTS TABLE
bzero(&cl,sizeof(cl));
//SET ALL FILEDESCRIPTORS TO -1
for(slot=0;slot<MAXCLIENTS;slot++)cl[slot].fd=-1;
FD_ZERO(&readfds);
FD_ZERO(&writefds);
FD_ZERO(&exceptfds);
FD_SET(sockfd,&readfds);
nfds=sockfd+1;

while(1){

//REBUILD SELECT DATA ON EACH LOOP
tv.tv_sec=30;
tv.tv_usec=0;
FD_ZERO(&readfds);
FD_SET(sockfd,&readfds);
nfds=sockfd;
for(slot=0;slot<MAXCLIENTS;slot++)if(cl[slot].fd!=-1){FD_SET(cl[slot].fd,&readfds);if(nfds<cl[slot].fd)nfds=cl[slot].fd;};
nfds++;
printf("%s ENTERING SELECT\n",srcbtime(0));
active=select(nfds,&readfds,NULL,NULL,&tv);
printf("%s EXITED SELECT WITH %d FILEDESCRIPTORS\n",srcbtime(0),active);

//FIND FIRST FREE SLOT
for(slot=0;(slot<MAXCLIENTS)&&(cl[slot].fd!=-1);slot++);
//ACCEPT 1 CLIENT PER LOOP
cl[slot].fd=accept(sockfd,NULL,0);//NON BLOCK
//DON'T OVERFLOW MAXCLIENTS TABLE
if(cl[slot].fd!=-1){
//HAVE CLIENT
if(slot<(MAXCLIENTS-1)){
cl[slot].lastvalid=0;
wipe(slot);
//FORCE NONBLOCK
fcntl(cl[slot].fd,F_SETFL,fcntl(cl[slot].fd,F_GETFL,0)|O_NONBLOCK);
true=1;//DISABLE NAGLE
setsockopt(cl[slot].fd,IPPROTO_TCP,TCP_NODELAY,(char*)&true,sizeof(int));
FD_SET(cl[slot].fd,&readfds);
if(nfds<(cl[slot].fd+1))nfds=cl[slot].fd+1;
printf("%s ACCEPTED SOURCE %d INTO SLOT %lu\n",srcbtime(0),cl[slot].fd,slot);
}else{
printf("%s REJECTED SOURCE %d\n",srcbtime(0),cl[slot].fd);
disconnect(slot);
};//MAXCLIENTS CHECK
};//HAVE CLIENT

for(slot=0;slot<MAXCLIENTS;slot++)if((cl[slot].fd!=-1)&&(FD_ISSET(cl[slot].fd,&readfds))){
bytes=recv(cl[slot].fd,&tcppacket,sizeof(tcppacket),MSG_DONTWAIT);
if(bytes==0){disconnect(slot);continue;};
//PARSE TCP PACKET INTO SEPERATE KISS PACKETS
if(bytes>0)for(n=0;n<bytes;n++){
cl[slot].kiss.data[cl[slot].kiss.offset++]=tcppacket[n];
while((cl[slot].kiss.data[0]==0xC0)&&(cl[slot].kiss.data[1]==0xC0)){printf("RESYNC!\n");wipe(slot);cl[slot].kiss.data[0]=0xC0;cl[slot].kiss.offset=1;};
if(cl[slot].kiss.offset>=MAXPACKETLENGTH-1){printf("OVERFLOW!\n");printpacket(slot);wipe(slot);continue;};
if(cl[slot].kiss.offset>1){
if(cl[slot].kiss.data[0]!=0xC0){printf("INVALID!\n");printpacket(slot);wipe(slot);continue;};
if(cl[slot].kiss.data[cl[slot].kiss.offset-1]==0xC0){
if(cl[slot].kiss.data[1]){printf("COMMAND OR WRONG CHANNEL!\n");printpacket(slot);wipe(slot);continue;};
if(cl[slot].kiss.offset<18){printf("UNDERSIZE!\n");printpacket(slot);wipe(slot);continue;};
if(cl[slot].kiss.data[1]==0x00){printf("COMPLETE!\n");cl[slot].lastvalid=time(NULL);printpacket(slot);broadcast(slot);wipe(slot);continue;};
};//FRAME ENDS WITH FEND
};//KISS LENGTH LARGER THAN 1
};//FOREACH CHAR
};//FOR CLIENTS LOOP
};//WHILE 1
};//MAIN
