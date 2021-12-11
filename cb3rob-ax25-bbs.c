//HRH Prince Sven Olaf of CyberBunker-Kamphuis
//CB3ROB TACTICAL SYSTEMS
//One CyberBunker Avenue
//Republic CyberBunker

// 'TELNETD' FOR AX.25 - STARTS BBS SHELL ENVIRONMENT ON A PTY

//ALPHA DEVELOPMENT STATUS - UNDER CONSTRUCTION - NO ASSUMPTIONS TOWARDS SECURITY

//root 9254  0.0  0.0   6592   808 pts/0    S+   12:51   0:00  \_ ./cb3rob-ax25-bbs KISSMX                <--- MAIN LISTEN DAEMON
//root 9289  0.0  0.0  15048  1832 pts/0    S+   12:52   0:00      \_ ./cb3rob-ax25-bbs KISSMX            <--- CHILD AX.25 HANDLER
//root 9290  0.0  0.0  85036  4544 pts/4    Ss   12:52   0:00          \_ /usr/sbin/cb3rob-ax25-bbs-login <--- CHILD PTY HANDLER EXEC

#include<fcntl.h>
#include<linux/ax25.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/time.h>
#include<sys/types.h>
#include<time.h>
#include<unistd.h>
#include<stdint.h>
#include<utmp.h>
#include<termios.h>
#include<pty.h>
#include<wait.h>
#include<signal.h>

#define MAXBACKLOG 16

int bsock;
int csock;
char tbuf[(AX25_MTU*7)];//MORE EFFECTIVE THROUGHPUT WHEN SENDING IN BURST
struct full_sockaddr_ax25 baddr;
struct full_sockaddr_ax25 caddr;
struct sigaction sigact;
socklen_t clen;
fd_set writefds;
fd_set readfds;
struct timeval tv;
int nfds;

char sourcecall[10];
char destcall[10];
char servicecall[10];
char interfacecall[10];

char*srcbtime(time_t t){
static char rcbt[22];
struct tm*ts;
if(!t)t=time(NULL);
ts=gmtime(&t);
memset(&rcbt,0,sizeof(rcbt));
snprintf(rcbt,sizeof(rcbt)-1,"%04d-%02d-%02dT%02d:%02d:%02dZ",ts->tm_year+1900,ts->tm_mon+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
return(rcbt);
};//SRCBTIME

int addresstoascii(ax25_address*bin,char*a){
unsigned char ssid;
//unsigned char control;
unsigned int n;
//HAVE TO RECAST STRUCT ANONYMOUS
uint8_t*b;
b=(uint8_t*)bin;
if((b[0]&0x01)||(b[1]&0x01)||(b[2]&0x01)||(b[3]&0x01)||(b[4]&0x01)||(b[5]&0x01))return(0);//BIT 0 is SET TO ZERO ON ALL BUT THE LAST OCTET
//BOGUS OUT IF INVALID BEFORE HANDLING THE REST FOR SPEED OPTIMALISATION
a[0]=(b[0]>>1);
if(((a[0]<0x30)||(a[0]>0x5A))||((a[0]>0x39)&&(a[0]<0x41)))return(0);//UPPER CASE ASCII AND NUMBERS ONLY
a[1]=(b[1]>>1);
if((a[1]!=0x20)&&(((a[1]<0x30)||(a[1]>0x5A))||((a[1]>0x39)&&(a[1]<0x41))))return(0);//SPACE OR UPPER CASE ASCII OR NUMBERS ONLY
a[2]=(b[2]>>1);
if((a[2]!=0x20)&&(((a[2]<0x30)||(a[2]>0x5A))||((a[2]>0x39)&&(a[2]<0x41))))return(0);//SPACE OR UPPER CASE ASCII AND NUMBERS ONLY
a[3]=(b[3]>>1);
if((a[3]!=0x20)&&(((a[3]<0x30)||(a[3]>0x5A))||((a[3]>0x39)&&(a[3]<0x41))))return(0);//SPACE OR UPPER CASE ASCII AND NUMBERS ONLY
a[4]=(b[4]>>1);
if((a[4]!=0x20)&&(((a[4]<0x30)||(a[4]>0x5A))||((a[4]>0x39)&&(a[4]<0x41))))return(0);//SPACE OR UPPER CASE ASCII AND NUMBERS ONLY
a[5]=(b[5]>>1);
if((a[5]!=0x20)&&(((a[5]<0x30)||(a[5]>0x5A))||((a[5]>0x39)&&(a[5]<0x41))))return(0);//SPACE OR UPPER CASE ASCII AND NUMBERS ONLY
a[6]=0;
a[7]=0;
a[8]=0;
a[9]=0;
//COMMAND-CONTROL BIT ON NORMAL ADDRESS - HAS-BEEN-REPEATED FIELD ON REPEATER ADDRESS - CLEARED WHEN PASSED THROUGH THAT REPEATER
//control=(b[6]&0x80);
//HANDLE PROTOCOL BITS
ssid=((b[6]>>1)&0x0F);
//CHANGE SPACE TERMINATION TO ZERO TERMINATION
for(n=5;(n>0)&&(a[n]==0x20);n--)a[n]=0x00;
n++;//SET N TO LAST CHARACTER+1;
//HANDLE SSID TO ASCII
if(ssid>0){a[n++]='-';if(ssid<10){a[n++]=0x30+ssid;}else{a[n++]=0x31;a[n++]=0x26+ssid;};};
return((b[6]&0x01)+1);
};//ADDRESSTOASCII

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

ssize_t sendclient(void*data,ssize_t total){
ssize_t bytes;
ssize_t thisblock;
ssize_t sent;
int flags;
if(total==0)total=strlen((char*)data);
bytes=0;
sent=0;
FD_ZERO(&writefds);//CSOCK DOESN'T CHANGE WHILE WITHIN THE CHILD
while((bytes!=-1)&&(total-sent>0)){
FD_SET(csock,&writefds);
tv.tv_sec=60;
tv.tv_usec=0;
//ACTUALLY HAVE TO SELECT BEFORE WRITE. OR STUFF GOES MISSING HERE TOO. WELCOME TO LINUX
printf("%s CLIENT %d WAIT FOR SELECT\n",srcbtime(0),getpid());
select(csock+1,NULL,&writefds,NULL,&tv);
//FALL THROUGH IS SEND ANYWAY TO CHECK IF STILL CONNECTED
thisblock=AX25_MTU;flags=MSG_DONTWAIT;if((total-sent)<=AX25_MTU){thisblock=(total-sent);flags|=MSG_EOR;};
printf("%s CLIENT %d SENDING: %ld SENT: %ld TOTAL: %ld\n",srcbtime(0),getpid(),thisblock,sent,total);
//SEND TO DISCONNECTED PEER ACTUALLY WILL BLOCK FOREVER ANYWAY REGARDLESS OF NONBLOCK SETTINGS ON AX.25 SOCK_SEQPACKET BUT IT WILL TRIGGER SIGPIPE... HANDLE SIGPIPE OR DEFUNCT PROCESS!
bytes=send(csock,(uint8_t*)data+sent,thisblock,flags);
printf("%s CLIENT %d SENT: %ld\n",srcbtime(0),getpid(),bytes);
if(bytes<1)break;
sent+=bytes;
};//WHILE DATA REMAINING
return(bytes);
};//SENDCLIENT

void setupsock(char*service,char*interface){
while(1){
if(bsock!=-1)close(bsock);
bsock=socket(PF_AX25,SOCK_SEQPACKET|SOCK_NONBLOCK,0);
if(bsock==-1)continue;
printf("MAIN SOCKET: %d\n",bsock);
memset(&baddr,0,sizeof(struct full_sockaddr_ax25));
baddr.fsa_ax25.sax25_family=AF_AX25;
if(calltobin(service,&baddr.fsa_ax25.sax25_call)==-1){printf("INVALID SERVICE-CALLSIGN: %s!\n",service);exit(EXIT_FAILURE);};
addresstoascii(&baddr.fsa_ax25.sax25_call,destcall);
//argv[argc] IS GUARANTEED TO BE NULL. NO OVERFLOW POSSIBLE
if(interface!=NULL){//USER SPECIFIED AN INTERFACE TO BIND TO
baddr.fsa_ax25.sax25_ndigis=1;
if(calltobin(interface,&baddr.fsa_digipeater[0])==-1){printf("INVALID INTERFACE-CALLSIGN: %s!\n",interface);exit(EXIT_FAILURE);};
addresstoascii(&baddr.fsa_digipeater[0],interfacecall);
};
if(bind(bsock,(struct sockaddr*)&baddr,sizeof(struct full_sockaddr_ax25))==-1){printf("BIND FAILED! - IS THERE AN INTERFACE WITH CALLSIGN %s?\n",((interface==NULL)?destcall:interfacecall));sleep(1);continue;};
if(listen(bsock,MAXBACKLOG)==-1){printf("LISTEN FAILED\n");sleep(1);continue;};
printf("BOUND TO: %s",destcall);
if(baddr.fsa_ax25.sax25_ndigis==1)printf(" ON INTERFACE: %s",interfacecall);
printf("\n");
break;
};//WHILE NOT SOCKET LOOP
};//SETUPSOCK

void termclient(int csock,int master,pid_t ptychild){
printf("%s CLIENT %d TERMINATING\n",srcbtime(0),getpid());
memset(&tbuf,0,sizeof(tbuf));
if(csock!=-1){printf("%s CLIENT %d CLOSING SOCKET %d\n",srcbtime(0),getpid(),csock);close(csock);csock=-1;};
//KILL LOGIN BEFORE CLOSING MASTER OR LOGIN WILL CAUSE SEGV UPON I/O TO CLOSED PTY
if(ptychild!=-1){printf("%s CLIENT %d KILLING LOGIN %d\n",srcbtime(0),getpid(),ptychild);kill(ptychild,SIGTERM);sleep(10);kill(ptychild,SIGKILL);ptychild=-1;};
if(master!=-1){printf("%s CLIENT %d CLOSING MASTER %d\n",srcbtime(0),getpid(),master);close(master);master=-1;};
printf("%s CLIENT %d TERMINATED\n",srcbtime(0),getpid());
exit(EXIT_SUCCESS);
};//TERMCLIENT

int clientcode(){
//FORK CHILD
ssize_t bytes;
struct termios trm;
struct winsize wins;
char slavetty[256];
//NO CONTROL-C IN THE CHILD. JUST IN THE MAIN PROCESS
setsid();
setpgid(0,0);
signal(SIGINT,SIG_IGN);
signal(SIGCHLD,SIG_DFL);//CHILD DOES CARE
pid_t ptychild;ptychild=-1;
int master;master=-1;
void calltermclient(int signum){printf("%s CLIENT %d TRIGGERED %s\n",srcbtime(0),getpid(),(signum==SIGTERM?"SIGTERM":"SIGPIPE"));termclient(csock,master,ptychild);};
//TERMINATE CLIENTS NICELY... SIGPIPE IS ACTUALLY NEEDED AS SEND() ON AX.25 SEQPACKET JUST HANGS WHEN THE OTHER SIDE IS GONE FIRST
memset(&sigact,0,sizeof(struct sigaction));
sigemptyset(&sigact.sa_mask);
sigact.sa_handler=calltermclient;
//NO CONTROL-C OR ANY SUCH NONSENSE BEFORE LOGIN IS FINISHED
sigaction(SIGTERM,&sigact,NULL);
sigaction(SIGPIPE,&sigact,NULL);

fcntl(csock,F_SETFL,fcntl(csock,F_GETFL,0)|O_NONBLOCK);
printf("%s CLIENT %d CONNECTED\n",srcbtime(0),getpid());
printf("%s CLIENT %d SOCKET: %d\n",srcbtime(0),getpid(),csock);
memset(&tbuf,0,sizeof(tbuf));
addresstoascii(&caddr.fsa_ax25.sax25_call,sourcecall);
snprintf(tbuf,sizeof(tbuf)-1,"%s %s -> %s\r\r",srcbtime(0),sourcecall,destcall);
if(sendclient(tbuf,0)<0)termclient(csock,master,ptychild);
memset(&tbuf,0,sizeof(tbuf));
memset(&trm,0,sizeof(struct termios));
//SET SOME BASIC TERMIOS STUFF TO AT LEAST GET CRNL - TERMIOS DOESN'T SEEM TO DO JUST CARRIAGE RETURN ONLY
//PACKET RADIO PROGRAMS PREFER CARRIAGE RETURN ONLY BUT WILL IGNORE NEWLINE (OR SHOULD).
//FILE TRANSFER PROGRAMS DEMAND 8 BIT TRANSPARENCY.
cfmakeraw(&trm);
trm.c_iflag|=ICRNL;
trm.c_oflag|=ONLCR|OPOST;
memset(&wins,0,sizeof(struct winsize));
wins.ws_row=24;
wins.ws_col=80;
ptychild=forkpty(&master,slavetty,&trm,&wins);
if(ptychild==0){
//CHILD (LOGIN)
close(csock);csock=-1;//DON'T WANT THAT HERE
char*loginargv[]={"/usr/sbin/cb3rob-ax25-bbs-login",sourcecall,destcall,NULL};
char*loginenvp[]={"TERM=dumb",NULL};
execve("/usr/sbin/cb3rob-ax25-bbs-login",&loginargv[0],&loginenvp[0]);
exit(EXIT_SUCCESS);
}else{
//PARENT (DATA RELAY)
if(fcntl(master,F_SETFL,O_NONBLOCK)==-1)exit(EXIT_FAILURE);
FD_ZERO(&readfds);
while(waitpid(ptychild,NULL,WNOHANG)!=ptychild){
FD_SET(master,&readfds);
FD_SET(csock,&readfds);
tv.tv_sec=600;
tv.tv_usec=0;
nfds=master;if(csock>master)nfds=csock;
select(nfds+1,&readfds,NULL,NULL,&tv);

//BYTES FROM PROGRAM
if(FD_ISSET(master,&readfds)){
//STICK TO MTU SIZE - TBUF IS ONE LONGER FOR TRAILING ZERO ON STRINGS INTERNALLY
bytes=read(master,&tbuf,sizeof(tbuf));
if(bytes<1)termclient(csock,master,ptychild);
if(bytes>0){
printf("%s CLIENT %d READ %ld BYTES FROM LOGIN %d\n",srcbtime(0),getpid(),bytes,ptychild);
//HAVE TERMIOS DO THIS
//for(n=0;n<bytes;n++)if(tbuf[n]==0x0A)tbuf[n]=0x0D;
if(sendclient(&tbuf,bytes)<1)termclient(csock,master,ptychild);
};//RECEIVED BYTES FROM PROGRAM
};//FD SET

//BYTES TO PROGRAM
if(FD_ISSET(csock,&readfds)){
bytes=recv(csock,&tbuf,sizeof(tbuf),0);
if(bytes<1)termclient(csock,master,ptychild);
if(bytes>0){
printf("%s CLIENT %d SENT %ld BYTES TO LOGIN %d\n",srcbtime(0),getpid(),bytes,ptychild);
//HAVE TERMIOS DO THIS
//for(n=0;n<bytes;n++)if(tbuf[n]==0x0D)tbuf[n]=0x0A;
if(write(master,&tbuf,bytes)<1)termclient(csock,master,ptychild);
};//SENT BYTES TO PROGRAM
};//FD SET
};//WHILE CHILD RUNNING
ptychild=-1;

};//PARENT

printf("%s CLIENT %d WAIT FOR SOCKET %d CLOSE\n",srcbtime(0),getpid(),csock);
//WAIT AT MOST 60 SECONDS FOR CLIENT TO CLOSE SOCKET OR CLOSE SOCKET OURSELVES.
FD_ZERO(&readfds);
tv.tv_sec=60;
tv.tv_usec=0;
//THIS BIT IS KINDA PROBLEMATIC AS CLOSING A SOCKET BEFORE ALL DATA IS FULLY PROCESSED ON THE OTHER SIDE LEADS TO REMAINING DATA GETTING LOST
//FOR EXAMPLE WHILE TYPING exit DURING A LONG ls -al OUTPUT - GIVE IT UP TO 60 SECONDS TO COMPLETE OR LET THE OTHER SIDE DISCONNECT FOR US
while((tv.tv_sec>0)||(tv.tv_usec>0)){
FD_SET(csock,&readfds);
select(csock+1,&readfds,NULL,NULL,&tv);
if(recv(csock,&tbuf,sizeof(tbuf),0)<1)break;
};//WAITCLIENTCLOSE
termclient(csock,master,ptychild);
exit(EXIT_SUCCESS);
};//CLIENTCODE

int main(int argc,char**argv){
if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

if(argc<2){printf("USAGE: %s <SERVICE-CALLSIGN-SSID> [INTERFACE-CALLSIGN]\n\nIF THE PROCESS IS TO LISTEN ON A (VIRTUAL) CALLSIGN OTHER THAN ONE OF AN INTERFACE SPECIFY THE INTERFACE AS WELL\n",argv[0]);exit(EXIT_FAILURE);};

signal(SIGHUP,SIG_IGN);
signal(SIGQUIT,SIG_IGN);
signal(SIGCHLD,SIG_IGN);//PARENT DOESN'T CARE

bsock=-1;setupsock(argv[1],argv[2]);

while(1){
FD_ZERO(&readfds);//BSOCK CHANGES IF INTERFACE CHANGES
FD_SET(bsock,&readfds);
tv.tv_sec=600;
tv.tv_usec=0;
printf("%s WAIT FOR CLIENT\n",srcbtime(0));
select(bsock+1,&readfds,NULL,NULL,&tv);
if(FD_ISSET(bsock,&readfds)){
clen=sizeof(struct full_sockaddr_ax25);
csock=accept(bsock,(struct sockaddr*)&caddr,&clen);
if(csock==-1)setupsock(argv[1],argv[2]);
if(csock!=-1){if(fork()==0){close(bsock);clientcode();}else{close(csock);};};//FORK CHILD AND CLOSE CLIENTSOCK IN PARENT
};//CLIENT IN QUEUE
};//WHILE 1 ACCEPT
};//MAIN
