//HRH Prince Sven Olaf of CyberBunker-Kamphuis
//CB3ROB TACTICAL SYSTEMS
//One CyberBunker Avenue
//Republic CyberBunker

//ALPHA DEVELOPMENT STATUS - UNDER CONSTRUCTION - NO ASSUMPTIONS TOWARDS SECURITY

//root 9254  0.0  0.0   6592   808 pts/0    S+   12:51   0:00  \_ ./cb3rob-ax25-bbs KISSMX                <--- MAIN LISTEN DAEMON
//root 9289  0.0  0.0  15048  1832 pts/0    S+   12:52   0:00      \_ ./cb3rob-ax25-bbs KISSMX            <--- CHILD AX.25 HANDLER

#define _GNU_SOURCE
#include<crypt.h>
#include<dirent.h>
#include<fcntl.h>
#include<grp.h>
#include<linux/ax25.h>
#include<pwd.h>
#include<signal.h>
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/resource.h>
#include<sys/socket.h>
#include<sys/stat.h>
#include<sys/time.h>
#include<sys/types.h>
#include<time.h>
#include<unistd.h>
#include<utmp.h>
#include<wait.h>

#define MAXBACKLOG 16
#define BPNLCR 1

time_t logintime;
char user[7];
uid_t uid;
gid_t gid;
fd_set readfds;
fd_set writefds;
struct timeval tv;
int nfds;
char homedir[256];
int bsock;
int csock;
char tbuf[(AX25_MTU*7)];//MORE EFFECTIVE THROUGHPUT WHEN SENDING IN BURST
struct full_sockaddr_ax25 baddr;
struct full_sockaddr_ax25 caddr;
struct sigaction sigact;
socklen_t clen;
fd_set writefds;
fd_set readfds;
int sel;

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
sel=select(csock+1,NULL,&writefds,NULL,&tv);
if(sel==-1){close(csock);exit(EXIT_FAILURE);};
//FALL THROUGH IS SEND ANYWAY TO CHECK IF STILL CONNECTED
thisblock=AX25_MTU;flags=0;if((total-sent)<=AX25_MTU){thisblock=(total-sent);flags|=MSG_EOR;};
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

//SEND BEACON TO KEEP DYNAMIC ROUTES TO US OPEN IN TIMES OF INACTIVITY
void sendbeacon(int signum){
int beacon;
char btext[]="MUTINY BBS\r";
struct full_sockaddr_ax25 beaconaddr;
printf("%s SENDING BEACON\n",srcbtime(0));
//ACTUALLY CANNOT SIMPY ABUSE SEQPACKET bsock FOR THIS - TRANSPORT ENDPOINT ALREADY CONNECTED
beacon=socket(PF_AX25,SOCK_DGRAM|SOCK_NONBLOCK,0);
if(beacon!=-1){
//WE CAN HOWEVER RECYCLE IT'S BIND SOCKADDR
if(bind(beacon,(struct sockaddr*)&baddr,sizeof(struct full_sockaddr_ax25))!=-1){
memset(&beaconaddr,0,sizeof(struct full_sockaddr_ax25));
beaconaddr.fsa_ax25.sax25_family=AF_AX25;
beaconaddr.fsa_ax25.sax25_call.ax25_call[0]=('Q'<<1);
beaconaddr.fsa_ax25.sax25_call.ax25_call[1]=('S'<<1);
beaconaddr.fsa_ax25.sax25_call.ax25_call[2]=('T'<<1);
beaconaddr.fsa_ax25.sax25_call.ax25_call[3]=(' '<<1);
beaconaddr.fsa_ax25.sax25_call.ax25_call[4]=(' '<<1);
beaconaddr.fsa_ax25.sax25_call.ax25_call[5]=(' '<<1);
beaconaddr.fsa_ax25.sax25_call.ax25_call[6]=(0x00<<1);
beaconaddr.fsa_ax25.sax25_ndigis=0;
if(sendto(beacon,btext,strlen(btext),MSG_DONTWAIT,(struct sockaddr*)&beaconaddr,sizeof(struct full_sockaddr_ax25))>0)printf("%s SENT BEACON\n",srcbtime(0));
};//IF BIND
close(beacon);
};//IF SOCKET
};//BEACON

//ALLOWS 8.3 FILENAMES WITH A-Z0-9 AND NOTHING ELSE
//FOR MKDIR AND FILE WRITES ONLY... DOESN'T ALLOW RELATIVE PATHS
int chkpath(char*path){
int remain;
int dotcount;
if(path==NULL)return(-1);
if(path[0]==0)return(-1);
//INIT
remain=8;
dotcount=0;
//SKIP LEADING SLASH NEUTRALLY
if(path[0]=='/')path++;//SKIP LEADING SINGLE SLASH
while(path[0]){//CONTINUE UNTIL END OF STRING
if((remain==8)&&(path[0]=='.'))return(-1);//NO DOTS AS FIRST CHARACTER
if((remain==8)&&(path[0]=='/'))return(-1);//NO DOUBLE SLASHES EITHER
if(path[0]=='/'){remain=8;dotcount=0;path++;continue;};
if(path[0]=='.'){remain=3;dotcount++;path++;};
if(remain==0)return(-1);//TOO LONG
if(dotcount>1)return(-1);//TOO LONG
//THIS WILL ALSO FETCH ANY . OR / IMMEDIATELY FOLLOWING ANOTHER . OR /
if(path[0]){//EOL?
if((path[0]<0x30)||(path[0]>0x5A)||((path[0]>0x39)&&(path[0]<0x41)))return(-1);
//ONLY INCREMENT IF WE HAVEN'T REACHED END OF LINE YET
remain--;
path++;
};//EOL CHECK
};//WHILE PATH
return(0);
};//CHKPATH

int chkcall(char*c){
int n;
if(c==NULL)return(-1);
if((c[0]<0x30)||(c[0]>0x5A)||((c[0]>0x39)&&(c[0]<0x41)))return(-1);//MUST START WITH A-Z0-9
for(n=1;(n<6)&&(c[n])&&(c[n]!=0x2D);n++){
if((c[n]<0x30)||(c[n]>0x5A)||((c[n]>0x39)&&(c[n]<0x41)))return(-1);//MUST START WITH A-Z0-9
}//
if(c[n]==0)return(n);//NO SSID - WE'RE DONE
if(c[n++]!=0x2D)return(-1);//SOMETHING INVALID
if((c[n]<0x30)||(c[n]>0x39))return(-1);//MUST BE 0-9
n++;
if(c[n]==0)return(n);//DONE - VALID WITH 1 DIGIT SSID
if(c[n-1]!=0x31)return(-1);//IF WE HAVE ANOTHER SSID-DIGIT THE FIRST DIGIT MUST BE 1
if((c[n]<0x30)||(c[n]>0x35))return(-1);//MUST BE 0-5
n++;
if(c[n]==0)return(n);//NO SSID
return(-1);//FALLTHROUGH INVALID
};//CHKCALL

ssize_t readfile(const char*filename,int asciimode){
uint8_t buf[AX25_MTU];
int ffd;
ssize_t rbytes;
ssize_t wbytes;
ssize_t total;
int n;
if(filename==NULL)return(-1);
ffd=open(filename,O_RDONLY);
if(ffd==-1)return(-1);
total=0;
wbytes=0;
rbytes=0;
while((rbytes=read(ffd,&buf,sizeof(buf)))>1){
if(asciimode&BPNLCR)for(n=0;n<rbytes;n++)if(buf[n]=='\n')buf[n]='\r';
if((wbytes=send(csock,&buf,rbytes,0))<1)break;
total+=wbytes;
};//WHILE READBLOCK
close(ffd);
//CLEAR MEMORY
memset(&buf,0,sizeof(buf));
if(wbytes<1)return(-1);
return(total);
};//READFILE

void printstatus(){
dprintf(csock,"TIME: %s\rCALL: %s\rUSER: %s\rNODE: %s\r\r",srcbtime(0),sourcecall,user,destcall);
};//PRINTWELCOME

void printwelcome(){
dprintf(csock,"=====================\rWelcome to MuTiNy BBS\r=====================\r");
};//PRINTBANNER

void printprompt(){
dprintf(csock,"\r[ %s @ %s : %s ]> ",user,destcall,getcwd(NULL,0));
};//PRINTPROMPT

char*getcommand(){
static unsigned char cmd[128];
int n;
int o;
o=0;//NON-SPACE OFFSET
memset(&cmd,0,sizeof(cmd));
while(!cmd[o]){//UNTIL WE HAVE A STRING THAT ISN'T EMPTY
if(recv(csock,(void*)&cmd,sizeof(cmd)-1,0)<1)return(NULL);//WILL JUST TRIGGER SIGPIPE ANYWAY IF IT FAILS
for(n=o;(n<sizeof(cmd))&&(cmd[n]);n++){
if((cmd[n]=='\r')||(cmd[n]=='\n')){cmd[n]=0;break;};
if((cmd[n]>=0x61)&&(cmd[n]<=0x7A)){cmd[n]&=0xDF;continue;};//ALL TO UPPER CASE
if((cmd[n]<0x20)||cmd[n]>0x7E){cmd[n]=0x20;continue;};//NO WEIRD BINARY STUFF
};//FOR
for(o=0;(o<sizeof(cmd))&&(cmd[o]==0x20);o++);//FAST FORWARD ALL THE BINARY STUFF THAT ARE NOW SPACES
};//WHILE EMPTY
dprintf(csock,"\rCOMMAND: %s\r\r",cmd+o);//PRINT IT IN CASE USER HAS ECHO OFF IN HIS TERMINAL
return((char*)&cmd+o);
};//GETCOMMAND

int inituser(char*username){
char directory[256];
char basepath[]="/var/bbs";
struct rlimit rlim;
struct passwd *pw;
struct passwd pwa;
if(username==NULL)return(-1);
// RLIMIT_CPU     /* CPU time in seconds */
// RLIMIT_FSIZE   /* Maximum filesize */
// RLIMIT_DATA    /* max data size */
// RLIMIT_STACK   /* max stack size */
// RLIMIT_CORE    /* max core file size */
// RLIMIT_RSS     /* max resident set size */
// RLIMIT_NPROC   /* max number of processes */
// RLIMIT_NOFILE  /* max number of open files */
// RLIMIT_MEMLOCK /* max locked-in-memory address space*/
rlim.rlim_cur=RLIM_INFINITY;
rlim.rlim_max=RLIM_INFINITY;
setrlimit(RLIMIT_CPU,&rlim);
rlim.rlim_cur=0;
rlim.rlim_max=0;
setrlimit(RLIMIT_CORE,&rlim);
rlim.rlim_cur=256;
rlim.rlim_max=256;
setrlimit(RLIMIT_NOFILE,&rlim);
rlim.rlim_cur=8388608;
rlim.rlim_max=8388608;
setrlimit(RLIMIT_STACK,&rlim);
rlim.rlim_cur=16;
rlim.rlim_max=16;
setrlimit(RLIMIT_NPROC,&rlim);
rlim.rlim_cur=33554432;
rlim.rlim_max=33554432;
setrlimit(RLIMIT_DATA,&rlim);
setrlimit(RLIMIT_MEMLOCK,&rlim);
setrlimit(RLIMIT_FSIZE,&rlim);
setrlimit(RLIMIT_RSS,&rlim);
//SLOW EM DOWN A BIT JUST IN CASE
nice(+19);
//NEED THIS FOR USER CREATION ANYWAY
memset(&homedir,0,sizeof(homedir));
snprintf(homedir,sizeof(homedir)-1,"%s/MEMBERS/%s",basepath,username);
uid=65535;
gid=65535;
FILE*fp;
struct group *gp;
struct group gpa;
gp=getgrnam("MUTINY");
if(gp==NULL){
gpa.gr_name="MUTINY";
gpa.gr_passwd="x";
gpa.gr_mem=NULL;
};//IF GP NULL
while(gp==NULL){
for(gpa.gr_gid=1000;getgrgid(gpa.gr_gid)!=NULL;gpa.gr_gid++);
fp=fopen("/etc/group","a");
putgrent(&gpa,fp);
fclose(fp);
gp=getgrnam("MUTINY");
};//WHILE GP NULL

//WE HAVE OUR GID
gid=gp->gr_gid;

pw=getpwnam(username);
if(pw==NULL){
char salt[3];
srand(time(NULL));
salt[0]=(rand()&0x3F)+0x2E;
if(salt[0]>0x39)salt[0]+=0x07;
if(salt[0]>0x5A)salt[0]+=0x06;
salt[1]=(rand()&0x3F)+0x2E;
if(salt[1]>0x39)salt[1]+=0x07;
if(salt[1]>0x5A)salt[1]+=0x06;
salt[2]=0x00;
memset(&pwa,0,sizeof(struct passwd));
pwa.pw_name=username;
pwa.pw_passwd=crypt(username,salt);
pwa.pw_dir=homedir;
pwa.pw_gid=gid;
pwa.pw_shell="/bin/false";
};//IF PW NULL
while(pw==NULL){
dprintf(csock,"NO USERDATA FOUND FOR USERNAME %s - CREATING...\r",username);
for(pwa.pw_uid=10000;getpwuid(pwa.pw_uid)!=NULL;pwa.pw_uid++);
//EHM YEAH. SHOULD USE THE SAME FILE LOCKING AND TEMPORARY FILE MECHANISM passwd USES HERE..
//BUT... STDIO BUFFERING... ETC.
//ALSO WE COULD END UP WITH 2 USERS WITH THE SAME UID IF 2 ARE CREATED AT EXACTLY THE SAME TIME
//THE EASIER OPTION IS TO JUST CONVERT THEIR CALLSIGN FROM THE MAX 6 DIGIT BASE 36 INTEGER THAT IT REALLY INTO A UID IS AND USE THAT
//MOST SYSTEMS WILL HAVE LARGER THAN 16 BIT UID'S ANYWAY NOWADAYS. IT FITS A 32 BIT UID AND ENSURES UNIQUENESS.
fp=fopen("/etc/passwd","a");
putpwent(&pwa,fp);
//putspent(
fclose(fp);
pw=getpwnam(username);
};//WHILE PW NULL

//WE HAVE OUR UID TOO
uid=pw->pw_uid;

dprintf(csock,"FOUND USERDATA UID: %d GID: %d\r",uid,gid);
//WE'LL GET TO THIS LATER. THEY'RE SET TO THE USERS CALLSIGN WITHOUT SSID FOR NOW
//WITH A SHELL THAT DENIES THEM ACCESS TO THE UNIX SHELL (COULD STILL GRANT THEM ACCCESS TO OTHER SERVICES!)
dprintf(csock,"NO PASSWORD FOR USER: %s SET SO NOT ASKING\r",username);


memset(&directory,0,sizeof(directory));
//MAKE SURE THE SYSTEM IS INITIALIZED AND ALL DIRECTORIES EXIST (TAKES LONGER TO CHECK THAN TO JUST TRY TO CREATE THEM IF NOT ;)
//SOOO MANY UNCHECKED RETURN VALUES... WHO CARES, GCC.. IT DOES IT UPON EVERY SINGLE LOGIN ANYWAY. AND IF THE DRIVE IS FULL IT'S FULL.
mkdir(basepath,00750);//EVERYTHING EXCEPT FOR /BIN SHOULD ACTUALLY BE ON A FILESYSTEM MOUNTED WITH NO EXECUTE BUT WE CAN'T DO THAT FROM HERE
chmod(basepath,00750);//FORCE FIX PERMISSIONS ON EXISTING DIRECTORIES
chown(basepath,0,gid);
snprintf(directory,sizeof(directory)-1,"%s/ETC",basepath);
mkdir(directory,00710);//NONE OF THE USERS CONCERN HERE - DATA FILES TO BE READ BY THIS PROGRAM
chmod(directory,00710);
chown(directory,0,gid);
snprintf(directory,sizeof(directory)-1,"%s/BIN",basepath);
mkdir(directory,00710);//NONE OF THE USERS CONCERN HERE - EXTERNAL PROGRAMS TO BE CALLED BY THIS ONE
chmod(directory,00710);
chown(directory,0,gid);
snprintf(directory,sizeof(directory)-1,"%s/UPLOAD",basepath);
mkdir(directory,01750);//SET STICKY BIT
chmod(directory,01750);
chown(directory,0,gid);
snprintf(directory,sizeof(directory)-1,"%s/FILES",basepath);
mkdir(directory,01750);//SET STICKY BIT - USERS CAN REMOVE FILES THEY UPLOADED
chmod(directory,01750);
chown(directory,0,gid);
snprintf(directory,sizeof(directory)-1,"%s/MEMBERS",basepath);
mkdir(directory,00750);//USER HOMEDIRECTORIES
chmod(directory,00750);
chown(directory,0,gid);
snprintf(directory,sizeof(directory)-1,"%s/MAIL",basepath);
mkdir(directory,00750);//USER MAIL
chmod(directory,00750);
chown(directory,0,gid);
snprintf(directory,sizeof(directory)-1,"%s/ANARCHY",basepath);
mkdir(directory,01770);//DO WHATEVER THEY LIKE
chmod(directory,01770);
chown(directory,0,gid);
memset(&directory,0,sizeof(directory));
//SYSTEM HOMEDIR NAME OF USER GENERATED ABOVE IN THE USER CREATION PART
mkdir(homedir,00700);
chmod(homedir,00700);
chown(homedir,uid,gid);
//HOMEDIR NAME FOR USE WITHIN THE CHROOT
snprintf(homedir,sizeof(homedir)-1,"/MEMBERS/%s",username);
//CHROOT
chroot(basepath);
chdir(homedir);
//DROP ROOT
setgroups(1,&gid);
setegid(gid);
setgid(gid);
setuid(uid);
seteuid(uid);
return(0);
};//INITUSER;

int cmdbye(char*username){
dprintf(csock,"SEE YOU AGAIN SOON %s\r",username);

sleep(10);
exit(EXIT_SUCCESS);
};//CMDBYE

void cmdinvalid(){
dprintf(csock,"INVALID COMMAND - TRY HELP\r");
};//CMDINVALID

void cmdhelp(){
char *helptext=\
"DIR   [PATH]  - LISTS FILES\r"
"CD    [PATH]  - CHANGES DIRECTORY\r"
"MD    <PATH>  - CREATES DIRECTORY\r"
"RM    <PATH>  - REMOVES FILE OR EMPTY DIRECTORY\r"
"READ  <PATH>  - READS TEXT FILE\r"
"BGET  <PATH>  - DOWNLOAD FILE USING THE #BIN# PROTOCOL\r"
"EXIT          - TERMINATES SESSION\r"
"\rPATHNAMES ARE 8.3 FORMAT [ A-Z 0-9 ]\r\r"
"AUTOBIN UPLOADS CAN BE STARTED WHILE ON THE PROMPT\r"
"UPLOADS TO YOUR HOMEDIR OR /FILES OR /ANARCHY ONLY\r";
sendclient(helptext,0);
};//CMDHELP

int cmddir(char*name){
DIR*curdir;
char *stattext[]={"UNKNOWN","COMPLETE","UPLOADING","STALLED"};
int fstatus;
struct dirent*direntry;
struct stat statbuf;
size_t total;
size_t files;
size_t dirs;
int n;
if(name==NULL)name=getcwd(NULL,0);
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(!name[0])name=getcwd(NULL,0);
chdir(name);//NEED THIS FOR FSTAT TO WORK
total=0;
files=0;
dirs=0;
fstatus=0;
curdir=opendir(name);
if(curdir==NULL){dprintf(csock,"ERROR OPENING DIRECTORY: %s\r",name);return(-1);};//ERROR
dprintf(csock,"DIRECTORY OF %s\r\r",name);
dprintf(csock,"./\r../\r");
while((direntry=readdir(curdir))!=NULL){
if((direntry->d_name[0]>=0x30&&direntry->d_name[0]<=0x39)||(direntry->d_name[0]>=0x41&&direntry->d_name[0]<=0x5A)||(direntry->d_name[0]>=0x61&&direntry->d_name[0]<=0x7A)){
switch(direntry->d_type){
case DT_REG:
if(stat(direntry->d_name,&statbuf)==-1){dprintf(csock,"ERROR ON READ STATUS: %s\r",direntry->d_name);continue;};
if(statbuf.st_mtime<time(NULL)-180)fstatus=3;//STALLED (3 MINUTES INACTIVE)
if(statbuf.st_mtime>=time(NULL)-180)fstatus=2;//STILL UPLOADING
if(statbuf.st_mode&00444)fstatus=1;//READ PERMISSION IS SET ON COMPLETE UPLOADS
if(statbuf.st_size>0)dprintf(csock,"%-27s %10lu (%s)\r",direntry->d_name,statbuf.st_size,stattext[fstatus]);//DON'T SHOW EMPTY FILES RESERVED DURING UPLOAD
total+=statbuf.st_size;
files++;
continue;
case DT_DIR:
dprintf(csock,"%s/\r",direntry->d_name);
dirs++;
continue;
default:
continue;
};//SWITCH ENTRY TYPE
};//VALID FILENAME
};//WHILE DIRENTRY
if(closedir(curdir)==-1)dprintf(csock,"ERROR CLOSING DIRECTORY\r");//ERROR;
dprintf(csock,"\rTOTAL: %lu BYTES IN: %lu FILES AND %lu DIRECTORIES\r",total,files,dirs);
return(0);
};//CMDDIR

void cmdchdir(char*name){
int n;
if(name!=NULL){
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(name[0]){//JUST SHOW PWD
if(chdir(name))dprintf(csock,"CHDIR TO %s FAILED\r",name);
};//IF PARAMETERS OTHER THAN SPACE
};//IF PARAMETERS
dprintf(csock,"CURRENT DIRECTORY: %s\r",getcwd(NULL,0));
};//CMDCHDIR

void cmdmkdir(char*name){
int n;
if(name!=NULL){
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(chkpath(name)==-1)dprintf(csock,"INVALID ABSOLUTE 8.3 FORMAT [A-Z 0-9] PATH: %s\r",name);
else if(mkdir(name,00750))dprintf(csock,"CREATE DIRECTORY %s FAILED\r",name);
else chdir(name);//WE CD INTO IT DIRECTLY
dprintf(csock,"CURRENT DIRECTORY: %s\r",getcwd(NULL,0));
};//IF PARAMETERS
};//CMDMKDIR

int cmderase(char*name){
int n;
int r;
if(name==NULL)return(-1);
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
r=remove(name);
if(r==-1)dprintf(csock,"ERASE %s FAILED\r",name);else dprintf(csock,"ERASED: %s\r",name);
return(r);
};//CMDERASE

void cmdtest(){
int n;
for(n=0;n<100;n++)dprintf(csock,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
};//CMDTEST

ssize_t cmdbget(char*name){
int n;
int ffd;
ssize_t rbytes;
ssize_t wbytes;
ssize_t remain;
struct stat statbuf;
uint8_t buf[AX25_MTU];
if(name==NULL)return(-1);
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(!name[0])return(-1);
//FLUSH STDIN
if(fcntl(csock,F_SETFL,fcntl(csock,F_GETFL,0)|O_NONBLOCK)){dprintf(csock,"SYSTEM ERROR\r");return(-1);};
while(recv(csock,&buf,sizeof(buf),0)>0);//FLUSH STDIN TO MAKE SURE PEERS #OK# IS AT THE START OF RECEPTION
if(fcntl(csock,F_SETFL,fcntl(csock,F_GETFL,0)&~O_NONBLOCK)){dprintf(csock,"SYSTEM ERROR\r");return(-1);};
//OPEN FILE
ffd=open(name,O_RDONLY,0);
if(ffd==-1){dprintf(csock,"ERROR OPENING: %s\r",name);return(-1);};
//FILE IS NOW OPEN
if(fstat(ffd,&statbuf)==-1){close(ffd);dprintf(csock,"SYSTEM ERROR\r");return(-1);};
if((!(statbuf.st_mode&S_IFMT&S_IFREG))||(!(statbuf.st_mode&00444))||(statbuf.st_size==0)){close(ffd);dprintf(csock,"ERROR OPENING: %s\r",name);return(-1);};
//START OUR SIDE
sprintf((char*)&buf,"#BIN#%lu\r",statbuf.st_size);
send(csock,&buf,strlen((char*)buf),0);
//WAIT FOR PEER
while(1){
tv.tv_sec=60;
tv.tv_usec=0;
FD_ZERO(&readfds);
FD_SET(csock,&readfds);
sel=select(csock+1,&readfds,NULL,NULL,&tv);
if(sel==-1){close(ffd);close(csock);exit(EXIT_FAILURE);};
if(sel>0)if(FD_ISSET(csock,&readfds)){
//'STATION A SHOULD IGNORE ANY DATA NOT BEGINNING WITH #OK# OR #NO#' - AS WE ARE RUNNING ON A PTY WE CAN'T BE ABSOLUTELY SURE OF AX.25 FRAME LIMITS THOUGH.
memset(&buf,0,sizeof(buf));
if(recv(csock,&buf,sizeof(buf),0)>0){
for(n=0;(n<sizeof(buf)-8)&&(buf[n]!='#');n++);//FAST FORWARD TO FIRST #, ALLOW -SOME- PLAYROOM FOR EVENTUAL '\r' AT THE START (ABORT DURING SETUP) AND OTHER CREATIVE INTERPRETATIONS
if(!bcmp(buf+n,"#NO#",4)){close(ffd);dprintf(csock,"BGET %s REFUSED BY PEER\r",name);return(-1);};
//GP ACCEPTS #ABORT# DURING SETUP, NOT JUST MID-STREAM AS PER DOCUMENTATION TOO.
if(!bcmp(buf+n,"#ABORT#",7)){close(ffd);dprintf(csock,"BGET %s REFUSED BY PEER\r",name);return(-1);};
if(!bcmp(buf+n,"#OK#",4))break;
};//HANDLE OK OR NOT OK
};//SELECT READ
};//WHILE FETCH DATA
//PEER HAS TO ACCEPT WITHIN 1 MINUTE - ALSO AT LEAST TRY TO FORCE THE PTY TO SEND THE ABORT IN IT'S VERY OWN PACKET AS PER DOCUMENTATION...
if((tv.tv_sec==0)&&(tv.tv_usec==0)){close(ffd);send(csock,"\r#ABORT#\r",9,0);dprintf(csock,"BGET: %s TIMED OUT\r",name);return(-1);};
//MOVE TOTAL BYTES TO TRANSFER INTO SUBSTRACTION REGISTER
remain=statbuf.st_size;
//WHILE BYTES TO SEND LEFT, SEND BLOCKS OF DATA
while(remain>0){
FD_ZERO(&readfds);
FD_SET(ffd,&readfds);
FD_SET(csock,&readfds);
tv.tv_sec=10;
tv.tv_usec=0;
nfds=csock;
if(csock>nfds)nfds=csock;
if(ffd>nfds)nfds=ffd;
sel=select(nfds+1,&readfds,NULL,NULL,&tv);
if(sel==-1){close(ffd);close(csock);exit(EXIT_FAILURE);};
if(sel>0){
//HANDLE ABORT -BEFORE SENDING DATA-, IGNORE ANYTHING ELSE THAT COMES IN, AS PER SPECIFICATION
if(FD_ISSET(csock,&readfds)){
memset(&buf,0,sizeof(buf));
if(recv(csock,&buf,sizeof(buf),0)>0){
if(!bcmp(buf+n,"\r#ABORT#\r",9)){close(ffd);dprintf(csock,"BGET: %s ABORTED BY PEER\r",name);return(-1);};
if(!bcmp(buf+n,"#ABORT#\r",8)){close(ffd);dprintf(csock,"BGET: %s ABORTED BY PEER\r",name);return(-1);};
};//IF READ
};//FD_ISSET PTY
//WRITE BYTES
if(FD_ISSET(ffd,&readfds)){
FD_ZERO(&writefds);
FD_SET(csock,&writefds);
tv.tv_sec=0;
tv.tv_usec=100000;
sel=select(csock+1,NULL,&writefds,NULL,&tv);
if(sel==-1){close(ffd);close(csock);exit(EXIT_FAILURE);};
if(sel>0)if(FD_ISSET(csock,&writefds)){
rbytes=read(ffd,&buf,sizeof(buf));
if(rbytes<1){close(ffd);send(csock,"\r#ABORT#\r",9,0);dprintf(csock,"BGET ABORTED: %s FILE READ ERROR\r",name);return(-1);};
remain-=rbytes;
wbytes=send(csock,&buf,rbytes,0);
if(wbytes<rbytes){close(ffd);send(csock,"\r#ABORT#\r",9,0);dprintf(csock,"BGET ABORTED: %s DATA TRANSMIT ERROR\r",name);return(-1);};
};//FDISSET WRITE
};//FDISSET FFD READ
};//SELECT READ FILEDESCRIPTORS
};//WHILE DATA LEFT TO SEND
close(ffd);
dprintf(csock,"\rBGET COMPLETED: %s BYTES: %ld\r",name,statbuf.st_size);
return(statbuf.st_size);
};//CMDBGET

ssize_t cmdread(char*name){
int n;
ssize_t r;
if(name==NULL)return(-1);
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(!name[0])return(-1);
r=readfile(name,BPNLCR);
if(r>=0)dprintf(csock,"\rREAD COMPLETED: %s BYTES: %ld\r",name,readfile(name,BPNLCR));else dprintf(csock,"ERROR OPENING: %s\r",name);
return(r);
};//CMDCHDIR

ssize_t cmdbput(char*bincmd,char*username){
ssize_t n;
ssize_t f;
ssize_t c;
ssize_t o;
int ffd;
ssize_t rbytes;
ssize_t wbytes;
ssize_t remain;
ssize_t okreturn;
uint8_t buf[AX25_MTU];
char name[256];
int parsefield;
memset(&name,0,sizeof(name));
parsefield=0;
okreturn=0;
remain=0;
if((bincmd==NULL)||(username==NULL))return(-1);
for(n=0;(bincmd[n]!=0)&&(bincmd[n]!='\r');n++){
if(bincmd[n]=='#'){
n++;//SKIP FIELD DELIMITER ITSELF
memset(&buf,0,sizeof(buf));
//COPY FIELD TO BUF
for(f=0;((n+f)<sizeof(buf)-1)&&(bincmd[n+f]!=0)&&(bincmd[n+f]!='\r')&&(bincmd[n+f]!='#');f++)buf[f]=bincmd[n+f];
if(parsefield==0)if(strcmp((char*)buf,"BIN")){send(csock,"#NO#\r",5,0);return(-1);};//NOT BIN PROTOCOL OR PARSE ERROR
if(parsefield==1){//FILE LENGTH
for(c=0;(c<sizeof(buf)-1)&&(buf[c]!=0);c++)if((buf[c]<0x30)||(buf[c]>0x39)){send(csock,"#NO#\r",5,0);return(-1);};//NOT A DECIMAL NUMBER
remain=atoll((char*)buf);
okreturn=remain;
if(remain<1){send(csock,"#NO#\r",5,0);return(-1);};//NOT BIN PROTOCOL OR PARSE ERROR
};//FILE LENGTH FIELD
if(parsefield==4){
o=0;
for(c=0;(c<sizeof(buf)-1)&&(buf[c]!=0);c++)if((buf[c]==0x5C)||(buf[c]==0x2F))o=c+1;//FAST FORWARD TO LAST SLASH
if(buf[o]!=0){//IF FILENAME AFTER SLASH
for(c=o;(c<sizeof(buf)-1)&&(buf[c]!=0);c++)if(buf[c]==0x09)buf[c]=0x20;//HTAB TO SPACE
for(c=o;(c<sizeof(buf)-1)&&(buf[c]!=0);c++)if((buf[c]<=0x20)||(buf[c]>0x7E))buf[c]='_';//JUST CHANGE ANY NON PRINTABLE CRAP TO '_'
for(c=o;(c<sizeof(buf)-1)&&(buf[c]!=0);c++)if((buf[c]>=0x61)&&(buf[c]<=0x7A))buf[c]&=0xDF;//ALL TO UPPER CASE
snprintf(name,sizeof(name)-1,"%s-%s",username,buf+o);
};//ACTUAL FILENAME AFTER THE SLASH?
};//FILENAME FIELD FOUND
n=n+f;//FAST FORWARD N COUNTER TO NEXT DELIMITER
n--;//PUT N BACK WHERE WE FOUND IT SO WE DON'T SKIP SEGMENTS
parsefield++;
};//FOR FIELDCOPY
};//FOR BYTE
//GENERATE RANDOM FILENAME IF NOT PRESENT OR INVALID
memset(&buf,0,sizeof(buf));
if(name[0]==0){
for(n=0;n<8;n++)buf[n]=(rand()&0x0F)+0x41;
buf[n++]=0x2D;
buf[n++]='B';
buf[n++]='I';
buf[n++]='N';
buf[n]=0x00;
snprintf(name,sizeof(name)-1,"%s-%s",username,buf);
};//FILENAME ZERO RANDOMIZER
ffd=open(name,O_WRONLY|O_CREAT|O_EXCL,00200);//WRITE ONLY PERMISSION MARKS INCOMPLETE FILES DURING UPLOAD (DO NOT SHOW IN DIR)
if(ffd==-1){send(csock,"#NO#\r",5,0);dprintf(csock,"BPUT ABORTED: %s PERMISSION DENIED OR FILE EXITS\r",name);return(-1);};
//GIVE OK FOR TRANSFER
send(csock,"#OK#\r",5,0);
while(remain>0){
tv.tv_sec=10;
tv.tv_usec=0;
FD_ZERO(&readfds);
FD_SET(csock,&readfds);
sel=select(csock+1,&readfds,NULL,NULL,&tv);
if(sel==-1){close(ffd);close(csock);exit(EXIT_FAILURE);};
if(sel>0)if(FD_ISSET(csock,&readfds)){
memset(&buf,0,sizeof(buf));
rbytes=recv(csock,&buf,sizeof(buf),0);
if(rbytes<1){close(ffd);unlink(name);send(csock,"\r#ABORT#\r",9,0);dprintf(csock,"BPUT ABORTED: %s DATA RECEIVE ERROR\r",name);return(-1);};
if(!bcmp(buf,"\r#ABORT#\r",9)){close(ffd);unlink(name);dprintf(csock,"BPUT: %s ABORTED BY PEER\r",name);return(-1);};
if(!bcmp(buf,"#ABORT#\r",8)){close(ffd);unlink(name);dprintf(csock,"BPUT: %s ABORTED BY PEER\r",name);return(-1);};
if(bcmp(buf,"SP\\-",4)){
wbytes=write(ffd,&buf,rbytes);
if(wbytes<rbytes){close(ffd);unlink(name);send(csock,"\r#ABORT#\r",9,0);dprintf(csock,"BPUT ABORTED: %s FILE WRITE ERROR\r",name);return(-1);};
remain-=wbytes;
};//IGNORE PRIVATE MESSAGES
};//FDISSET FILE
};//WHILE DATA LEFT TO SEND
close(ffd);
if(chmod(name,00640)){unlink(name);dprintf(csock,"BPUT ERROR: %s CHANGE FILE AVAILABILITY\r",name);return(-1);};
dprintf(csock,"\rBPUT COMPLETED: %s BYTES: %ld\r",name,okreturn);
return(okreturn);
};//CMDBPUT

void calltermclient(int signum){printf("%s CLIENT %d TRIGGERED %s\n",srcbtime(0),getpid(),(signum==SIGTERM?"SIGTERM":"SIGPIPE"));exit(signum);};

int clientcode(){
int n;
char*currentcmd;
setsid();
setpgid(0,0);
signal(SIGINT,SIG_IGN);
memset(&sigact,0,sizeof(struct sigaction));
sigemptyset(&sigact.sa_mask);
sigact.sa_handler=calltermclient;
sigaction(SIGTERM,&sigact,NULL);
sigaction(SIGPIPE,&sigact,NULL);
fcntl(csock,F_SETFL,fcntl(csock,F_GETFL,0)&~O_NONBLOCK);
printf("%s CLIENT %d CONNECTED\n",srcbtime(0),getpid());
printf("%s CLIENT %d SOCKET: %d\n",srcbtime(0),getpid(),csock);
memset(&tbuf,0,sizeof(tbuf));
addresstoascii(&caddr.fsa_ax25.sax25_call,sourcecall);
dprintf(csock,"%s %s -> %s\r\r",srcbtime(0),sourcecall,destcall);
memset(&tbuf,0,sizeof(tbuf));

logintime=time(NULL);
//STRIP SSID
memset(user,0,sizeof(user));
for(n=0;(n<sizeof(user)-1)&&(sourcecall[n])&&(sourcecall[n]!='-');n++)user[n]=sourcecall[n];
if(fcntl(csock,F_SETFL,fcntl(csock,F_GETFL,0)&~O_NONBLOCK))dprintf(csock,"SYSTEM ERROR\r");
//INIT USER
inituser(user);
printstatus();
printwelcome();
readfile("/ETC/WELCOME.TXT",BPNLCR);

while(1){
printprompt();
currentcmd=getcommand();
if(currentcmd==NULL)break;//BLOCKING READ FELL THROUGH AS CONNECTION CLOSED
if(!bcmp(currentcmd,"#BIN#",5)){cmdbput(currentcmd,user);continue;};//RELAY THE ENTIRE CMD LINE TO BPUT ROUTINE
for(n=0;currentcmd[n]!=0;n++)if(currentcmd[n]==0x5C)currentcmd[n]=0x2F;//FETCH STRINGLENGTH AND TRANSLATE PATHS
if(n>0)for(n--;(n>=0)&&(currentcmd[n]==0x20);n--)currentcmd[n]=0;//REMOVE TRAILING SPACE WORKING BACKWARDS
//DIR
if(!bcmp(currentcmd,"DIR",3))if((currentcmd[3]==0x20)||(currentcmd[3]==0)){cmddir((char*)currentcmd+3);continue;};
if(!bcmp(currentcmd,"LS",2))if((currentcmd[2]==0x20)||(currentcmd[2]==0)){cmddir((char*)currentcmd+2);continue;};
if(!bcmp(currentcmd,"LIST",4))if((currentcmd[4]==0x20)||(currentcmd[4]==0)){cmddir((char*)currentcmd+4);continue;};
//CHANGE DIR
if(!bcmp(currentcmd,"CHDIR",5))if((currentcmd[5]==0x20)||(currentcmd[5]==0)){cmdchdir((char*)currentcmd+5);continue;};
if(!bcmp(currentcmd,"CD",2))if((currentcmd[2]==0x20)||(currentcmd[2]==0)){cmdchdir((char*)currentcmd+2);continue;};
//MAKE DIR
if(!bcmp(currentcmd,"MKDIR",5))if((currentcmd[5]==0x20)||(currentcmd[5]==0)){cmdmkdir((char*)currentcmd+5);continue;};
if(!bcmp(currentcmd,"MD",2))if((currentcmd[2]==0x20)||(currentcmd[2]==0)){cmdmkdir((char*)currentcmd+2);continue;};
//ERASE
if(!bcmp(currentcmd,"ERASE",5))if((currentcmd[5]==0x20)||(currentcmd[5]==0)){cmderase((char*)currentcmd+5);continue;};
if(!bcmp(currentcmd,"DEL",3))if((currentcmd[3]==0x20)||(currentcmd[3]==0)){cmderase((char*)currentcmd+3);continue;};
if(!bcmp(currentcmd,"DELETE",6))if((currentcmd[6]==0x20)||(currentcmd[6]==0)){cmderase((char*)currentcmd+6);continue;};
if(!bcmp(currentcmd,"RMDIR",5))if((currentcmd[5]==0x20)||(currentcmd[5]==0)){cmderase((char*)currentcmd+5);continue;};
if(!bcmp(currentcmd,"RM",2))if((currentcmd[2]==0x20)||(currentcmd[2]==0)){cmderase((char*)currentcmd+2);continue;};
//READ ASCII
if(!bcmp(currentcmd,"READ",4))if((currentcmd[4]==0x20)||(currentcmd[4]==0)){cmdread((char*)currentcmd+4);continue;};
//READ BIN
if(!bcmp(currentcmd,"BGET",4))if((currentcmd[4]==0x20)||(currentcmd[4]==0)){cmdbget((char*)currentcmd+4);continue;};
//TRANSFER TEST
if(!strcmp(currentcmd,"TEST")){cmdtest(user);continue;};
//HELP
if(!strcmp(currentcmd,"HELP")){cmdhelp();continue;};
//DISCONNECT
if(!strcmp(currentcmd,"BYE")){cmdbye(user);continue;};
if(!strcmp(currentcmd,"EXIT")){cmdbye(user);break;};
if(!strcmp(currentcmd,"QUIT")){cmdbye(user);break;};
if(!strcmp(currentcmd,"SALIR")){cmdbye(user);break;};
if(!bcmp(currentcmd,"DISC",4)){cmdbye(user);break;};//DISCONNECT IS GOOD WITH ANY ABBREVIATION
//FALLTHROUGH INVALID
cmdinvalid();
};//COMMAND LOOP
printf("%s CLIENT %d WAIT FOR SOCKET %d CLOSE\n",srcbtime(0),getpid(),csock);
//WAIT AT MOST 60 SECONDS FOR CLIENT TO CLOSE SOCKET OR CLOSE SOCKET OURSELVES.
FD_ZERO(&readfds);
tv.tv_sec=60;
tv.tv_usec=0;
//THIS BIT IS KINDA PROBLEMATIC AS CLOSING A SOCKET BEFORE ALL DATA IS FULLY PROCESSED ON THE OTHER SIDE LEADS TO REMAINING DATA GETTING LOST
//FOR EXAMPLE WHILE TYPING exit DURING A LONG ls -al OUTPUT - GIVE IT UP TO 60 SECONDS TO COMPLETE OR LET THE OTHER SIDE DISCONNECT FOR US
while((tv.tv_sec>0)||(tv.tv_usec>0)){
FD_SET(csock,&readfds);
sel=select(csock+1,&readfds,NULL,NULL,&tv);
if(sel==-1)break;
if(recv(csock,&tbuf,sizeof(tbuf),0)<1)break;
};//WAITCLIENTCLOSE
close(csock);
exit(EXIT_SUCCESS);
};//CLIENTCODE

int main(int argc,char**argv){
if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};
if(argc<2){printf("USAGE: %s <SERVICE-CALLSIGN-SSID> [INTERFACE-CALLSIGN]\n\nIF THE PROCESS IS TO LISTEN ON A (VIRTUAL) CALLSIGN OTHER THAN ONE OF AN INTERFACE SPECIFY THE INTERFACE AS WELL\n",argv[0]);exit(EXIT_FAILURE);};
signal(SIGHUP,SIG_IGN);
signal(SIGQUIT,SIG_IGN);
signal(SIGCHLD,SIG_IGN);//PARENT DOESN'T CARE
bsock=-1;setupsock(argv[1],argv[2]);
//SEND FIRST BEACON IMMEDIATELY AFTER STARTUP
sendbeacon(0);
while(1){
FD_ZERO(&readfds);//BSOCK CHANGES IF INTERFACE CHANGES
FD_SET(bsock,&readfds);
tv.tv_sec=300;//ALSO BEACON TIME
tv.tv_usec=0;
printf("%s WAIT FOR CLIENT\n",srcbtime(0));
sel=select(bsock+1,&readfds,NULL,NULL,&tv);
if(sel==-1)setupsock(argv[1],argv[2]);
if(FD_ISSET(bsock,&readfds)){
clen=sizeof(struct full_sockaddr_ax25);
csock=accept(bsock,(struct sockaddr*)&caddr,&clen);
if(csock==-1)setupsock(argv[1],argv[2]);
if(csock!=-1){if(fork()==0){close(bsock);clientcode();}else{close(csock);};};//FORK CHILD AND CLOSE CLIENTSOCK IN PARENT
};//CLIENT IN QUEUE
//BEACON REQUIRES A FILLED OUT BADDR STRUCT
//WILL BE SENT WHENEVER THERE ARE NO NEW CONNECTS DURING THE SELECT TIME...
//MAYBE CHANGE TO WATCHDOG TIMER SIGNAL HANDLER FOR ANY NETWORK ACTIVITY
if((tv.tv_sec==0)&&(tv.tv_usec==0))sendbeacon(0);
};//WHILE 1 ACCEPT
};//MAIN
