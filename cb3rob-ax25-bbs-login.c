#define _GNU_SOURCE
#include<crypt.h>
#include<dirent.h>
#include<fcntl.h>
#include<grp.h>
#include<pwd.h>
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include<sys/resource.h>
#include<sys/stat.h>
#include<sys/time.h>
#include<sys/types.h>
#include<termios.h>
#include<time.h>
#include<unistd.h>

#define BPNLCR 1

time_t login;
char*node;
char*call;
char*line;
char user[7];
uid_t uid;
gid_t gid;

struct timeval tv;
fd_set readfds;
fd_set writefds;
int nfds;

struct termios trmorgin;
struct termios trmorgout;
struct termios trmorgerr;
struct termios trmraw;

char homedir[256];

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

char*srcbtime(time_t t){
static char rcbt[22];
struct tm*ts;
if(!t)t=time(NULL);
ts=gmtime(&t);
memset(&rcbt,0,sizeof(rcbt));
snprintf(rcbt,sizeof(rcbt)-1,"%04d-%02d-%02dT%02d:%02d:%02dZ",ts->tm_year+1900,ts->tm_mon+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
return(rcbt);
};//SRCBTIME

ssize_t readfile(const char*filename,int asciimode){
uint8_t buf[512];
int ffd;
ssize_t rbytes;
ssize_t wbytes;
ssize_t total;
int n;
if(filename==NULL)return(-1);
ffd=open(filename,O_RDONLY,O_NONBLOCK|O_SYNC);
if(ffd==-1)return(-1);
total=0;
wbytes=0;
rbytes=0;
while((rbytes=read(ffd,&buf,sizeof(buf)))>1){
if(asciimode&BPNLCR)for(n=0;n<rbytes;n++)if(buf[n]=='\n')buf[n]='\r';
if((wbytes=write(STDOUT_FILENO,&buf,rbytes))<1)break;
sync();
total+=wbytes;
};//WHILE READBLOCK
close(ffd);
//CLEAR MEMORY
memset(buf,0,sizeof(buf));
if(wbytes<1)return(-1);
return(total);
};//READFILE

void printstatus(){
printf("TIME: %s\rCALL: %s\rUSER: %s\rNODE: %s\rLINE: %s\r\r",srcbtime(0),call,user,node,line);
};//PRINTWELCOME

void printwelcome(){
printf("=====================\rWelcome to MuTiNy BBS\r=====================\r");
};//PRINTBANNER

void printprompt(){
printf("[ %s @ %s : %s ]> ",user,node,getcwd(NULL,0));
};//PRINTPROMPT

void terminit(){
memset(&trmorgin,0,sizeof(struct termios));
memset(&trmorgout,0,sizeof(struct termios));
memset(&trmorgerr,0,sizeof(struct termios));
memset(&trmraw,0,sizeof(struct termios));
tcgetattr(STDIN_FILENO,&trmorgin);
tcgetattr(STDOUT_FILENO,&trmorgout);
tcgetattr(STDERR_FILENO,&trmorgerr);
cfmakeraw(&trmraw);
};//TERMINIT

void termorg(){
tcsetattr(STDIN_FILENO,0,&trmorgin);
tcsetattr(STDOUT_FILENO,0,&trmorgout);
tcsetattr(STDERR_FILENO,0,&trmorgerr);
};//TERMORG

void termraw(){
tcsetattr(STDIN_FILENO,0,&trmraw);
tcsetattr(STDOUT_FILENO,0,&trmraw);
tcsetattr(STDERR_FILENO,0,&trmraw);
};//TERMRAW

char*getcommand(){
static unsigned char cmd[128];
int n;
memset(&cmd,0,sizeof(cmd));
//BLOCKING MODE?!. IT'D BETTER BE BLOCKING.
if(fcntl(STDIN_FILENO,F_SETFL,fcntl(STDIN_FILENO,F_GETFL,0)&~O_NONBLOCK))return(NULL);
//STDOUT TOO (PTYS CAN GET 'FULL')
if(fcntl(STDOUT_FILENO,F_SETFL,fcntl(STDOUT_FILENO,F_GETFL,0)&~O_NONBLOCK))return(NULL);
for(n=0;n<sizeof(cmd)-1;n++){
if(read(STDIN_FILENO,(void*)&cmd+n,1)!=1)return(NULL);
if((cmd[n]>=0x61)&&(cmd[n]<=0x7A))cmd[n]&=0xDF;//ALL TO UPPER CASE
if(cmd[n]==0x09)cmd[n]=0x20;//HTAB TO SPACE
if(cmd[n]=='\n')cmd[n]='r';//LINUX CRAP TO CARRIAGE RETURN (IF DOS, NEXT ONE WILL BOGUS OUT AT THE 'NO ENTERS AT START OF LINE' IN THE NEXT ROUND)
if((n==0)&&((cmd[n]==0x20)||(cmd[n]=='\r'))){cmd[n]=0;n--;continue;};//NO SPACES OR ENTERS AT START OF LINE
if(cmd[n]=='\r'){cmd[n]=0;break;};//DONE
if((cmd[n]<0x20)||cmd[n]>0x7E){cmd[n]=0;n--;continue;};//NO WEIRD BINARY STUFF
};//FOR
printf("\rCOMMAND: %s\r\r",cmd);//PRINT IT IN CASE USER HAS ECHO OFF IN HIS TERMINAL
return((char*)&cmd);
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
printf("NO USERDATA FOUND FOR USERNAME %s - CREATING...\r",username);
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

printf("FOUND USERDATA UID: %d GID: %d\r",uid,gid);
//WE'LL GET TO THIS LATER. THEY'RE SET TO THE USERS CALLSIGN WITHOUT SSID FOR NOW
//WITH A SHELL THAT DENIES THEM ACCESS TO THE UNIX SHELL (COULD STILL GRANT THEM ACCCESS TO OTHER SERVICES!)
printf("NO PASSWORD FOR USER: %s SET SO NOT ASKING\r",username);


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
mkdir(directory,01750);//SET STICKY BIT - TEMP FILES DURING UPLOADS
chmod(directory,01750);//PROBABLY NONE OF THE USERS CONCERN. CONTAINS UNFINISHED TEMPORARY FILES
chown(directory,0,gid);//MAYBE DO THIS WITH O_TMPFILE INSTEAD
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
//CHOWN OUR TTY TOO. MAYBE IT SHOULD HAVE GROUP TTY ON SOME SYSTEMS
chown(line,uid,gid);
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
printf("SEE YOU AGAIN SOON %s\r\r",username);
sync();
sleep(10);
exit(EXIT_SUCCESS);
};//CMDBYE

void cmdinvalid(){
printf("INVALID COMMAND - TRY HELP\r\r");
};//CMDINVALID

void cmdhelp(){
printf("DIR   [PATH]  - LISTS FILES\r");
printf("CD    [PATH]  - CHANGES DIRECTORY\r");
printf("MD    <PATH>  - CREATES DIRECTORY\r");
printf("RM    <PATH>  - REMOVES FILE OR EMPTY DIRECTORY\r");
printf("READ  <PATH>  - READS TEXT FILE\r");
printf("BGET  <PATH>  - DOWNLOAD FILE USING THE #BIN# PROTOCOL\r");
printf("EXIT          - TERMINATES SESSION\r");
printf("\rPATHNAMES ARE 8.3 FORMAT [ A-Z 0-9 ]\r\r");
//printf("AUTOBIN UPLOADS CAN BE STARTED WHILE ON THE PROMPT\r");
//prrint("UPLOADS TO YOUR HOMEDIR OR /FILES OR /ANARCHY ONLY\r");
};//CMDHELP

int cmddir(char*name){
DIR*curdir;
struct dirent*direntry;
struct stat filestat;
size_t total;
size_t files;
size_t dirs;
int n;
if(name==NULL)name=getcwd(NULL,0);
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(!name[0])name=getcwd(NULL,0);
total=0;
files=0;
dirs=0;
curdir=opendir(name);
if(curdir==NULL){printf("ERROR OPENING DIRECTORY: %s\r\r",name);return(-1);};//ERROR
printf("DIRECTORY OF %s\r\r",name);
printf("./\r");
printf("../\r");
while((direntry=readdir(curdir))!=NULL){
if((direntry->d_name[0]>=0x30&&direntry->d_name[0]<=0x39)||(direntry->d_name[0]>=0x41&&direntry->d_name[0]<=0x5A)||(direntry->d_name[0]>=0x61&&direntry->d_name[0]<=0x7A)){
switch(direntry->d_type){
case DT_REG:
if(stat(direntry->d_name,&filestat)==-1){printf("ERROR ON FILESTAT%s\r",direntry->d_name);continue;};
printf("%s %lu\r",direntry->d_name,filestat.st_size);
total+=filestat.st_size;
files++;
continue;
case DT_DIR:
printf("%s/\r",direntry->d_name);
dirs++;
continue;
default:
continue;
};//SWITCH ENTRY TYPE
};//VALID FILENAME
};//WHILE DIRENTRY
if(closedir(curdir)==-1)printf("ERROR CLOSING DIRECTORY\r");//ERROR;
printf("\rTOTAL: %lu BYTES IN: %lu FILES AND %lu DIRECTORIES\r\r",total,files,dirs);
return(0);
};//CMDDIR

void cmdchdir(char*name){
int n;
if(name!=NULL){
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(name[0]){//JUST SHOW PWD
if(chdir(name))printf("CHDIR TO %s FAILED\r",name);
};//IF PARAMETERS OTHER THAN SPACE
};//IF PARAMETERS
printf("CURRENT DIRECTORY: %s\r\r",getcwd(NULL,0));
};//CMDCHDIR

void cmdmkdir(char*name){
int n;
if(name!=NULL){
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(chkpath(name)==-1)printf("INVALID ABSOLUTE 8.3 FORMAT [A-Z 0-9] PATH: %s\r",name);
else if(mkdir(name,00750))printf("CREATE DIRECTORY %s FAILED\r",name);
else chdir(name);//WE CD INTO IT DIRECTLY
printf("CURRENT DIRECTORY: %s\r\r",getcwd(NULL,0));
};//IF PARAMETERS
};//CMDMKDIR

void cmderase(char*name){
int n;
if(name!=NULL){
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(chkpath(name)==-1)printf("INVALID ABSOLUTE 8.3 FORMAT [A-Z 0-9] PATH: %s\r",name);
else if(remove(name))printf("ERASE %s FAILED\r",name);
printf("CURRENT DIRECTORY: %s\r\r",getcwd(NULL,0));
};//IF PARAMETERS
};//CMDERASE

//void cmdshell(){
//NO WORKY IN CHROOT... PROBABLY THE COPIED SHELL IS NOT STATIC COMPILED
//termorg();
//system("/bin/sh");
//termraw();
//};//CMDSHELL

void cmdtest(){
int n;
for(n=0;n<100;n++)printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
};//CMDTEST

ssize_t cmdbget(char*name){
int n;
int ffd;
ssize_t rbytes;
ssize_t wbytes;
ssize_t remain;
struct stat statbuf;
uint8_t buf[256];
if(name==NULL)return(-1);
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(!name[0])return(-1);
//MAKE SURE STDIN IS IN NON BLOCKING MODE
if(fcntl(STDIN_FILENO,F_SETFL,fcntl(STDIN_FILENO,F_GETFL,0)|O_NONBLOCK)){printf("SYSTEM ERROR\r\r");return(-1);};
while(read(STDIN_FILENO,&buf,sizeof(buf))>0);//FLUSH STDIN TO MAKE SURE PEERS #OK# IS AT THE START OF RECEPTION
//OPEN FILE
ffd=open(name,O_RDONLY,O_NONBLOCK|O_SYNC);
if(ffd==-1){printf("ERROR OPENING: %s\r\r",name);return(-1);};
//FILE IS NOW OPEN
if(fstat(ffd,&statbuf)==-1){close(ffd);printf("SYSTEM ERROR\r\r");return(-1);};
if((!(statbuf.st_mode&S_IFMT&S_IFREG))||(statbuf.st_size==0)){close(ffd);printf("ERROR OPENING: %s\r\r",name);return(-1);};
//START OUR SIDE
sprintf((char*)&buf,"#BIN#%lu\r",statbuf.st_size);
write(STDOUT_FILENO,&buf,strlen((char*)buf));
//WAIT FOR PEER
while(1){
sync();
tv.tv_sec=60;
tv.tv_usec=0;
FD_ZERO(&readfds);
FD_SET(STDIN_FILENO,&readfds);
select(STDIN_FILENO+1,&readfds,NULL,NULL,&tv);
if(FD_ISSET(STDIN_FILENO,&readfds))
//'STATION A SHOULD IGNORE ANY DATA NOT BEGINNING WITH #OK# OR #NO#' - AS WE ARE RUNNING ON A PTY WE CAN'T BE ABSOLUTELY SURE OF AX.25 FRAME LIMITS THOUGH.
memset(&buf,0,sizeof(buf));
if(read(STDIN_FILENO,&buf,sizeof(buf))>0){
for(n=0;(n<sizeof(buf)-7)&&(buf[n]!='#');n++);//FAST FORWARD TO FIRST #, ALLOW -SOME- PLAYROOM FOR EVENTUAL '\r' AT THE START (ABORT DURING SETUP) AND OTHER CREATIVE INTERPRETATIONS
if(!bcmp(&buf+n,"#NO#",4)){close(ffd);printf("BGET %s REFUSED BY PEER\r\r",name);return(-1);};
//GP ACCEPTS #ABORT# DURING SETUP, NOT JUST MID-STREAM AS PER DOCUMENTATION TOO.
if(!bcmp(&buf+n,"#ABORT#",7)){close(ffd);printf("BGET %s REFUSED BY PEER\r\r",name);return(-1);};
if(!bcmp(&buf+n,"#OK#",4))break;
};//HANDLE OK OR NOT OK
};//WHILE FETCH DATA
//PEER HAS TO ACCEPT WITHIN 1 MINUTE - ALSO AT LEAST TRY TO FORCE THE PTY TO SEND THE ABORT IN IT'S VERY OWN PACKET AS PER DOCUMENTATION...
if((tv.tv_sec==0)&&(tv.tv_usec==0)){close(ffd);sync();sleep(1);write(STDOUT_FILENO,"\r#ABORT#\r",9);sync();sleep(1);printf("BGET: %s TIMED OUT\r\r",name);return(-1);};
//MOVE TOTAL BYTES TO TRANSFER INTO SUBSTRACTION REGISTER
remain=statbuf.st_size;
//WHILE BYTES TO SEND LEFT, SEND BLOCKS OF DATA
while(remain>0){
tv.tv_sec=10;
tv.tv_usec=0;
FD_ZERO(&readfds);
FD_ZERO(&writefds);
FD_SET(STDIN_FILENO,&readfds);
FD_SET(STDOUT_FILENO,&writefds);
FD_SET(ffd,&readfds);
nfds=STDIN_FILENO;
if(STDOUT_FILENO>nfds)nfds=STDOUT_FILENO;
if(ffd>nfds)nfds=ffd;
select(nfds+1,&readfds,&writefds,NULL,&tv);
//HANDLE ABORT -BEFORE SENDING DATA-, IGNORE ANYTHING ELSE THAT COMES IN, AS PER SPECIFICATION
if(FD_ISSET(STDIN_FILENO,&readfds)){
memset(&buf,0,sizeof(buf));
if(read(STDIN_FILENO,&buf,sizeof(buf))>0){
for(n=0;(n<sizeof(buf)-7)&&(buf[n]!='#');n++);//FAST FORWARD TO FIRST # (ABORT IS SUPPOSED TO BE BETWEEN 2 \r's IN A PACKET OF IT'S OWN BUT WE'RE LESS PICKY)
if(!bcmp(&buf+n,"#ABORT#",7)){close(ffd);printf("BGET: %s ABORTED BY PEER\r\r",name);return(-1);};
};//IF DATA
};//FD_ISSET PTY
//SEND DATA - AND YES WE MUST CHECK IF THE PTY IS READY TO TAKE IT OR THINGS GO REALLY BONKERS
if(FD_ISSET(ffd,&readfds)&&FD_ISSET(STDOUT_FILENO,&writefds)){
rbytes=read(ffd,&buf,sizeof(buf));
if(rbytes<1){close(ffd);sync();sleep(1);write(STDOUT_FILENO,"\r#ABORT#\r",9);sync();sleep(1);printf("BGET ABORTED: %s FILE READ ERROR\r\r",name);return(-1);};
remain-=rbytes;
wbytes=write(STDOUT_FILENO,&buf,rbytes);
if(wbytes<rbytes){close(ffd);sync();sleep(1);write(STDOUT_FILENO,"\r#ABORT#\r",9);sync();sleep(1);printf("BGET ABORTED: %s DATA TRANSMIT ERROR\r\r",name);return(-1);};
};//FDISSET FILE
//BANGING THE CPU A BIT HERE IF THE PTY IS -NOT- READY TO ACCEPT MORE DATA (STDOUT -> PTY (BUFFER) -> MASTER -> SENDCLIENT() (BUFFER TO SLOW NETWORK) -> USUALLY SLLOOWWW CLIENT ALSO TRYING TO CRC IT)
if(!FD_ISSET(STDOUT_FILENO,&writefds))sleep(1);//HAVE CPU DO OTHER THINGS. THIS WHOLE THING IS SINGLE TASKING ANYWAY.
};//WHILE DATA LEFT TO SEND
close(ffd);
//STDIN BACK TO BLOCKING MODE TO BE SURE
if(fcntl(STDIN_FILENO,F_SETFL,fcntl(STDIN_FILENO,F_GETFL,0)&~O_NONBLOCK)){printf("SYSTEM ERROR\r");};
printf("\rBINSEND FILE: %s BYTES: %ld\r\r",name,statbuf.st_size);
return(statbuf.st_size);
};//CMDBGET

void cmdread(char*name){
int n;
if(name!=NULL){
for(n=0;name[n]==0x20;n++);
name=name+n;//STRIP LEADING SPACE
if(name[0])printf("\rREAD: %ld BYTES\r\r",readfile(name,BPNLCR));else printf("ERROR OPENING: %s FILENAME?\r\r",name);
};//IF PARAMETERS
};//CMDCHDIR

void cmdbput(char*bincmd,char*username){
int n;
int f;
int ffd;
ssize_t rbytes;
ssize_t wbytes;
ssize_t remain;
struct stat statbuf;
uint8_t buf[256];
uint16_t crc;
size_t rsize;
int parsefield;
parsefield=0;
sync();sleep(1);write(STDOUT_FILENO,"#NO#\r",5);sync();sleep(1);//DENY UPLOAD
for(n=0;(bincmd[n]!=0)&&(bincmd[n]!='\r');n++){
if(bincmd[n]=='#'){
n++;//SKIP FIELD DELIMITER ITSELF
memset(&buf,0,sizeof(buf));
//COPY FIELD TO BUF
for(f=0;((n+f)<sizeof(buf)-1)&&(bincmd[n+f]!=0)&&(bincmd[n+f]!='\r')&&(bincmd([n+f]!='#');f++)buf[f]=bincmd[n+f];
printf("FIELD: %d: [%s]\r",parsefield,buf);
n=n+f;//FAST FORWARD N COUNTER TO NEXT DELIMITER
n--;//PUT N BACK WHERE WE FOUND IT SO WE DON'T SKIP SEGMENTS
parsefield++;
//};//FOR FIELDCOPY
};//FOR BYTE
printf("ERROR: AUTOBIN NOT IMPLEMENTED YET\r\r");
};//CMDBPUT

int main(int argc,char**argv){
int n;
char*currentcmd;

if(argc!=4){printf("THIS PROGRAM SHOULD BE EXECUTED BY CB3ROB AX25 BBS ONLY\n");exit(EXIT_FAILURE);};
if((strcmp(argv[3],"CB3ROB-MUTINY-AX25-BBS"))||(chkcall(argv[1])==-1)||(chkcall(argv[2])==-1)){printf("THIS PROGRAM SHOULD BE EXECUTED BY CB3ROB AX25 BBS ONLY\n");exit(EXIT_FAILURE);};
if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

login=time(NULL);
call=argv[1];
node=argv[2];
line=ttyname(STDIN_FILENO);//DO THIS BEFORE CHROOT

//STRIP SSID
memset(user,0,sizeof(user));
for(n=0;(n<sizeof(user)-1)&&(call[n])&&(call[n]!='-');n++)user[n]=call[n];

//TURN OFF STDOUT BUFFERING TO BE ABLE TO USE PRINTF WITH CARRIAGE RETURN
//AS THE ONLY PLACE HERE WHERE IT WILL FIND THAT NEWLINE IT'S WAITING FOR IS BINARY TRANSFERS
//WE'LL SIMPLY HAVE TO PRINTF() THE ENTIRE PACKET PAYLOAD IN ONE GO AS MUCH AS POSSIBLE, RESULTING IN ONE WRITE()
//LINUX REFUSES TO SEE CARRIAGE RETURN AS A DELIMITER OF ANY KIND
setbuf(stdout,NULL);

//INITIALIZE TERMIOS
terminit();
//TERMINAL RAW
termraw();
//INIT USER
inituser(user);

printstatus();
printwelcome();
readfile("/ETC/WELCOME.TXT",BPNLCR);
while(1){//IF THE PARENT DIES WE DIE BY SIGNAL ANYWAY
printprompt();
currentcmd=getcommand();
if(currentcmd==NULL)break;//BLOCKING READ FELL THROUGH AS PARENT CLOSED PTY (MOST LIKELY)
if(!bcmp(currentcmd,"#BIN#",5)){cmdbput(currentcmd,user);continue;};//RELAY THE ENTIRE CMD LINE TO THE AUTOBIN PROGRAM
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
if(!bcmp(currentcmd,"RMDIR",5))if((currentcmd[5]==0x20)||(currentcmd[5]==0)){cmderase((char*)currentcmd+5);continue;};
if(!bcmp(currentcmd,"RM",2))if((currentcmd[2]==0x20)||(currentcmd[2]==0)){cmderase((char*)currentcmd+2);continue;};
//READ ASCII
if(!bcmp(currentcmd,"READ",4))if((currentcmd[4]==0x20)||(currentcmd[4]==0)){cmdread((char*)currentcmd+4);continue;};
//READ BIN
if(!bcmp(currentcmd,"BGET",4))if((currentcmd[4]==0x20)||(currentcmd[4]==0)){cmdbget((char*)currentcmd+4);continue;};
//TRANSFER TEST
if(!strcmp(currentcmd,"TEST")){cmdtest(user);continue;};
//DISCONNECT
if(!strcmp(currentcmd,"BYE")){cmdbye(user);continue;};
if(!strcmp(currentcmd,"EXIT")){cmdbye(user);continue;};
if(!strcmp(currentcmd,"QUIT")){cmdbye(user);continue;};
if(!strcmp(currentcmd,"SALIR")){cmdbye(user);continue;};
if(!bcmp(currentcmd,"DISC",4)){cmdbye(user);continue;};//DISCONNECT IS GOOD WITH ANY ABBREVIATION
//HELP
if(!strcmp(currentcmd,"HELP")){cmdhelp();continue;};
//if(!strcmp(currentcmd,"GODMODE")){cmdshell();continue;};
//FALLTHROUGH INVALID
cmdinvalid();
};//COMMAND LOOP
exit(EXIT_SUCCESS);
};//MAIN
