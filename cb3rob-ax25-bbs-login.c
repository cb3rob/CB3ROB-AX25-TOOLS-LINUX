#include<dirent.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<termios.h>
#include<time.h>
#include<unistd.h>

#define BPNLCR 1

time_t login;
char *node;
char *call;
char *line;
char user[7];

struct termios trmorgin;
struct termios trmorgout;
struct termios trmorgerr;
struct termios trmraw;

char homedir[256];

char*srcbtime(time_t t){
static char rcbt[22];
struct tm*ts;
if(!t)t=time(NULL);
ts=gmtime(&t);
memset(&rcbt,0,sizeof(rcbt));
snprintf(rcbt,sizeof(rcbt)-1,"%04d-%02d-%02dT%02d:%02d:%02dZ",ts->tm_year+1900,ts->tm_mon+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
return(rcbt);
};//SRCBTIME

ssize_t readfile(const char *filename,int asciimode){
uint8_t rbuf[512];
int ffd;
ssize_t rbytes;
ssize_t wbytes;
ssize_t total;
int n;
if(filename==NULL)return(0);
ffd=open(filename,O_RDONLY,O_NONBLOCK|O_SYNC);
if(ffd==-1)return(-1);
total=0;
wbytes=0;
rbytes=0;
while((rbytes=read(ffd,rbuf,sizeof(rbuf)))>1){
if(asciimode&BPNLCR)for(n=0;n<rbytes;n++)if(rbuf[n]=='\n')rbuf[n]='\r';
if((wbytes=write(STDOUT_FILENO,rbuf,rbytes))<1)break;
sync();
total+=wbytes;
};//WHILE READBLOCK
close(ffd);
//CLEAR MEMORY
memset(rbuf,0,sizeof(rbuf));
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
for(n=0;n<sizeof(cmd)-1;n++){
if(read(STDIN_FILENO,(void*)&cmd+n,1)!=1)return(NULL);
if((cmd[n]>=0x61)&&(cmd[n]<=0x7A))cmd[n]&=0xDF;//ALL TO UPPER CASE
if(cmd[n]==0x09)cmd[n]=0x20;//HTAB TO SPACE
if(cmd[n]=='\n')cmd[n]='r';//LINUX CRAP TO CARRIAGE RETURN (IF DOS, NEXT ONE WILL BOGUS OUT AT THE 'NO ENTERS AT START OF LINE' IN THE NEXT ROUND)
if((n==0)&&((cmd[n]==0x20)||(cmd[n]=='\r'))){cmd[n]=0;n--;continue;};//NO SPACES OR ENTERS AT START OF LINE
if(cmd[n]=='\r'){cmd[n]=0;break;};//DONE
if((cmd[n]<0x20)||cmd[n]>0x7E){cmd[n]=0;n--;continue;};//NO WEIRD BINARY STUFF
};//FOR
printf("\rCOMMAND: %s\r",cmd);//PRINT IT IN CASE USER HAS ECHO OFF IN HIS TERMINAL
return((char*)&cmd);
};//GETCOMMAND

int inituser(char *username){
char directory[256];
if(user==NULL)return(-1);
char basepath[]="/var/bbs";
memset(&directory,0,sizeof(directory));
//MAKE SURE THE SYSTEM IS INITIALIZED AND ALL DIRECTORIES EXIST (TAKES LONGER TO CHECK THAN TO JUST TRY TO CREATE THEM IF NOT ;)
mkdir(basepath,00710);
snprintf(directory,sizeof(directory)-1,"%s/ETC",basepath);
mkdir(directory,00710);//NONE OF THE USERS CONCERN HERE
snprintf(directory,sizeof(directory)-1,"%s/BIN",basepath);
mkdir(directory,00710);//NONE OF THE USERS CONCERN HERE
snprintf(directory,sizeof(directory)-1,"%s/UPLOAD",basepath);
mkdir(directory,01710);//SET STICKY BIT - TEMP FILES DURING UPLOADS
snprintf(directory,sizeof(directory)-1,"%s/FILES",basepath);
mkdir(directory,01750);//SET STICKY BIT - USERS CAN REMOVE FILES THEY UPLOADED
snprintf(directory,sizeof(directory)-1,"%s/MEMBERS",basepath);
mkdir(directory,00710);//NO LISTING THE OTHER CALLSIGNS
snprintf(directory,sizeof(directory)-1,"%s/MAIL",basepath);
mkdir(directory,00710);//JUST YOUR OWN
memset(&directory,0,sizeof(directory));
//GETPWNAM() TO SEE IF FIRST VISIT
//ASK FOR PASSWORD IF SET, EXPLAIN HOW TO SET ONE IF NOT
//ADD USER TO NIS/YP/PASSWD IF FIRST VISIT
memset(&homedir,0,sizeof(homedir));
snprintf(homedir,sizeof(homedir)-1,"%s/MEMBERS/%s",basepath,username);
mkdir(homedir,00710);
snprintf(homedir,sizeof(homedir)-1,"/MEMBERS/%s",username);
//SETRLIMITS HERE
//DROP ROOT HERE
chroot(basepath);
chdir(homedir);
return(0);
};//INITUSER;

int cmdbye(char *username){
printf("SEE YOU AGAIN SOON %s\r",username);
sync();
sleep(10);
exit(EXIT_SUCCESS);
};//CMDBYE

void cmdhello(char *username){
printf("HELLO %s\r",username);
};//CMDHELLO

void cmdinvalid(){
printf("INVALID COMMAND - TRY HELP\r");
};//CMDINVALID

void cmdhelp(){
printf("HELLO - SAYS HELLO\r");
printf("DIR   - LISTS FILES\r");
printf("CHDIR - CHANGES DIRECTORY\r");
printf("READ  - READS TEXT FILE\r");
printf("EXIT  - TERMINATES SESSION\r");
};//CMDHELP

int cmddir(){
DIR *curdir;
struct dirent *direntry;
struct stat filestat;
size_t total;
size_t files;
size_t dirs;
total=0;
files=0;
dirs=0;
curdir=opendir(".");
if(curdir==NULL){printf("ERROR OPENING DIRECTORY\r");return(-1);};//ERROR
printf("\rDIRECTORY OF %s\r\r",getcwd(NULL,0));
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
printf("\rTOTAL: %lu BYTES IN: %lu FILES AND %lu DIRECTORIES\r\r",total,files,dirs);
if(closedir(curdir)==-1){printf("ERROR CLOSING DIRECTORY\r");return(-1);};//ERROR;
return(0);
};//CMDDIR

void cmdchdir(char*dir){
int n;
if(dir!=NULL){
for(n=0;dir[n]==0x20;n++);
dir=dir+n;//STRIP LEADING SPACE
if(dir[0]){//JUST SHOW PWD
if(chdir(dir))printf("CHDIR TO %s FAILED\r",dir);
};//IF PARAMETERS OTHER THAN SPACE
};//IF PARAMETERS
printf("CURRENT DIRECTORY: %s\r\r",getcwd(NULL,0));
};//CMDCHDIR

void cmdread(char*filename){
int n;
if(filename!=NULL){
for(n=0;filename[n]==0x20;n++);
filename=filename+n;//STRIP LEADING SPACE
if(filename[0])printf("\rREAD: %ld BYTES\r\r",readfile(filename,BPNLCR));else printf("FILENAME?\r\r");
};//IF PARAMETERS
};//CMDCHDIR

void cmdautobin(char *bincmd,char*username){
printf("\r#ABORT#\r");
sync();
sleep(2);
printf("ERROR: AUTOBIN NOT IMPLEMENTED YET\r");
};//CMDAUTOBIN

int main(int argc,char**argv){
int n;
char *currentcmd;

if(argc<3){printf("THIS PROGRAM SHOULD BE EXECUTED BY CB3ROB AX25 BBS ONLY\n");exit(EXIT_FAILURE);};
if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

login=time(NULL);
call=argv[1];
node=argv[2];
line=ttyname(STDIN_FILENO);//DO THIS BEFORE CHROOT

//STRIP SSID
memset(user,0,sizeof(user));
for(n=0;(n<sizeof(user)-1)&&(call[n])&&(call[n]!='-');n++)user[n]=call[n];

//TURN OFF STDOUT BUFFERING TO USE PRINTF WITH CARRIAGE RETURN
setbuf(stdout,NULL);

//INITIALIZE TERMIOS
terminit();
//TERMINAL RAW
termraw();
//INIT USER
inituser(user);

printstatus();
printwelcome();
printf("\rREAD: %ld BYTES\r\r",readfile("/ETC/WELCOME.TXT",BPNLCR));
while(1){//IF THE PARENT DIES WE DIE BY SIGNAL ANYWAY
printprompt();
currentcmd=getcommand();
if(!bcmp(currentcmd,"#BIN#",5)){cmdautobin(currentcmd,user);continue;};
if(!bcmp(currentcmd,"CHDIR",5))if((currentcmd[5]==0x20)||(currentcmd[5]==0)){cmdchdir((char*)currentcmd+5);continue;};
if(!bcmp(currentcmd,"READ",4))if((currentcmd[4]==0x20)||(currentcmd[4]==0)){cmdread((char*)currentcmd+4);continue;};
if(!strcmp(currentcmd,"HELLO")){cmdhello(user);continue;};
if(!strcmp(currentcmd,"BYE")){cmdbye(user);continue;};
if(!strcmp(currentcmd,"EXIT")){cmdbye(user);continue;};
if(!strcmp(currentcmd,"QUIT")){cmdbye(user);continue;};
if(!strcmp(currentcmd,"HELP")){cmdhelp();continue;};
if(!strcmp(currentcmd,"DIR")){cmddir();continue;};
cmdinvalid();
};//COMMAND LOOP
exit(EXIT_SUCCESS);
};//MAIN

