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
char user[7];

struct termios trmorgin;
struct termios trmorgout;
struct termios trmorgerr;
struct termios trmraw;

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
ssize_t bytes;
ssize_t total;
int n;
if(filename==NULL)return(0);
ffd=open(filename,O_RDONLY,O_NONBLOCK|O_SYNC);
if(ffd==-1)return(0);
total=0;
bytes=0;
while((bytes=read(ffd,rbuf,sizeof(rbuf)))>1){
if(asciimode&BPNLCR)for(n=0;n<bytes;n++)if(rbuf[n]=='\n')rbuf[n]='\r';
if((bytes=write(STDOUT_FILENO,rbuf,bytes))<1)break;
sync();
total+=bytes;
};//WHILE READBLOCK
close(ffd);
//CLEAR MEMORY
memset(rbuf,0,sizeof(rbuf));
if(bytes==-1)return(0);
return(total);
};//READFILE

void printstatus(){
printf("TIME: %s\rCALL: %s\rUSER: %s\rNODE: %s\rLINE: %s\r\r",srcbtime(0),call,user,node,ttyname(STDIN_FILENO));
};//PRINTWELCOME

void printwelcome(){
printf("=====================\rWelcome to MuTiNy BBS\r=====================\r");
};//PRINTBANNER

void printprompt(){
printf("%s @ %s> ",user,node);
};//PRINTPROMPT

void printinvalid(){
printf("INVALID COMMAND\r");
};//PRINTINVALID

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

unsigned char *getcommand(){
static unsigned char cmd[128];
int n;
memset(&cmd,0,sizeof(cmd));
for(n=0;n<sizeof(cmd)-1;n++){
if(read(STDIN_FILENO,(void*)&cmd+n,1)!=1){ ; };//BLOCKING MODE?!. IT'D BETTER BE.
if(cmd[n]==0x09)cmd[n]=0x20;//HTAB TO SPACE
if(cmd[n]=='\n')cmd[n]='r';//LINUX CRAP TO CARRIAGE RETURN (IF DOS, NEXT ONE WILL BOGUS OUT AT THE 'NO ENTERS AT START OF LINE' IN THE NEXT ROUND)
if((n==0)&&((cmd[n]==0x20)||(cmd[n]=='\r'))){cmd[n]=0;n--;continue;};//NO SPACES OR ENTERS AT START OF LINE
if(cmd[n]=='\r'){cmd[n]=0;break;};//DONE
if((cmd[n]<0x20)||cmd[n]>0x7E){cmd[n]=0;n--;continue;};//NO WEIRD BINARY STUFF
};//FOR
printf("\rCOMMAND: %s\r",cmd);//PRINT IT IN CASE USER HAS ECHO OFF IN HIS TERMINAL
return(cmd);
};//GETCOMMAND

int main(int argc,char**argv){
int n;
unsigned char *currentcmd;

if(argc<3){printf("THIS PROGRAM SHOULD BE EXECUTED BY CB3ROB AX25 BBS ONLY\n");exit(EXIT_FAILURE);};
if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

login=time(NULL);
call=argv[1];
node=argv[2];

//STRIP SSID
memset(user,0,sizeof(user));
for(n=0;(n<sizeof(user)-1)&&(call[n])&&(call[n]!='-');n++)user[n]=call[n];

//TURN OFF STDOUT BUFFERING TO USE PRINTF WITH CARRIAGE RETURN
setbuf(stdout,NULL);

//INITIALIZE TERMIOS
terminit();
//TERMINAL RAW
termraw();

printstatus();
printwelcome();
printf("\rRead: %ld Bytes\r\r",readfile("/etc/passwd",BPNLCR));
printprompt();
currentcmd=getcommand();
printf("Got command: %s\r",currentcmd);
printf("BYE\r\r");
sync();
sleep(10);
exit(EXIT_SUCCESS);
};

