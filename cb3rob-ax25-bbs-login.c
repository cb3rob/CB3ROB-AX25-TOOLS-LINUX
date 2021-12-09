#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<time.h>

time_t login;
char *node;
char *call;
char user[7];

char*srcbtime(time_t t){
static char rcbt[22];
struct tm*ts;
if(!t)t=time(NULL);
ts=gmtime(&t);
memset(&rcbt,0,sizeof(rcbt));
snprintf(rcbt,sizeof(rcbt)-1,"%04d-%02d-%02dT%02d:%02d:%02dZ",ts->tm_year+1900,ts->tm_mon+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
return(rcbt);
};//SRCBTIME

void printwelcome(){
printf("TIME: %s\rCALL: %s\rUSER: %s\rNODE: %s\rLINE: %s\r",srcbtime(0),call,user,node,ttyname(0));
};//PRINTWELCOME

void printbanner(){
printf("Welcome to MuTiNy BBS\r\r");
};//PRINTBANNER

int main(int argc,char**argv){
int n;

if(argc<3){printf("THIS PROGRAM SHOULD BE EXECUTED BY CB3ROB AX25 BBS ONLY\n");exit(EXIT_FAILURE);};
if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

login=time(NULL);
node=argv[1];
call=argv[2];

//STRIP SSID
memset(user,0,sizeof(user));
for(n=0;(n<sizeof(user)-1)&&(call[n])&&(call[n]!='-');n++)user[n]=call[n];

//TURN OFF STDOUT BUFFERING TO USE PRINTF WITH CARRIAGE RETURN
setbuf(stdout,NULL);

printwelcome();
sleep(10);

printf("\r\rBYE\r");
exit(0);
};

