//HRH Prince Sven Olaf of CyberBunker-Kamphuis
//CB3ROB TACTICAL SYSTEMS
//One CyberBunker Avenue
//Republic CyberBunker

//COMPILE WITH gcc -O3 -o cb3rob-axudp-attach cb3rob-axudp-attach.c
//openpty() REQUIRES -lutil

//TO BRING UP AN AX.25 AXUDP INTERFACE (bpq0,bpq1,etc) TO AN AXUDP CONCENTRATOR SERVER:

//TESTED TO WORK AGAINST THAT SILLY OLD AX25IPD (HAD TO TEST IT AGAINST SOMETHING... BUT SERIOUSLY... -2- PROGRAMS AND -2- CONFIG FILES JUST TO GET IT TO WORK?)
//(WHICH CAN'T EVEN BRING IT'S OWN INTERFACE UP AND CAN'T KEEP TRACK OF DYNAMIC SOURCE/PORT CLIENTS, AND ALSO SEEMS TO THINK 'ROUTING' IS A 1 CALLSIGN AT A TIME THING ;)
//DON'T ASK ;P HINT PEOPLE... RECEIVED VALID PACKET... SOUCE ADDRESS+PORT, TIMESTAMP AND THE THING DOESN'T EVEN NEED TO KNOW WHAT A CALLSIGN IS :P

//NOTE THAT AXUDP LACKS AN RFC OF IT'S OWN AND BASICALLY SAYS 'ITS AXIP BUT WITH UDP'. AXIP DOES HAVE AN RFC... BBBUT... IT'S 10 LINES LONG. LOL.
//HENCE THE TESTING AGAINST OTHER SOFTWARE CLAIMING TO SUPPORT IT. (LOTS OF UNCLARITY ABOUT FLAGS, FCS, ETC), TURNS OUT IT'S NO FLAGS, NO LEADING CHANNEL(KISS) BYTE, BUT ENFORCES AN FCS

//AXUDP capability at: KE8GCL-7 ax.prime41.com 10093
//AXUDP 149.210.161.112 93 AXNODE.AX25.NL

// ./cb3rob-axudp-attach NOCALL X.X.X.X 10093 &

//WARNING - TEST VERSION - NASTY CODING - NO GUARANTEES

//OUR APOLOGIES FOR THIS BEING THE BIGGEST PILE OF BURNING GARBAGE CODING EVER UPLOADED SO INMATURELY - BUT IT WORKS.
//IT WAS PRIMARILY NEEDED TO GET ONTO SOME OTHER PEOPLE'S AXUDP NODES :P - NOT A PROTOCOL WE INTEND ON DOING MUCH WITH FOR NOW.

//OK. SO. TODAY WE SHALL DEMONSTRATE... CONVERTING AN NO-FLAGS-BUT-WITH-FCS AXUDP PACKET FROM AND TO ETHERNET II BPQ ETHER FORMAT :P
//AS FOR SOME REASON DESPITE PRETENDING TO BE A 'UNIVERSAL' INTERFACE TUNTAP GETS AS FAR AS BRINGING UP A 'BPQ' INTERFACE -WITHOUT- A CORRESPONDING ETHERNET INTERFACE
//BUT THEN CAN'T SET IT'S CALLSIGN ADDRESS (IT ALSO DOESN'T WORK. IT DOES GET AS FAR AS BRINGING IT UP WITH AN AX.25 INTERFACE TYPE DIRECTLY THO ;)
//SOOOO WE SIMPLY SET UP AN ACTUAL ETHERNET FRAMED TAP DEVICE AND JUST COMPOSE THE REST OF THE ETHERNET II FRAME HERE IN THE PROGRAM...
//RATHER NASTY WAY WITH system() TO HACK THE CORRESPONDING bpq INTERFACE UP OUT OF PROC... SHOULD BE SOME IOCTL FOR THAT... (OR REALLY, JUST NATIVE AX.25 'TAP' DEVICES ;)

#include<net/if_arp.h>
#include<arpa/inet.h>
#include<fcntl.h>
#include<linux/ax25.h>
#include<linux/if_slip.h>
#include<linux/tcp.h>
#include<net/if.h>
#include<netdb.h>
#include<netinet/in.h>
#include<pty.h>//COMPILE WITH -lutil
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<sys/stat.h>
#include<sys/time.h>
#include<sys/types.h>
#include<syslog.h>
#include<termios.h>
#include<time.h>
#include<unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

struct sockaddr_in saddr;
struct sockaddr_in baddr;//BIND ADDRESS BECAUSE AX25IPD IS TOO STUPID TO MAINTAIN A DYNAMIC LIST OF LAST HEARD SOURCEIPS:PORTS FOR EACH 'CONNECTION' AND THAT'S THE ONLY PIECE OF DUNG WE CAN TEST THIS AGAINST.
                         //WE SIMPLY BIND TO WHATEVER PORT THE SERVER IS ON TOO (AS PER ARGV) - TAKE NOTE THAT THIS SHOULD NOT BE AN ISSUE AS STUFF LIKE AX25IPD SHOULD JUST DYNAMICALLY KEEP TRACK OF PEERS
struct timeval tv;
struct hostent *he;
int sock;
int tap;
int devno;
char dev[IFNAMSIZ];
int nfds;
struct ifreq ifr;
int fdx;
int encap;
fd_set readfds;
fd_set writefds;
fd_set exceptfds;
ax25_address call;
char systemline[256];

struct bpqethhdr{
uint8_t ethdst[6];
uint8_t ethsrc[6];
uint16_t ptype;
uint16_t len;
unsigned char payload[2048];
};

union{
uint16_t fcs16;
uint8_t fcs8[2];
}fcs;

struct bpqethhdr sockpacket;
struct bpqethhdr tappacket;


//SOME RIPPED STUFF TO GET THE CRC TO WORK. DON'T ASK.

/* crc.c 		Computations involving CRCs */

/*
 **********************************************************************
 * The following code was taken from Appendix B of RFC 1171
 * (Point-to-Point Protocol)
 *
 * The RFC credits the following sources for this implementation:
 *
 *   Perez, "Byte-wise CRC Calculations", IEEE Micro, June, 1983.
 *
 *   Morse, G., "Calculating CRC's by Bits and Bytes", Byte,
 *   September 1986.
 *
 *   LeVan, J., "A Fast CRC", Byte, November 1987.
 *
 *
 * The HDLC polynomial: x**0 + x**5 + x**12 + x**16
 */

/*
 * u16 represents an unsigned 16-bit number.  Adjust the typedef for
 * your hardware.
 */
typedef unsigned short u16;


/*
 * FCS lookup table as calculated by the table generator in section 2.
 */
static u16 fcstab[256] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

#define PPPINITFCS      0xffff	/* Initial FCS value */
#define PPPGOODFCS      0xf0b8	/* Good final FCS value */

/*
 * Calculate a new fcs given the current fcs and the new data.
 */
u16 pppfcs(u16 fcs, unsigned char *cp, int len)
{
/*    ASSERT(sizeof (u16) == 2); */
/*    ASSERT(((u16) -1) > 0);    */
	while (len--)
		fcs = (fcs >> 8) ^ fcstab[(fcs ^ *cp++) & 0xff];

	return fcs;
}

/*
 * End code from Appendix B of RFC 1171
 **********************************************************************
 */

/*
 *  The following routines are simply convenience routines...
 *  I'll merge them into the mainline code when suitably debugged
 */

/* Return the computed CRC */
unsigned short int compute_crc(unsigned char *buf, int l)
{
	int fcs;
        fcs = PPPINITFCS;
	fcs = pppfcs(fcs, buf, l);
	fcs ^= 0xffff;
	return fcs;
}

/* Return true if the CRC is correct */
int ok_crc(unsigned char *buf, int l)
{
	int fcs;

	fcs = PPPINITFCS;
	fcs = pppfcs(fcs, buf, l);
	return fcs == PPPGOODFCS;
}

int tapalloc(char*tdev){
if(tap!=-1)close(tap);
struct ifreq ifr;
int tap, err;
if((tap=open("/dev/net/tun",O_RDWR))<0)return(-1);
bzero(&ifr,sizeof(ifr));
if(*tdev)strncpy(ifr.ifr_name,tdev,IFNAMSIZ);
ifr.ifr_flags=IFF_TAP|IFF_NO_PI;
if((err=ioctl(tap,TUNSETIFF,(void*)&ifr))<0){close(tap);return(-1);};
//int val = ARPHRD_AX25; //ETH_P_AX25
//if(ioctl(tap,TUNSETLINK,(unsigned long)val)<0)perror("TUNSETLINK");
//if(ioctl(tap,TUNSETPERSIST,0)<0){close(tap);return(-1);};

//strcpy(tdev,ifr.ifr_name);
//SET AX.25 NETWORK DEVICE FLAGS
fdx=socket(PF_AX25,SOCK_DGRAM,0);
bzero(&ifr,sizeof(struct ifreq));
strcpy(ifr.ifr_name,tdev);
//ifr.ifr_mtu=AX25_MTU;
//ioctl(fdx,SIOCSIFMTU,&ifr);
//ifr.ifr_hwaddr.sa_family=ARPHRD_AX25;
//bzero(ifr.ifr_hwaddr.sa_data,sizeof(ifr.ifr_hwaddr.sa_data));
//bcopy(&call,ifr.ifr_hwaddr.sa_data,7);
//ioctl(fdx,SIOCSIFHWADDR,&ifr);
ifr.ifr_flags=IFF_UP|IFF_RUNNING;
ioctl(fdx,SIOCSIFFLAGS,&ifr);
if(ioctl(fdx,SIOCGIFINDEX,&ifr)<0){perror("IOCTL");exit(EXIT_FAILURE);};
printf("INTERFACE INDEX: %d\n",ifr.ifr_ifindex);
if(ioctl(fdx,SIOCGIFHWADDR,&ifr)<0){perror("IOCTL");exit(EXIT_FAILURE);};
printf("INTERFACE FAMILY: %d\n",ifr.ifr_hwaddr.sa_family);
bcopy(ifr.ifr_hwaddr.sa_data,sockpacket.ethsrc,sizeof(sockpacket.ethsrc));
close(fdx);
//SUCH NASTYNESS.
//BUT CAN'T MAKE THE TAP INTERFACE ARPHRD_AX25 DIRECTLY BECAUSE IT REFUSES 7 BYTE sa_data FIELDS IN SIOCSIFHWADDR ONLY WAY TO FIND THE ASSOCIATED ETHERNET DEVICE IS THROUGH PROC IT SEEMS... YUK.
//ANYWAY CODE THIS BETTER. LOL. "IT WORKS ON MY COMPUTER - BUT WE'RE NOT SHIPPING YOUR COMPUTER TO THE CLIENT". ANYWAY IT WORKS FOR NOW.
sprintf(systemline,"ifconfig `cat /proc/net/bpqether|grep axudp%d|cut -d' ' -f1` hw ax25 AXUDP-%d up",devno,devno);
system(systemline);
//GIVE THE BRIDGE (IF ANY) A KICK TO RE-INDEX INTERFACES AND START BRIDGING TO THIS ONE
system("killall -HUP cb3rob-ax25-bridge");
return(tap);
};//TAPALLOC

char *srcbtime(time_t t){
static char rcbt[22];
struct tm *ts;
if(!t)t=time(NULL);
ts=gmtime(&t);
bzero(&rcbt,sizeof(rcbt));
snprintf(rcbt,sizeof(rcbt)-1,"%04d-%02d-%02dT%02d:%02d:%02dZ",ts->tm_year+1900,(ts->tm_mon)+1,ts->tm_mday,ts->tm_hour,ts->tm_min,ts->tm_sec);
return(rcbt);
};//SRCBTIME

int calltobin(char *ascii,ax25_address *bin){
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

void udpconnect(char*host,char*port){
//(RE-)CONNECT UDP
if(sock!=-1)close(sock);
sock=-1;
while(sock==-1){
//ALWAYS LOOK UP THE HOST AGAIN
he=gethostbyname(host);
if((he==NULL)||(he->h_addrtype!=AF_INET)||(he->h_length!=4)){printf("%s INVALID SERVER: %s\n",srcbtime(0),host);sleep(1);continue;};
saddr.sin_family=AF_INET;
bcopy(he->h_addr_list[0],&saddr.sin_addr.s_addr,sizeof(saddr.sin_addr.s_addr));
saddr.sin_port=htons(atoi(port));
sock=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
baddr.sin_family=AF_INET;
baddr.sin_addr.s_addr=INADDR_ANY;
baddr.sin_port=htons(atoi(port));
bind(sock,(struct sockaddr*)&baddr,sizeof(baddr));
if(sock==-1){printf("%s SOCKET SETUP ERROR\n",srcbtime(0));sleep(1);continue;};
printf("%s CONNECTING: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));
if(connect(sock,(struct sockaddr*)&saddr,sizeof(saddr))!=0){close(sock);sock=-1;printf("%s CONNECT ERROR: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));sleep(1);continue;};
printf("%s CONNECTED: %s:%d\n",srcbtime(0),inet_ntoa(saddr.sin_addr),ntohs(saddr.sin_port));
};//WHILE SOCK -1
};//UDPCONNECT

int main(int argc,char **argv){

if(getuid()!=0){printf("THIS PROGRAM MUST RUN AS ROOT\n");exit(EXIT_FAILURE);};

if(argc<4){printf("USAGE: %s <CALLSIGN[-SSID]> <AXUDP-SERVER> <PORT>\n",argv[0]);exit(EXIT_FAILURE);};

if(calltobin(argv[1],&call)<1){printf("INVALID DEVICE CALLSIGN: %s\n",argv[1]);exit(EXIT_FAILURE);};

sock=-1;udpconnect(argv[2],argv[3]);
devno=0;
for(tap=-1;tap==-1;devno++){sprintf(dev,"axudp%d",devno);tap=tapalloc(dev);};

fcntl(sock,F_SETFL,fcntl(sock,F_GETFL,0)|O_NONBLOCK);
fcntl(tap,F_SETFL,fcntl(tap,F_GETFL,0)|O_NONBLOCK);

printf("%s AX.25 BOUND TO DEVICE %s\n",srcbtime(0),dev);

//LOOP DATA
ssize_t bytes;
ssize_t n;

FD_ZERO(&readfds);
FD_ZERO(&writefds);
FD_ZERO(&exceptfds);

//EHM YEP. YOU'D SAY WE COULD DO SOME NIFTY STUFF WITH DUP2() AND REDIRECTS HERE (BY LACK OF A 'REVERSE' PIPE() ;). BUT NAH. CAN'T.
//EITHER WAY IT DOESN'T MATTER MUCH IF THE KERNEL OR THE PROGRAM MOVES THE DATA.

sockpacket.ethdst[0]=0xFF;
sockpacket.ethdst[1]=0xFF;
sockpacket.ethdst[2]=0xFF;
sockpacket.ethdst[3]=0xFF;
sockpacket.ethdst[4]=0xFF;
sockpacket.ethdst[5]=0xFF;
sockpacket.ptype=htons(ETH_P_BPQ);
sockpacket.len=0;

while(1){
FD_ZERO(&readfds);
FD_SET(tap,&readfds);
FD_SET(sock,&readfds);
nfds=sock;if(tap>sock)nfds=tap;
tv.tv_sec=30;
tv.tv_usec=0;
select(nfds+1,&readfds,&writefds,&exceptfds,&tv);

//PACKETS THAT ARRIVE FROM AXUDP SERVER

if(FD_ISSET(sock,&readfds)){
bytes=recv(sock,&sockpacket.payload,sizeof(sockpacket.payload),MSG_DONTWAIT);
if(bytes==0){printf("%s DISCONNECTED\n",srcbtime(0));sleep(1);udpconnect(argv[2],argv[3]);};
//if(bytes>=17){//2 7 BYTE ADDRESSES, 1 CONTROL BYTE, 2 BYTE FCS
if(bytes>=15){//2 7 BYTE ADDRESSES, 1 CONTROL BYTE, 2 BYTE FCS
//printf("%s SOCKET RECV: %ld BYTES:",srcbtime(0),bytes);for(n=0;n<bytes;n++)printf(" %02X",sockpacket.payload[n]);printf("\n");
//NOPE. DON'T CARE FOR THE FCS FOR NOW. JUST THROW IT AWAY. IT'S PROBABLY FINE (IT SHOULD BE, IT CAME OVER THE INTERNET ;)
//FIX THIS FOR RELEASE BUT FOR NOW IT KINDA WORKS. (AXIP AND AXUDP LITERALLY BEING THE ONLY 2 NON AIR LINK PROTOCOLS THAT NEED FCS ;)
sockpacket.len=htons(bytes+3);//+5=INCLUDE FCS +3= STRIP THE FCS ON BPQETHER, ALSO BELOW
//printf("%s TAP WRITE: %ld BYTES:",srcbtime(0),bytes+14);for(n=0;n<(bytes+14);n++)printf(" %02X",sockpacket.ethdst[n]);printf("\n");
if(write(tap,&sockpacket,bytes+14)<1)printf("%s ERROR WRITING TO INTERFACE: %s\n",srcbtime(0),dev);
};//BYTES>0
};//FDSET

//PACKETS THAT GO TO AXUDP SERVER

if(FD_ISSET(tap,&readfds)){
bytes=read(tap,&tappacket,sizeof(struct bpqethhdr)-2);//LEAVE 2 BYTES SPACE TO ADD THE FCS
if(bytes>=(16+15)){
if(tappacket.ptype==ntohs(ETH_P_BPQ)){
//printf("%s TAP READ: %ld BYTES",srcbtime(0),bytes);
//for(n=0;n<bytes;n++)printf(" %02X",(char*)&tappacket.ethdst+n);
//printf("\n");
fcs.fcs16=compute_crc(tappacket.payload,bytes-16);
//FIX THIS PROPERLY WITH HOST TO NETWORK BYTE ORDER!!!!!
tappacket.payload[(bytes-16)]=fcs.fcs8[0];
tappacket.payload[(bytes-16)+1]=fcs.fcs8[1];
//printf("%s SOCK FCS: %04X SEND: %ld BYTES:",srcbtime(0),fcs.fcs16,bytes-14);
//for(n=0;n<(bytes-14);n++)printf(" %02X",(char*)&tappacket.payload+n);
//printf("\n");
if(send(sock,&tappacket.payload,bytes-14,MSG_DONTWAIT)<1){printf("%s DISCONNECTED\n",srcbtime(0));sleep(1);udpconnect(argv[2],argv[3]);};
};//BPQ FRAME
};//BYTES>0
};//FDSET

};//WHILE 1
};//MAIN
