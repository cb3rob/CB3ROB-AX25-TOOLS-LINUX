## CB3ROB-AX25-TOOLS-LINUX 2021-12-11T21:16:49Z (SATURDAY)
#
### cb3rob-kiss-tcp-attach.c
links ax0 interface to KISS-TCP TNC, soundmodem (direwolf), or multiplexer server
### cb3rob-kiss-tcp-multiplexer.c
KISS-TCP server pretending to be a transparent radio network with KISS-TCP TNCs to clients
### cb3rob-ax25-bridge.c
AX.25 Bridge software to link all AX.25 interfaces on a linux box together and link them to one or more bpq ethernet segments transparently (or just no BPQ and link for example 2 KISS ports together)... you know... to simply have AX.25 terminal software on your laptop with wifi over bpq... and your tranceivers somewhere in the actual antenna masts. and so everything can just happily and directly talk to each other over ethernet, mainly. but it'll also bridge literally any other AX.25 interface type it finds. no digipeaters in the path. no nothing. as if it was all the same single network. kill -HUP to force re-read of interface list if new ones were added. removals are automatic.
### cb3rob-ax25-bbs.c
'telnetd' part of the BBS
### cb3rob-ax25-bbs-login.c
client handler shell of the BBS
### cb3rob-ax25-getty.c
'telnetd' for AX.25 - runs /bin/login in a pty which gives a shell after logging in
### cb3rob-axudp-attach.c
links bpq0 interface to AXUDP server (or back to back use)
#
#### None of this needs that old broken ax25lib crap or /etc/ax25/ports. just plain old linux.
#### Also note that the KISS-TCP stuff exclusively uses channel '0' as the KISS protocol documentation is not clear on how to handle channel 'C' in regards to FEND escapes (whoopsie - guess nobody ever sold a tnc with all 16 HDLC interfaces.. ;). it would either result in 2 's in a row or not be 'the second byte' yet the documentation proclaims to support 16 channels... don't believe in any actual need for 'channels' anyway. just do the switching/routing at layer 2/3 ;)
