## CB3ROB-AX25-TOOLS-LINUX 2021-12-18T10:02:29Z (SATURDAY)
### cb3rob-kiss-tcp-attach.c
creates ax0 interface and connects to KISS-TCP TNC, soundmodem (direwolf), or multiplexer server
### cb3rob-ax25-sctp-attach.c
creates bpq0 interface and connects to AX25-SCTP TNC, or multiplexer server
### cb3rob-kiss-tcp-multiplexer.c
KISS-TCP server pretending to be a transparent radio network with KISS-TCP TNCs to clients
### cb3rob-ax25-sctp-multiplexer.c
AX25-over-SCTP server pretending to be a transparent radio network with AX25-SCTP TNCs to clients
### cb3rob-ax25-bridge.c
AX.25 bridge software to link all AX.25 interfaces on a linux box together and link them to one or more BPQ ethernet segments transparently (or just no BPQ and link for example 2 KISS ports together)... you know... to simply have AX.25 terminal software on your laptop with wifi over BPQ... and your tranceivers somewhere in the actual antenna masts. and so everything can just happily and directly talk to each other over ethernet, mainly. but it'll also bridge literally any other AX.25 interface type it finds. no digipeaters in the path. no nothing. as if it was all the same single network. kill -HUP to force re-read of interface list if new ones were added. removals are automatic.
### cb3rob-ax25-switch.c
AX.25 software switch, same functionality as cb3rob-ax25-bridge, but only sends the traffic to callsigns from which it has recently seen traffic on a source interface, to that specific interface. not flooding other networks with your internal traffic.
This enables you to have gigabits of AX.25 traffic on your LAN and WAN and only 'leak' some SABM's and beacons to the narrowband radio links or peered other networks while still allowing for fully transparent connections from and to everything on all networks
### cb3rob-ax25-bbs.c
standalone AX.25 BBS
### cb3rob-ax25-getty.c
'telnetd' for AX.25 - runs /bin/login in a pty which gives a shell after logging in
### cb3rob-axudp-attach.c
creates bpq0 interface and connects to AXUDP server, or connects networks back to back without a server
#
#### None of this needs that old broken ax25lib crap or /etc/ax25/ports. just plain old linux.
#### Also note that the KISS-TCP stuff exclusively uses channel '0' as the KISS protocol documentation is not clear on how to handle channel 'C' in regards to FEND escapes (whoopsie - guess nobody ever sold a tnc with all 16 HDLC interfaces.. ;). it would either result in 2 's in a row or not be 'the second byte' yet the documentation proclaims to support 16 channels... don't believe in any actual need for 'channels' anyway. just do the switching/routing at layer 2/3 ;)
