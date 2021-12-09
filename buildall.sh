#!/bin/sh
gcc -Wall -O3 -o cb3rob-ax25-bbs cb3rob-ax25-bbs.c -lutil
gcc -Wall -O3 -o cb3rob-ax25-bridge cb3rob-ax25-bridge.c
gcc -Wall -O3 -o cb3rob-ax25-getty cb3rob-ax25-getty.c -lutil
gcc -Wall -O3 -o cb3rob-axudp-attach cb3rob-axudp-attach.c
gcc -Wall -O3 -o cb3rob-kiss-tcp-attach cb3rob-kiss-tcp-attach.c -lutil
gcc -Wall -O3 -o cb3rob-kiss-tcp-multiplexer cb3rob-kiss-tcp-multiplexer.c
strip cb3rob-ax25-bbs
strip cb3rob-ax25-bridge
strip cb3rob-ax25-getty
strip cb3rob-axudp-attach
strip cb3rob-kiss-tcp-attach
strip cb3rob-kiss-tcp-multiplexer
chown root.root cb3rob-ax25-bbs
chown root.root cb3rob-ax25-bridge
chown root.root cb3rob-ax25-getty
chown root.root cb3rob-axudp-attach
chown root.root cb3rob-kiss-tcp-attach
chown root.root cb3rob-kiss-tcp-multiplexer
chmod 710 cb3rob-ax25-bbs
chmod 710 cb3rob-ax25-bridge
chmod 710 cb3rob-ax25-getty
chmod 710 cb3rob-axudp-attach
chmod 710 cb3rob-kiss-tcp-attach
chmod 710 cb3rob-kiss-tcp-multiplexer
killall -9 cb3rob-ax25-bbs
killall -9 cb3rob-ax25-bridge
killall -9 cb3rob-ax25-getty
killall -9 cb3rob-axudp-attach
killall -9 cb3rob-kiss-tcp-attach
killall -9 cb3rob-kiss-tcp-multiplexer
cp -v cb3rob-ax25-bbs cb3rob-ax25-bridge cb3rob-ax25-getty cb3rob-axudp-attach cb3rob-kiss-tcp-attach cb3rob-kiss-tcp-multiplexer /usr/sbin

