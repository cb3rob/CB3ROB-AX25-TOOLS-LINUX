#!/bin/sh
gcc -Wall -O3 -o cb3rob-ax25-bbs cb3rob-ax25-bbs.c
gcc -Wall -O3 -o cb3rob-ax25-bridge cb3rob-ax25-bridge.c
gcc -Wall -O3 -o cb3rob-kiss-tcp-attach cb3rob-kiss-tcp-attach.c -lutil
gcc -Wall -O3 -o cb3rob-kiss-tcp-multiplexer cb3rob-kiss-tcp-multiplexer.c
