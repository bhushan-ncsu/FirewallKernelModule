This directory contains the source code for the kernel module that provides the following rules:
   Rule 1: Drops all ICMP echo request messages sent to nodes other than the WebServer from any nodes outside the local network. The ICMP echo reply messages are not dropped to support the nodes in the LAN to ping the nodes outside the LAN.
   Rule 2: Drop all SSH packets from any nodes outside the LAN.
   Rule 3: Drop all TCP Port 80 packets to nodes other than the Web-Server from any node outside the LAN.

compile the kernel module:
    make

insert the kernel module: 
    sudo insmod firewall.ko

remove the kernel module:
    sudo rmmod firewall

The kernel module is develeped on and tested for the following linux distribution:
    Linux ubuntu 3.13.0-68-generic #111-Ubuntu SMP Fri Nov 6 18:17:06 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
