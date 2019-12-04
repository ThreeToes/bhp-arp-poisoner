# arp_poison.py

A scapy based ARP cache poisoner, taken from Black Hat Python and modified. 

## Input options
* `-target`, `-t` - The machine to target
* `-gateway`, `-g` - The gateway machine to spoof
* `-packets`, `-p` - Number of packets to sniff
* `-output`, `-o` - The output file for the packet capture

## Extras
You will need to enable IPv4 forwarding, which can be done with the following
### Linux
`echo 1 > /proc/sys/net/ipv4/ip_forward`
### Mac
`sudo sysctl -w net.inet.ip.forwarding=1`