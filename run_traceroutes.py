from scapy.all import IP, TCP, RandShort, PacketList, sr, wrpcap
import json
from datetime import datetime

def traceroute(addresses, starting_ttl=5, max_ttl=30, timeout=5):
    probes = PacketList()

    for addr in addresses:
        print(f"Probing {addr}")
        packet_list = IP(dst=addr, ttl=(starting_ttl, max_ttl), id=RandShort()) / TCP()

        ans, _ = sr(packet_list, inter=0.05, multi=False, timeout=timeout, verbose=1)
        probes += ans

    return probes


with open("host_list.json") as host_file:
    host_list = json.load(host_file)

addrs = [h[1] for h in host_list]
probes = traceroute(addrs)

now = datetime.now()
timestamp = now.strftime("%Y%m%d_%H%M%S")
filename = f"captures/{timestamp}.cap"

with open(filename, 'wb') as write_file:
    wrpcap(write_file, probes)