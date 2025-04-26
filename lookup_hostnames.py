from scapy.all import Net
from tranco import Tranco
import json

def get_tranco_hosts(count: int, start: int = 0):
    tranco_list = Tranco(cache=True, cache_dir='.tranco').list(date='2025-04-15')
    return sorted(tranco_list.list, key=tranco_list.list.get)[start:start + count]


hostnames = get_tranco_hosts(500, start=1_000)
hostnames.extend(get_tranco_hosts(500, start=10_000))
hostnames.extend(get_tranco_hosts(500, start=100_000))

ranks = list(range(1_000, 1500)) + list(range(10_000, 10500)) + list(range(100_000, 100500))

host_list = []

# Try to find address for each hostname
addresses = []
for r, h in zip(ranks, hostnames):
    for url in (h, "www." + h, "http://www." + h,"https://www." + h):
        try:
            host_list.append((r, str(Net(h))))
            break
        except OSError:
            continue

with open("host_list.json", 'w') as outfile:
    json.dump(host_list, outfile)