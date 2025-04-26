from scapy.all import IP, TCP, ICMP, IPerror, TCPerror, Net, RandShort, PacketList, sr, wrpcap, rdpcap
from tranco import Tranco
import geoip2.database
from geoip2.errors import AddressNotFoundError
import numpy as np
import pandas as pd
import os
import matplotlib.pyplot as plt


INITIAL_PROBE_FNAME = "100K_to_101K_initial.cap"
FOLLOWUP_FNAME = "100K_to_101K_followup.cap"


HEADER_STRUCTURE = [
    ("IP_VER", 4),
    ("IHL", 4),
    ("DSCP", 6),
    ("ECN", 2),
    ("IP_LEN", 16),
    ("IP_ID", 16),
    ("FLAGS", 3),
    ("FRG_OFF", 13),
    ("TTL", 8),
    ("PROT", 8),
    ("HDR_CKSM", 8),
    ("SADDR", 32),
    ("DADDR", 32),
    ("SPORT", 16),
    ("DPORT", 16),
    ("SQN", 32),
    ("ACKN", 32),
    ("DOFF", 4),
    ("RES", 4),
    ("CWR", 1),
    ("ECE", 1),
    ("URG", 1),
    ("ACK", 1),
    ("PSH", 1),
    ("RST", 1),
    ("SYN", 1),
    ("FIN", 1),
    ("WNDW", 16),
    ("CKSM", 16),
    ("URG_PTR", 16),
]


def traceroute(addresses, starting_ttl=5, max_ttl=30, timeout=5):
    probes = PacketList()

    for addr in addresses:
        print(f"Probing {addr}")
        packet_list = IP(dst=addr, ttl=(starting_ttl, max_ttl), id=RandShort()) / TCP()
        print(packet_list)

        ans, _ = sr(packet_list, inter=0.05, multi=False, timeout=timeout, verbose=1)
        probes += ans

    return probes
    

def analyze_discovery_probes(sent_packets, recieved_packets):
    reply_length_by_IP = {}

    ip_list = []
    ttl_list = []
    hostname_list = []
    reply_length_list = []

    for snd, rcv in zip(sent_packets, recieved_packets):
        reply_len = len(rcv[TCPerror])

        if rcv.src in reply_length_by_IP.keys() and reply_length_by_IP[rcv.src] != reply_len:
            print(f"IP {rcv.src} has multiple different reply lengths")
            reply_length_by_IP[rcv.src] = None
        else:
            reply_length_by_IP[rcv.src] = reply_len

            ttl_list.append(snd.ttl)
            ip_list.append(rcv.src)
            hostname_list.append(snd.dst)
            reply_length_list.append(reply_len)


    probe_df = pd.DataFrame({"ip": ip_list, "ttl": ttl_list, "hostname": hostname_list, "reply_len": reply_length_list})

    print("\nAnalyzing probes")
    print(f"Total responsive probes: {len(probe_df)}")
    print(f"Unique IPs: {np.unique(probe_df["ip"]).size}")
    print(f"Destination count: {probe_df["hostname"].nunique()}")

    print("\nReply length frequencies")
    print(probe_df.groupby("reply_len").nunique())

    # probe_df[["ip", "ttl", "reply_len"]].groupby(["ttl", "reply_len"]).nunique().unstack().plot(kind="bar", stacked=True,
    #                                                                                             title="Unique IPs grouped by reply length",
    #                                                                                             xlabel="Initial TTL", ylabel="Count of Unique IPs")
    # plt.legend(np.unique(probe_df["reply_len"]), title="Reply Length")
    # for container in plt.gca().containers:
    #     plt.bar_label(container, label_type="center", fmt=lambda x: f'{x:.0f}' if x > 0 else '')
    # 
    # plt.show()

    responsive_hosts = probe_df[probe_df["reply_len"] >= 20]
    # print(f"Responsive Hosts:\n{responsive_hosts}")
    last_hop_indicies = responsive_hosts.groupby("hostname")["ttl"].idxmax()
    # print(f"Last Hop Indicies:\n{last_hop_indicies}")
    last_hop_hosts = responsive_hosts.loc[last_hop_indicies]
    last_hop_hosts.drop_duplicates(subset='ip')

    with open("last_hop_hosts.csv", 'w') as out_file:
        out_file.write(last_hop_hosts.to_csv(index=False))


def get_tranco_hosts(count: int, start: int = 0):
    tranco_list = Tranco(cache=True, cache_dir='.tranco').list(date='2025-04-15')
    return sorted(tranco_list.list, key=tranco_list.list.get)[start:start + count]


def probe_network_routes():
    with open("last_hop_hosts.csv", 'r') as csv_file:
        hosts_df = pd.read_csv(csv_file)

    probes = []
    for _, row in hosts_df.iterrows():
        probes.append(IP(
            dst=row["hostname"],
            ttl=row["ttl"],
            id=RandShort()) / \
        TCP(
            flags=0x2  # SYN
        ))

    print("\nSending route test probes")
    matched_probes, _ = sr(probes, inter=0.05, multi=False, verbose=1, timeout=10)

    filtered_probes = matched_probes.filter(lambda _, rcv: isinstance(rcv.payload, ICMP) and rcv[ICMP].type == 11)

    # Save probes for future analysis
    with open(FOLLOWUP_FNAME, 'wb') as write_file:
        wrpcap(write_file, filtered_probes)


def analyze_route_probes(packets):
    sent_packets = packets.filter(lambda p: isinstance(p.payload, TCP))
    recieved_packets = packets.filter(lambda p: isinstance(p.payload, ICMP))

    byte_diff_counts = np.zeros(len(sent_packets[0]))
    section_diff_counts = np.zeros(len(HEADER_STRUCTURE))
    cmp_count = 0


    for snd, rcv in zip(sent_packets, recieved_packets):

        snd_bytes = bytes(snd)
        rcv_bytes = bytes(rcv[IPerror])
        snd_bitstring = bin(int.from_bytes(snd_bytes))[2:]
        rcv_bistring = bin(int.from_bytes(rcv_bytes))[2:]

        if len(rcv_bytes) < len(snd_bytes):
            print("Reply too short, skipping...")
            continue
        rcv_bytes = rcv_bytes[:len(snd_bytes)]

        for i in range(len(byte_diff_counts)):
            byte_diff_counts[i] += int(snd_bytes[i] != rcv_bytes[i])

        bit_idx = 0
        nams = []
        for sec_id, (sec_name, sec_len) in enumerate(HEADER_STRUCTURE):
            section_diff_counts[sec_id] += int(snd_bitstring[bit_idx:bit_idx+sec_len] != rcv_bistring[bit_idx:bit_idx+sec_len])
            bit_idx += sec_len
            nams.append(sec_name)
        
        cmp_count += 1
    
    byte_diff_rates = byte_diff_counts / cmp_count
    section_diff_rates = section_diff_counts / cmp_count

    plt.bar(nams, section_diff_rates)
    plt.title("Change rate by header section")
    plt.yscale('log')
    plt.xticks(rotation=45, ha='right')
    plt.show()
    
    # Print diff rates
    print("\nFrequency of byte changes (per 100):")
    b = 0
    while b < len(byte_diff_rates):
        print(f"{b:02d} | " + ' '.join(f"{int(n * 100):3d}" for n in byte_diff_rates[b:b+4]))
        b += 4

    print("\nFrequency of section changes")
    for i in range(len(HEADER_STRUCTURE)):
        print(f"{HEADER_STRUCTURE[i][0]}: {section_diff_rates[i]:02f}")

    # Plot router locations
    locations = []
    with geoip2.database.Reader('GeoLite2-City_20250415/GeoLite2-City.mmdb') as geoip_reader:

        for snd, rcv in zip(sent_packets, recieved_packets):
            try:
                geoip_lookup = geoip_reader.city(rcv[IP].src)
                locations.append((geoip_lookup.location.longitude, geoip_lookup.location.latitude))
            except AddressNotFoundError:
                locations.append(None)

    from mpl_toolkits.basemap import Basemap

    basemap = Basemap(projection='cyl',llcrnrlat=-90,urcrnrlat=90,\
            llcrnrlon=-180,urcrnrlon=180,resolution='c')
    basemap.fillcontinents(color='lightgray',lake_color='white')
    # basemap.drawcoastlines()
    
    markers = [basemap(*l) for l in locations if l is not None and None not in l]
    
    # Combine nearby markers
    combined_markers = []
    for m in markers:
        for cm in combined_markers:
            if (m[0] - cm[0]) ** 2 + (m[1] - cm[1]) ** 2 < 1:
                cm[0] = (cm[0] * cm[2] + m[0]) / (cm[2] + 1)
                cm[1] = (cm[1] * cm[2] + m[1]) / (cm[2] + 1)
                cm[2] += 1
                break
        combined_markers.append([m[0], m[1], 1])

    plt.scatter(*zip(*[(cm[0], cm[1], 3 * cm[2]) for cm in combined_markers]), c='r')

    plt.title("Locations of Last-Hop Routers")
    plt.show()


if __name__ == "__main__":
    try:
        # Load saved probes
        with open(INITIAL_PROBE_FNAME, 'rb') as read_file:
            filtered_probes = rdpcap(read_file)

        sent_packets = filtered_probes.filter(lambda p: isinstance(p.payload, TCP))
        recieved_packets = filtered_probes.filter(lambda p: isinstance(p.payload, ICMP))

    except FileNotFoundError:
        # Run probe
        hostnames = get_tranco_hosts(1000, start=100_000)
        
        # Try to find address for each hostname
        addresses = []
        for h in hostnames:
            for url in (h, "www." + h, "http://www." + h):
                try:
                    addresses.append(Net(h))
                    break
                except OSError:
                    continue

        print(f"Probing {len(addresses)} hosts")
        probes = traceroute(addresses)
        
        filtered_probes = probes.filter(lambda _, rcv: isinstance(rcv.payload, ICMP) and rcv[ICMP].type == 11)

        # Save probes for future analysis
        with open(INITIAL_PROBE_FNAME, 'wb') as write_file:
            wrpcap(write_file, filtered_probes)

        sent_packets, recieved_packets = zip(*filtered_probes)

    analyze_discovery_probes(sent_packets, recieved_packets)

    # Test routes for meddling
    if not os.path.exists(FOLLOWUP_FNAME):
        probe_network_routes()
    
    with open(FOLLOWUP_FNAME, 'rb') as read_file:
        route_test_packets = rdpcap(read_file)

    analyze_route_probes(route_test_packets)
    
