from scapy.all import rdpcap
import pandas as pd

def extract_features(pcap_path, label):

    packets = rdpcap(pcap_path)
    records = []

    first_packet_time = None

    for pkt in packets:
        if pkt.haslayer('TCP'):
            if first_packet_time is None:
                first_packet_time = pkt.time

            record = {
                'src_ip': pkt['IP'].src,
                'dst_ip': pkt['IP'].dst,
                'src_port': pkt['TCP'].sport,
                'dst_port': pkt['TCP'].dport,
                'length': len(pkt),
                'timestamp': pkt.time,
                'time_delta': pkt.time - first_packet_time,
                'is_syn': 1 if 'S' in pkt['TCP'].flags else 0 ,
                'is_ack': 1 if 'A' in pkt['TCP'].flags else 0 ,
                'is_fin': 1 if 'F' in pkt['TCP'].flags else 0 ,
                'is_rst': 1 if 'R' in pkt['TCP'].flags else 0 ,
                'label': label,
                'payload_size': len(pkt['TCP'].payload),
                'ttl': pkt['IP'].ttl
            }
            records.append(record)

    return pd.DataFrame(records)



pcap_dict = {
    'pcap_files/normal_traffic.pcapng': 0,
    'pcap_files/portscan.pcapng': 1,
    'pcap_files/bruteforce.pcapng': 2,
    'pcap_files/synflood.pcapng': 3,
}

dfs = []

for pcap_path, label in pcap_dict.items():
    df = extract_features(pcap_path, label)
    dfs.append(df)

dataset = pd.concat(dfs, ignore_index=True)

import os
os.makedirs('dataset', exist_ok=True)

dataset.to_csv('dataset/dataset2.csv', index=False)

print(dataset.shape)
print(dataset.head(3))
print(dataset.isnull().sum())