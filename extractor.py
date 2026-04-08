from scapy.all import rdpcap
from collections import defaultdict
import pandas as pd
import numpy as np
import os

def extract_flows(pcap_path, label):
    print(f"Reading {pcap_path}...")
    packets = rdpcap(pcap_path)
    print(f" {len(packets)} packets found")

    flows = defaultdict(list)

    for pkt in packets:
        if not pkt.haslayer('IP'):
            continue
        
        ip = pkt['IP']
        proto = ip.proto
        src = ip.src
        dst = ip.dst

        src_port, dst_port = 0, 0
        if pkt.haslayer('TCP'):
            src_port = pkt['TCP'].sport
            dst_port = pkt['TCP'].dport
        elif pkt.haslayer('UDP'):
            src_port = pkt['UDP'].sport
            dst_port = pkt['UDP'].dport


        flow_key = (src, dst, src_port, dst_port, proto)
        flows[flow_key].append(pkt)
    
    print(f" {len(flows)} flows extracted")

    records=[]
    for flow_key, pkts in flows.items():
        src, dst, src_port, dst_port, proto = flow_key

        lengths = [len(p) for p in pkts]
        times = [float(p.time) for p in pkts]
        iats = [times[i+1] - times[i] for i in range(len(times)-1)] if len(times) > 1 else [0]

        syn_count = sum(1 for p in pkts if p.haslayer('TCP') and p['TCP'].flags & 0x02)
        ack_count = sum(1 for p in pkts if p.haslayer('TCP') and p['TCP'].flags & 0x10)
        fin_count = sum(1 for p in pkts if p.haslayer('TCP') and p['TCP'].flags & 0x01)
        rst_count = sum(1 for p in pkts if p.haslayer('TCP') and p['TCP'].flags & 0x04)

        duration = times[-1] - times[0] if len(times) > 1 else 0

        record = {
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': proto,
            'duration': duration,
            'packet_count': len(pkts),
            'total_bytes': sum(lengths),
            'mean_pkt_len': np.mean(lengths),
            'std_pkt_len': np.std(lengths),
            'max_pkt_len': np.max(lengths),
            'min_pkt_len': np.min(lengths),
            'mean_iat': np.mean(iats),
            'std_iat': np.std(iats),
            'max_iat': np.max(iats),
            'min_iat': np.min(iats),
            'syn_count': syn_count,
            'ack_count': ack_count,
            'fin_count': fin_count,
            'rst_count': rst_count,
            'bytes_per_sec': sum(lengths) / duration if duration > 0 else 0,
            'pkts_per_sec': len(pkts) / duration if duration > 0 else 0,
            'label': label
        }
        records.append(record)
    
    return pd.DataFrame(records)

if __name__ == "__main__":
    pcap_files = {
        'pcap_files/normal_traffic.pcapng': 0,
        'pcap_files/portscan.pcapng': 1,
        'pcap_files/bruteforce.pcapng': 2,
        'pcap_files/synflood.pcapng': 3,
    }

    os.makedirs('dataset', exist_ok=True)

    dfs = []
    for pcap_path, label in pcap_files.items():
        df = extract_flows(pcap_path, label)
        dfs.append(df)

    dataset = pd.concat(dfs, ignore_index=True)
    dataset.to_csv('dataset/dataset.csv', index=False)

    print("\n--- Dataset Summary ---")
    print(f"Total flows: {len(dataset)}")
    print("\nClass distribution:")
    labels = {0: 'Normal', 1: 'Port Scan', 2: 'Brute Force', 3: 'DoS'}
    for label, count in dataset['label'].value_counts().sort_index().items():
        print(f"  {labels[label]}: {count} flows")
    
    print("\nNull values:")
    print(dataset.isnull().sum())
    
    print("\nSaved to dataset/dataset.csv")