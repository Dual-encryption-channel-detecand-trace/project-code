from pathlib import Path
from scapy.all import *

# 读取pcap文件

# 用于存储每个源IP和目标IP对的数据包列表
def split_pcap_by_ip(pcapname,pcapdir):
    pcapfile=Path(pcapdir)/pcapname
    packets = rdpcap(str(pcapfile))
    ip_pairs = {}
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_pair = '-'.join(sorted([src_ip, dst_ip]))
            if ip_pair not in ip_pairs:
                ip_pairs[ip_pair] = []
            ip_pairs['%s'%ip_pair].append(pkt)
    filename=pcapname.split(".")[0]
    aimdir=Path(pcapdir)/filename
    if not aimdir.exists():
        aimdir.mkdir()
    for ips, pkts in ip_pairs.items():
        aimpcap=aimdir/f'{ips}.pcap'
        wrpcap(str(aimpcap), pkts)

if __name__=='__main__':
    pass