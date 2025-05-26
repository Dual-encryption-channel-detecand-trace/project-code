from pathlib import Path
from scapy.all import *

def getdetail(pcap_file):
    pcap_file=str(pcap_file)
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    proto_stats = defaultdict(lambda: {'count': 0, 'bytes': 0})
    start_time = None
    end_time = None
    total_bytes = 0

    for pkt in packets:
        # 时间统计
        current_time = pkt.time
        start_time = min(start_time, current_time) if start_time else current_time
        end_time = max(end_time, current_time) if end_time else current_time
        
        # 协议分析
        layers = []
        layer = pkt
        while layer:
            layers.append(layer.name)
            layer = layer.payload
        
        # 更新统计
        pkt_len = len(pkt)
        total_bytes += pkt_len
        for proto in set(layers):  # 去重处理
            proto_stats[proto]['count'] += 1
            proto_stats[proto]['bytes'] += pkt_len

    # 计算结果
    duration = end_time - start_time if start_time and end_time else 0
    throughput = total_bytes / duration if duration > 0 else 0
    
    # 输出报告
    # print("PCAP分析报告（Scapy版）")
    # print("════════════════════════")
    # print(f"文件路径: {pcap_file}")
    # print(f"时间范围: {duration:.2f} 秒")
    # print(f"总数据包: {len(packets)}")
    # print(f"总流量: {total_bytes} 字节")
    # print(f"平均吞吐量: {throughput:.2f} B/s\n")
    
    # print("协议统计:")
    # print(f"{'协议':<15} {'数据包数':>10} {'流量(bytes)':>15}")
    linkdetail=[]
    detail={}
    for proto, stats in sorted(proto_stats.items(), key=lambda x: x[1]['count'], reverse=True):
        detail['proto']=proto
        detail['count']=stats['count']
        detail['bytes']=stats['bytes']
        linkdetail.append(detail.copy())
    return linkdetail.copy()

# def getdetail(file):
#     file=Path(file)

if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("使用方法: python pcap_analyzer.py <pcap文件路径>")
#         sys.exit(1)
    xxx=Path('D:\\DTDEC\\meek_1c1g_2020-05-27_04_37_07.836652.pcap')
    # analyze_pcap_scapy(xxx)