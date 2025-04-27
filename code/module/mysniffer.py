import pyshark
from pathlib import Path
from datetime import datetime
import subprocess

def chooseinterface():
    try:
        # 调用 tshark 命令列出所有接口
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        interfaces = []
        print("可用接口:")
        for line in result.stdout.splitlines():
            if "." in line:
                print(line)
                parts = line.split(". ", 1)
                iface = parts[1].split(" (")[0].strip()
                interfaces.append((iface))
        print("输入接口序号：")
        id=int(input())
        return interfaces[id-1]          #with no check
        
    except subprocess.CalledProcessError as e:
        return []

# 使用示例

def pktsniff(interface,timeout=30,display_filter='',output_file=None):
    if output_file!=None:
        output_file=output_file
    if output_file!=None:
        capture=pyshark.LiveCapture(
            interface=interface,
            display_filter=display_filter,
            output_file=str(output_file),
        )
        capture.apply_on_packets(lambda pkt: ..., timeout=timeout)

pcapdir="D:\\pcap"
detectpcapdir="detect"
pcapdir=Path(pcapdir)
detectpcapdir = pcapdir/Path(detectpcapdir)

if __name__=="__main__":
    current_time = datetime.now()
    output_file=current_time.strftime("%Y_%m_%d_%H_%M_%S.pcap")            # %d在这里才是正确的
    # output_file=current_time.strftime("%Y_%m_%D_%H_%M_%S.pcap")
    output_file=detectpcapdir/Path(output_file)
    interface=chooseinterface()
    pktsniff(interface=interface,output_file=output_file)