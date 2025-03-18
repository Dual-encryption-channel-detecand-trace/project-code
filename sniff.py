import os
from scapy.all import *

FilePath=__file__+"/../pcap"
PacketBlocks=[]
NewPacketBlocks=[]

linklist=[]

def ReadFromPcap():
    filelist=os.listdir(FilePath)
    for pcapfile in filelist:
        PacketBlocks.append(rdpcap(FilePath+"/"+pcapfile))
    PacketBlocks[0][3].show()

def CheckVmess(PayLoad):
    pass

# open 
def CheckPacket(packet):                                  #包处理
    packet.show()
    link=(packet[IP].src,packet[IP].dst)
    knil=(packet[IP].dst,packet[IP].src)
    if link not in linklist or knil not in linklist :
        linklist.append(link)
        NewPacketBlocks.append([packet])
    else:
        if link in linklist :
            reglink=link
        else :
            reglink=knil
        i=linklist.index(reglink)
        NewPacketBlocks[i].append(packet)

MyFliter="tcp and not (http or icmp or IPv6)"

def sniffer():
    sniff(prn=CheckPacket,store=False,filter=MyFliter,count=100,promisc=True)

# cheat 

# get allthings 

# return 

def PrintToPcap():
    i=0
    for NewBlock in NewPacketBlocks:
        wrpcap(FilePath+"/mixed%d.pcap"%i,NewBlock)
        i=i+1

if __name__=="__main__":
    sniffer()
    # ReadFromPcap()
    NewPacketBlocks.append(NewBlock)
    PrintToPcap()