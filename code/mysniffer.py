import pyshark

def pktsniff(interface,timeout=30,display_filter='',output_file=None):
    if output_file!=None:
        output_file=output_file
    if output_file!=None:
        capture=pyshark.LiveCapture(
            interface=interface,
            display_filter=display_filter,
            output_file=output_file,
            # tshark_path='D:\\Program Files\\Wireshark\\tshark.exe'
        )
        capture.apply_on_packets(lambda pkt: ..., timeout=timeout)

if __name__=="__main__":
    output_file="%s\\..\\testsniff.pcap"%__file__
    interface='\\Device\\NPF_{0C9F3CBE-BBBB-43F8-A59B-B6650A7828C5}'
    pktsniff(interface=interface,output_file=output_file)