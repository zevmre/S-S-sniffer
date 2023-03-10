from scapy.all import *
from scapy.utils import wrpcap
import dpkt
import socket

def sniff_callback(packet):
    packet.summary()
    # print(packet.show())

# snf=sniff(iface='wifi0',count=3)
sniff(iface='Software Loopback Interface 1',filter='port 8001',prn=sniff_callback,count=10)
# snf=sniff(iface='Software Loopback Interface 1',filter='port 8001',prn=sniff_callback,count=10)
# print(snf)
# wrpcap("demo.pcap",snf)
