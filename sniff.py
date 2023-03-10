from scapy.all import *
from scapy.utils import wrpcap
import dpkt
import socket
ip_adr="192.168.43.241"
# snf=sniff(iface='wifi0',count=3)
snf=sniff(iface='Software Loopback Interface 1',filter='port 8001',count=10)
print(snf)
wrpcap("demo.pcap",snf)
