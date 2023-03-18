from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from scapy.all import *

Ethertypes={2048:'IP',2054:'ARP',34525:'IPv6'}
ProtocolNumbers={1:'ICMP',6:'TCP',17:'UDP',58:'ICMPv6'}
PortNumbers={7:'Echo',9:'Discard',13:'Daytime',17:'Quote of the Day',20:'FTP data',21:'FTP control',22:'SSH',23:'Telnet',25:'SMTP',37:'Time',42:'Host Name',43:'Whois',53:'DNS',80:'HTTP',115:'SimpleFTP',123:'NTP',443:'HTTPS',546:'DHCPv6 Client',547:'DHCPv6 Server'}

def getEther(pkt):
    keys=['Protocol','Destination','Source','EtherType']
    begin=[0,0,48,96]
    end=[111,47,95,111]
    value=['Ethernet',pkt.dst,pkt.src,Ethertypes[pkt.type]]
    return keys,value,begin,end,Ethertypes[pkt.type]

def getIP(pkt):
    keys=['Protocol','Version','Header Length',['Differentiated Services Field','Differentiated Services Codepoint','Explicit Congestion Notification'],'Total Length','Identification',['Flags','Reserved bit','Don\'t fragment','More fragments'],'Fragment Offset','Time to Live','Protocol','Header Checksum','Source Address','Destination Address','options']
    begin=[0,0,4,[8,8,14],16,32,[48,48,49,50],51,64,72,80,96,128,160]
    end=[pkt.ihl*32,3,7,[15,13,15],31,47,[50,48,49,50],63,71,79,95,127,159,pkt.ihl*32]
    tos_bin=bin(pkt.tos)[2:]
    tos_str="0"*(8-len(tos_bin))+tos_bin
    value=['IP',pkt.version,pkt.ihl,[tos_str,tos_str[:6],tos_str[6:]],pkt.len,pkt.id,[str(pkt.flags),0,(pkt.flags.value>>1)&1,(pkt.flags.value&1)],pkt.frag,pkt.ttl,ProtocolNumbers[pkt.proto],pkt.chksum,pkt.src,pkt.dst,pkt.options]
    return keys,value,begin,end,ProtocolNumbers[pkt.proto]

def getTCP(pkt):
    keys=['Protocol','Source Port','Destination Port','Sequence Number','Acknowledgment Number','Header Length','Reserved',['Flags','Congestion Window Reduced','ECN-Echo','Urgent','Acknowledgment','Push','Reset','SYN','FIN'],'Window Size','Checksum','Urgent Pointer','options']
    begin=[0,0,16,32,64,96,100,[104,104,105,106,107,108,109,110,111],112,128,144,160]
    end=[pkt.dataofs*32,15,31,63,95,99,103,[111,104,105,106,107,108,109,110,111],127,143,159,pkt.dataofs*32]
    flags_bin=bin(pkt.flags.value)[2:]
    flags_str="0"*(8-len(flags_bin))+flags_bin
    if(pkt.sport in PortNumbers):sport=PortNumbers[pkt.sport]
    else: sport=pkt.sport
    if(pkt.dport in PortNumbers):dport=PortNumbers[pkt.dport]
    else: dport=pkt.dport
    value=['TCP',sport,dport,pkt.seq,pkt.ack,pkt.dataofs,pkt.reserved,[flags_str,flags_str[0],flags_str[1],flags_str[2],flags_str[3],flags_str[4],flags_str[5],flags_str[6],flags_str[7]],pkt.window,pkt.chksum,pkt.urgptr,pkt.options]
    return keys,value,begin,end,False

def getUDP(pkt):
    keys=['Protocol','Source Port','Destination Port','Length','Checksum']
    begin=[0,0,16,32,48]
    end=[63,15,31,47,63]
    value=['UDP',pkt.sport,pkt.dport,pkt.len,pkt.chksum]
    return keys,value,begin,end,False

class sniffer(QObject):
    progress=pyqtSignal(list)
    # finished=pyqtSignal()
    def __init__(self,filter_str=""):
        super().__init__()
        self.sniffer=AsyncSniffer(filter=filter_str,store=False,prn=(lambda x:self.callback(x)))
        self.database=scapy.plist.PacketList()
        self.history=scapy.plist.PacketList()
        self.show=(lambda pkt:True)
    def process(self,pkt):
        link=pkt[Ether]
        proto=link.type
        protostr=""
        if(proto==2048):
            internet=pkt[IP]
            proto=internet.proto
            protostr='IP'
            if(proto==6): protostr='TCP/'+protostr
            elif(proto==17): protostr='UDP/'+protostr
            elif(proto==1): protostr='ICMP/'+protostr
            else: raise "NewProtocol"
            data=[internet.src,internet.dst,protostr,internet.len]
        elif(proto==34525):
            internet=pkt[IPv6]
            proto=internet.nh
            protostr='IPv6'
            if(proto==6): protostr='TCP/'+protostr
            elif(proto==17): protostr='UDP/'+protostr
            elif(proto==58): protostr='ICMPv6/'+protostr
            else: raise "NewProtocol"
            data=[internet.src,internet.dst,protostr,internet.plen]
        elif(pkt[Ether].type==2054):
            internet=pkt[ARP]
            proto=internet.ptype
            protostr='ARP'
            if(proto==2048): protostr='IP/'+protostr
            elif(proto==34525): protostr='IPv6/'+protostr
            else: raise "NewProtocol"
            data=[internet.psrc,internet.pdst,protostr,internet.plen]
        else: raise "NewProtocol"
        data.append(pkt.summary())
        return data
    def callback(self,pkt):
        self.database.append(pkt)
        if(not self.show(pkt)):return
        self.history.append(pkt)
        try: self.progress.emit(self.process(pkt))
        except:
            print(pkt.show())
            raise RuntimeError
    def running(self):
        return self.sniffer.running
    def start(self):
        self.sniffer.start()
    def pause(self):
        if(self.sniffer.running):self.sniffer.stop()
    def filter(self):
        self.history=self.database.filter(self.show)
        for pkt in self.history:
            try: self.progress.emit(self.process(pkt))
            except:
                print(pkt.show())
                raise RuntimeError

if __name__=="__main__":
    scapy.layers.l2.Ether.getinfo=getEther
    scapy.layers.inet.IP.getinfo=getIP

    ans=sniff(count=1,filter='tcp')
    test=ans[0]
    print(test[IP].getinfo())
    print(test[IP].keys())
    # pkt=test[]
    # print(getIP(pkt))
