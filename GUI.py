from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from scapy.all import *
from scapy.utils import wrpcap
import dpkt
import socket

Headers=['Source','Destination','Protocol','Length']
sniff_result=[]

class TableView(QTableWidget):
    def __init__(self,*args):
        super().__init__(*args)
        self.setHorizontalHeaderLabels(Headers)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setColumnWidth(0,400)
        self.setColumnWidth(1,400)
        self.setColumnWidth(2,200)
        self.setColumnWidth(3,100)
        self.rowcount=0
        # self.SignalConnect()
    def AddRow(self,data):
        self.insertRow(self.rowcount)
        for i in range(len(data)):
            self.setItem(self.rowcount,i,QTableWidgetItem(str(data[i])))
        self.rowcount=self.rowcount+1
    def myclear(self):
        for i in range(self.rowcount):
            self.removeRow(0)
        self.rowcount=0

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

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('MySniffer')
        self.setWindowState(Qt.WindowMaximized)

        self.table=TableView(0,4,self)
        self.detail=QPlainTextEdit(self)
        self.info=QPlainTextEdit(self)
        self.btnstart=QPushButton('Start',self)
        self.btnpause=QPushButton('Pause',self)
        self.btnpause.setEnabled(False)
        self.bpf=QPlainTextEdit(self)
        self.bpfbtn=QPushButton('sniff',self)
        self.res=QPlainTextEdit(self)
        self.resbtn=QPushButton('filter',self)

        self.sniffer=sniffer()
        self.layout()
        self.connect()
    def connect(self):
        self.table.doubleClicked.connect(self.GetInfo)
        self.sniffer.progress.connect(self.table.AddRow)
        self.btnstart.clicked.connect(self.sniffer.start)
        self.btnstart.clicked.connect(lambda:self.btnstart.setEnabled(False))
        self.btnstart.clicked.connect(lambda:self.btnpause.setEnabled(True))
        self.btnstart.clicked.connect(lambda:self.bpfbtn.setEnabled(False))
        self.btnpause.clicked.connect(self.sniffer.pause)
        self.btnpause.clicked.connect(lambda:self.btnpause.setEnabled(False))
        self.btnpause.clicked.connect(lambda:self.btnstart.setEnabled(True))
        self.bpfbtn.clicked.connect(self.startover)
        self.resbtn.clicked.connect(self.resfilter)
    def GetInfo(self,index):
        row=index.row()
        self.detail.setPlainText(self.sniffer.history[row].show(dump=True))
        self.info.setPlainText(self.sniffer.history[row].summary())
    def layout(self):
        self.table.resize(1200,1500)
        self.table.move(0,100)

        self.detail.setReadOnly(True)
        self.detail.resize(700,1600)
        self.detail.move(1200,0)

        self.info.setReadOnly(True)
        self.info.resize(1900,100)
        self.info.move(0,1600)

        self.btnstart.resize(200,100)
        self.btnstart.move(0,0)

        self.btnpause.resize(200,100)
        self.btnpause.move(200,0)

        self.bpf.resize(700,50)
        self.bpf.move(400,0)
        self.bpfbtn.resize(100,50)
        self.bpfbtn.move(1100,0)

        self.res.resize(700,50)
        self.res.move(400,50)
        self.resbtn.resize(100,50)
        self.resbtn.move(1100,50)

        self.show()
    def startover(self):
        bpf_filter=self.bpf.toPlainText()
        self.sniffer.progress.disconnect(self.table.AddRow)
        self.btnstart.clicked.disconnect(self.sniffer.start)
        self.btnpause.clicked.disconnect(self.sniffer.pause)
        self.sniffer=sniffer(bpf_filter)
        self.sniffer.progress.connect(self.table.AddRow)
        self.btnstart.clicked.connect(self.sniffer.start)
        self.btnpause.clicked.connect(self.sniffer.pause)
    def filter_func(self):
        filter_str=self.res.toPlainText()
        internet_protocols=['IP','IPv6','ARP']
        transport_protocols=['TCP','UDP','ICMP','ICMPv6']
        elems=filter_str.split(' and ')
        func_str='True'
        for ele in elems:
            func_str=func_str+" and"
            ele=ele.upper()
            if ('not' in ele):
                ele=ele[4:]
                func_str=func_str+" not"
            if(ele in internet_protocols):
                internet=ele
                func_str=func_str+" pkt.haslayer("+ele+")"
            elif(ele in transport_protocols):
                transport=ele
                func_str=func_str+" pkt.haslayer("+ele+")"
            else:
                port_num=ele.split(" ")[-1]
                func_str=func_str+" (pkt["+transport+"].sport=="+port_num+" or pkt["+transport+"].dport=="+port_num+")"
        return (lambda pkt:eval(func_str))
    def resfilter(self):
        self.sniffer.pause()
        self.table.myclear()
        self.sniffer.show=self.filter_func()
        self.sniffer.filter()

app=QApplication([])
app.setStyle('Fusion')
win=MainWindow()

app.exec_()
