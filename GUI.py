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
        self.history=scapy.plist.PacketList()
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
        self.bpf=QPlainTextEdit(self)
        self.bpfbtn=QPushButton('Sniff',self)
        self.res=QPlainTextEdit(self)
        self.resbtn=QPushButton('filter',self)

        self.sniffer=sniffer()
        self.layout()
        self.connect()
    def connect(self):
        self.table.doubleClicked.connect(self.GetInfo)
        self.sniffer.progress.connect(self.table.AddRow)
        self.btnstart.clicked.connect(self.sniffer.start)
        self.btnpause.clicked.connect(self.sniffer.pause)
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
        # QMessageBox().about(self,'test',bpf_filter)
        self.sniffer.pause()
        self.sniffer.progress.disconnect(self.table.AddRow)
        self.btnstart.clicked.disconnect(self.sniffer.start)
        self.btnpause.clicked.disconnect(self.sniffer.pause)
        self.sniffer=sniffer(bpf_filter)
        self.table.myclear()
        # self.table.doubleClicked.connect(self.GetInfo)
        self.sniffer.progress.connect(self.table.AddRow)
        self.btnstart.clicked.connect(self.sniffer.start)
        self.btnpause.clicked.connect(self.sniffer.pause)
    def resfilter(self):
        result_filter=self.res.toPlainText()
        self.table.myclear()
        self.sniffer.pause()
        after_filter=self.sniffer.history.filter(lambda x:x.haslayer(result_filter))
        self.sniffer.history=after_filter
        for i in after_filter:
            self.table.AddRow(self.sniffer.process(i))
        # self.table.make_table(self.sniffer.history)

app=QApplication([])
app.setStyle('Fusion')
win=MainWindow()

app.exec_()
