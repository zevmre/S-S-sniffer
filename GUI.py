from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
# from scapy.all import *
from mysniffer import *

Headers=['Source','Destination','Protocol','Length']
sniff_result=[]

class MessageBox(QMessageBox):
    def __init__():
        # show_interfaces()
        return

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
    def AddRow(self,data):
        self.insertRow(self.rowcount)
        for i in range(len(data)):
            item=QTableWidgetItem(str(data[i]))
            item.setTextAlignment(Qt.AlignHCenter)
            # item.setBackground(QColor(255,0,0))
            self.setItem(self.rowcount,i,item)
            # self.item(self.rowcount,i).setBackground(QColor(255,0,0))
        self.rowcount=self.rowcount+1
    def myclear(self):
        for i in range(self.rowcount):
            self.removeRow(0)
        self.rowcount=0

class TreeView(QTreeWidget):
    def __init__(self,parent):
        super().__init__(parent)
        self.setColumnCount(2)
        self.setHeaderLabels(['Key','Value'])
        self.rowcount=0
    def getItem(self,key,value):
        ele=QTreeWidgetItem()
        if(not isinstance(key,list)):
            ele.setText(0,key)
            ele.setText(1,str(value))
            return ele
        ele.setText(0,key[0])
        ele.setText(1,str(value[0]))
        for i in range(1,len(key)):
            ele.addChild(self.getItem(key[i],value[i]))
        return ele
    def work(self,key,value):
        self.insertTopLevelItem(self.rowcount,self.getItem(key,value))
        self.rowcount=self.rowcount+1
    def myclear(self):
        self.clear()
        self.rowcount=0

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
        self.tree=TreeView(self)

        self.sniffer=sniffer()
        self.layout()
        self.connect()
    def connect(self):
        self.table.clicked.connect(self.GetInfo)
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
        pkt=self.sniffer.history[row]
        self.detail.setPlainText(pkt.show(dump=True))
        self.info.setPlainText(pkt.summary())

        self.tree.myclear()
        keys,value,next=pkt[Ether].getinfo()
        self.tree.work(keys,value)
        if(next!='IP'):return
        keys,value,next=pkt[next].getinfo()
        self.tree.work(keys,value)
        keys,value,next=pkt[next].getinfo()
        self.tree.work(keys,value)
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

        self.tree.resize(500,1600)
        self.tree.move(1900,0)

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
app.setFont(QFont('Courier'))
scapy.layers.l2.Ether.getinfo=getEther
scapy.layers.inet.IP.getinfo=getIP
scapy.layers.inet.TCP.getinfo=getTCP
scapy.layers.inet.UDP.getinfo=getUDP
win=MainWindow()

app.exec_()
