from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
# from scapy.all import *
from mysniffer import *
from math import floor

class TableView(QTableWidget):
    def __init__(self,*args):
        super().__init__(*args)
        self.setHorizontalHeaderLabels(['Source','Destination','Protocol','Length','Info'])
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.rowcount=0
        self.setColumnWidth(0,600)
        self.setColumnWidth(1,600)
        self.setColumnWidth(2,300)
        self.setColumnWidth(3,200)
        self.setColumnWidth(4,200)
        header=self.horizontalHeader()
        header.setSectionResizeMode(0,QHeaderView.Interactive)
        header.setSectionResizeMode(1,QHeaderView.Interactive)
        header.setSectionResizeMode(2,QHeaderView.Interactive)
        header.setSectionResizeMode(3,QHeaderView.Interactive)
        header.setSectionResizeMode(4,QHeaderView.Stretch)
    def AddRow(self,data):
        self.insertRow(self.rowcount)
        for i in range(len(data)):
            item=QTableWidgetItem(str(data[i]))
            item.setTextAlignment(Qt.AlignHCenter)
            # item.setBackground(QColor(255,0,0))
            self.setItem(self.rowcount,i,item)
            # self.item(self.rowcount,i).setBackground(QColor(255,0,0))
        # self.resizeRowsToContents()
        self.rowcount=self.rowcount+1
    def myclear(self):
        for i in range(self.rowcount):
            self.removeRow(0)
        self.rowcount=0

class HexTable(QTableWidget):
    def __init__(self,*args):
        super().__init__(*args)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        for i in range(16):self.setColumnWidth(i,40)
        self.setColumnWidth(16,40)
        for i in range(17,33):self.setColumnWidth(i,10)
        self.rowcount=0
        header=self.horizontalHeader()
        # header.setSectionResizeMode(16,QHeaderView.Stretch)
        header.hide()
        self.high_begin=0
        self.high_end=0
    def work(self,hexs):
        tmp=hexs.split('  ')
        self.high_begin=0
        self.high_end=-1
        hexcode,hextext=tmp[0].split(' '),tmp[1]
        for i in range(self.rowcount):self.removeRow(0)
        rownum=floor((len(hexcode)-1)/16)+1
        self.rowcount=rownum
        for i in range(rownum):self.insertRow(0)
        self.setVerticalHeaderLabels(["%0.4d"%(i*10) for i in range(rownum)])
        numi,numj=0,0
        for i in range(len(hexcode)):
            self.setItem(numi,numj,QTableWidgetItem(hexcode[i]))
            self.setItem(numi,numj+17,QTableWidgetItem(hextext[i]))
            numj=numj+1
            if(numj==16):numi,numj=numi+1,0
    def myclear(self):
        for i in range(self.rowcount):
            self.removeRow(0)
        self.rowcount=0
    def color(self,begin,end,R,G,B):
        # print(begin,end,R,G,B)
        numi,numj=floor(begin/16),(begin%16)
        for i in range(begin,end+1):
            self.item(numi,numj).setBackground(QColor(R,G,B))
            self.item(numi,numj+17).setBackground(QColor(R,G,B))
            numj=numj+1
            if(numj==16):numi,numj=numi+1,0
    def highlight(self,begin,end):
        self.color(self.high_begin,self.high_end,255,255,255)
        self.high_begin=begin
        self.high_end=end
        self.color(self.high_begin,self.high_end,22,119,179)

class TreeView(QTreeWidget):
    def __init__(self,parent):
        super().__init__(parent)
        self.setColumnCount(2)
        self.setHeaderLabels(['Key','Value'])
        self.setColumnWidth(0,600)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rowcount=0
    def getItem(self,key,value,begin,end,offset):
        ele=QTreeWidgetItem()
        if(not isinstance(key,list)):
            ele.setText(0,key)
            ele.setText(1,str(value))
            ele.begin=begin+offset
            ele.end=end+offset
            return ele
        ele.setText(0,key[0])
        ele.setText(1,str(value[0]))
        ele.begin=begin[0]+offset
        ele.end=end[0]+offset
        for i in range(1,len(key)):
            ele.addChild(self.getItem(key[i],value[i],begin[i],end[i],offset))
        return ele
    def work(self,key,value,begin,end,offset):
        self.insertTopLevelItem(self.rowcount,self.getItem(key,value,begin,end,offset))
        self.rowcount=self.rowcount+1
    def myclear(self):
        self.clear()
        self.rowcount=0
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('MySniffer')
        self.setWindowState(Qt.WindowMaximized)
        faces=str(IFACES).split('\n')
        text,ok=QInputDialog.getItem(self,'Choose an Interface',faces[0],faces[1:])
        if(ok):index=text.split('  ')[1]
        else:index=0
        bpf_filter,ok=QInputDialog.getText(self,'Input BPF filter','Would you like a BPF Filter?')

        self.sniffer=sniffer(index,bpf_filter)

        self.table=TableView(0,5,self)
        # self.detail=QPlainTextEdit(self)
        # self.info=QPlainTextEdit(self)
        # self.hexpanel=QPlainTextEdit(self)
        # self.hexpanel.setReadOnly(True)
        self.hexpanel=HexTable(0,33,self)
        self.btnstart=QPushButton('Start',self)
        self.btnpause=QPushButton('Pause',self)
        self.btnpause.setEnabled(False)
        # self.bpf=QPlainTextEdit(self)
        # self.bpfbtn=QPushButton('sniff',self)
        self.res=QPlainTextEdit(self)
        self.resbtn=QPushButton('Filter',self)
        self.tree=TreeView(self)

        btns=QSplitter(Qt.Horizontal)
        btns.addWidget(self.btnstart)
        btns.addWidget(self.btnpause)
        btns.addWidget(self.res)
        btns.addWidget(self.resbtn)
        btns.setStretchFactor(2,1)
        btns.setSizes([200,200,200,200])

        hexs=QSplitter(Qt.Horizontal)
        hexs.addWidget(self.tree)
        hexs.addWidget(self.hexpanel)
        hexs.setStretchFactor(0,1)
        hexs.setStretchFactor(1,1)

        tops=QSplitter(Qt.Vertical)
        tops.addWidget(btns)
        tops.addWidget(self.table)
        # tops.addWidget(self.info)
        tops.addWidget(hexs)
        tops.setStretchFactor(1,2)
        tops.setStretchFactor(2,1)
        # tops.setStretchFactor(3,1)
        tops.setSizes([100,200,200,200])

        self.setCentralWidget(tops)
        self.show()

        # self.layout()
        self.connect()
    def connect(self):
        self.table.clicked.connect(self.GetInfo)
        self.sniffer.progress.connect(self.table.AddRow)
        self.btnstart.clicked.connect(self.sniffer.start)
        self.btnstart.clicked.connect(lambda:self.btnstart.setEnabled(False))
        self.btnstart.clicked.connect(lambda:self.btnpause.setEnabled(True))
        # self.btnstart.clicked.connect(lambda:self.bpfbtn.setEnabled(False))
        self.btnpause.clicked.connect(self.sniffer.pause)
        self.btnpause.clicked.connect(lambda:self.btnpause.setEnabled(False))
        self.btnpause.clicked.connect(lambda:self.btnstart.setEnabled(True))
        # self.bpfbtn.clicked.connect(self.startover)
        self.resbtn.clicked.connect(self.resfilter)
        self.tree.clicked.connect(self.matchhex)
    def matchhex(self,index):
        item=self.tree.currentItem()
        if(item):self.hexpanel.highlight(floor(item.begin/8),floor(item.end/8))
    def GetInfo(self,index):
        row=index.row()
        pkt=self.sniffer.history[row]
        # self.detail.setPlainText(pkt.show(dump=True))
        # self.info.setPlainText(pkt.summary())
        # self.hexpanel.setPlainText(hexdump(pkt,dump=True))
        self.hexpanel.work(hexstr(pkt))

        self.tree.myclear()
        if(pkt.haslayer('Ether')):
            keys,value,begin,end,next=pkt[Ether].getinfo()
        elif(pkt.haslayer('Loopback')):
            keys,value,begin,end,next=pkt[Loopback].getinfo()
        ether_end=end[0]+1
        self.tree.work(keys,value,begin,end,0)
        if(not 'ARP' in next):
            keys,value,begin,end,next=pkt[next].getinfo()
            internet_end=end[0]+ether_end+1
            self.tree.work(keys,value,begin,end,ether_end)
            if(not 'ICMP' in next):
                keys,value,begin,end,next=pkt[next].getinfo()
                transport_end=end[0]+internet_end+1
                self.tree.work(keys,value,begin,end,internet_end)
    def filter_func(self):
        filter_str=self.res.toPlainText()
        internet_protocols=['IP','IPv6','ARP']
        transport_protocols=['TCP','UDP','ICMP','ICMPv6']
        elems=filter_str.split(' and ')
        func_str='True'
        # print(elems)
        for ele in elems:
            # print(ele)
            if(not ele):continue
            func_str=func_str+" and"
            # ele=ele.upper()
            if ('not' in ele):
                ele=ele[4:]
                func_str=func_str+" not"
            # for i in internet_protocols:
            #     if(i in ele):
            #         internet=ele
            #         func_str=func_str+" pkt.haslayer("+ele+")"
            if(ele in internet_protocols):
                internet=ele
                func_str=func_str+" pkt.haslayer("+ele+")"
            elif(ele in transport_protocols):
                transport=ele
                func_str=func_str+" pkt.haslayer("+ele+")"
            elif('port' in ele):
                port_num=ele.split(" ")[-1]
                func_str=func_str+" (pkt["+transport+"].sport=="+port_num+" or pkt["+transport+"].dport=="+port_num+")"
        return (lambda pkt:eval(func_str))
    def resfilter(self):
        if(self.sniffer.running()):
            flag=True
            self.sniffer.pause()
        else:flag=False
        self.table.myclear()
        self.sniffer.show=self.filter_func()
        self.sniffer.filter()
        if(flag):self.sniffer.start()

app=QApplication([])
app.setStyle('Fusion')
app.setFont(QFont('Courier'))
scapy.layers.l2.Loopback.getinfo=getLoop
scapy.layers.l2.Ether.getinfo=getEther
scapy.layers.inet.IP.getinfo=getIP
scapy.layers.inet6.IPv6.getinfo=getIPv6
scapy.layers.inet.TCP.getinfo=getTCP
scapy.layers.inet.UDP.getinfo=getUDP
win=MainWindow()

app.exec_()
