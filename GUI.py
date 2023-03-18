from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
# from scapy.all import *
from mysniffer import *
from math import floor

class MessageBox(QMessageBox):
    def __init__():
        # show_interfaces()
        return

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
        # 16+...+16=33
        super().__init__(*args)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        for i in range(16):self.setColumnWidth(i,40)
        self.setColumnWidth(16,40)
        for i in range(17,33):self.setColumnWidth(i,10)
        self.rowcount=0
        header=self.horizontalHeader()
        # header.setSectionResizeMode(16,QHeaderView.Stretch)
        header.hide()
    def work(self,hexs):
        tmp=hexs.split('  ')
        hexcode,hextext=tmp[0].split(' '),tmp[1]
        for i in range(self.rowcount):self.removeRow(0)
        rownum=floor((len(hexcode)-1)/16)+1
        self.rowcount=rownum
        for i in range(rownum):self.insertRow(0)
        self.setVerticalHeaderLabels(["%0.4d"%(i*10) for i in range(rownum)])
        numi,numj=0,0
        for i in range(len(hexcode)):
            self.setItem(numi,numj,QTableWidgetItem(hexcode[i]))
            numj=numj+1
            if(numj==16):numi,numj=numi+1,0
        numi,numj=0,17
        for i in range(len(hextext)):
            self.setItem(numi,numj,QTableWidgetItem(hextext[i]))
            numj=numj+1
            if(numj==33):numi,numj=numi+1,17
    def myclear(self):
        for i in range(self.rowcount):
            self.removeRow(0)
        self.rowcount=0

class TreeView(QTreeWidget):
    def __init__(self,parent):
        super().__init__(parent)
        self.setColumnCount(2)
        self.setHeaderLabels(['Key','Value'])
        self.setColumnWidth(0,600)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
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
        self.first_flag=True

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
        self.resbtn=QPushButton('Sniff',self)
        self.tree=TreeView(self)

        self.sniffer=sniffer()

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
        self.btnstart.clicked.connect(self.startover)
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
        print(index.row(),index.column())
        print(dir(index))
        print(index.siblingAtRow())
        print(item.text(0),item.text(1))
        print(dir(item))
    def GetInfo(self,index):
        row=index.row()
        pkt=self.sniffer.history[row]
        # self.detail.setPlainText(pkt.show(dump=True))
        # self.info.setPlainText(pkt.summary())
        # self.hexpanel.setPlainText(hexdump(pkt,dump=True))
        self.hexpanel.work(hexstr(pkt))

        self.tree.myclear()
        keys,value,next=pkt[Ether].getinfo()
        self.tree.work(keys,value)
        if(next!='IP'):return
        keys,value,next=pkt[next].getinfo()
        self.tree.work(keys,value)
        keys,value,next=pkt[next].getinfo()
        self.tree.work(keys,value)
    def startover(self):
        if(self.first_flag):
            self.resbtn.setText('Filter')
            self.first_flag=False
        self.sniffer.start()
    def filter_func(self):
        filter_str=self.res.toPlainText()
        internet_protocols=['IP','IPv6','ARP']
        transport_protocols=['TCP','UDP','ICMP','ICMPv6']
        elems=filter_str.split(' and ')
        func_str='True'
        for ele in elems:
            func_str=func_str+" and"
            # ele=ele.upper()
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
        if(self.first_flag):
            bpf_filter=self.res.toPlainText()
            self.sniffer.progress.disconnect(self.table.AddRow)
            self.btnstart.clicked.disconnect(self.startover)
            self.btnpause.clicked.disconnect(self.sniffer.pause)
            self.sniffer=sniffer(bpf_filter)
            self.sniffer.progress.connect(self.table.AddRow)
            self.btnstart.clicked.connect(self.startover)
            self.btnpause.clicked.connect(self.sniffer.pause)
            return
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
