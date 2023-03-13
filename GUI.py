from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from scapy.all import *
from scapy.utils import wrpcap
import dpkt
import socket

Headers=['Source','Destination','Protocol','Length']
sniff_result=[]
class TableItem(QPushButton):
    def __init__(self,massage):
        super().__init__(self,massage)
        self.clicked.connect(self.click)
    def click():
        QMessage.about()

class TableView(QTableWidget):
    def __init__(self,*args):
        super().__init__(*args)
        self.setHorizontalHeaderLabels(Headers)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.resize(1200,1500)
        self.setColumnWidth(0,450)
        self.setColumnWidth(1,450)
        self.setColumnWidth(2,100)
        self.setColumnWidth(3,100)
    def AddRow(self,data):
        row_num=self.rowCount()
        self.insertRow(row_num)
        for i in range(len(data)):
            self.setItem(row_num,i,QTableWidgetItem(str(data[i])))
    def GetInfo(self,index):
        global sniff_result
        row=index.row()
        QMessageBox.about(self,"test",sniff_result[row].show(dump=True))

    def work(self):
        self.thread=QThread()
        self.worker=sniff_data()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.progress.connect(self.AddRow)
        self.doubleClicked.connect(self.GetInfo)
        self.thread.start()

class sniff_data(QObject):
    progress=pyqtSignal(list)
    finished=pyqtSignal()
    def __init__(self):
        super().__init__()
    def callback(self,pkt):
        global sniff_result
        sniff_result.append(pkt)
        try:
            link=pkt[Ether]
            proto=link.type
            protostr=""
            pktlen=0
            if(proto==2048):
                internet=pkt[IP]
                proto=internet.proto
                protostr='IP'
                if(proto==6):
                    protostr='TCP/'+protostr
                elif(proto==17):
                    protostr='UDP/'+protostr
                data=[internet.src,internet.dst,protostr,internet.len]
            elif(proto==34525):
                internet=pkt[IPv6]
                proto=internet.nh
                protostr='IPv6'
                if(proto==6):
                    protostr='TCP/'+protostr
                elif(proto==17):
                    protostr='UDP/'+protostr
                data=[internet.src,internet.dst,protostr,internet.plen]
            elif(pkt[Ether].type==2054):
                # ARP
                internet=pkt[ARP]
                proto=internet.ptype
                protostr='ARP'
                if(proto==2048):
                    protostr='IP/'+protostr
                elif(proto==34525):
                    protostr='IPv6/'+protostr
                data=[internet.psrc,internet.pdst,protostr,internet.plen]
            else:
                raise "NewProtocol"
            self.progress.emit(data)
        except:
            print(pkt.show())
            raise RuntimeError
    def run(self):
        sniff(prn=(lambda x:self.callback(x)),count=0)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # self.resize(2000,731)
        # self.move(200,200)
        self.setWindowTitle('MySniffer')
        self.setWindowState(Qt.WindowMaximized)
    def work(self):
        self.table=TableView(0,4,self)
        self.table.move(0,0)
        self.show()
        self.table.work()

app=QApplication([])
app.setStyle('Fusion')
win=MainWindow()
win.work()

# sniff(iface='Software Loopback Interface 1',filter='port 8001',prn=sniff_callback,count=10)
# sniff(filter='tcp',prn=sniff_callback,count=10)

app.exec_()
