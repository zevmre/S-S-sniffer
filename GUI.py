from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from scapy.all import *
from scapy.utils import wrpcap
import dpkt
import socket

Headers=['Source','Destination','sPort','dPort']

class TableView(QTableWidget):
    def __init__(self,*args):
        QTableWidget.__init__(self,*args)
        self.setHorizontalHeaderLabels(Headers)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.resize(600,200)
        # self.resizeColumnsToContents()
        # self.resizeRowsToContents()
    def AddRow(self,data):
        row_num=self.rowCount()
        self.insertRow(row_num)
        for i in range(len(data)):
            self.setItem(row_num,i,QTableWidgetItem(str(data[i])))
        self.update()
        self.resizeColumnsToContents()
        self.resizeRowsToContents()
    def work(self):
        self.thread=QThread()
        self.worker=sniff_data()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.progress.connect(self.AddRow)
        self.thread.start()

class sniff_data(QObject):
    progress=pyqtSignal(list)
    finished=pyqtSignal()
    def __init__(self):
        super().__init__()
    def callback(self,pkt):
        try:
            data=[pkt[IP].src,pkt[IP].dst,pkt[TCP].sport,pkt[TCP].dport]
            self.progress.emit(data)
        except:
            print(pkt.show())
            # raise RuntimeError
    def run(self):
        sniff(filter='tcp',prn=(lambda x:self.callback(x)),count=50)

app=QApplication([])
app.setStyle('Fusion')

table=TableView(0,4)
table.show()
table.work()

# sniff(iface='Software Loopback Interface 1',filter='port 8001',prn=sniff_callback,count=10)
# sniff(filter='tcp',prn=sniff_callback,count=10)

app.exec_()
