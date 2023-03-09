import socket as sk
import threading
def work(sock,target,target_type):
	global flag
	try: exec(target)
	except (sk.error, RuntimeError) as e:
		print('Oops,',target_type,'Error!')
		flag=0
	except sk.timeout:
		print('Oops, Time OUT!')
		flag=0

class chat_read(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
	def run(self):
		while 1:
			work(conn,send_expr,'send')
			if not flag:
				conn.close()
				break
			print('S>> ',end='')

class chat_write(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
	def run(self):
		while 1:
			work(conn,recv_expr,'recv')
			if not flag:
				conn.close()
				break

sock=sk.socket(sk.AF_INET,sk.SOCK_STREAM)
print('Socket Created')
ip=sk.gethostbyname(sk.gethostname())
print('Your IP address:',ip)
work(sock,'sock.bind((ip,8001))','bind')
sock.listen(5)
flag=1
send_expr='''
data=input('');
if data=='exit':
	raise RuntimeError
conn.sendall(data.encode());
'''
recv_expr='''
data=sock.recv(4096).decode();
if not data:
	raise RuntimeError
print('\\b\\b\\b\\bC>>',data,'\\nS>> ',end='');
'''
while 1:
	print("Waiting...")
	conn,addr=sock.accept()
	print("Oh? A client FOUND")
	flag=1
	try:
		conn.settimeout(30)
		print('S>> ',end='')
		chat_r=chat_read()
		chat_w=chat_write()
		chat_r.start()
		chat_w.start()
		while threading.active_count()!=1:
			pass
	except sk.timeout:
		print('Time out')
	#conn.close()
sock.close()
