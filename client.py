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
			work(sock,send_expr,'send')
			if not flag:
				sock.close()
				break
			print('C>> ',end='')

class chat_write(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
	def run(self):
		while 1:
			work(sock,recv_expr,'recv')
			if not flag:
				sock.close()
				break

sock=sk.socket(sk.AF_INET,sk.SOCK_STREAM)
ip=input("The IP address of server?")
# ip='10.206.54.204'
# ip='127.0.0.1'
work(sock,'sock.connect((ip,8001))','connection')
flag=1
chat_r=chat_read()
chat_w=chat_write()
send_expr='''
data=input('');
if data=='exit':
	sock.shutdown(sk.SHUT_RDWR)
else:sock.sendall(data.encode());
'''
#输入exit退出通信
recv_expr='''
data=sock.recv(4096).decode();
if not data:
	raise RuntimeError
print('\\b\\b\\b\\bS>>',data,'\\nC>> ',end='');
'''
#recv_expr中的not data指的是对方关闭了通信，这时再recv会受到空字符
print('C>> ',end='')
chat_r.start()
chat_w.start()
while threading.active_count()!=1:#threading编程之正常退出，剩下一个Main-threading
	pass
#sock.close()
