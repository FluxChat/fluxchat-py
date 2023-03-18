import socket
import selectors

class Server():
	_config: dict
	_selectors: selectors.DefaultSelector
	_socket: socket.socket

	def __init__(self, config: dict):
		print('-> Server.__init__()')

		self._selectors = selectors.DefaultSelector()

		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		self._socket.bind((config['address'], config['port']))

		print('-> listen: {} {}'.format(config['address'], config['port']))
		self._socket.listen()
		self._socket.setblocking(False)
		self._selectors.register(self._socket, selectors.EVENT_READ, data=None)

		print('-> accept')
		# conn, addr = self._socket.accept()

		# print('-> conn', conn)
		# print('-> addr', addr)

		# with conn:
		# 	print(f'Connected by {addr}')
		# 	while True:
		# 		data = conn.recv(1024)
		# 		if not data:
		# 			break
		# 		conn.sendall(data)
