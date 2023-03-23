
import os
import socket
import selectors

from sty import fg
from lib.client import Client
from lib.address_book import AddressBook

class Server():
	_config: dict
	_selectors: selectors.DefaultSelector
	_socket: socket.socket
	_address_book: AddressBook

	def __init__(self, config: dict):
		print('-> Server.__init__()')

		self._config = config

		address_book_path = os.path.join(self._config['data_dir'], 'address_book.json')
		self._address_book = AddressBook(address_book_path)

		self._selectors = selectors.DefaultSelector()
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		print('-> bind: {} {}'.format(self._config['address'], self._config['port']))
		self._socket.bind((self._config['address'], self._config['port']))

		print('-> listen')
		self._socket.listen()
		self._socket.setblocking(False)
		self._selectors.register(self._socket, selectors.EVENT_READ, data={'type': 'server'})

	def __del__(self):
		print('-> Server.__del__()')
		self._selectors.close()

	def _accept(self, sock, mask):
		print('-> Server._accept()')

		conn, addr = sock.accept()
		conn.setblocking(False)

		self._selectors.register(conn, selectors.EVENT_READ, data={
			'type': 'new_client',
		})

	def _client_read(self, sock, mask, client: Client = None):
		print('-> Server._client_read({}, {}, {})'.format(type(sock), type(mask), type(client)))

		raw = sock.recv(1024)
		if raw:
			data = raw.decode('utf-8').strip()

			print('-> raw', raw)
			if data[0:2] == 'ID':
				items = data.split(':')[1:]
				print('-> items', items)

				client = self._address_book.get_client(items[2])
				if client == None:
					print('-> client not found')
					self._address_book.add_client(items)
				else:
					print('-> client found')

				self._selectors.unregister(sock)
				self._selectors.register(sock, selectors.EVENT_READ, data={
					'type': 'full_client',
					'client': client,
				})

				sock.send("OK\r\n".encode('utf-8'))
		else:
			print('-> no data')
			self._selectors.unregister(sock)
			sock.close()

	def run(self):
		# print('-> Server.run()')

		events = self._selectors.select(timeout=0.1)
		for key, mask in events:
			print('-> key', key, 'mask', mask)

			if key.data != None:
				print('-> data', key.data)

				if key.data['type'] == 'server':
					self._accept(key.fileobj, mask)

				elif key.data['type'] == 'new_client':
					self._client_read(key.fileobj, mask)
