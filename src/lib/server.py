
import os
import socket
import selectors
import struct

from sty import fg
from lib.client import Client
from lib.address_book import AddressBook

class Server():
	_config: dict
	_selectors: selectors.DefaultSelector
	_socket: socket.socket
	_address_book: AddressBook

	_new_clients: list
	_in_clients: list
	_out_clients: list

	def __init__(self, config: dict):
		print('-> Server.__init__()')

		self._config = config

		address_book_path = os.path.join(self._config['data_dir'], 'address_book.json')
		self._address_book = AddressBook(address_book_path)

		bootstrap_path = os.path.join(self._config['data_dir'], 'bootstrap.json')
		if os.path.isfile(bootstrap_path):
			self._address_book.add_bootstrap(bootstrap_path)

		self._new_clients = []

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

	def _accept(self, sock: socket.socket):
		print('-> Server._accept()')

		conn, addr = sock.accept()
		conn.setblocking(False)

		print('-> conn: {}'.format(conn))
		print('-> addr: {}'.format(addr))
		print('-> accepted: {} {}'.format(addr[0], addr[1]))

		client = Client()
		client.conn_mode = 1
		client.refresh_seen_at()

		self._selectors.register(conn, selectors.EVENT_READ, data={
			'type': 'client',
			'client': client,
		})

		self._new_clients.append(client)

	def _client_read(self, sock: socket.socket, client: Client):
		print('-> Server._client_read({})'.format(client))

		raw = sock.recv(1024)
		if raw:
			print('-> raw', raw)
			data = raw.decode('utf-8').strip()

			if client.data_mode == 't':
				if data[0:2] == 'ID':
					cid_addr, cid_port, cid_id = items = data.split(':')[1:]
					print('-> items', items)

					_client = self._address_book.get_client(items[2])
					if _client == None:
						print('-> client not found')
						_client = self._address_book.add_client(items)
						sock.send("OK A\r\n".encode('utf-8'))
					else:
						print('-> client found')
						sock.send("OK B\r\n".encode('utf-8'))

					_client.conn_mode = 2

					print(f'{_client}')

					self._selectors.unregister(sock)
					self._selectors.register(sock, selectors.EVENT_READ, data={
						'type': 'client',
						'client': _client,
					})

				elif data[0:6] == 'BINARY':
					print('-> BINARY MODE')
					sock.send("OK\r\n".encode('utf-8'))
					client.data_mode = 'b'

				elif data[0:4] == 'EXIT':
					print('-> EXIT')
					sock.send("OK\r\n".encode('utf-8'))
					sock.close()
					self._selectors.unregister(sock)

			elif client.data_mode == 'b':
				print('-> processing binary data')
				group = raw[0]
				command = raw[1]
				length = struct.unpack('<I', raw[2:6])[0]
				payload = raw[6:]
				payload_l = []

				pos = 0
				while pos < length:
					item_l = payload[pos]
					pos += 1
					item = payload[pos:pos + item_l]
					payload_l.append(item)

				print('-> group', group)
				print('-> command', command)
				print('-> length', length)
				print('-> payload', payload)
				print('-> payload_l', payload_l)

				if group == 1:
					if command == 1:
						print('-> ID command')
						pass

		else:
			print('-> no data')
			self._selectors.unregister(sock)
			sock.close()

	def _client_write(self, sock: socket.socket, group: int, command: int, data: list):
		print('-> Server._client_write()')
		payload_l = []
		for item in data:
			payload_l.append(chr(len(item)))
			payload_l.append(item)
		payload = ''.join(payload_l)

		raw = (chr(group) + chr(command)).encode('utf-8') + len(payload).to_bytes(4, byteorder='little') + payload.encode('utf-8')

		print('-> send raw', raw)
		sock.send(raw)

	def _client_send_id(self, sock: socket.socket):
		print('-> Server._client_send_id()')
		data = [
			self._config['address'],
			str(self._config['port']),
			self._config['id'],
		]
		self._client_write(sock, 1, 1, data)

	def run(self) -> bool:
		print('-> Server.run()')

		data_processed = False

		events = self._selectors.select(timeout=0)
		for key, mask in events:
			#print('-> key', key, 'mask', mask)

			if key.data != None:
				print('-> data', key.data)

				if key.data['type'] == 'server':
					self._accept(key.fileobj)

				elif key.data['type'] == 'client':
					self._client_read(key.fileobj, key.data['client'])

			data_processed = True

		return data_processed # will be returned to the Scheduler

	def contact_address_book(self):
		print('-> Server.contact_address_book()')

		for client_uuid, client in self._address_book.get_clients().items():
			pass
		# TODO

	def handle_new_clients(self):
		print('-> Server.handle_new_clients() -> {}'.format(len(self._new_clients)))

		for client in self._new_clients:
			self._client_send_id(client.conn)

		self._new_clients = []

	def handle_out_clients(self):
		print('-> Server.handle_out_clients()')

		for client in self._out_clients:
			pass
		# TODO
