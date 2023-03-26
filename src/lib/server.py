
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

	_clients: list
	_new_clients: list
	_known_clients: list

	def __init__(self, config: dict):
		print('-> Server.__init__()')

		self._config = config

		address_book_path = os.path.join(self._config['data_dir'], 'address_book.json')
		self._address_book = AddressBook(address_book_path)

		bootstrap_path = os.path.join(self._config['data_dir'], 'bootstrap.json')
		if os.path.isfile(bootstrap_path):
			self._address_book.add_bootstrap(bootstrap_path)

		self._clients = []
		self._new_clients = []
		self._known_clients = []

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

	def _client_is_connected(self, client: Client) -> bool:
		print('-> Server._client_is_connected({})'.format(client))

		ffunc = lambda _client: _client.uuid == client.uuid or _client.id == client.id or _client.address == client.address and _client.port == client.port
		clients = list(filter(ffunc, self._clients))
		# print('-> clients: {}'.format(clients))
		return len(clients) > 0

	def _accept(self, server_sock: socket.socket):
		print('-> Server._accept()')

		client_sock, addr = server_sock.accept()
		client_sock.setblocking(False)

		print('-> client_sock: {}'.format(client_sock))
		print('-> addr: {}'.format(addr))
		print('-> accepted: {} {}'.format(addr[0], addr[1]))

		client = Client()
		client.sock = client_sock
		client.conn_mode = 1
		client.dir_mode = 'i'

		self._selectors.register(client_sock, selectors.EVENT_READ, data={
			'type': 'client',
			'client': client,
		})

		self._clients.append(client)

	def _client_connect(self, client: Client):
		print('-> Server._client_connect({})'.format(client))

		client.conn_mode = 1
		client.dir_mode = 'o'

		client.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			client.sock.connect((client.address, client.port))
		except ConnectionRefusedError:
			print('-> ConnectionRefusedError')
			return

		client.sock.setblocking(False)

		self._selectors.register(client.sock, selectors.EVENT_READ, data={
			'type': 'client',
			'client': client,
		})

		self._clients.append(client)

	def _client_read(self, sock: socket.socket, client: Client):
		print('-> Server._client_read({})'.format(client))

		raw = sock.recv(2048)
		if raw:
			raw_len = len(raw)
			print('-> recv raw {} {}'.format(raw_len, raw))

			print('-> processing binary data')

			raw_pos = 0
			commands = []
			while raw_pos < raw_len:
				group = raw[raw_pos]
				command = raw[raw_pos + 1]
				length = struct.unpack('<I', raw[raw_pos + 2:raw_pos + 6])[0]
				payload = raw[raw_pos + 6:]
				payload_l = []

				print('-> group', group)
				print('-> command', command)
				print('-> length', length, type(length))

				pos = 0
				while pos < length:
					item_l = payload[pos]
					print('-> item_l', item_l, type(item_l))
					pos += 1
					item = payload[pos:pos + item_l]
					print('-> item', item)
					payload_l.append(item)
					pos += item_l

				commands.append([group, command, payload_l])
				raw_pos += 7 + length
				print('-> raw_pos', raw_pos)

			for command_raw in commands:
				group_i, command_i, payload_l = command_raw

				print('-> group', group_i, 'command', command_i)
				print('-> payload_l', payload_l)

				if group_i == 0:
					if command_i == 0:
						print('-> OK command')
				elif group_i == 1:
					if command_i == 1:
						print('-> ID command')

						c_contact, c_id = payload_l
						c_id = c_id.decode('utf-8')
						c_contact_addr, c_contact_port = c_contact.decode('utf-8').split(':')
						c_contact_port = int(c_contact_port)

						_client = self._address_book.get_client(c_id)
						if _client == None:
							print('-> client not found A')
							_client = self._address_book.get_client_by_addr_port(c_contact_addr, c_contact_port)
							if _client == None:
								print('-> client not found B')
								_client = self._address_book.add_client([c_contact_addr, c_contact_port, c_id])
							else:
								print('-> client found B: {}'.format(_client))
						else:
							print('-> client found A: {}'.format(_client))

						_client.address = c_contact_addr
						_client.port = c_contact_port
						_client.id = c_id
						_client.sock = sock
						_client.conn_mode = client.conn_mode
						_client.dir_mode = client.dir_mode
						_client.auth = client.auth | 2
						_client.refresh_seen_at()

						self._address_book.changed()

						self._clients.remove(client)
						self._clients.append(_client)

						self._selectors.unregister(sock)
						self._selectors.register(sock, selectors.EVENT_READ, data={
							'type': 'client',
							'client': _client,
						})

						self._client_send_ok(sock)

						print(f'{_client}')
					elif command_i == 2:
						print('-> PING command')
						self._client_send_pong(sock)
					elif command_i == 3:
						print('-> PONG command')

		else:
			print('-> no data')
			self._selectors.unregister(sock)
			sock.close()
			client.conn_mode = 0

	def _client_write(self, sock: socket.socket, group: int, command: int, data: list = []):
		print('-> Server._client_write()')
		payload_l = []
		for item in data:
			payload_l.append(chr(len(item)))
			payload_l.append(item)
		payload = ''.join(payload_l)

		print('-> payload {} "{}"'.format(len(payload), payload))

		cmd_grp = (chr(group) + chr(command)).encode('utf-8')
		len_payload = len(payload).to_bytes(4, byteorder='little')

		print('-> cmd_grp', cmd_grp)
		print('-> len_payload', len_payload)

		raw = cmd_grp + len_payload + (payload + chr(0)).encode('utf-8')

		print('-> send raw {} {}'.format(len(raw), raw))
		res = sock.sendall(raw)
		print('-> sent', res)

	def _client_send_ok(self, sock: socket.socket):
		print('-> Server._client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_id(self, sock: socket.socket):
		print('-> Server._client_send_id()')
		data = [
			self._config['contact'],
			self._config['id'],
		]
		self._client_write(sock, 1, 1, data)

	def _client_send_ping(self, sock: socket.socket):
		print('-> Server._client_send_ping()')
		self._client_write(sock, 1, 2)

	def _client_send_pong(self, sock: socket.socket):
		print('-> Server._client_send_pong()')
		self._client_write(sock, 1, 3)

	def run(self) -> bool:
		# print('-> Server.run()')

		data_processed = False

		events = self._selectors.select(timeout=0)
		for key, mask in events:
			print('-> key', key, 'mask', mask)

			if key.data != None:
				if key.data['type'] == 'server':
					self._accept(key.fileobj)

				elif key.data['type'] == 'client':
					self._client_read(key.fileobj, key.data['client'])

			data_processed = True

		return data_processed # will be returned to the Scheduler

	def contact_address_book(self) -> bool:
		print('-> Server.contact_address_book()')

		for client_uuid, client in self._address_book.get_clients().items():
			print('-> contact client', client)
			if not self._client_is_connected(client):
				print('-> client is not connected')
				self._client_connect(client)

		return True

	def handle_clients(self) -> bool:
		# print('-> Server.handle_clients()')

		for client in self._clients:
			# print('handle', client)

			if client.conn_mode == 0:
				print('-> remove client')
				self._clients.remove(client)

			if client.conn_mode == 1 and client.auth & 1 == 0:
				print('-> send ID')
				self._client_send_id(client.sock)
				client.auth |= 1

			if client.auth == 3:
				client.conn_mode = 2

		return True

	def ping_clients(self) -> bool:
		print('-> Server.ping_clients() -> {}'.format(len(self._clients)))

		for client in self._clients:
			if client.conn_mode == 2:
				print('-> send PING')
				self._client_send_ping(client.sock)

		return True

	def debug_clients(self) -> bool:
		print('-> Server.debug_clients() -> {}'.format(len(self._clients)))

		for client in self._clients:
			print('->', client)

		return True
