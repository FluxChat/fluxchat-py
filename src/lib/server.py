
import os
import socket
import selectors
import struct

from sty import fg
from lib.client import Client
from lib.address_book import AddressBook
import lib.overlay as overlay

class Server():
	_config: dict
	_selectors: selectors.DefaultSelector
	_main_server_socket: socket.socket
	_discovery_socket: socket.socket
	_address_book: AddressBook
	_hostname: str
	_lan_ip: str

	_clients: list
	_local_node: overlay.Node

	def __init__(self, config: dict):
		print('-> Server.__init__()')

		self._host_name = socket.gethostname()
		self._lan_ip = socket.gethostbyname(self._host_name)

		print('-> host_name: {}'.format(self._host_name))
		print('-> lan_ip: {}'.format(self._lan_ip))

		self._config = config

		address_book_path = os.path.join(self._config['data_dir'], 'address_book.json')
		self._address_book = AddressBook(address_book_path, self._config['address_book'])

		bootstrap_path = os.path.join(self._config['data_dir'], 'bootstrap.json')
		if os.path.isfile(bootstrap_path):
			self._address_book.add_bootstrap(bootstrap_path)

		self._clients = []
		self._local_node = overlay.Node(self._config['id'])

		self._selectors = selectors.DefaultSelector()
		self._main_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._main_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		print('-> bind: {} {}'.format(self._config['address'], self._config['port']))
		self._main_server_socket.bind((self._config['address'], self._config['port']))

		print('-> listen')
		self._main_server_socket.listen()
		self._main_server_socket.setblocking(False)
		self._selectors.register(self._main_server_socket, selectors.EVENT_READ, data={'type': 'main_server'})

		# print(self._main_server_socket)
		# print(self._main_server_socket.getsockname())

		if 'discovery' in self._config and self._config['discovery']:
			print('-> discovery')
			self._discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
			self._discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			self._discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self._discovery_socket.bind(('', 26000))
			self._discovery_socket.setblocking(False)

			if self.has_contact():
				print('-> send broadcast')
				res = self._discovery_socket.sendto(self.get_contact().encode('utf-8'), ('<broadcast>', 26000))
				print('-> res', res)

			self._selectors.register(self._discovery_socket, selectors.EVENT_READ, data={'type': 'discovery_server'})

	def __del__(self):
		print('-> Server.__del__()')
		self._selectors.close()

	def has_contact(self) -> bool:
		if 'contact' in self._config:
			if self._config['contact'] == 'disabled' or self._config['contact'] == 'private':
				return False
			elif bool(self._config['contact']) == False:
				return False

			return True

		return False

	def get_contact(self) -> str:
		if self.has_contact():
			items = self._config['contact'].split(':')
			item_len = len(items)

			if item_len == 1:
				return '{}:{}'.format(items[0], self._config['port'])

			return self._config['contact']

		return 'N/A'

	def _client_is_connected(self, client: Client) -> bool:
		print('-> Server._client_is_connected({})'.format(client))

		ffunc = lambda _client: _client.uuid == client.uuid or _client.id == client.id or _client.address == client.address and _client.port == client.port
		clients = list(filter(ffunc, self._clients))
		print('-> clients: {}'.format(clients))

		return len(clients) > 0

	def _accept_main_server(self, server_sock: socket.socket):
		print('-> Server._accept_main_server()')

		client_sock, addr = server_sock.accept()
		client_sock.setblocking(False)

		print('-> client_sock: {}'.format(client_sock))
		print('-> addr: {}'.format(addr))
		print('-> accepted: {} {}'.format(addr[0], addr[1]))

		client = Client()
		client.sock = client_sock
		client.conn_mode = 1
		client.dir_mode = 'i'
		client.debug_add = 'accept'

		self._selectors.register(client_sock, selectors.EVENT_READ, data={
			'type': 'main_client',
			'client': client,
		})

		self._clients.append(client)

	def _read_discovery_server(self, server_sock: socket.socket):
		print('-> Server._read_discovery_server()')

		data, addr = server_sock.recvfrom(1024)
		c_contact = data.decode('utf-8')
		c_contact_items = c_contact.split(':')
		c_contact_items_len = len(c_contact_items)

		print('-> data: {}'.format(data))
		print('-> addr: {}'.format(addr))
		print('-> c_contact_items: {}'.format(c_contact_items))

		if addr[0] == self._lan_ip:
			return

		if c_contact_items_len == 1:
			c_contact_addr = c_contact_items[0]
			c_contact_port = None
		elif c_contact_items_len == 2:
			c_contact_addr = c_contact_items[0]
			c_contact_port = int(c_contact_items[1])

		if c_contact_addr == 'public':
			print('-> public', server_sock.getsockname())
			c_contact_addr = addr[0]
		elif c_contact_addr == 'private':
			return

		if c_contact_port == None:
			return

		client = Client()
		client.address = c_contact_addr
		client.port = c_contact_port
		client.debug_add = 'discovery'

		self._client_connect(client)

	def _client_connect(self, client: Client):
		print('-> Server._client_connect({})'.format(client))

		if client.address == self._lan_ip:
			return
		if client.node == self._local_node:
			return
		if client.address == None or client.port == None:
			return

		client.conn_mode = 1
		client.dir_mode = 'o'

		client.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client.sock.settimeout(2)
		try:
			# print('-> client.sock.connect to')
			client.sock.connect((client.address, client.port))
			# print('-> client.sock.connect done')
		except ConnectionRefusedError as e:
			print('-> ConnectionRefusedError', e)
			return
		except TimeoutError as e:
			print('-> TimeoutError', e)
			return
		except socket.timeout as e:
			print('-> socket.timeout', e)
			return

		client.sock.settimeout(None)
		client.sock.setblocking(False)

		self._selectors.register(client.sock, selectors.EVENT_READ, data={
			'type': 'main_client',
			'client': client,
		})

		self._clients.append(client)

	def _client_read(self, sock: socket.socket, client: Client):
		print('-> Server._client_read({})'.format(client))

		try:
			raw = sock.recv(2048)
		except TimeoutError as e:
			print('-> TimeoutError', e)
			return
		except ConnectionResetError as e:
			print('-> ConnectionResetError', e)
			raw = False

		if raw:
			raw_len = len(raw)
			print('-> recv raw {} {}'.format(raw_len, raw))

			raw_pos = 0
			commands = []
			while raw_pos < raw_len:
				try:
					group = raw[raw_pos]
					command = raw[raw_pos + 1]
				except IndexError as e:
					print('-> IndexError', e)
					print(f'{fg.red}-> conn mode 0{fg.rs}')
					client.conn_mode = 0
					return
				try:
					length = struct.unpack('<I', raw[raw_pos + 2:raw_pos + 6])[0]
				except struct.error as e:
					print('-> struct.error', e)
					print(f'{fg.red}-> conn mode 0{fg.rs}')
					client.conn_mode = 0
					return
				payload_raw = raw[raw_pos + 6:]
				payload_items = []

				# print('-> group', group)
				# print('-> command', command)
				# print('-> length', length, type(length))

				if length >= 2048:
					print('-> length too big', length)
					return

				pos = 0
				while pos < length:
					item_l = payload_raw[pos]
					# print('-> item_l', item_l, type(item_l))
					pos += 1
					item = payload_raw[pos:pos + item_l]
					# print('-> item', item)
					payload_items.append(item.decode('utf-8'))
					pos += item_l

				commands.append([group, command, payload_items])
				raw_pos += 7 + length
				# print('-> raw_pos', raw_pos)

			for command_raw in commands:
				group_i, command_i, payload = command_raw
				payload_len = len(payload)

				print('-> group', group_i, 'command', command_i)
				print('-> payload', payload)

				if group_i == 0: # Basic
					if command_i == 0:
						print('-> OK command')
				elif group_i == 1: # Connection, Authentication, etc
					if command_i == 1:
						print('-> ID command')
						if client.auth & 2 != 0:
							print('-> already authenticated')
							continue

						c_switch = False

						c_id = payload[0]
						print('-> c_id', c_id)

						c_has_contact_info = False
						if payload_len >= 2:
							# Client sent contact info
							c_contact = payload[1]

							c_contact_items = c_contact.split(':')
							c_contact_items_len = len(c_contact_items)

							if c_contact_items_len == 1:
								c_has_contact_info = False
							elif c_contact_items_len == 2:
								c_contact_addr = c_contact_items[0]
								c_contact_port = int(c_contact_items[1])

							if c_contact_addr == 'public':
								print('-> public', sock.getsockname())
								c_has_contact_info = True
							elif c_contact_addr == 'private':
								c_has_contact_info = False
							else:
								c_has_contact_info = True

						if client.dir_mode == 'i':
							# Client is incoming
							print('-> client is incoming')

							if c_has_contact_info:
								# Client sent contact info
								_client = self._address_book.get_client(c_id)
								if _client == None:
									print('-> client not found A')

									_client = self._address_book.get_client_by_addr_port(c_contact_addr, c_contact_port)
									if _client == None:
										print('-> client not found B')

										c_switch = True
										_client = self._address_book.add_client(c_id, c_contact_addr, c_contact_port)
										_client = client.dir_mode
										_client.debug_add = 'id command, incoming, contact infos, not found by id, not found by addr:port, original: ' + client.debug_add
									else:
										print('-> client found B: {}'.format(_client))
								else:
									print('-> client found A: {}'.format(_client))

								_client.address = c_contact_addr
								_client.port = c_contact_port
							else:
								# Client sent no contact info
								_client = self._address_book.get_client(c_id)
								if _client == None:
									print('-> client not found C')

									_client = self._address_book.add_client(c_id)
									_client = client.dir_mode
									_client.debug_add = 'id command, incoming, no contact infos, not found by id, original: ' + client.debug_add
								else:
									print('-> client found C: {}'.format(_client))

								c_switch = True

						elif client.dir_mode == 'o':
							# Client is outgoing
							print('-> client is outgoing')

							_client = client

							_existing_client = self._address_book.get_client(c_id)
							if _existing_client == None:
								# Client is outgoing but not found by id
								# This can happen because of the UDP discovery service.
								print('-> client not found D')
								_client = self._address_book.add_client(c_id, client.address, client.port)
								_client = client.dir_mode
								_client.debug_add = 'id command, outgoing, not found by id, original: ' + client.debug_add

								c_switch = True
							else:
								print('-> client found D: {}'.format(_existing_client))

								if _existing_client == client:
									print('-> client is equal')
								else:
									print('-> client is NOT equal')
									# raise Exception('Not Implemented, what to do if client is not equal?')

							if c_has_contact_info:
								print('-> client has contact infos')
								_client.address = c_contact_addr
								_client.port = c_contact_port
							else:
								print('-> client has NO contact infos')

						if _client.id == None:
							_client.id = c_id

						print(f'Client A: {client}')
						print(f'Client B: {_client}')

						_client.refresh_seen_at()
						_client.inc_meetings()

						_client.sock = sock
						_client.conn_mode = client.conn_mode
						_client.auth = client.auth | 2

						# Update Address Book because also an existing client can be updated
						self._address_book.changed()

						if c_switch and not _client == client:
							print('-> switch client')
							self._clients.remove(client)
							self._clients.append(_client)

							self._selectors.unregister(sock)
							self._selectors.register(_client.sock, selectors.EVENT_READ, data={
								'type': 'main_client',
								'client': _client,
							})

						self._client_send_ok(_client.sock)

						print(f'{fg.blue}Client Z: {_client}{fg.rs}')
					elif command_i == 2:
						print('-> PING command')
						self._client_send_pong(sock)
					elif command_i == 3:
						print('-> PONG command')
				elif group_i == 2: # Overlay, Address Book, Routing, etc
					if client.auth != 3:
						print('-> not authenticated', client.auth)
						print(f'{fg.red}-> conn mode 0{fg.rs}')
						client.conn_mode = 0
						continue

					if command_i == 1:
						print('-> GET_NEAREST_TO command')
						node = overlay.Node(payload[0])
						client_ids = []
						clients = self._address_book.get_nearest_to(node)
						for _client in clients:
							print('-> client', _client, _client.distance(node))
							if _client.id != self._local_node.id and _client.id != node.id:
								if _client.has_contact():
									contact_infos = [_client.id, _client.address, str(_client.port)]
									print('-> contact infos', contact_infos)
									client_ids.append(':'.join(contact_infos))

						self._client_send_get_nearest_response(sock, client_ids)

					elif command_i == 2:
						print('-> GET_NEAREST_TO RESPONSE command')

						if not client.has_action('nearest_response', True):
							print('-> not requested')
							continue

						nearest_client = None
						distance = overlay.Distance()
						for c_contact in payload:
							print('-> client contact', c_contact)
							c_id, c_addr, c_port = c_contact.split(':')
							if c_id == self._local_node.id:
								continue

							_client = self._address_book.get_client(c_id)
							_
							if _client == None:
								print('-> client not found')
								_client = self._address_book.add_client(c_id, c_addr, c_port)
								_client.debug_add = 'nearest response, not found by id'

								_c_distance = _client.distance(self._local_node)
								if _c_distance < distance:
									# distance = _client.distance(self._local_node)
									distance = _c_distance
									print('-> new distance', distance)

									nearest_client = _client
							else:
								print('-> client found', _client)

						if nearest_client != None:
							print('-> nearest client', nearest_client)
							# TODO: connect to nearest client
							# limit the clients to connect to.
				else:
					print('-> unknown group', group_i, 'command', command_i)
					print(f'{fg.red}-> conn mode 0{fg.rs}')
					client.conn_mode = 0

		else:
			print('-> no data')
			# self._selectors.unregister(sock)
			# sock.close()

			print(f'{fg.red}-> conn mode 0{fg.rs}')
			client.conn_mode = 0

	def _client_write(self, sock: socket.socket, group: int, command: int, data: list = []):
		print('-> Server._client_write()')
		payload_l = []
		for item in data:
			payload_l.append(chr(len(item)))
			payload_l.append(item)
		payload = ''.join(payload_l)

		# print('-> payload {} "{}"'.format(len(payload), payload))

		cmd_grp = (chr(group) + chr(command)).encode('utf-8')
		len_payload = len(payload).to_bytes(4, byteorder='little')

		# print('-> cmd_grp', cmd_grp)
		# print('-> len_payload', len_payload)

		raw = cmd_grp + len_payload + (payload + chr(0)).encode('utf-8')

		# print('-> send raw {} {}'.format(len(raw), raw))
		res = sock.sendall(raw)
		# print('-> sent', res)

	def _client_send_ok(self, sock: socket.socket):
		print('-> Server._client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_id(self, sock: socket.socket):
		print('-> Server._client_send_id()')
		data = [
			self._config['id'],
		]
		if self.has_contact():
			data.append(self.get_contact())

		print('-> data', data)
		self._client_write(sock, 1, 1, data)

	def _client_send_ping(self, sock: socket.socket):
		print('-> Server._client_send_ping()')
		self._client_write(sock, 1, 2)

	def _client_send_pong(self, sock: socket.socket):
		print('-> Server._client_send_pong()')
		self._client_write(sock, 1, 3)

	def _client_send_get_nearest_to(self, sock: socket.socket, id: str):
		print('-> Server._client_send_get_nearest_to()')
		self._client_write(sock, 2, 1, [id])

	def _client_send_get_nearest_response(self, sock: socket.socket, client_ids: list):
		print('-> Server._client_send_get_nearest_response()')
		self._client_write(sock, 2, 2, client_ids)

	def run(self) -> bool:
		# print('-> Server.run()')

		data_processed = False

		events = self._selectors.select(timeout=0)
		for key, mask in events:
			# print('-> key', key, 'mask', mask)

			if key.data != None:
				if key.data['type'] == 'main_server':
					self._accept_main_server(key.fileobj)

				elif key.data['type'] == 'main_client':
					self._client_read(key.fileobj, key.data['client'])

				elif key.data['type'] == 'discovery_server':
					print('-> discovery server')
					self._read_discovery_server(key.fileobj)

				# elif key.data['type'] == 'discovery_client':
				# 	print('-> discovery client')
				# 	self._read_discovery_client(key.fileobj)

			data_processed = True

		return data_processed # will be returned to the Scheduler

	def contact_address_book(self) -> bool:
		print('-> Server.contact_address_book()')

		_clients = list(self._address_book.get_clients().values())
		_clients.sort(key=lambda _client: _client.meetings, reverse=True)

		print('-> clients', len(_clients))

		connect_to_clients = []
		zero_meetings_clients = []
		for client in _clients:
			print('-> contact', client)

			if client.meetings > 0:
				print('-> client is meeting')
				if not self._client_is_connected(client):
					print('-> client is not connected')
					connect_to_clients.append(client)
			else:
				print('-> client is not meeting')
				zero_meetings_clients.append(client)

		zero_meetings_clients.sort(key=lambda _client: _client.distance(self._local_node))
		for client in zero_meetings_clients:
			print('-> contact', client)

			if not self._client_is_connected(client):
				print('-> client is not connected')
				connect_to_clients.append(client)

		is_bootstrapping = self.is_bootstrap_phase()
		print('-> is_bootstrapping', is_bootstrapping)

		for client in connect_to_clients:
			if is_bootstrapping:
				client.add_action('bootstrap')
			self._client_connect(client)

		return True

	def clean_up_address_book(self) -> bool:
		self._address_book.clean_up()
		return True

	def handle_clients(self) -> bool:
		# print('-> Server.handle_clients()')

		for client in self._clients:
			# print('handle', client)

			if client.conn_mode == 0:
				print('-> remove client', client)
				self._selectors.unregister(client.sock)
				# try:
					# self._selectors.unregister(client.sock)
				# except ValueError as e:
				# 	print('-> ValueError', e)
				client.sock.close()
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

	def save(self) -> bool:
		print('-> Server.save()')

		self._address_book.save()

		return True

	def debug_clients(self) -> bool:
		print('-> Server.debug_clients() -> {}'.format(len(self._clients)))

		for client in self._clients:
			print('-> debug', client)

		return True

	def client_actions(self) -> bool:
		# print('-> Server.client_actions() -> {}'.format(len(self._clients)))
		had_actions = False

		for client in self._clients:
			# print('-> action client', client)
			for action in client.get_actions(True):
				print('-> action', action)
				if action == 'bootstrap':
					self._client_send_get_nearest_to(client.sock, self._local_node.id)
					client.add_action('nearest_response')

		return had_actions

	def is_bootstrap_phase(self) -> bool:
		clients_len = self._address_book.get_clients_len()
		bootstrap_clients_len = self._address_book.get_bootstrap_clients_len()
		return clients_len <= bootstrap_clients_len
