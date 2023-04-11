
import os
import socket
import selectors
import struct
import base64

from sty import fg
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from lib.client import Client, Action
from lib.address_book import AddressBook
from lib.helper import resolve_contact, is_valid_uuid
from lib.mail import Message, Queue as MessageQueue, Database as MessageDatabase
from lib.network import Network
import lib.overlay as overlay

class Server(Network):
	_config: dict
	_selectors: selectors.DefaultSelector
	_main_server_socket: socket.socket
	_discovery_socket: socket.socket
	_ipc_server_socket: socket.socket
	_address_book: AddressBook
	_message_queue: MessageQueue
	_message_db: MessageDatabase
	_hostname: str
	_lan_ip: str

	_clients: list
	_local_node: overlay.Node
	_public_key_b64: str

	def __init__(self, config: dict = {}):
		# print('-> Server.__init__()')

		self._host_name = socket.gethostname()
		self._lan_ip = socket.gethostbyname(self._host_name)
		self._clients = []
		self._selectors = selectors.DefaultSelector()
		self._public_key = None
		self._public_key_b64 = None
		self._private_key = None
		self._address_book = None
		self._message_queue = None
		self._message_db = None

		self._config = config
		if 'address_book' not in self._config:
			self._config['address_book'] = {
				'max_clients': 20,
				'client_retention_time': 24,
			}

		if 'data_dir' in self._config:
			pid_file_path = os.path.join(self._config['data_dir'], 'pychat.pid')
			if os.path.isfile(pid_file_path):
				print('-> Another instance of PyChat is already running.')
				print('-> If this is not the case, delete the file: {}'.format(pid_file_path))
				exit(1)
			with open(pid_file_path, 'w') as fh:
				fh.write(str(os.getpid()))

			if 'public_key_file' not in self._config:
				self._config['public_key_file'] = os.path.join(self._config['data_dir'], 'public_key.pem')
			if 'private_key_file' not in self._config:
				self._config['private_key_file'] = os.path.join(self._config['data_dir'], 'private_key.pem')

			if 'keys_dir' not in self._config:
				self._config['keys_dir'] = os.path.join(self._config['data_dir'], 'keys')
			if not os.path.isdir(self._config['keys_dir']):
				os.mkdir(self._config['keys_dir'])

			# create messages directory if it doesn't exist
			# if 'messages_dir' not in self._config:
			# 	self._config['messages_dir'] = os.path.join(self._config['data_dir'], 'messages')
			# if not os.path.isdir(self._config['messages_dir']):
			# 	os.mkdir(self._config['messages_dir'])

			address_book_path = os.path.join(self._config['data_dir'], 'address_book.json')
			self._address_book = AddressBook(address_book_path, self._config)
			self._address_book.load()

			bootstrap_path = os.path.join(self._config['data_dir'], 'bootstrap.json')
			if os.path.isfile(bootstrap_path):
				self._address_book.add_bootstrap(bootstrap_path)

			message_queue_path = os.path.join(self._config['data_dir'], 'message_queue.json')
			self._message_queue = MessageQueue(message_queue_path, self._config)
			self._message_queue.load()

			message_db_path = os.path.join(self._config['data_dir'], 'message_db.json')
			self._message_db = MessageDatabase(message_db_path)
			self._message_db.load()

		if 'id' in self._config:
			self._local_node = overlay.Node.parse(self._config['id'])

		if isinstance(self._config['discovery'], bool):
			self._config['discovery'] = {
				'enabled': self._config['discovery'],
				'port': 26000,
			}

		if 'bootstrap' not in self._config:
			self._config['bootstrap'] = 'default'

	def __del__(self):
		# print('-> Server.__del__()')
		self._selectors.close()

		if self._address_book:
			self._address_book.save()

		if self._message_queue:
			self._message_queue.save()

		if self._message_db:
			self._message_db.save()

	def start(self): # pragma: no cover
		print('-> Server.start()')
		self._load_public_key_from_pem_file()
		self._load_private_key_from_pem_file()

		self._main_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._main_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		print('-> bind: {} {}'.format(self._config['address'], self._config['port']))

		try:
			self._main_server_socket.bind((self._config['address'], self._config['port']))
		except OSError as e:
			print('-> OSError: {}'.format(e))
			print('-> Is another instance of PyChat already running?')
			exit(1)

		print('-> listen')
		self._main_server_socket.listen()
		self._main_server_socket.setblocking(False)
		self._selectors.register(self._main_server_socket, selectors.EVENT_READ, data={'type': 'main_server'})

		if 'discovery' in self._config and self._config['discovery']['enabled']:
			print('-> discovery')
			self._discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
			self._discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			self._discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			try:
				self._discovery_socket.bind(('', self._config['discovery']['port']))
			except OSError as e:
				print('-> OSError: {}'.format(e))
			self._discovery_socket.setblocking(False)

			if self.has_contact():
				print('-> send broadcast')
				# TODO for production: set port to self._config['discovery']['port'] instead of hard-coded 26000
				res = self._discovery_socket.sendto(self.get_contact().encode('utf-8'), ('<broadcast>', 26000))
				print('-> res', res)

			self._selectors.register(self._discovery_socket, selectors.EVENT_READ, data={'type': 'discovery'})

		if 'ipc' in self._config and self._config['ipc']:
			print('-> ipc')
			ipc_addr = (self._config['ipc']['address'], self._config['ipc']['port'])
			self._ipc_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self._ipc_server_socket.bind(ipc_addr)
			self._ipc_server_socket.listen()
			self._ipc_server_socket.setblocking(False)

			self._selectors.register(self._ipc_server_socket, selectors.EVENT_READ, data={'type': 'ipc_server'})

	def _load_private_key_from_pem_file(self) -> None:
		print('-> Server._load_private_key_from_pem_file()')

		if not os.path.isfile(self._config['private_key_file']):
			raise Exception('private key file not found: {}'.format(self._config['private_key_file']))

		with open(self._config['private_key_file'], 'rb') as f:
			self._private_key = serialization.load_pem_private_key(f.read(), password=None)

		print('-> private key: {}'.format(self._private_key))

	def _load_public_key_from_pem_file(self) -> None:
		print('-> Server._load_public_key_from_pem_file()')

		if not os.path.isfile(self._config['public_key_file']):
			raise Exception('public key file not found: {}'.format(self._config['public_key_file']))

		with open(self._config['public_key_file'], 'rb') as f:
			self._public_key = serialization.load_pem_public_key(f.read())

		print('-> public key: {}'.format(self._public_key))

		public_bytes = self._public_key.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		self._public_key_b64 = base64.b64encode(public_bytes).decode('utf-8')

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

	def _client_is_connected(self, client: Client) -> bool: # pragma: no cover
		print('-> Server._client_is_connected()')

		ffunc = lambda _client: _client.uuid == client.uuid or _client.id == client.id or _client.address == client.address and _client.port == client.port
		clients = list(filter(ffunc, self._clients))
		# print('-> clients: {}'.format(clients))

		return len(clients) > 0

	def _accept_main_server(self, server_sock: socket.socket): # pragma: no cover
		print('-> Server._accept_main_server()')

		client_sock, addr = server_sock.accept()
		client_sock.setblocking(False)

		# print('-> client_sock: {}'.format(client_sock))
		# print('-> addr: {}'.format(addr))
		# print('-> accepted: {} {}'.format(addr[0], addr[1]))

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

		print('-> accept_main_server client: {}'.format(client))

	def _read_discovery(self, server_sock: socket.socket): # pragma: no cover
		print('-> Server._read_discovery()')

		data, addr = server_sock.recvfrom(1024)
		c_contact = data.decode('utf-8')

		print('-> data: {}'.format(data))
		print('-> addr: {}'.format(addr))

		if addr[0] == self._lan_ip and addr[1] == self._config['discovery']['port']:
			print('-> skip self')
			return

		c_contact_addr, c_contact_port, c_has_contact_info = resolve_contact(c_contact, addr[0])

		if not c_has_contact_info:
			return

		client = self._address_book.get_client_by_addr_port(c_contact_addr, c_contact_port)
		if client == None:
			client = self._address_book.add_client(addr=c_contact_addr, port=c_contact_port)
			client.debug_add = 'discovery, contact: {}'.format(c_contact)
		else:
			print('-> client: {}'.format(client))

		print('-> read_discovery client: {}'.format(client))

		self._client_connect(client)

	def _accept_ipc_server(self, server_sock: socket.socket): # pragma: no cover
		print('-> Server._accept_ipc_server()')

		client_sock, addr = server_sock.accept()
		client_sock.setblocking(False)

		self._selectors.register(client_sock, selectors.EVENT_READ, data={
			'type': 'ipc_client',
		})

	def _client_connect(self, client: Client) -> bool: # pragma: no cover
		print('{}-> Server._client_connect({}){}'.format(fg.blue, client, fg.rs))

		# TODO: activate for production
		# if client.address == self._lan_ip and os.environ.get('ALLOW_SELF_CONNECT') != '1':
		# 	print('-> skip, client.address == self._lan_ip')
		# 	return False
		if client.node == self._local_node:
			print('-> skip, client.node == self._local_node')
			return False
		if client.address == None or client.port == None:
			print('-> skip, client.address == None or client.port == None')
			return False

		client.conn_mode = 1
		client.dir_mode = 'o'

		client.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client.sock.settimeout(2)
		try:
			print('-> client.sock.connect to')
			client.sock.connect((client.address, client.port))
			print('-> client.sock.connect done')
		except ConnectionRefusedError as e:
			print('-> ConnectionRefusedError', e)
			return False
		except TimeoutError as e:
			print('-> TimeoutError', e)
			return False
		except socket.timeout as e:
			print('-> socket.timeout', e)
			return False

		client.sock.settimeout(None)
		client.sock.setblocking(False)

		self._selectors.register(client.sock, selectors.EVENT_READ, data={
			'type': 'main_client',
			'client': client,
		})

		self._clients.append(client)

		print('-> Server._client_connect done'.format())
		return True

	def _client_read(self, sock: socket.socket, client: Client): # pragma: no cover
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
					flags_i = raw[raw_pos]
					raw_pos += 1

					group = raw[raw_pos]
					raw_pos += 1

					command = raw[raw_pos]
					raw_pos += 1
				except IndexError as e:
					print('-> IndexError', e)
					print(f'{fg.red}-> conn mode 0{fg.rs}')
					client.conn_mode = 0
					return

				lengths_are_4_bytes = flags_i & 1 != 0

				try:
					length = struct.unpack('<I', raw[raw_pos:raw_pos + 4])[0]
					raw_pos += 4
				except struct.error as e:
					print('-> struct.error', e)
					print(f'{fg.red}-> conn mode 0{fg.rs}')
					client.conn_mode = 0
					return

				payload_raw = raw[raw_pos:]
				payload_items = []

				print('-> group', group)
				print('-> command', command)
				print('-> length', length, type(length))

				if length >= 2048:
					print('-> length too big', length)
					return

				pos = 0
				while pos < length:
					if lengths_are_4_bytes:
						item_len = struct.unpack('<I', payload_raw[pos:pos + 4])[0]
						pos += 3
					else:
						item_len = payload_raw[pos]
					pos += 1

					# print('-> item len', item_len, type(item_len))

					item = payload_raw[pos:pos + item_len]
					# print('-> item content', item)

					payload_items.append(item.decode('utf-8'))
					pos += item_len

				commands.append([group, command, payload_items])
				raw_pos += length + 1
				# print('-> raw_pos', raw_pos)

			self._client_commands(sock, client, commands)
		else:
			print('-> no data')

			print(f'{fg.red}-> conn mode 0{fg.rs}')
			client.conn_mode = 0

	def _client_commands(self, sock: socket.socket, client: Client, commands: list): # pragma: no cover
		for command_raw in commands:
			group_i, command_i, payload = command_raw
			payload_len = len(payload)

			print('-> group', group_i, 'command', command_i)
			print('-> payload', payload)

			if group_i >= 2 and client.auth != 3:
				print('-> not authenticated', client.auth)
				print(f'{fg.red}-> conn mode 0{fg.rs}')
				client.conn_mode = 0
				continue

			if group_i == 0: # Basic
				if command_i == 0:
					print(f'{fg.red}-> OK command{fg.rs}')
			elif group_i == 1: # Connection, Authentication, etc
				if command_i == 1:
					print(f'{fg.red}-> ID command{fg.rs}')
					if client.auth & 2 != 0:
						print('-> skip, already authenticated')
						continue

					c_id = payload[0]
					print('-> c_id', c_id)

					if self._local_node == c_id:
						print('-> skip, ID is local node')
						print(f'{fg.red}-> conn mode 0{fg.rs}')
						client.conn_mode = 0
						continue

					c_switch = False
					c_has_contact_info = False
					if payload_len >= 2:
						addr = sock.getpeername()

						# Client sent contact info
						c_contact_addr, c_contact_port, c_has_contact_info = resolve_contact(payload[1], addr[0])

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

									_client = self._address_book.add_client(c_id, c_contact_addr, c_contact_port)
									_client.dir_mode = client.dir_mode
									_client.debug_add = 'id command, incoming, contact infos, not found by id, not found by addr:port, original: ' + client.debug_add

									c_switch = True
								else:
									print('-> client found B: {}'.format(_client))
									c_switch = True
							else:
								print('-> client found A: {}'.format(_client))
								c_switch = True

							_client.address = c_contact_addr
							_client.port = c_contact_port
						else:
							# Client sent no contact info
							_client = self._address_book.get_client(c_id)
							if _client == None:
								print('-> client not found C')

								_client = self._address_book.add_client(c_id)
								_client.dir_mode = client.dir_mode
								_client.debug_add = 'id command, incoming, no contact infos, not found by id, original: ' + client.debug_add
							else:
								print('-> client found C: {}'.format(_client))

							c_switch = True

					elif client.dir_mode == 'o':
						# Client is outgoing
						print('-> client is outgoing')

						_client = client

						if c_has_contact_info:
							print('-> client has contact infos')
							_client.address = c_contact_addr
							_client.port = c_contact_port
						else:
							print('-> client has NO contact infos')

					if _client.id == None:
						_client.id = c_id

					print(f'{fg.blue}Client A: {client}{fg.rs}')
					print(f'{fg.blue}Client B: {_client}{fg.rs}')

					_client.refresh_seen_at()
					_client.inc_meetings()

					_client.sock = sock
					_client.conn_mode = client.conn_mode
					_client.auth = client.auth | 2
					_client.actions = client.actions

					# Update Address Book because also an existing client can be updated
					self._address_book.changed()

					if c_switch and _client != client:
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
					print(f'{fg.red}-> PING command{fg.rs}')
					self._client_send_pong(sock)
				elif command_i == 3:
					print(f'{fg.red}-> PONG command{fg.rs}')
			elif group_i == 2: # Overlay, Address Book, Routing, etc
				if command_i == 1:
					print(f'{fg.red}-> GET_NEAREST_TO command{fg.rs}')

					try:
						node = overlay.Node(payload[0])
					except:
						print('-> invalid node')
						continue

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
					print(f'{fg.red}-> GET_NEAREST_TO RESPONSE command{fg.rs}')

					action = client.resolve_action('nearest_response')
					if action == None:
						print('-> not requested')
						continue

					print('-> action', action)

					nearest_client = None
					distance = overlay.Distance()
					for c_contact in payload:
						print('-> client contact', c_contact)

						c_id, c_contact = c_contact.split(':', 1)
						print(c_id, c_contact)

						c_addr, c_port, c_has_contact_info = resolve_contact(c_contact)
						print(c_addr, c_port, c_has_contact_info)

						if c_id == self._local_node.id:
							continue

						_client = self._address_book.get_client(c_id)
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

						bootstrap_count = action.data - 1
						print('-> bootstrap count', bootstrap_count)

						if bootstrap_count > 0 and not self._client_is_connected(nearest_client):
							self._client_connect(nearest_client)
							nearest_client.add_action('bootstrap', bootstrap_count)

				elif command_i == 3:
					print(f'{fg.red}-> REQUEST PUBLIC KEY FOR NODE command{fg.rs}')

					node_id = payload[0]
					print('-> node id', node_id)

					if node_id == self._local_node.id:
						print('-> local node')
						self._client_response_public_key_for_node(sock, node_id, self._public_key_b64)
					else:
						print('-> not local node')

						_client = self._address_book.get_client_by_id(node_id)
						if _client == None:
							print('-> client not found')
							# TODO implement
						else:
							print('-> client found', _client)

							if _client.has_public_key():
								print('-> client has public key')
								self._client_response_public_key_for_node(sock, node_id, _client.get_der_base64_public_key())
							else:
								print('-> client does not have public key')
								# TODO implement

				elif command_i == 4:
					print(f'{fg.red}-> RESPONSE PUBLIC KEY FOR NODE command{fg.rs}')

					node_id, public_key_raw = payload
					print('-> node id', node_id)
					print('-> public key raw', public_key_raw)

					try:
						node = overlay.Node.parse(node_id)
						print('-> node', node)
					except:
						print('-> invalid node')
						continue

					action = client.resolve_action('request_public_key_for_node', node.id, force_remove=True)
					if action == None:
						print('-> not requested')
						continue

					print('-> action', action)

					_client = self._address_book.get_client_by_id(node.id)
					if _client == None:
						print('-> client not found')

						_client = self._address_book.add_client(node.id)
						print('-> client added', _client)

						_client.load_public_key_from_base64_der(public_key_raw)

						if _client.verify_public_key():
							print('-> public key verified')
						else:
							print('-> public key not verified')
							self._address_book.remove_client(_client)
							_client = None
					else:
						print('-> client found', _client)
						# _client.set_public_key(public_key_txt)
						if _client.has_public_key():
							print('-> client has public key')
						else:
							_client.load_public_key_from_base64_der(public_key_raw)
							if _client.verify_public_key():
								print('-> public key verified')
								self._address_book.changed()
							else:
								print('-> public key not verified')
								_client.reset_public_key()

					if _client != None and _client.has_public_key():
						print('-> client is set and has public key')
						action.func(_client)

			elif group_i == 3: # Message
				if command_i == 1:
					print(f'{fg.red}-> SEND MESSAGE command{fg.rs}')

					message_uuid, message_target, message_data = payload

					print('-> message uuid', message_uuid)
					if not is_valid_uuid(message_uuid):
						print('-> invalid message uuid')
						continue

					if self._message_db.has_message(message_uuid):
						print('-> DB, message already exists')
						continue

					if self._message_queue.has_message(message_uuid):
						print('-> QUEUE, message already exists')
						continue

					try:
						message_target = overlay.Node.parse(message_target)
						print('-> message target', message_target)
					except:
						print('-> invalid message target')
						continue

					print('-> message data', message_data)

					message = Message(message_target.id, message_data)
					message.uuid = message_uuid
					message.is_encrypted = True

					if message_target == self._local_node:
						print('-> message target is local node')
						self._decrypt_message(message)
						self._message_db.add_message(message)
					else:
						print('-> message target is not local node')
						message.forwarded_to.append(client.id)
						self._message_queue.add_message(message)

			else:
				print('-> unknown group', group_i, 'command', command_i)
				print(f'{fg.red}-> conn mode 0{fg.rs}')
				client.conn_mode = 0

	def _client_send_ok(self, sock: socket.socket): # pragma: no cover
		print('-> Server._client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_id(self, sock: socket.socket): # pragma: no cover
		print('-> Server._client_send_id()')
		data = [
			self._config['id'],
		]
		if self.has_contact():
			data.append(self.get_contact())

		# print('-> data', data)
		self._client_write(sock, 1, 1, data)

	def _client_send_ping(self, sock: socket.socket): # pragma: no cover
		print('-> Server._client_send_ping()')
		self._client_write(sock, 1, 2)

	def _client_send_pong(self, sock: socket.socket): # pragma: no cover
		print('-> Server._client_send_pong()')
		self._client_write(sock, 1, 3)

	def _client_send_get_nearest_to(self, sock: socket.socket, id: str): # pragma: no cover
		print('-> Server._client_send_get_nearest_to()')
		self._client_write(sock, 2, 1, [id])

	def _client_send_get_nearest_response(self, sock: socket.socket, client_ids: list): # pragma: no cover
		print('-> Server._client_send_get_nearest_response()')
		self._client_write(sock, 2, 2, client_ids)

	def _client_request_public_key_for_node(self, sock: socket.socket, id: str): # pragma: no cover
		print('-> Server._client_request_public_key_for_node({})'.format(id))
		self._client_write(sock, 2, 3, [id])

	def _client_response_public_key_for_node(self, sock: socket.socket, id: str, public_key: str): # pragma: no cover
		print('-> Server._client_response_public_key_for_node()')
		print(type(id))
		print(type(public_key))
		print(public_key)

		self._client_write(sock, 2, 4, [id, public_key])

	def _client_send_message(self, sock: socket.socket, message: Message): # pragma: no cover
		print('-> Server._client_send_message()')
		if not message.is_encrypted:
			print('-> message not encrypted')
			return

		print('-> message:', type(message.body))

		self._client_write(sock, 3, 1, [
			message.uuid,
			message.target.id,
			message.body,
		])

	def _ipc_client_read(self, sock: socket.socket): # pragma: no cover
		print('{}-> Server._ipc_client_read(){}'.format(fg.blue, fg.rs))

		try:
			raw = sock.recv(2048)
		except TimeoutError as e:
			print('-> IPC TimeoutError', e)
			return
		except ConnectionResetError as e:
			print('-> IPC ConnectionResetError', e)
			raw = False

		if raw:
			raw_len = len(raw)

			raw_pos = 0
			commands = []
			while raw_pos < raw_len:
				try:
					flags_i = raw[raw_pos]
					raw_pos += 1

					group = raw[raw_pos]
					raw_pos += 1

					command = raw[raw_pos]
					raw_pos += 1
				except IndexError as e:
					print('-> IPC IndexError', e)
					print(f'{fg.red}-> IPC unregister socket{fg.rs}')
					self._selectors.unregister(sock)
					return

				lengths_are_4_bytes = flags_i & 1 != 0

				try:
					length = struct.unpack('<I', raw[raw_pos:raw_pos + 4])[0]
					raw_pos += 4
				except struct.error as e:
					print('-> IPC struct.error', e)
					print(f'{fg.red}-> IPC unregister socket{fg.rs}')
					self._selectors.unregister(sock)
					return

				payload_raw = raw[raw_pos:]
				payload_items = []

				print('-> group', group)
				print('-> command', command)
				print('-> length', length, type(length))

				if length >= 2048:
					print('-> IPC length too big', length)
					return

				pos = 0
				while pos < length:
					if lengths_are_4_bytes:
						item_len = struct.unpack('<I', payload_raw[pos:pos + 4])[0]
						pos += 3
					else:
						item_len = payload_raw[pos]
					pos += 1

					item = payload_raw[pos:pos + item_len]

					payload_items.append(item.decode('utf-8'))
					pos += item_len

				commands.append([group, command, payload_items])
				raw_pos += length + 1

			self._ipc_client_commands(sock, commands)
		else:
			print('-> no data')

			print(f'{fg.red}-> IPC unregister socket{fg.rs}')
			self._selectors.unregister(sock)

	def _ipc_client_commands(self, sock: socket.socket, commands: list): # pragma: no cover
		print('{}-> Server._ipc_client_commands(){}'.format(fg.blue, fg.rs))
		print('-> commands', commands)

		for command_raw in commands:
			group_i, command_i, payload = command_raw
			payload_len = len(payload)

			print('-> group', group_i, 'command', command_i)
			print('-> payload', payload)

			if group_i == 0: # Basic
				if command_i == 0:
					print('-> OK command')
			elif group_i == 1:
				if command_i == 0:
					print('-> SEND MESSAGE command')
					target, message = payload
					print('-> target', target)
					print('-> message', message)

					message = Message(target, message)
					self._message_queue.add_message(message)

					print('-> uuid', message.uuid)

					self._client_send_ok(sock)

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

				elif key.data['type'] == 'discovery':
					print('-> discovery')
					self._read_discovery(key.fileobj)

				elif key.data['type'] == 'ipc_server':
					self._accept_ipc_server(key.fileobj)

				elif key.data['type'] == 'ipc_client':
					self._ipc_client_read(key.fileobj)

			data_processed = True

		return data_processed # will be returned to the Scheduler

	def contact_address_book(self) -> bool:
		# print('-> Server.contact_address_book()')

		_clients = list(self._address_book.get_clients().values())
		_clients.sort(key=lambda _client: _client.meetings, reverse=True)

		# print('-> clients', len(_clients))

		connect_to_clients = []
		zero_meetings_clients = []
		for client in _clients:
			print('-> contact', client)

			if client.meetings > 0:
				if not self._client_is_connected(client):
					print('-> client is not connected A')
					connect_to_clients.append(client)
			else:
				zero_meetings_clients.append(client)

		zero_meetings_clients.sort(key=lambda _client: _client.distance(self._local_node))
		for client in zero_meetings_clients:
			print('-> zero_meetings_client', client)
			if not self._client_is_connected(client):
				print('-> client is not connected B')
				connect_to_clients.append(client)

		is_bootstrapping = self.is_bootstrap_phase()

		for client in connect_to_clients:
			if is_bootstrapping:
				client.add_action(Action('bootstrap', data=2)) # TODO: set to 7
			self._client_connect(client)

		return True

	def clean_up_address_book(self) -> bool:
		self._address_book.clean_up(self._local_node.id)
		return True

	def add_client(self, client: Client):
		self._clients.append(client)

	def handle_clients(self) -> bool:
		for client in self._clients:

			if client.conn_mode == 0:
				print('-> remove client', client)
				self._selectors.unregister(client.sock)
				client.sock.close()
				self._clients.remove(client)

				client.reset()

			if client.conn_mode == 1 and client.auth & 1 == 0:
				print('-> send ID')
				self._client_send_id(client.sock)
				client.auth |= 1

			if client.auth == 3:
				client.conn_mode = 2

		return True

	def ping_clients(self) -> bool:
		# print('-> Server.ping_clients() -> {}'.format(len(self._clients)))

		for client in self._clients:
			if client.conn_mode == 2:
				print('-> send PING')
				self._client_send_ping(client.sock)

		return True

	def save(self) -> bool:
		print('-> Server.save()')

		self._address_book.save()
		self._message_queue.save()
		self._message_db.save()

		return True

	def clean_up(self) -> bool:
		print('-> Server.clean_up()')

		self.clean_up_address_book()
		self._message_queue.clean_up()

		return True

	def debug_clients(self) -> bool: # pragma: no cover
		print('-> Server.debug_clients() -> {}'.format(len(self._clients)))

		for client in self._clients:
			print('-> debug', client)

		return True

	def client_actions(self) -> bool:
		print('-> Server.client_actions() -> {}'.format(len(self._clients)))

		had_actions = False

		for client in self._clients:
			print('-> client', client)

			for action in client.get_actions(soft_reset=True):
				print('-> action', action)

				if action.id == 'bootstrap':
					self._client_send_get_nearest_to(client.sock, self._local_node.id)
					client.add_action(Action('nearest_response', data=action.data))

				elif action.id == 'request_public_key_for_node':
					print('-> request_public_key_for_node', action)

					if action.data['step'] == 0:
						action.data['step'] += 1
						self._client_request_public_key_for_node(client.sock, action.data['target'].id)

				elif action.id == 'message':
					message = action.data
					print('-> message', message)

					self._client_send_message(client.sock, message)

					message.forwarded_to.append(client.id)
					message.is_delivered = client.id == message.target

					self._message_queue.changed()

				elif action.id == 'test':
					had_actions = True

		return had_actions

	def is_bootstrap_phase(self) -> bool:
		if self._config['bootstrap'] == 'default':
			clients_len = self._address_book.get_clients_len()
			bootstrap_clients_len = self._address_book.get_bootstrap_clients_len()
			return clients_len <= bootstrap_clients_len

		return bool(self._config['bootstrap'])

	def handle_message_queue(self) -> bool:
		print('-> Server.handle_message_queue()')

		for message_uuid, message in self._message_queue.get_messages():
			print('-> message', message)

			if message.is_delivered:
				print('-> message is delivered')
				continue

			if message.target == None:
				print('-> message has no target')
				continue

			if message.target == self._local_node.id:
				print('-> message is for me')
				continue

			clients = self._address_book.get_nearest_to(message.target)
			print('-> clients', clients)

			for client in clients:
				print('-> client', client)
				if self._client_is_connected(client):
					print('-> client is connected')
				else:
					print('-> client is not connected C')
					self._client_connect(client)

			if message.is_encrypted:
				print('-> message is encrypted')

				for client in clients:
					print('-> client', client)
					print('-> forwarded_to', message.forwarded_to)

					if not self._client_is_connected(client):
						print('-> client is not connected D')
						continue

					if client.id in message.forwarded_to:
						print('-> client already received message')
						continue

					if client.has_action('message', message.uuid):
						print('-> client already has action')
						continue

					# message.forwarded_to.append(client.id)
					# self._message_queue.changed()

					print('-> add action for message')
					action = Action('message', message.uuid, data=message)
					client.add_action(action)
			else:
				print('-> message is not encrypted')

				client = self._address_book.get_client_by_id(message.target.id)
				if client == None or not client.has_public_key():
					print('-> client is set and has not public key')
					for client in clients:
						print('-> client', client)

						if not client.has_action('request_public_key_for_node', message.target.id):
							action_data = {
								'target': message.target,
								'level': 0, # 0 = original sender, 1 = relay
								'step': 0, # 0 = request created, 1 = send request to client, 2 = response
							}
							action = Action('request_public_key_for_node', message.target.id, data=action_data)
							action.is_strong = True
							action.func = lambda _client: self._encrypt_message(message, _client)

							client.add_action(action)
				else:
					self._encrypt_message(message, client)

		return True

	def _encrypt_message(self, message: Message, client: Client):
		print('-> Server._encrypt_message() -> {}'.format(message.is_encrypted))
		print('-> message', message)
		print('-> client', client)

		if message.is_encrypted:
			print('-> message is already encrypted')
			return

		# base64 decode body
		body = base64.b64decode(message.body)
		print('-> body', body)

		encrypted = client.encrypt(body)
		print('-> encrypted', encrypted)

		encoded = base64.b64encode(encrypted)
		print('-> b64 encoded', encoded)

		decoded = encoded.decode('utf-8')
		print('-> b64 decoded', decoded)

		message.body = decoded
		message.is_encrypted = True

		self._message_queue.changed()

	def _decrypt_message(self, message: Message):
		print('-> Server._decrypt_message()')

		if not message.is_encrypted:
			print('-> message is not encrypted')
			return

		print('-> body', message.body)

		# base64 decode body
		decoded = base64.b64decode(message.body)
		print('-> decoded', decoded)

		decrypted_b = self._private_key.decrypt(
			decoded,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		print('-> decrypted', decrypted_b)

		encoded = base64.b64encode(decrypted_b)
		print('-> encoded', encoded)

		decoded = encoded.decode('utf-8')
		print('-> decoded', decoded)

		message.body = decoded
		message.is_encrypted = False
