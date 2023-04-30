
import logging
import os
import socket
import selectors
import struct
import base64
import uuid
import datetime as dt

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from lib.client import Client, Action
from lib.address_book import AddressBook
from lib.helper import resolve_contact, is_valid_uuid
from lib.mail import Mail, Queue as MailQueue, Database as MailDatabase
from lib.network import Network
from lib.cash import Cash
import lib.overlay as overlay

VERSION = 1

class Server(Network):
	_config: dict
	_selectors: selectors.DefaultSelector
	_main_server_socket: socket.socket
	_discovery_socket: socket.socket
	_ipc_server_socket: socket.socket
	_address_book: AddressBook
	_mail_queue: MailQueue
	_mail_db: MailDatabase
	_hostname: str
	_lan_ip: str
	_clients: list
	_local_node: overlay.Node
	_public_key_b64: str
	_pid_file_path: str
	_wrote_pid_file: bool
	_client_auth_timeout: dt.timedelta
	_client_action_retention_time: dt.timedelta

	def __init__(self, config: dict = {}):
		self._host_name = socket.gethostname()
		self._lan_ip = socket.gethostbyname(self._host_name)
		self._clients = []
		self._selectors = selectors.DefaultSelector()
		self._public_key = None
		self._public_key_b64 = None
		self._private_key = None
		self._address_book = None
		self._mail_queue = None
		self._mail_db = None
		self._wrote_pid_file = False
		self._client_auth_timeout = None
		self._client_action_retention_time = None

		self._logger = logging.getLogger('server')
		self._logger.info('init()')

		self._config = config
		if 'address_book' not in self._config:
			self._config['address_book'] = {
				'max_clients': 20,
				'client_retention_time': 24,
			}

		if 'client' not in self._config:
			self._config['client'] = {
				'auth_timeout': 2,
				'action_retention_time': 5,
			}
		self._client_auth_timeout = dt.timedelta(seconds=self._config['client']['auth_timeout'])
		self._client_action_retention_time = dt.timedelta(minutes=self._config['client']['action_retention_time'])

		if 'data_dir' in self._config:
			self._pid_file_path = os.path.join(self._config['data_dir'], 'server.pid')
			self._write_pid_file()

			if 'public_key_file' not in self._config:
				self._config['public_key_file'] = os.path.join(self._config['data_dir'], 'public_key.pem')
			if 'private_key_file' not in self._config:
				self._config['private_key_file'] = os.path.join(self._config['data_dir'], 'private_key.pem')

			if 'keys_dir' not in self._config:
				self._config['keys_dir'] = os.path.join(self._config['data_dir'], 'keys')
			if not os.path.isdir(self._config['keys_dir']):
				os.mkdir(self._config['keys_dir'])

			address_book_path = os.path.join(self._config['data_dir'], 'address_book.json')
			self._address_book = AddressBook(address_book_path, self._config)
			self._address_book.load()

			bootstrap_path = os.path.join(self._config['data_dir'], 'bootstrap.json')
			if os.path.isfile(bootstrap_path):
				self._address_book.add_bootstrap(bootstrap_path)

			mail_queue_path = os.path.join(self._config['data_dir'], 'mail_queue.json')
			self._mail_queue = MailQueue(mail_queue_path, self._config)
			self._mail_queue.load()

			mail_db_path = os.path.join(self._config['data_dir'], 'mail_db.json')
			self._mail_db = MailDatabase(mail_db_path)
			self._mail_db.load()

		if 'challenge' not in self._config:
			self._config['challenge'] = {'min': 15, 'max': 20}

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
		self._logger.info('__del__()')
		self._selectors.close()

		if self._address_book:
			self._address_book.save()

		if self._mail_queue:
			self._mail_queue.save()

		if self._mail_db:
			self._mail_db.save()

		self._remove_pid_file()

		self._logger.info('__del__() end')

	def _write_pid_file(self):
		if os.path.isfile(self._pid_file_path):
			self._logger.error('Another instance of FluxChat is already running.')
			self._logger.error('If this is not the case, delete the file: %s', self._pid_file_path)
			exit(1)

		with open(self._pid_file_path, 'w') as fh:
			fh.write(str(os.getpid()))
		self._wrote_pid_file = True

	def _remove_pid_file(self):
		self._logger.info('_remove_pid_file()')
		if not self._wrote_pid_file:
			return
		if os.path.isfile(self._pid_file_path):
			os.remove(self._pid_file_path)

	def start(self): # pragma: no cover
		self._logger.info('start')

		self._load_public_key_from_pem_file()
		self._load_private_key_from_pem_file()

		self._main_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._main_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		try:
			self._logger.debug('bind %s:%s', self._config['address'], self._config['port'])
			self._main_server_socket.bind((self._config['address'], self._config['port']))
		except OSError as e:
			self._logger.error('OSError: %s', e)
			raise e

		self._logger.debug('listen')
		self._main_server_socket.listen()
		self._main_server_socket.setblocking(False)
		self._selectors.register(self._main_server_socket, selectors.EVENT_READ, data={'type': 'main_server'})

		if 'discovery' in self._config and self._config['discovery']['enabled']:
			self._logger.debug('discovery')

			self._discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
			self._discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			self._discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

			try:
				self._discovery_socket.bind(('', self._config['discovery']['port']))
			except OSError as e:
				self._logger.error('OSError: %s', e)
				raise e

			self._discovery_socket.setblocking(False)

			if self.has_contact():
				self._logger.debug('send broadcast')
				# TODO for production: set port to self._config['discovery']['port'] instead of hard-coded 26000
				res = self._discovery_socket.sendto(self.get_contact().encode('utf-8'), ('<broadcast>', 26000))
				self._logger.debug('res %s', res)

			self._selectors.register(self._discovery_socket, selectors.EVENT_READ, data={'type': 'discovery'})

		if 'ipc' in self._config and self._config['ipc']['enabled']:
			ipc_addr = (self._config['ipc']['address'], self._config['ipc']['port'])
			self._logger.debug('ipc %s', ipc_addr)

			self._ipc_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self._ipc_server_socket.bind(ipc_addr)
			self._ipc_server_socket.listen()
			self._ipc_server_socket.setblocking(False)

			self._selectors.register(self._ipc_server_socket, selectors.EVENT_READ, data={'type': 'ipc_server'})

	def _load_private_key_from_pem_file(self) -> None:
		self._logger.debug('load private key from pem file')

		if not os.path.isfile(self._config['private_key_file']):
			raise Exception('private key file not found: {}'.format(self._config['private_key_file']))

		with open(self._config['private_key_file'], 'rb') as f:
			self._private_key = serialization.load_pem_private_key(f.read(), password=None)

	def _load_public_key_from_pem_file(self) -> None:
		self._logger.debug('load public key from pem file')

		if not os.path.isfile(self._config['public_key_file']):
			raise Exception('public key file not found: {}'.format(self._config['public_key_file']))

		with open(self._config['public_key_file'], 'rb') as f:
			self._public_key = serialization.load_pem_public_key(f.read())

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
		self._logger.debug('_client_is_connected()')

		ffunc = lambda _client: _client.uuid == client.uuid or _client.id == client.id or _client.address == client.address and _client.port == client.port
		clients = list(filter(ffunc, self._clients))

		return len(clients) > 0

	def _accept_main_server(self, server_sock: socket.socket): # pragma: no cover
		self._logger.debug('_accept_main_server()')

		client_sock, addr = server_sock.accept()
		client_sock.setblocking(False)

		# self._logger.debug('client_sock: %s', client_sock)
		# self._logger.debug('addr: %s', addr)
		# self._logger.debug('accepted: %s:%d', addr[0], addr[1])

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

		self._logger.debug('_accept_main_server() client: %s', client)

	def _read_discovery(self, server_sock: socket.socket): # pragma: no cover
		self._logger.debug('_read_discovery()')

		data, addr = server_sock.recvfrom(1024)
		c_contact = data.decode('utf-8')

		self._logger.debug('data: %s', data)
		self._logger.debug('addr: %s', addr)

		if addr[0] == self._lan_ip and addr[1] == self._config['discovery']['port']:
			self._logger.debug('skip self')
			return

		c_contact_addr, c_contact_port, c_has_contact_info = resolve_contact(c_contact, addr[0])

		if not c_has_contact_info:
			return

		client = self._address_book.get_client_by_addr_port(c_contact_addr, c_contact_port)
		if client == None:
			client = self._address_book.add_client(addr=c_contact_addr, port=c_contact_port)
			client.debug_add = 'discovery, contact: {}'.format(c_contact)
		else:
			self._logger.debug('client: %s', client)

		self._logger.debug('read_discovery client: %s', client)

		self._client_connect(client)

	def _accept_ipc_server(self, server_sock: socket.socket): # pragma: no cover
		self._logger.debug('_accept_ipc_server()')

		client_sock, addr = server_sock.accept()
		client_sock.setblocking(False)

		self._selectors.register(client_sock, selectors.EVENT_READ, data={
			'type': 'ipc_client',
		})

	def _client_connect(self, client: Client) -> bool: # pragma: no cover
		self._logger.debug('_client_connect(%s)', client)

		# TODO: activate for production
		# if client.address == self._lan_ip and os.environ.get('ALLOW_SELF_CONNECT') != '1':
		# 	self._logger.debug('skip, client.address == self._lan_ip')
		# 	return False
		if client.node == self._local_node:
			self._logger.debug('skip, client.node == self._local_node')
			return False
		if client.address == None or client.port == None:
			self._logger.debug('skip, client.address == None or client.port == None')
			return False

		client.conn_mode = 1
		client.dir_mode = 'o'
		client.refresh_used_at()

		client.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client.sock.settimeout(2)
		try:
			self._logger.error('client.sock.connect to %s:%s', client.address, client.port)
			client.sock.connect((client.address, client.port))
			self._logger.error('client.sock.connect done')
		except ConnectionRefusedError as e:
			self._logger.error('ConnectionRefusedError: %s', e)
			return False
		except TimeoutError as e:
			self._logger.error('TimeoutError: %s', e)
			return False
		except socket.timeout as e:
			self._logger.error('socket.timeout: %s', e)
			return False

		client.sock.settimeout(None)
		client.sock.setblocking(False)

		self._selectors.register(client.sock, selectors.EVENT_READ, data={
			'type': 'main_client',
			'client': client,
		})

		self._clients.append(client)

		self._logger.debug('_client_connect done')
		return True

	def _client_read(self, sock: socket.socket, client: Client): # pragma: no cover
		self._logger.debug('_client_read(%s)', client)

		try:
			raw = sock.recv(2048)
		except TimeoutError as e:
			self._logger.debug('TimeoutError: %s', e)
			return
		except ConnectionResetError as e:
			self._logger.debug('ConnectionResetError: %s', e)
			raw = False

		if raw:
			raw_len = len(raw)
			self._logger.debug('recv raw %d %s', raw_len, raw)

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
					self._logger.debug('IndexError: %s', e)
					self._logger.debug('conn mode 0')
					client.conn_mode = 0
					client.conn_msg = 'array index out of range'
					return

				lengths_are_4_bytes = flags_i & 1 != 0

				try:
					length = struct.unpack('<I', raw[raw_pos:raw_pos + 4])[0]
					raw_pos += 4
				except struct.error as e:
					self._logger.debug('struct.error: %s', e)
					self._logger.debug('conn mode 0')
					client.conn_mode = 0
					client.conn_msg = 'unpack error'
					return

				payload_raw = raw[raw_pos:]
				payload_items = []

				self._logger.debug('group: %d', group)
				self._logger.debug('command: %d', command)
				self._logger.debug('length: %d %s', length, type(length))

				if length >= 2048:
					self._logger.error('length too big: %d', length)
					return

				pos = 0
				while pos < length:
					if lengths_are_4_bytes:
						item_len = struct.unpack('<I', payload_raw[pos:pos + 4])[0]
						pos += 3
					else:
						item_len = payload_raw[pos]
					pos += 1

					# self._logger.debug('item len: %d %s', item_len, type(item_len))

					item = payload_raw[pos:pos + item_len]
					# self._logger.debug('item content: %s', item)

					payload_items.append(item.decode('utf-8'))
					pos += item_len

				commands.append([group, command, payload_items])
				raw_pos += length + 1
				# self._logger.debug('raw_pos: %d', raw_pos)

			self._client_commands(sock, client, commands)
		else:
			self._logger.debug('no data')

			self._logger.debug('conn mode 0')
			client.conn_mode = 0
			client.conn_msg = 'no data'

	def _client_commands(self, sock: socket.socket, client: Client, commands: list): # pragma: no cover
		for command_raw in commands:
			group_i, command_i, payload = command_raw
			payload_len = len(payload)

			self._logger.debug('group: %d, command %d', group_i, command_i)
			self._logger.debug('payload: %s', payload)

			if group_i >= 2 and client.auth != 15:
				self._logger.debug('not authenticated: %s', client.auth)
				self._logger.debug('conn mode 0')
				client.conn_mode = 0
				client.conn_msg = 'not authenticated'
				continue

			if group_i == 0: # Basic
				if command_i == 0:
					self._logger.debug('OK command')

			elif group_i == 1: # Connection, Authentication, etc
				if command_i == 1:
					self._logger.debug('CHALLENGE command')

					if client.auth & 2 != 0:
						self._logger.debug('skip, already got CHALLENGE')
						continue

					client.auth |= 2
					client.challenge[0] = int(payload[0]) # min
					client.challenge[1] = int(payload[1]) # max
					client.challenge[2] = str(payload[2]) # data

					self._logger.debug('challenge: %s', client.challenge)

					c_data_len = len(client.challenge[2])
					if c_data_len > 36:
						self._logger.warning('skip, challenge data too long: %d > 36', c_data_len)
						self._logger.debug('conn mode 0')
						client.conn_mode = 0
						client.conn_msg = 'challenge data too long'
						continue

					if client.challenge[0] > self._config['challenge']['max']:
						self._logger.warning('skip, challenge min is too big: %d > %d', client.challenge[0], self._config['challenge']['max'])
						self._logger.debug('conn mode 0')
						client.conn_mode = 0
						client.conn_msg = 'challenge min is too big'
						continue

					cash = Cash(client.challenge[2], client.challenge[0])
					self._logger.debug('mine')
					cash.mine()
					self._logger.debug('mine done')
					client.challenge[3] = cash.proof
					client.challenge[4] = cash.nonce

					self._logger.debug('challenge: %s', client.challenge)

				elif command_i == 2:
					self._logger.debug('ID command')

					if client.auth & 2 == 0:
						self._logger.warning('skip, client has first to send CHALLENGE')
						continue

					if client.auth & 8 != 0:
						self._logger.debug('skip, already authenticated')
						continue

					c_version = int.from_bytes(payload[0].encode('utf-8'), 'little')
					c_id = payload[1]
					c_cc_proof = payload[2]
					c_cc_nonce = int(payload[3])

					self._logger.debug('c_version: %s', c_version)
					self._logger.debug('c_id: %s', c_id)
					self._logger.debug('c_cc_proof: %s', c_cc_proof)
					self._logger.debug('c_cc_nonce: %s', c_cc_nonce)

					# Local
					if self._local_node == c_id:
						self._logger.debug('skip, ID is local node')
						self._logger.debug('conn mode 0')
						client.conn_mode = 0
						client.conn_msg = 'ID is local node'
						continue

					# Version
					# if c_version < self._config['version']['min']:
					# 	self._logger.warning('skip, version is too old: %d < %d', c_version, self._config['version']['min'])
					# 	self._logger.debug('conn mode 0')
					# 	client.conn_mode = 0
					# 	client.conn_msg = 'version is too old'
					# 	continue

					# Challenge
					if not client.cash.verify(c_cc_proof, c_cc_nonce):
						self._logger.warning('skip, challenge not verified')
						self._logger.debug('conn mode 0')
						client.conn_mode = 0
						client.conn_msg = 'challenge not verified'
						continue
					self._logger.debug('cash verified')

					# Contact info
					c_has_contact_info = False
					if payload_len >= 5:
						addr = sock.getpeername()

						# Client sent contact info
						c_contact_addr, c_contact_port, c_has_contact_info = resolve_contact(payload[4], addr[0])

					c_switch = False
					if client.dir_mode == 'i':
						# Client is incoming
						self._logger.debug('client is incoming')

						if c_has_contact_info:
							# Client sent contact info
							_client = self._address_book.get_client_by_id(c_id)
							if _client == None:
								self._logger.debug('client not found A')

								_client = self._address_book.get_client_by_addr_port(c_contact_addr, c_contact_port)
								if _client == None:
									self._logger.debug('client not found B')

									_client = self._address_book.add_client(c_id, c_contact_addr, c_contact_port)
									_client.dir_mode = client.dir_mode
									_client.debug_add = 'id command, incoming, contact infos, not found by id, not found by addr:port, original: ' + client.debug_add

									c_switch = True
								else:
									self._logger.debug('client found B: %s', _client)
									c_switch = True
							else:
								self._logger.debug('client found A: %s', _client)
								c_switch = True

							_client.address = c_contact_addr
							_client.port = c_contact_port
						else:
							# Client sent no contact info
							_client = self._address_book.get_client_by_id(c_id)
							if _client == None:
								self._logger.debug('client not found C')

								_client = self._address_book.add_client(c_id)
								_client.dir_mode = client.dir_mode
								_client.debug_add = 'id command, incoming, no contact infos, not found by id, original: ' + client.debug_add
							else:
								self._logger.debug('client found C: {}'.format(_client))

							c_switch = True

					elif client.dir_mode == 'o':
						# Client is outgoing
						self._logger.debug('client is outgoing')

						_client = client

						if c_has_contact_info:
							self._logger.debug('client has contact infos')
							_client.address = c_contact_addr
							_client.port = c_contact_port
						else:
							self._logger.debug('client has NO contact infos')

					if _client.id == None:
						_client.id = c_id

					self._logger.debug('Client A: %s', client)
					self._logger.debug('Client B: %s', _client)

					_client.refresh_seen_at()
					_client.refresh_used_at()
					_client.inc_meetings()

					_client.sock = sock
					_client.conn_mode = client.conn_mode
					_client.auth = client.auth | 8
					_client.actions = client.actions
					_client.challenge = client.challenge

					# Update Address Book because also an existing client can be updated
					self._address_book.changed()

					if c_switch and _client != client:
						self._logger.debug('switch client')
						self._clients.remove(client)
						self._clients.append(_client)

						self._selectors.unregister(sock)
						self._selectors.register(_client.sock, selectors.EVENT_READ, data={
							'type': 'main_client',
							'client': _client,
						})

					self._client_send_ok(_client.sock)

					self._logger.debug('Client Z: %s', _client)
				elif command_i == 3:
					self._logger.debug('PING command')
					self._client_send_pong(sock)
				elif command_i == 4:
					self._logger.debug('PONG command')

			elif group_i == 2: # Overlay, Address Book, Routing, etc
				if command_i == 1:
					self._logger.debug('GET_NEAREST_TO command')

					try:
						node = overlay.Node(payload[0])
					except:
						self._logger.debug('invalid node')
						continue

					client_ids = []
					clients = self._address_book.get_nearest_to(node, with_contact_infos=True)
					for _client in clients:
						self._logger.debug('client: %s %s', _client, _client.distance(node))
						if _client.id != self._local_node.id and _client.id != node.id:
							contact_infos = [_client.id, _client.address, str(_client.port)]
							self._logger.debug('contact infos: %s', contact_infos)
							client_ids.append(':'.join(contact_infos))

					self._client_send_get_nearest_response(sock, client_ids)

				elif command_i == 2:
					self._logger.debug('GET_NEAREST_TO RESPONSE command')

					action = client.resolve_action('nearest_response')
					if action == None:
						self._logger.debug('not requested')
						continue

					self._logger.debug('action: %s', action)

					nearest_client = None
					distance = overlay.Distance()
					for c_contact in payload:
						self._logger.debug('client contact A: %s', c_contact)

						c_id, c_contact = c_contact.split(':', 1)
						self._logger.debug('client contact B: %s %s', c_id, c_contact)

						c_addr, c_port, c_has_contact_info = resolve_contact(c_contact)
						self._logger.debug('client contact C: %s %s %s', c_addr, c_port, c_has_contact_info)

						if c_id == self._local_node.id:
							continue

						_client = self._address_book.get_client_by_id(c_id)
						if _client == None:
							self._logger.debug('client not found')
							_client = self._address_book.add_client(c_id, c_addr, c_port)
							_client.debug_add = 'nearest response, not found by id'

							_c_distance = _client.distance(self._local_node)
							if _c_distance < distance:
								# distance = _client.distance(self._local_node)
								distance = _c_distance
								self._logger.debug('new distance: %s', distance)

								nearest_client = _client
						else:
							self._logger.debug('client found: %s', _client)

					if nearest_client != None:
						self._logger.debug('nearest client: %s', nearest_client)

						bootstrap_count = action.data - 1
						self._logger.debug('bootstrap count: %d', bootstrap_count)

						if bootstrap_count > 0 and not self._client_is_connected(nearest_client):
							self._client_connect(nearest_client)
							nearest_client.add_action('bootstrap', bootstrap_count)

				elif command_i == 3:
					self._logger.debug('REQUEST PUBLIC KEY FOR NODE command')

					is_relay = False
					fwd_clients = []
					node_id = payload[0]
					self._logger.debug('node id: %s', node_id)

					try:
						target = overlay.Node.parse(node_id)
					except:
						self._logger.debug('invalid node')
						continue

					if target == self._local_node:
						self._logger.debug('local node')
						self._client_response_public_key_for_node(sock, target.id, self._public_key_b64)
					else:
						self._logger.debug('not local node')

						_client = self._address_book.get_client_by_id(target.id)
						if _client == None:
							self._logger.debug('client not found')

							is_relay = True
							fwd_clients = self._address_book.get_nearest_to(target, with_contact_infos=True)
						else:
							self._logger.debug('client found: %s', _client)

							if _client.has_public_key():
								self._logger.debug('client has public key')

								self._client_response_public_key_for_node(sock, target.id, _client.get_der_base64_public_key())
							else:
								self._logger.debug('client does not have public key')

								self._logger.debug('relay')
								is_relay = True
								fwd_clients = [_client]

					if is_relay:
						for _client in fwd_clients:
							if client == _client:
								self._logger.debug('client is self')
								continue

							self._logger.debug('client: %s', _client)

							if _client.has_action('request_public_key_for_node', target.id):
								self._logger.debug('client already has action request_public_key_for_node/%s', target.id)
							else:
								self._logger.debug('create action request_public_key_for_node/%s', target.id)

								action = self._create_action_request_public_key_for_node(target, 'r')

								action.func = lambda _arg_client: self._client_response_public_key_for_node(sock, target.id, _arg_client.get_der_base64_public_key())

								_client.add_action(action)

				elif command_i == 4:
					self._logger.debug('RESPONSE PUBLIC KEY FOR NODE command')

					node_id, public_key_raw = payload
					self._logger.debug('node id: %s', node_id)
					self._logger.debug('public key raw: %s', public_key_raw)

					try:
						node = overlay.Node.parse(node_id)
						self._logger.debug('node: %s', node)
					except:
						self._logger.debug('invalid node')
						continue

					action = client.resolve_action('request_public_key_for_node', node.id, force_remove=True)
					if action == None:
						self._logger.debug('not requested')
						continue

					self._logger.debug('action: %s', action)

					_client = self._address_book.get_client_by_id(node.id)
					if _client == None:
						self._logger.debug('client not found')

						_client = Client()
						_client.debug_add = 'public key response'
						_client.set_id(node.id)
						_client.load_public_key_from_base64_der(public_key_raw)

						if _client.verify_public_key():
							self._logger.debug('public key verified')

							self._address_book.append_client(_client)
							self._logger.debug('client added: %s', _client)
						else:
							self._logger.debug('public key not verified')
							_client = None
					else:
						self._logger.debug('client found: %s', _client)

						if _client.has_public_key():
							self._logger.debug('client has public key')
						else:
							_client.load_public_key_from_base64_der(public_key_raw)
							if _client.verify_public_key():
								self._logger.debug('public key verified')
								self._address_book.changed()
							else:
								self._logger.debug('public key not verified')
								_client.reset_public_key()

					if _client != None and _client.has_public_key():
						self._logger.debug('client is set and has public key')
						self._logger.debug('client: %s', _client)
						action.func(_client)

			elif group_i == 3: # Mail
				if command_i == 1:
					self._logger.debug('SEND MAIL command')

					mail_uuid, mail_target, mail_data = payload

					self._logger.debug('mail uuid: %s', mail_uuid)
					if not is_valid_uuid(mail_uuid):
						self._logger.debug('invalid mail uuid')
						continue

					if self._mail_db.has_mail(mail_uuid):
						self._logger.debug('DB, mail already exists')
						continue

					if self._mail_queue.has_mail(mail_uuid):
						self._logger.debug('QUEUE, mail already exists')
						continue

					try:
						mail_target = overlay.Node.parse(mail_target)
						self._logger.debug('mail target: %s', mail_target)
					except:
						self._logger.debug('invalid mail target')
						continue

					self._logger.debug('mail data: %s', mail_data)

					mail = Mail(mail_target.id, mail_data)
					mail.uuid = mail_uuid
					mail.is_encrypted = True
					mail.received_now()

					if mail_target == self._local_node:
						self._logger.debug('mail target is local node')
						self._decrypt_mail(mail)
						self._mail_db.add_mail(mail)
					else:
						self._logger.debug('mail target is not local node')
						mail.forwarded_to.append(client.id)
						self._mail_queue.add_mail(mail)

			else:
				self._logger.debug('unknown group %d, command %d', group_i, command_i)
				self._logger.debug('conn mode 0')
				client.conn_mode = 0
				client.conn_msg = 'unknown group %d, command %d' % (group_i, command_i)

	def _client_send_ok(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_challenge(self, sock: socket.socket, challenge: str): # pragma: no cover
		self._logger.debug('_client_send_challenge(%s)', challenge)

		self._client_write(sock, 1, 1, [
			str(self._config['challenge']['min']),
			str(self._config['challenge']['max']),
			challenge,
		])

	def _client_send_id(self, sock: socket.socket, proof: str, nonce: str): # pragma: no cover
		self._logger.debug('_client_send_id(%s, %s)', proof, nonce)
		data = [
			VERSION,
			self._config['id'],
			proof,
			nonce,
		]
		if self.has_contact():
			data.append(self.get_contact())

		# self._logger.debug('data: %s', data)
		self._client_write(sock, 1, 2, data)

	def _client_send_ping(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_client_send_ping()')
		self._client_write(sock, 1, 3)

	def _client_send_pong(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_client_send_pong()')
		self._client_write(sock, 1, 4)

	def _client_send_get_nearest_to(self, sock: socket.socket, id: str): # pragma: no cover
		self._logger.debug('_client_send_get_nearest_to()')
		self._client_write(sock, 2, 1, [id])

	def _client_send_get_nearest_response(self, sock: socket.socket, client_ids: list): # pragma: no cover
		self._logger.debug('_client_send_get_nearest_response()')
		self._client_write(sock, 2, 2, client_ids)

	def _client_request_public_key_for_node(self, sock: socket.socket, id: str): # pragma: no cover
		self._logger.debug('_client_request_public_key_for_node(%s)', id)
		self._client_write(sock, 2, 3, [id])

	def _client_response_public_key_for_node(self, sock: socket.socket, id: str, public_key: str): # pragma: no cover
		self._logger.debug('_client_response_public_key_for_node()')
		# self._logger.debug('type: %s', type(id))
		# self._logger.debug('type: %s', type(public_key))
		self._logger.debug('public key: %s', public_key)

		self._client_write(sock, 2, 4, [id, public_key])

	def _client_send_mail(self, sock: socket.socket, mail: Mail): # pragma: no cover
		self._logger.debug('_client_send_mail()')
		if not mail.is_encrypted:
			self._logger.debug('mail not encrypted')
			return

		self._logger.debug('mail: %s', type(mail.body))

		self._client_write(sock, 3, 1, [
			mail.uuid,
			mail.target.id,
			mail.body,
		])

	def _ipc_client_read(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_ipc_client_read()')

		try:
			raw = sock.recv(2048)
		except TimeoutError as e:
			self._logger.error('IPC TimeoutError: %s', e)
			return
		except ConnectionResetError as e:
			self._logger.error('IPC ConnectionResetError: %s', e)
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
					self._logger.error('IPC IndexError: %s', e)
					self._logger.error('IPC unregister socket')
					self._selectors.unregister(sock)
					return

				lengths_are_4_bytes = flags_i & 1 != 0

				try:
					length = struct.unpack('<I', raw[raw_pos:raw_pos + 4])[0]
					raw_pos += 4
				except struct.error as e:
					self._logger.error('IPC struct.error: %s', e)
					self._logger.error('IPC unregister socket')
					self._selectors.unregister(sock)
					return

				payload_raw = raw[raw_pos:]
				payload_items = []

				self._logger.debug('IPC group: %d', group)
				self._logger.debug('IPC command: %d', command)
				self._logger.debug('IPC length: %d %s', length, type(length))

				if length >= 2048:
					self._logger.error('IPC length too big: %d', length)
					return

				pos = 0
				while pos < length:
					self._logger.debug('IPC pos: %d', pos)
					if lengths_are_4_bytes:
						item_len = struct.unpack('<I', payload_raw[pos:pos + 4])[0]
						pos += 3
					else:
						item_len = payload_raw[pos]
					pos += 1

					self._logger.debug('IPC item len: %d', item_len)

					item = payload_raw[pos:pos + item_len]
					self._logger.debug('IPC item: %s', item)

					payload_items.append(item.decode('utf-8'))
					pos += item_len

				commands.append([group, command, payload_items])
				raw_pos += length + 1

			self._ipc_client_commands(sock, commands)
		else:
			self._logger.debug('no data')

			self._logger.debug('IPC unregister socket')
			self._selectors.unregister(sock)

	def _ipc_client_commands(self, sock: socket.socket, commands: list): # pragma: no cover
		self._logger.debug('_ipc_client_commands()')
		self._logger.debug('commands: %s', commands)

		for command_raw in commands:
			group_i, command_i, payload = command_raw
			payload_len = len(payload)

			self._logger.debug('group %d, command %d', group_i, command_i)
			self._logger.debug('payload: %s', payload)

			if group_i == 0: # Basic
				if command_i == 0:
					self._logger.debug('OK command')

			elif group_i == 1:
				if command_i == 0:
					self._logger.debug('SEND MAIL command')

					target, mail = payload
					self._logger.debug('target: %s', target)
					self._logger.debug('mail: %s', mail)

					mail = Mail(target, mail)
					self._mail_queue.add_mail(mail)

					self._logger.debug('uuid: %s', mail.uuid)

					self._client_send_ok(sock)

			elif group_i == 2:
				if command_i == 0:
					self._logger.debug('SAVE command')
					self.save()

	def handle_sockets(self) -> bool:
		# self._logger.debug('handle_sockets()')

		data_processed = False

		events = self._selectors.select(timeout=0)
		for key, mask in events:
			if key.data != None:
				if key.data['type'] == 'main_server':
					self._accept_main_server(key.fileobj)

				elif key.data['type'] == 'main_client':
					self._client_read(key.fileobj, key.data['client'])

				elif key.data['type'] == 'discovery':
					self._logger.debug('discovery')
					self._read_discovery(key.fileobj)

				elif key.data['type'] == 'ipc_server':
					self._accept_ipc_server(key.fileobj)

				elif key.data['type'] == 'ipc_client':
					self._ipc_client_read(key.fileobj)

			data_processed = True

		return data_processed # will be returned to the Scheduler

	def contact_address_book(self) -> bool:
		self._logger.debug('contact_address_book()')

		_clients = list(self._address_book.get_clients().values())
		_clients.sort(key=lambda _client: _client.meetings, reverse=True)

		# self._logger.debug('clients: %d', len(_clients))

		connect_to_clients = []
		zero_meetings_clients = []
		for client in _clients:
			self._logger.debug('contact: %s', client)

			if client.meetings > 0:
				if not self._client_is_connected(client):
					self._logger.debug('client is not connected A')
					connect_to_clients.append(client)
			else:
				zero_meetings_clients.append(client)

		zero_meetings_clients.sort(key=lambda _client: _client.distance(self._local_node))
		for client in zero_meetings_clients:
			self._logger.debug('zero_meetings_client: %s', client)
			if not self._client_is_connected(client):
				self._logger.debug('client is not connected B')
				connect_to_clients.append(client)

		is_bootstrapping = self.is_bootstrap_phase()

		for client in connect_to_clients:
			if is_bootstrapping:
				client.add_action(Action('bootstrap', data=2)) # TODO for production: set to 7
			self._client_connect(client)

		return True

	def add_client(self, client: Client):
		self._clients.append(client)

	def handle_clients(self) -> bool:
		for client in self._clients:

			# Remove clients that are not connected
			if client.conn_mode == 0:
				self._logger.debug('remove client: %s', client)
				self._logger.debug('reason: %s', client.conn_msg)
				self._selectors.unregister(client.sock)
				client.sock.close()
				self._clients.remove(client)

				client.reset()

			if client.conn_mode == 1:
				if client.auth & 1 == 0:
					data_org = str(uuid.uuid4())
					client.cash = Cash(data_org, self._config['challenge']['min'])

					self._logger.debug('send CHALLENGE')
					self._client_send_challenge(client.sock, data_org)
					client.auth |= 1

				elif client.auth & 2 != 0 and client.auth & 4 == 0:
					self._logger.debug('send ID')
					self._client_send_id(client.sock, client.challenge[3], str(client.challenge[4]))
					client.auth |= 4

				if client.auth == 15:
					client.conn_mode = 2

				if dt.datetime.utcnow() - client.used_at >= self._client_auth_timeout:
					self._logger.debug('client used_at: %s', client.used_at)
					self._logger.debug('client timeout (%s)', self._client_auth_timeout)
					client.conn_mode = 0
					client.conn_msg = 'timeout'

		return True

	def ping_clients(self) -> bool:
		for client in self._clients:
			if client.conn_mode == 2:
				self._logger.debug('send PING')
				self._client_send_ping(client.sock)

		return True

	def save(self) -> bool:
		self._logger.debug('save()')

		self._address_book.save()
		self._mail_queue.save()
		self._mail_db.save()

		return True

	def clean_up(self) -> bool:
		self._logger.debug('clean_up')

		# self._address_book.hard_clean_up(self._local_node.id)
		self._address_book.soft_clean_up(self._local_node.id)

		self._mail_queue.clean_up()

		return True

	def debug_clients(self) -> bool: # pragma: no cover
		self._logger.debug('debug_clients() -> %d', len(self._clients))

		for client in self._clients:
			self._logger.debug('debug %s', client)

		return True

	def client_actions(self) -> bool:
		self._logger.debug('client_actions() -> %d', len(self._clients))

		had_actions = False

		for client in self._clients:
			self._logger.debug('client %s', client)

			for action in client.get_actions(soft_reset=True):
				self._logger.debug('action %s', action)

				if action.id == 'bootstrap':
					self._client_send_get_nearest_to(client.sock, self._local_node.id)
					client.add_action(Action('nearest_response', data=action.data))

				elif action.id == 'request_public_key_for_node':
					self._logger.debug('request_public_key_for_node (try: %d)', action.data['try'])

					self._client_request_public_key_for_node(client.sock, action.data['target'].id)
					action.data['try'] += 1

				elif action.id == 'mail':
					mail = action.data
					self._logger.debug('mail %s', mail)

					self._client_send_mail(client.sock, mail)

					mail.forwarded_to.append(client.id)
					mail.is_delivered = client.id == mail.target

					self._mail_queue.changed()

				elif action.id == 'test':
					had_actions = True

				if dt.datetime.utcnow() >= action.valid_until:
					self._logger.debug('action is invalid: %s', action)
					client.remove_action(action)

		return had_actions

	def _create_action_request_public_key_for_node(self, target: overlay.Node, mode: str) -> Action:
		self._logger.debug('create_action_request_public_key_for_node()')

		action_data = {
			'target': target,
			'mode': mode, # (o)riginal sender, (r)elay
			# 'step': 0, # 0 = request created, 1 = send request to client
			'try': 0, # 0 = first try, 1 = second try, etc
		}
		action = Action('request_public_key_for_node', target.id, data=action_data)
		action.valid_until = dt.datetime.utcnow() + self._client_action_retention_time
		action.is_strong = True

		return action

	def is_bootstrap_phase(self) -> bool:
		if self._config['bootstrap'] == 'default':
			clients_len = self._address_book.get_clients_len()
			bootstrap_clients_len = self._address_book.get_bootstrap_clients_len()
			return clients_len <= bootstrap_clients_len

		return bool(self._config['bootstrap'])

	def handle_mail_queue(self) -> bool:
		self._logger.debug('handle_mail_queue()')

		for mail_uuid, mail in self._mail_queue.get_mails():
			self._logger.debug('mail %s', mail)

			if mail.is_delivered:
				self._logger.debug('mail is delivered')
				continue

			if mail.target == None:
				self._logger.debug('mail has no target')
				continue

			if mail.target == self._local_node.id:
				self._logger.debug('mail is for me')
				continue

			clients = self._address_book.get_nearest_to(mail.target, with_contact_infos=True)
			self._logger.debug('clients %s', clients)

			for client in clients:
				self._logger.debug('client for mail: %s', client)
				if self._client_is_connected(client):
					self._logger.debug('client is connected')
				else:
					self._logger.debug('client is not connected C')
					self._client_connect(client)

			if mail.is_encrypted:
				self._logger.debug('mail is encrypted')

				for client in clients:
					self._logger.debug('client %s', client)
					self._logger.debug('forwarded_to %s', mail.forwarded_to)

					if not self._client_is_connected(client):
						self._logger.debug('client is not connected D')
						continue

					if client.id in mail.forwarded_to:
						self._logger.debug('client already received mail')
						continue

					if client.has_action('mail', mail.uuid):
						self._logger.debug('client already has action')
						continue

					self._logger.debug('add action for mail')
					action = Action('mail', mail.uuid, data=mail)
					action.valid_until = dt.datetime.utcnow() + self._client_action_retention_time
					client.add_action(action)
			else:
				self._logger.debug('mail is not encrypted yet')

				client = self._address_book.get_client_by_id(mail.target.id)
				if client == None or not client.has_public_key():
					self._logger.debug('client is set and has no public key')
					for client in clients:

						if client.has_action('request_public_key_for_node', mail.target.id):
							self._logger.debug('client already has action request_public_key_for_node/%s', mail.target.id)
						else:
							self._logger.debug('create action request_public_key_for_node from client: %s', client)

							action = self._create_action_request_public_key_for_node(mail.target, 'o')

							action.func = lambda _client: self._encrypt_mail(mail, _client)

							client.add_action(action)
				else:
					self._encrypt_mail(mail, client)

		return True

	def _encrypt_mail(self, mail: Mail, client: Client):
		self._logger.debug('_encrypt_mail() -> {}'.format(mail.is_encrypted))
		self._logger.debug('mail %s', mail)
		self._logger.debug('client %s', client)

		if mail.is_encrypted:
			self._logger.debug('mail is already encrypted')
			return

		# base64 decode body
		body = base64.b64decode(mail.body)
		self._logger.debug('body raw "%s"', body)

		# Sign-than-encrypt
		# https://crypto.stackexchange.com/questions/5458/should-we-sign-then-encrypt-or-encrypt-then-sign
		signature = self._private_key.sign(
			body,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		sig_len = len(signature).to_bytes(2, 'little')
		self._logger.debug('sign len: %d', sig_len)
		body += b'\x30' + sig_len + signature
		self._logger.debug('body+sign "%s"', body)

		encrypted = client.encrypt(body)
		# self._logger.debug('encrypted: %s', encrypted)

		encoded = base64.b64encode(encrypted)
		# self._logger.debug('b64 encoded: %s', encoded)

		decoded = encoded.decode('utf-8')
		# self._logger.debug('b64 decoded: %s', decoded)

		mail.body = decoded
		mail.is_encrypted = True

		self._mail_queue.changed()

		client.refresh_used_at()
		self._address_book.changed()

	def _decrypt_mail(self, mail: Mail):
		self._logger.debug('_decrypt_mail()')

		if not mail.is_encrypted:
			self._logger.debug('mail already decrypted')
			return

		self._logger.debug('body %s', mail.body)

		# base64 decode body
		decoded = base64.b64decode(mail.body)
		self._logger.debug('decoded: %s', decoded)

		decrypted_b = self._private_key.decrypt(
			decoded,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		self._logger.debug('decrypted: %s', decrypted_b)

		mail.is_encrypted = False
		mail.is_new = True
		mail.decode(decrypted_b)
