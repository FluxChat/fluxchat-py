
import datetime as dt
from socket import socket as Socket, timeout as SocketTimeout, gaierror as SocketGetaddrinfo, gethostname, gethostbyname, create_server, AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR, SO_BROADCAST
from selectors import DefaultSelector, EVENT_READ
from ssl import TLSVersion, SSLContext, PROTOCOL_TLS_SERVER, PROTOCOL_TLS_CLIENT, CERT_NONE
from struct import unpack, error as StructError
from base64 import b64encode, b64decode
from typing import Optional, cast
from uuid import uuid4
from os import path, getenv, getpid, mkdir, remove
from logging import Logger, getLogger

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature

from lib.client import Client, Action
from lib.database import Database
from lib.helper import is_valid_uuid, binary_encode, binary_decode, password_key_derivation
from lib.mail import Mail
from lib.network import Network, RawCommandsType, SslHandshakeError
from lib.cash import Cash
from lib.contact import Contact
from lib.overlay import Node, Distance


VERSION = 1
SSL_HANDSHAKE_WAIT = 0.3
SSL_HANDSHAKE_TIMEOUT = 5
SSL_MINIMUM_VERSION = TLSVersion.TLSv1_2

class Server(Network):
	_logger: Logger
	_ipc_logger: Logger
	_config: dict
	_selectors: DefaultSelector
	_main_server_socket: Socket
	_discovery_socket: Socket
	_ipc_server_socket: Socket
	_database: Database
	_hostname: str
	_lan_ip: str
	_clients: list[Client]
	_local_node: Node
	_public_key_b64: str
	_pid_file_path: str
	_wrote_pid_file: bool
	_client_auth_timeout: dt.timedelta
	_client_action_retention_time: dt.timedelta
	_contact: Contact

	def __init__(self, config: dict = {}):
		self._host_name = gethostname()
		self._lan_ip = gethostbyname(self._host_name)
		self._clients = []
		self._database = None
		self._selectors = DefaultSelector()
		self._public_key = None
		self._public_key_b64 = None
		self._private_key = None
		self._wrote_pid_file = False
		self._client_auth_timeout = None
		self._client_action_retention_time = None
		self._ssl_handshake_timeout = dt.timedelta(seconds=SSL_HANDSHAKE_TIMEOUT)

		self._logger = getLogger('app.server')
		self._logger.info('init()')

		self._ipc_logger = getLogger('app.ipc')
		self._ipc_logger.info('init()')

		self._config = config

		# TODO: use self._contact
		if 'contact' in self._config:
			self._contact = Contact.resolve(self._config['contact'])
		else:
			self._contact = Contact()

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
			self._pid_file_path = path.join(self._config['data_dir'], 'server.pid')
			self._write_pid_file()

			if 'public_key_file' not in self._config:
				self._config['public_key_file'] = path.join(self._config['data_dir'], 'public_key.pem')
			if 'private_key_file' not in self._config:
				self._config['private_key_file'] = path.join(self._config['data_dir'], 'private_key.pem')

			self._certificate_file = path.join(self._config['data_dir'], 'certificate.pem')

			if 'keys_dir' not in self._config:
				self._config['keys_dir'] = path.join(self._config['data_dir'], 'keys')
			if not path.isdir(self._config['keys_dir']):
				mkdir(self._config['keys_dir'])

			if 'database' in self._config:
				self._database = Database(self._config)
				self._database.load()

				bootstrap_path = path.join(self._config['data_dir'], 'bootstrap.json')
				if path.isfile(bootstrap_path):
					self._database.add_bootstrap(bootstrap_path)

		if 'challenge' not in self._config:
			self._config['challenge'] = {'min': 15, 'max': 20}

		if 'id' in self._config:
			self._local_node = Node.parse(self._config['id'])

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

		if self._database is not None:
			self._database.save()

		self._remove_pid_file()

		self._logger.info('__del__() end')

	def _write_pid_file(self):
		if path.isfile(self._pid_file_path):
			self._logger.error('Another instance of FluxChat is already running.')
			self._logger.error('If this is not the case, delete the file: %s', self._pid_file_path)
			exit(1)

		with open(self._pid_file_path, 'w') as fh:
			fh.write(str(getpid()))
		self._wrote_pid_file = True

	def _remove_pid_file(self):
		self._logger.info('_remove_pid_file()')
		if not self._wrote_pid_file:
			return
		if path.isfile(self._pid_file_path):
			remove(self._pid_file_path)

	def start(self):
		self._logger.info('start')

		self._logger.info('password_key_derivation')
		self._pkd = password_key_derivation(getenv('FLUXCHAT_KEY_PASSWORD', 'password').encode()).encode()

		self._load_public_key_from_pem_file()
		self._load_private_key_from_pem_file()

		self._main_server_ssl = SSLContext(PROTOCOL_TLS_SERVER)
		self._main_server_ssl.minimum_version = SSL_MINIMUM_VERSION
		self._main_server_ssl.load_cert_chain(certfile=self._certificate_file, keyfile=self._config['private_key_file'], password=self._pkd)

		try:
			self._logger.debug('create server %s:%s', self._config['address'], self._config['port'])
			# IPv4
			self._main_server_socket = create_server((self._config['address'], self._config['port']), family=AF_INET, reuse_port=True)
		except OSError as e:
			self._logger.error('OSError: %s', e)
			raise e
		except Exception as e:
			self._logger.error('Exception: %s', e)
			raise e

		self._logger.debug('listen')
		self._main_server_socket.listen()
		self._main_server_socket.setblocking(False)
		self._selectors.register(self._main_server_socket, EVENT_READ, data={'type': 'main_server'})

		if 'discovery' in self._config and self._config['discovery']['enabled']:
			self._logger.debug('discovery')

			# IPv4
			self._discovery_socket = Socket(AF_INET, SOCK_DGRAM) # UDP
			self._discovery_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
			self._discovery_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

			try:
				self._discovery_socket.bind(('0.0.0.0', self._config['discovery']['port']))
			except OSError as e:
				self._logger.error('OSError: %s', e)
				raise e

			self._discovery_socket.setblocking(False)

			if self.has_contact():
				self._logger.debug('send broadcast')
				# TODO for production: set port to self._config['discovery']['port'] instead of hard-coded 26000
				res = self._discovery_socket.sendto(self.get_contact().encode(), ('<broadcast>', 26000))
				self._logger.debug('res %s', res)

			self._selectors.register(self._discovery_socket, EVENT_READ, data={'type': 'discovery'})

		if 'ipc' in self._config and self._config['ipc']['enabled']:
			ipc_addr = (self._config['ipc']['address'], self._config['ipc']['port'])
			self._ipc_logger.debug('ipc %s', ipc_addr)

			# IPv4
			self._ipc_server_socket = Socket(AF_INET, SOCK_STREAM)
			self._ipc_server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
			self._ipc_server_socket.bind(ipc_addr)
			self._ipc_server_socket.listen()
			self._ipc_server_socket.setblocking(False)

			self._selectors.register(self._ipc_server_socket, EVENT_READ, data={'type': 'ipc_server'})

	def _load_private_key_from_pem_file(self) -> None:
		self._logger.debug('load private key from pem file')

		if not path.isfile(self._config['private_key_file']):
			raise Exception('private key file not found: {}'.format(self._config['private_key_file']))

		_pkd = password_key_derivation(getenv('FLUXCHAT_KEY_PASSWORD', 'password').encode()).encode()

		with open(self._config['private_key_file'], 'rb') as f:
			self._private_key = serialization.load_pem_private_key(f.read(), password=_pkd)

	def _load_public_key_from_pem_file(self) -> None:
		self._logger.debug('load public key from pem file')

		if not path.isfile(self._config['public_key_file']):
			raise Exception('public key file not found: {}'.format(self._config['public_key_file']))

		with open(self._config['public_key_file'], 'rb') as f:
			self._public_key = serialization.load_pem_public_key(f.read())

		# DER is binary representation of public key.
		public_bin = self._public_key.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		self._public_key_b64 = b64encode(public_bin).decode()

	# TODO: remove, replace with Contact class
	def has_contact(self) -> bool:
		if 'contact' in self._config:
			if self._config['contact'] == 'disabled' or self._config['contact'] == 'private':
				return False
			elif bool(self._config['contact']) == False:
				return False

			return True

		return False

	# TODO: remove, replace with Contact class
	def get_contact(self) -> str:
		if self.has_contact():
			items = self._config['contact'].split(':')
			item_len = len(items)

			if item_len == 1:
				return '{}:{}'.format(items[0], self._config['port'])

			return self._config['contact']

		return 'N/A'

	def get_local_node(self) -> Node:
		return self._local_node

	def _client_is_connected(self, client: Client) -> bool:
		# self._logger.debug('_client_is_connected()')
		def ffunc(_client: Client):
			return _client.uuid == client.uuid \
				or _client.pubid == client.pubid \
				or _client.address == client.address \
				and _client.port == client.port

		clients = list(filter(ffunc, self._clients))

		return len(clients) > 0

	def _accept_main_server(self, server_sock: Socket):
		self._logger.debug('_accept_main_server()')

		client_sock, addr = server_sock.accept()
		client_sock.setblocking(False)

		client_ssl = self._main_server_ssl.wrap_socket(client_sock, server_side=True, do_handshake_on_connect=False)

		try:
			self._ssl_handshake(client_ssl)
		except SslHandshakeError as e:
			self._logger.error('ssl handshake error: %s', e)
			return

		self._logger.debug('client_sock: %s', client_sock)
		self._logger.debug('client_ssl: %s', client_ssl)
		self._logger.debug('accepted: %s', addr)

		client = Client()
		client.sock = client_ssl
		client.conn_mode = 1
		client.dir_mode = 'i'
		client.debug_add = 'accept'

		self._selectors.register(client_ssl, EVENT_READ, data={
			'type': 'main_client',
			'client': client,
		})

		self._clients.append(client)

		self._logger.debug('_accept_main_server() client: %s', client)

	def _read_discovery(self, server_sock: Socket):
		self._logger.debug('_read_discovery()')

		data, addr = server_sock.recvfrom(1024)
		c_contact_raw = data.decode()

		self._logger.debug('data: %s', data)
		self._logger.debug('addr: %s', addr)

		if addr[0] == self._lan_ip and addr[1] == self._config['discovery']['port']:
			self._logger.debug('skip self')
			return

		c_contact = Contact.resolve(c_contact_raw, addr[0])

		if not c_contact.is_valid:
			return

		client = self._database.get_client_by_addr_port(c_contact.addr, c_contact.port)
		if client is None:
			client = self._database.add_client(addr=c_contact.addr, port=c_contact.port)
			client.debug_add = 'discovery, contact: {}'.format(c_contact_raw)
		else:
			self._logger.debug('client: %s', client)

		self._logger.debug('read_discovery client: %s', client)

		self._client_connect(client)

	def _accept_ipc_server(self, server_sock: Socket):
		self._logger.debug('_accept_ipc_server()')

		client_sock, addr = server_sock.accept()
		client_sock.setblocking(False)

		self._selectors.register(client_sock, EVENT_READ, data={
			'type': 'ipc_client',
		})

	def _client_connect(self, client: Client) -> bool:
		self._logger.debug('_client_connect(%s)', client)

		# TODO: activate for production
		# if client.address == self._lan_ip and os.environ.get('ALLOW_SELF_CONNECT') != '1':
		# 	self._logger.debug('skip, client.address == self._lan_ip')
		# 	return False
		if client.node == self._local_node:
			self._logger.debug('skip, client.node == self._local_node')
			return False
		if client.address is None or client.port is None:
			self._logger.debug('skip, client.address is None or client.port is None')
			return False

		client.conn_mode = 1
		client.dir_mode = 'o'
		client.refresh_used_at()

		client_ssl = SSLContext(PROTOCOL_TLS_CLIENT)
		client_ssl.minimum_version = SSL_MINIMUM_VERSION
		client_ssl.check_hostname = False
		client_ssl.verify_mode = CERT_NONE

		# IPv4
		client_sock = Socket(AF_INET, SOCK_STREAM)
		client_sock.settimeout(2)
		try:
			self._logger.debug('client sock connect to %s:%s', client.address, client.port)
			client_sock.connect((client.address, client.port))
			self._logger.debug('client sock connect done')
		except ConnectionRefusedError as e:
			self._logger.error('ConnectionRefusedError: %s', e)
			return False
		except TimeoutError as e:
			self._logger.error('TimeoutError: %s', e)
			return False
		except SocketTimeout as e:
			self._logger.error('SocketTimeout: %s', e)
			return False
		except SocketGetaddrinfo as e:
			self._logger.error('SocketGetaddrinfo: %s', e)
			return False
		except OSError as e:
			self._logger.error('OSError: %s', e)
			return False

		client_sock.settimeout(None)
		client_sock.setblocking(False)

		client_ssl = client_ssl.wrap_socket(client_sock, do_handshake_on_connect=False)
		# client.sock = client_sock
		client.sock = client_ssl

		self._selectors.register(client_ssl, EVENT_READ, data={
			'type': 'main_client',
			'client': client,
		})

		self._clients.append(client)

		try:
			self._ssl_handshake(client_ssl)
		except SslHandshakeError as e:
			self._logger.error('ssl handshake error: %s', e)
			return False

		self._logger.debug('_client_connect done')
		return True

	def _client_commands(self, sock: Socket, client: Client, commands: RawCommandsType):
		self._logger.debug('_client_commands(%s)', client)

		for group_i, command_i, payload in commands:
			#group_i, command_i, payload = raw_command
			payload_len = len(payload)

			self._logger.debug('group: %d, command %d', group_i, command_i)
			self._logger.debug('payload: %d %s', payload_len, payload)

			if group_i >= 2 and client.auth != 15:
				self._logger.debug('not authenticated: %s', client.auth)
				self._logger.debug('conn mode 0')
				client.conn_mode = 0
				client.conn_msg = 'not authenticated'
				continue

			if group_i == 0: # Basic
				if command_i == 0:
					self._logger.info('OK command')

			elif group_i == 1: # Connection, Authentication, etc
				if command_i == 1:
					self._logger.info('CHALLENGE command')

					if client.auth & 2 != 0:
						self._logger.debug('skip, already got CHALLENGE')
						continue

					client.auth |= 2

					client.challenge.min = int.from_bytes(payload[0], 'little')
					client.challenge.max = int.from_bytes(payload[1], 'little')
					client.challenge.data = str(payload[2].decode())

					self._logger.debug('challenge: %s', client.challenge)

					c_data_len = len(client.challenge.data)
					if c_data_len > 36:
						self._logger.warning('skip, challenge data too long: %d > 36', c_data_len)
						self._logger.debug('conn mode 0')
						client.conn_mode = 0
						client.conn_msg = 'challenge data too long'
						continue

					if client.challenge.min > self._config['challenge']['max']:
						self._logger.warning('skip, challenge min is too big: %d > %d', client.challenge.min, self._config['challenge']['max'])
						self._logger.debug('conn mode 0')
						client.conn_mode = 0
						client.conn_msg = 'challenge min is too big: %d > %d'.format(client.challenge.min, self._config['challenge']['max'])
						continue

					cash = Cash(client.challenge.data, client.challenge.min)
					self._logger.debug('mine')
					cash.mine()
					self._logger.debug('mine done')

					client.challenge.proof = cash.proof
					client.challenge.nonce = cash.nonce

					self._logger.debug('challenge: %s', client.challenge)
					self._logger.debug('cash.min: %s', client.challenge.min)
					self._logger.debug('cash.max: %s', client.challenge.max)
					self._logger.debug('cash.data: %s', client.challenge.data)
					self._logger.debug('cash.proof: %s', cash.proof)
					self._logger.debug('cash.nonce: %s', cash.nonce)

				elif command_i == 2:
					self._logger.info('ID command')

					if client.auth & 2 == 0:
						self._logger.warning('skip, client has first to send CHALLENGE')
						continue

					if client.auth & 8 != 0:
						self._logger.debug('skip, already authenticated')
						continue

					c_version = int.from_bytes(payload[0], 'little')
					c_id = payload[1].decode()
					c_contact_s = payload[2].decode()
					c_cc_proof = payload[3].decode()
					c_cc_nonce = int.from_bytes(payload[4], 'little')

					self._logger.debug('c_version: %s', c_version)
					self._logger.debug('c_id: %s', c_id)
					self._logger.debug('c_contact_s: %s', c_contact_s)
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
					if c_version != VERSION:
						self._logger.warning('skip, version mismatch: %d != %d', c_version, VERSION)
						self._logger.debug('conn mode 0')
						client.conn_mode = 0
						client.conn_msg = 'version mismatch'
						continue

					# Challenge
					if not client.cash.verify(c_cc_proof, c_cc_nonce):
						self._logger.warning('skip, challenge not verified')
						self._logger.debug('conn mode 0')
						client.conn_mode = 0
						client.conn_msg = 'challenge not verified'
						continue
					self._logger.debug('cash verified')

					# Contact info
					addr = sock.getpeername()
					c_contact = Contact.resolve(c_contact_s, addr[0])
					c_contact_addr = c_contact.addr
					c_contact_port = c_contact.port
					c_has_contact_info = c_contact.is_valid

					c_switch = False
					if client.dir_mode == 'i':
						# Client is incoming
						self._logger.debug('client is incoming')

						if c_has_contact_info:
							# Client sent contact info
							_client = self._database.get_client_by_pubid(c_id)
							if _client is None:
								self._logger.debug('client not found by ID (A)')

								_client = self._database.get_client_by_addr_port(c_contact_addr, c_contact_port)
								if _client is None:
									self._logger.debug('client not found by Addr:Port (B)')

									_client = self._database.add_client(c_id, c_contact_addr, c_contact_port)
									_client.dir_mode = client.dir_mode
									_client.debug_add = 'id command, incoming, contact infos, not found by id, not found by addr:port, original: ' + client.debug_add
								else:
									self._logger.debug('client found B: %s', _client)
							else:
								self._logger.debug('client found A: %s', _client)

							_client.address = c_contact_addr
							_client.port = c_contact_port
						else:
							# Client sent no contact info
							_client = self._database.get_client_by_pubid(c_id)
							if _client is None:
								self._logger.debug('client not found C')

								_client = self._database.add_client(c_id)
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

					if _client.pubid is None:
						print(f'-> client.pubid is None: {c_id}')
						_client.set_pubid(c_id)

					self._logger.debug('Client A: %s', client)
					self._logger.debug('Client B: %s', _client)

					_client.refresh_seen_at()
					_client.refresh_used_at()
					_client.inc_meetings()
					_client.changed()

					_client.sock = sock
					_client.conn_mode = client.conn_mode
					_client.auth = client.auth | 8
					_client.actions = client.actions
					_client.challenge = client.challenge

					# Update Address Book because also an existing client can be updated
					self._database.changed()

					if c_switch and _client != client:
						self._logger.debug('switch client')
						self._clients.remove(client)
						self._clients.append(_client)

						self._selectors.unregister(sock)
						self._selectors.register(_client.sock, EVENT_READ, data={
							'type': 'main_client',
							'client': _client,
						})

					self._client_send_ok(_client.sock)

					self._logger.debug('Client Z: %s', _client)

				elif command_i == 3:
					self._logger.info('PING command')
					self._client_send_pong(sock)

				elif command_i == 4:
					self._logger.info('PONG command')

			elif group_i == 2: # Overlay, Address Book, Routing, etc
				if command_i == 1:
					self._logger.info('GET_NEAREST_TO command')

					try:
						node = Node(payload[0].decode())
					except:
						self._logger.warning('skip, invalid node')
						continue

					client_ids = []
					clients = self._database.get_nearest_to(node, with_contact_infos=True)
					for _client in clients:
						self._logger.debug('client: %s %s', _client, _client.distance(node))
						if _client.pubid != self._local_node.pubid and _client.pubid != node.pubid:
							contact_infos = [_client.pubid, _client.address, str(_client.port)]
							self._logger.debug('contact infos: %s', contact_infos)
							client_ids.append(':'.join(contact_infos))

					self._client_send_get_nearest_response(sock, client_ids)

				elif command_i == 2:
					self._logger.info('GET_NEAREST_TO RESPONSE command')

					action = client.resolve_action('nearest_response')
					if action is None:
						self._logger.warning('skip, not requested')
						continue

					self._logger.debug('action: %s', action)

					nearest_client = None
					distance = Distance()
					for c_contact in payload:
						self._logger.debug('client contact A: %s', c_contact)

						c_id, c_contact_raw = c_contact.decode().split(':', 1)
						self._logger.debug('client contact B: %s %s', c_id, c_contact_raw)

						c_contact = Contact.resolve(c_contact_raw)
						self._logger.debug('client contact C: %s %s %s', c_contact.addr, c_contact.port, c_contact.is_valid)

						if c_id == self._local_node.pubid:
							continue

						_client = self._database.get_client_by_pubid(c_id)
						if _client is None:
							self._logger.debug('client not found')
							_client = self._database.add_client(c_id, c_contact.addr, c_contact.port)
							_client.debug_add = 'nearest response, not found by id'

							_c_distance = _client.distance(self._local_node)
							if _c_distance < distance:
								distance = _c_distance
								self._logger.debug('new distance: %s', distance)

								nearest_client = _client
						else:
							self._logger.debug('client found: %s', _client)

					if nearest_client is not None:
						self._logger.debug('nearest client: %s', nearest_client)

						bootstrap_count = action.data - 1
						self._logger.debug('bootstrap count: %d', bootstrap_count)

						if bootstrap_count > 0 and not self._client_is_connected(nearest_client):
							self._client_connect(nearest_client)

							nearest_client.add_action(Action('bootstrap', data=bootstrap_count))

				elif command_i == 3:
					self._logger.info('REQUEST PUBLIC KEY FOR NODE command')

					is_relay = False
					fwd_clients: list[Client] = []
					node_id = payload[0].decode()
					self._logger.debug('node id: %s', node_id)

					try:
						target = Node.parse(node_id)
					except:
						self._logger.debug('skip, invalid node')
						continue

					if target == self._local_node:
						self._logger.debug('local node')
						self._client_response_public_key_for_node(sock, target.pubid, self._public_key_b64)
					else:
						self._logger.debug('not local node')

						_client = self._database.get_client_by_pubid(target.pubid)
						if _client is None:
							self._logger.debug('client not found')

							is_relay = True
							fwd_clients = self._database.get_nearest_to(target, with_contact_infos=True)
						else:
							self._logger.debug('client found: %s', _client)

							if _client.has_public_key():
								self._logger.debug('client has public key')

								self._client_response_public_key_for_node(sock, target.pubid, _client.get_base64_public_key())
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

							if _client.has_action('request_public_key_for_node', target.pubid):
								self._logger.debug('client already has action request_public_key_for_node/%s', target.pubid)
							else:
								self._logger.debug('create action request_public_key_for_node/%s', target.pubid)

								action = self._create_action_request_public_key_for_node(target, 'r')

								def _action_func(_arg_client: Client):
									self._client_response_public_key_for_node(sock, target.pubid, _arg_client.get_base64_public_key())

								action.func = _action_func
								_client.add_action(action)

				elif command_i == 4:
					self._logger.info('RESPONSE PUBLIC KEY FOR NODE command')

					node_id = payload[0].decode()
					public_key_raw = payload[1].decode()
					self._logger.debug('node id: %s', node_id)
					self._logger.debug('public key raw: %s', public_key_raw)

					try:
						node = Node.parse(node_id)
						self._logger.debug('node: %s', node)
					except:
						self._logger.debug('skip, invalid node')
						continue

					action = client.resolve_action('request_public_key_for_node', node.pubid, force_remove=True)
					if action is None:
						self._logger.warning('skip, not requested')
						continue

					if node == self._local_node:
						self._logger.warning('skip, local node')
						continue

					self._logger.debug('action: %s', action)

					_client = self._database.get_client_by_pubid(node.pubid)
					if _client is None:
						self._logger.debug('client not found')

						_client = Client()
						_client.debug_add = 'public key response'
						_client.set_pubid(node.pubid)
						_client.load_public_key_from_pem(public_key_raw)

						if _client.verify_public_key():
							self._logger.debug('public key verified')

							self._database.append_client(_client)
							self._logger.debug('client added: %s', _client)
						else:
							self._logger.debug('public key not verified')
							_client = None
					else:
						self._logger.debug('client found: %s', _client)

						if _client.has_public_key():
							self._logger.debug('client has public key')
						else:
							_client.load_public_key_from_pem(public_key_raw)
							if _client.verify_public_key():
								self._logger.debug('public key verified')
								_client.changed()
								self._database.changed()
							else:
								self._logger.debug('public key not verified')
								_client.reset_public_key()

					if _client is not None and _client.has_public_key():
						self._logger.debug('client is set and has public key')
						self._logger.debug('client: %s', _client)

						if action.func is not None:
							self._logger.debug('action has func')
							self._logger.debug('call func')
							action.func(_client)

			elif group_i == 3: # Mail
				if command_i == 1:
					self._logger.debug('SEND MAIL command')

					mail_uuid, mail_target, mail_data = payload

					self._logger.debug('mail uuid: %s', mail_uuid)
					if not is_valid_uuid(mail_uuid):
						self._logger.debug('invalid mail uuid')
						continue

					if self._database.has_mail(mail_uuid):
						self._logger.debug('DB, mail already exists')
						continue

					if self._database.has_queue_mail(mail_uuid):
						self._logger.debug('QUEUE, mail already exists')
						continue

					try:
						mail_target = Node.parse(mail_target)
						self._logger.debug('mail target: %s', mail_target)
					except:
						self._logger.debug('invalid mail target')
						continue

					self._logger.debug('mail data: %s', mail_data)

					mail = Mail(mail_uuid)
					mail.receiver = mail_target.pubid
					mail.target = mail_target
					mail.body = mail_data
					mail.is_encrypted = True
					mail.received_now()

					if mail_target == self._local_node:
						self._logger.debug('mail target is local node')
						self._decrypt_mail(mail)

						self._database.add_mail(mail)
					else:
						self._logger.debug('mail target is not local node')
						mail.forwarded_to.append(client.pubid)

						self._database.get_queue_mails(mail)

			else:
				self._logger.debug('unknown group %d, command %d', group_i, command_i)
				self._logger.debug('conn mode 0')
				client.conn_mode = 0
				client.conn_msg = 'unknown group %d, command %d' % (group_i, command_i)

	def _client_send_ok(self, sock: Socket):
		self._logger.debug('_client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_challenge(self, sock: Socket, challenge: str):
		self._logger.debug('_client_send_challenge(%s)', challenge)

		self._client_write(sock, 1, 1, [
			self._config['challenge']['min'],
			self._config['challenge']['max'],
			challenge,
		])

	def _client_send_id(self, sock: Socket, proof: str, nonce: int):
		self._logger.debug('_client_send_id(p=%s, n=%d)', proof, nonce)
		data = [
			VERSION,
			self._config['id'],
			self._config['contact'],
			proof,
			nonce,
		]

		# self._logger.debug('data: %s', data)
		self._client_write(sock, 1, 2, data)

	def _client_send_ping(self, sock: Socket):
		self._logger.debug('_client_send_ping()')
		self._client_write(sock, 1, 3)

	def _client_send_pong(self, sock: Socket):
		self._logger.debug('_client_send_pong()')
		self._client_write(sock, 1, 4)

	def _client_send_get_nearest_to(self, sock: Socket, id: str):
		self._logger.debug('_client_send_get_nearest_to()')
		self._client_write(sock, 2, 1, [id])

	def _client_send_get_nearest_response(self, sock: Socket, client_ids: list):
		self._logger.debug('_client_send_get_nearest_response()')
		self._client_write(sock, 2, 2, client_ids)

	def _client_request_public_key_for_node(self, sock: Socket, id: str):
		self._logger.debug('_client_request_public_key_for_node(%s)', id)
		self._client_write(sock, 2, 3, [id])

	def _client_response_public_key_for_node(self, sock: Socket, id: str, public_key: str):
		self._logger.debug('_client_response_public_key_for_node()')
		# self._logger.debug('type: %s', type(id))
		# self._logger.debug('type: %s', type(public_key))
		self._logger.debug('public key: %s', public_key)

		self._client_write(sock, 2, 4, [id, public_key])

	def _client_send_mail(self, sock: Socket, mail: Mail):
		self._logger.debug('_client_send_mail()')
		if not mail.is_encrypted:
			self._logger.debug('mail not encrypted')
			return

		self._logger.debug('mail: %s', type(mail.body))

		self._client_write(sock, 3, 1, [
			mail.pubid,
			mail.target.pubid,
			mail.body,
		])

	def _ipc_client_read(self, sock: Socket):
		self._logger.debug('_ipc_client_read()')

		try:
			raw = sock.recv(2048)
		except TimeoutError as e:
			self._ipc_logger.error('TimeoutError: %s', e)
			return
		except ConnectionResetError as e:
			self._ipc_logger.error('ConnectionResetError: %s', e)
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
					self._ipc_logger.error('IndexError: %s', e)
					self._ipc_logger.error('unregister socket')
					self._selectors.unregister(sock)
					return

				lengths_are_4_bytes = flags_i & 1 != 0

				try:
					# length = unpack('<I', raw[raw_pos:raw_pos + 4])[0]
					length = int.from_bytes(raw[raw_pos:raw_pos + 4], 'little')
					raw_pos += 4
				except StructError as e:
					self._ipc_logger.error('struct.error: %s', e)
					self._ipc_logger.error('unregister socket')
					self._selectors.unregister(sock)
					return

				payload_raw = raw[raw_pos:]
				payload_items = []

				self._ipc_logger.debug('group: %d', group)
				self._ipc_logger.debug('command: %d', command)
				self._ipc_logger.debug('length: %d %s', length, type(length))

				pos = 0
				while pos < length:
					self._ipc_logger.debug('pos: %d', pos)
					if lengths_are_4_bytes:
						# item_len = unpack('<I', payload_raw[pos:pos + 4])[0]
						item_len = int.from_bytes(payload_raw[pos:pos + 4], 'little')
						pos += 3
					else:
						item_len = payload_raw[pos]
					pos += 1

					self._ipc_logger.debug('item len: %d', item_len)

					item = payload_raw[pos:pos + item_len]
					self._ipc_logger.debug('item: %s', item)

					payload_items.append(item.decode())
					pos += item_len

				commands.append([group, command, payload_items])
				raw_pos += length + 1

			self._ipc_client_commands(sock, commands)
		else:
			self._ipc_logger.debug('no data')

			self._ipc_logger.debug('unregister socket')
			self._selectors.unregister(sock)

	def _ipc_client_commands(self, sock: Socket, commands: RawCommandsType):
		self._ipc_logger.debug('_ipc_client_commands()')
		self._ipc_logger.debug('commands: %s', commands)

		for group_i, command_i, payload in commands:
			payload_len = len(payload)

			self._ipc_logger.debug('group %d, command %d', group_i, command_i)
			self._ipc_logger.debug('payload_len: %d', payload_len)
			self._ipc_logger.debug('payload: %s', payload)

			if group_i == 0: # Basic
				if command_i == 0:
					self._ipc_logger.info('OK command')

			elif group_i == 1:
				if command_i == 0:
					self._ipc_logger.info('SEND MAIL command')

					print(f'-> payload: {payload}')

					target = payload[0]
					body = payload[1]
					self._ipc_logger.debug('target: %s', target)
					self._ipc_logger.debug('body: %s', body)

					mail = Mail()
					mail.set_receiver(target)
					mail.body = body

					self._database.add_queue_mail(mail)

					self._ipc_logger.debug('pubid: %s', mail.pubid)

					self._client_send_ok(sock)

				elif command_i == 1:
					self._ipc_logger.info('LIST MAILS command')

					flags_i = int.from_bytes(payload[0], 'little')
					only_new = flags_i & 1 != 0
					self._ipc_logger.debug('flags_i: %d', flags_i)
					self._ipc_logger.debug('only_new: %s', only_new)

					mails = list(self._database.get_mails())

					if only_new:
						def filter_mails(_mail_t: tuple[str, Mail]) -> bool:
							_mail = cast(Mail, _mail_t[1])
							return _mail.is_new
						mails = list(filter(filter_mails, self._database.get_mails()))

					print(f'mails: {mails}')

					def filter_encoded_mails(_mail_t: tuple[str, Mail]) -> bytes:
						_mail = cast(Mail, _mail_t[1])
						return _mail.ipc_encode()

					chunks: list[bytes] = []
					for n in range(0, len(mails), 5):
						encoded_mails = list(map(filter_encoded_mails, mails[n:n + 5]))
						chunks.append(encoded_mails)

					chunks_len = len(chunks)
					self._ipc_logger.debug('chunks_len: %d', chunks_len)

					for n in range(chunks_len):
						self._ipc_logger.debug('chunk n: %d', n)
						self._ipc_client_send_list_mail(sock, chunks_len, n, chunks[n])

				elif command_i == 2:
					self._ipc_logger.info('READ MAIL command')

					m_uuid = payload[0].decode()
					self._ipc_logger.debug('m_uuid: %s', m_uuid)

					mail = self._database.get_mail(m_uuid)
					if mail is None:
						self._ipc_logger.error('mail not found')
						mail_encoded = None
					else:
						self._ipc_logger.debug('mail: %s', mail)

						mail_encoded = mail.ipc_encode()
						self._ipc_logger.debug('mail_encoded: %s', mail_encoded)

					self._ipc_client_send_read_mail(sock, mail_encoded)

			elif group_i == 2:
				if command_i == 0:
					self._ipc_logger.debug('SAVE command')
					self.save()

				if command_i == 1:
					self._ipc_logger.debug('STOP command')
					# self._scheduler.shutdown('STOP command') # TODO

	def _ipc_client_send_list_mail(self, sock: Socket, chunks_len: int, chunk_num: int, mails: list[bytes]):
		self._ipc_logger.debug('_ipc_client_send_list_mail()')
		self._ipc_logger.debug('mails: %s', mails)

		self._client_write(sock, 1, 1, [chunks_len, chunk_num] + mails)

	def _ipc_client_send_read_mail(self, sock: Socket, mail: str):
		self._ipc_logger.debug('_ipc_client_send_read_mail()')
		self._ipc_logger.debug('mail: %s', mail)

		if mail is not None:
			data = [1, mail]
		else:
			data = [0]

		self._client_write(sock, 1, 2, data)

	def handle_sockets(self) -> bool:
		# self._logger.debug('handle_sockets()')

		data_processed = False

		events = self._selectors.select(timeout=0)
		for key, mask in events:
			self._logger.debug('handle_sockets mask: %d', mask)

			if key.data is not None:
				if key.data['type'] == 'main_server':
					self._accept_main_server(key.fileobj)

				elif key.data['type'] == 'main_client':
					status = self._client_read(key.fileobj)

					if status.disconnect:
						self._logger.debug('client disconnect: %s', status.msg)
						key.data['client'].conn_mode = 0
						key.data['client'].conn_msg = status.msg

					self._client_commands(key.fileobj, key.data['client'], status.commands)

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

		if self._database is None:
			self._logger.debug('database is None')
			return False

		_clients = list(self._database.get_clients().values())
		_clients.sort(key=lambda _client: _client.meetings, reverse=True)

		# self._logger.debug('clients: %d', len(_clients))

		connect_to_clients: list[Client] = []
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

	def get_clients(self) -> list[Client]:
		return self._clients

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
					data_org = str(uuid4())
					client.cash = Cash(data_org, self._config['challenge']['min'])

					self._logger.debug('send CHALLENGE')
					self._client_send_challenge(client.sock, data_org)
					client.auth |= 1

				elif client.auth & 2 != 0 and client.auth & 4 == 0:
					self._logger.debug('send ID')
					self._client_send_id(client.sock, client.challenge.proof, client.challenge.nonce)
					client.auth |= 4

				if client.auth == 15:
					client.conn_mode = 2

				# Auth Timeout
				if dt.datetime.now(dt.UTC) - client.used_at >= self._client_auth_timeout:
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
		if self._database is not None:
			self._database.save()
		return True

	def clean_up(self) -> bool:
		self._logger.debug('clean_up')

		if self._database is not None:
			self._database.hard_clean_up(self._local_node.pubid)
			self._database.soft_clean_up(self._local_node.pubid)
			self._database.clean_queue_up()

		return True

	def debug_clients(self) -> bool:
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
					self._client_send_get_nearest_to(client.sock, self._local_node.pubid)
					client.add_action(Action('nearest_response', data=action.data))

				elif action.id == 'request_public_key_for_node':
					self._logger.debug('request_public_key_for_node (try: %d)', action.data['try'])

					target = cast(Node, action.data['target'])
					target_pubid = target.pubid

					self._client_request_public_key_for_node(client.sock, target_pubid)
					action.data['try'] += 1

				elif action.id == 'mail':
					mail = cast(Mail, action.data)
					self._logger.debug('mail %s', mail)

					self._client_send_mail(client.sock, mail)

					mail.forwarded_to.append(client.pubid)
					mail.is_delivered = client.pubid == mail.target
					mail.changed()

					self._database.changed()

				elif action.id == 'test':
					had_actions = True

				if action.valid_until is not None and dt.datetime.now(dt.UTC) >= action.valid_until:
					self._logger.debug('action is invalid: %s', action)
					client.remove_action(action)

		return had_actions

	def _create_action_request_public_key_for_node(self, target_node: Node, mode: str) -> Action:
		self._logger.debug('_create_action_request_public_key_for_node(%s, %s)', target_node, mode)

		action_data = {
			'target': target_node,
			'mode': mode, # (o)riginal sender, (r)elay
			# 'step': 0, # 0 = request created, 1 = send request to client
			'try': 0, # 0 = first try, 1 = second try, etc
		}
		action = Action('request_public_key_for_node', target_node.pubid, data=action_data)
		action.valid_until = dt.datetime.now(dt.UTC) + self._client_action_retention_time
		action.is_strong = True

		return action

	def is_bootstrap_phase(self) -> bool:
		if self._config['bootstrap'] == 'default':
			if self._database is None:
				return True
			else:
				clients_len = self._database.get_clients_len()
				bootstrap_clients_len = self._database.get_bootstrap_clients_len()

				return clients_len <= bootstrap_clients_len

		return bool(self._config['bootstrap'])

	def handle_mail_queue(self) -> bool:
		self._logger.debug('handle_mail_queue() -> mails: %d', len(self._database.get_mails()))

		for mail_uuid, mail in self._database.get_queue_mails().items():
			self._logger.debug('handle_mail_queue: mail %s', mail)

			if mail.is_delivered:
				self._logger.debug('handle_mail_queue: mail is delivered')
				mail.status = 'mail is delivered'
				continue

			if mail.target is None:
				self._logger.debug('handle_mail_queue: mail has no target')
				mail.status = 'mail has no target'
				continue

			if mail.target == self._local_node.pubid:
				self._logger.debug('handle_mail_queue: mail is for me')
				mail.status = 'mail is for me'
				continue

			clients = self._database.get_nearest_to(mail.target, with_contact_infos=True)
			self._logger.debug('handle_mail_queue: nearest clients to %s: %s', mail.target, clients)

			if len(clients) == 0:
				self._logger.debug('handle_mail_queue: no nearest clients found. look for connected clients')
				def sort_key(_client: Client) -> Distance:
					return _client.node.distance(mail.target)
				clients = list(self._clients) # make copy
				clients.sort(key=sort_key)

			for client in clients:
				self._logger.debug('handle_mail_queue: client for mail: %s', client)
				if self._client_is_connected(client):
					# self._logger.debug('client is connected')
					mail.status = f'client is connected: {client}'
				else:
					self._logger.debug('handle_mail_queue: client is not connected C')
					mail.status = f'client is not connected C: {client}'
					self._client_connect(client)

			if mail.is_encrypted:
				self._logger.debug('handle_mail_queue: mail is encrypted')
				mail.status = 'mail is encrypted'

				for client in clients:
					self._logger.debug('handle_mail_queue: client %s', client)
					self._logger.debug('handle_mail_queue: forwarded_to %s', mail.forwarded_to)

					if not self._client_is_connected(client):
						self._logger.debug('handle_mail_queue: client is not connected D')
						mail.status = f'client is not connected D: {client}'
						continue

					if client.pubid in mail.forwarded_to:
						self._logger.debug('handle_mail_queue: client already received mail')
						mail.status = f'client already received mail: {client}'
						continue

					if client.has_action('mail', mail.pubid):
						self._logger.debug('handle_mail_queue: client already has action')
						mail.status = f'client already has action A: {client}'
						continue

					self._logger.debug('handle_mail_queue: add action for mail')
					action = Action('mail', mail.pubid, data=mail)
					action.valid_until = dt.datetime.now(dt.UTC) + self._client_action_retention_time
					client.add_action(action)
					mail.status = f'added action for mail: {client}'
			else:
				self._logger.debug('handle_mail_queue: mail is not encrypted yet')

				client = self._database.get_client_by_pubid(mail.target.pubid)
				if client is None or not client.has_public_key():
					self._logger.debug('handle_mail_queue: client is set and has no public key (clients=%d)', len(clients))

					for client in clients:
						if client.has_action('request_public_key_for_node', mail.target.pubid):
							self._logger.debug('handle_mail_queue: client already has action request_public_key_for_node/%s', mail.target.pubid)
							mail.status = f'client already has action B: {client}'
						else:
							self._logger.debug('handle_mail_queue: create action request_public_key_for_node from client: %s', client)
							mail.status = f'create action from client: {client}'

							action = self._create_action_request_public_key_for_node(mail.target, 'o')

							action.func = lambda _client: self._encrypt_mail(mail, _client)

							client.add_action(action)
				else:
					self._encrypt_mail(mail, client)
					if mail.is_encrypted:
						mail.status = 'mail is encrypted'

		return True

	def delete_mail_queue(self) -> int:
		self._logger.debug('delete_mail_queue()')
		return self._database.delete_queue_mails()

	def handle_mail_db(self) -> bool:
		self._logger.debug('handle_mail_db() -> len=%d', len(self._database.get_mails()))

		for mail_uuid, mail in self._database.get_mails().items():
			self._logger.debug('handle_mail_db: mail %s', mail)

			clients = self._database.get_nearest_to(mail.origin, with_contact_infos=True)
			self._logger.debug('handle_mail_db: clients %s', clients)

			for client in clients:
				self._logger.debug('handle_mail_db: client for mail: %s', client)
				if self._client_is_connected(client):
					pass
					self._logger.debug('handle_mail_db: client is connected')
				else:
					self._logger.debug('handle_mail_db: client is not connected C')
					self._client_connect(client)

			if mail.verified == 'n':
				self._logger.debug('handle_mail_db: mail is not verified')

				_client = self._database.get_client_by_pubid(mail.origin.id)

				request_public_key_for_node_action = False
				if _client is None:
					self._logger.debug('handle_mail_db: client not found by id: %s', mail.origin.id)
					request_public_key_for_node_action = True
				else:
					self._logger.debug('handle_mail_db: client found by id: %s', mail.origin.id)
					if _client.has_public_key():
						self._logger.debug('handle_mail_db: client has public key')
						self._verify_mail(mail, _client)
					else:
						self._logger.debug('handle_mail_db: client has no public key')
						request_public_key_for_node_action = True

				if request_public_key_for_node_action:
					for client in clients:
						if client.has_action('request_public_key_for_node', mail.origin.id):
							self._logger.debug('handle_mail_db: client already has action request_public_key_for_node/%s', mail.origin.id)
						else:
							self._logger.debug('handle_mail_db: create action request_public_key_for_node from client: %s', client)
							action = self._create_action_request_public_key_for_node(mail.origin, 'o')
							action.func = lambda client: self._verify_mail(mail, client)
							client.add_action(action)

		self._logger.debug('handle_mail_db() end')

	# Use public key to encrypt symmetric key.
	# Use symmetric key to encrypt mail body.
	def _encrypt_mail(self, mail: Mail, client: Client):
		self._logger.debug('_encrypt_mail() -> is_encrypted={}'.format(mail.is_encrypted))
		self._logger.debug('mail %s', mail)
		self._logger.debug('client %s', client)

		if mail.is_encrypted:
			self._logger.debug('mail is already encrypted')
			return

		# Raw Body
		raw_body = b64decode(mail.body)
		raw_body_len = len(raw_body).to_bytes(2, 'little')
		self._logger.debug('raw body "%s"', raw_body)
		self._logger.debug('raw body len %s', raw_body_len)

		# Symmetric Key
		sym_key = Fernet.generate_key()
		self._logger.debug('sym_key: %s', sym_key)
		self._logger.debug('sym_key hex: %s', sym_key.hex())

		# Signature Data
		hasher = hashes.Hash(hashes.SHA256())
		hasher.update(sym_key)
		hasher.update(raw_body)
		sign_hash = hasher.finalize()

		sign_hash_b64 = b64encode(sign_hash).decode()
		self._logger.debug('sign_hash: %s', sign_hash_b64)

		# Signature
		signature = self._private_key.sign(
			sign_hash,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		sig_len = len(signature).to_bytes(2, 'little')
		self._logger.debug('sign len: %d %s', len(signature), sig_len)
		self._logger.debug('signature: %s', signature)

		# Symmetric Data
		sym_items = {
			0x00: signature,
			0x01: raw_body,
		}
		sym_data = binary_encode(sym_items, 2)

		# Symmetric Key encrypted
		f = Fernet(sym_key)
		token = f.encrypt(sym_data)
		token_len = len(token).to_bytes(4, 'little')
		self._logger.debug('token_len "%s"', token_len)
		self._logger.debug('token "%s"', token)

		# Encrypted Symmetric Key using Public Key
		enc_sym_key = client.encrypt(sym_key)
		enc_sym_key_len = len(enc_sym_key).to_bytes(2, 'little')
		self._logger.debug('enc_sym_key_len "%s"', enc_sym_key_len)
		self._logger.debug('enc_sym_key "%s"', enc_sym_key)

		# Public Data
		pub_items = {
			0x00: enc_sym_key,
			0x01: token,
		}
		# 4 bytes for length = 4 * 8 bits = 32 bits = 2^32 = 4.294.967.296 bytes
		pub_data = binary_encode(pub_items, 4)

		encoded = b64encode(pub_data).decode()
		self._logger.debug('pub data b64 "%s"', encoded)

		mail.body = encoded
		mail.is_encrypted = True
		mail.changed()

		client.refresh_used_at()
		self._database.changed()

	def _decrypt_mail(self, mail: Mail):
		self._logger.debug('_decrypt_mail()')

		if not mail.is_encrypted:
			self._logger.debug('mail already decrypted')
			return

		self._logger.debug('body %s', mail.body)

		# base64 decode body
		pub_data = b64decode(mail.body)
		self._logger.debug('pub_data: %s', pub_data)

		pub_items = binary_decode(pub_data, 4)
		self._logger.debug('pub_items: %s', pub_items)
		enc_sym_key = pub_items[0x00]
		token = pub_items[0x01]

		# Private key decryption
		sym_key = self._private_key.decrypt(
			enc_sym_key,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		self._logger.debug('sym_key: %s', sym_key)

		# Decrypt token
		f = Fernet(sym_key)
		sym_data = f.decrypt(token)
		# self._logger.debug('sym_data:', sym_data)

		sym_items = binary_decode(sym_data, 2)
		# self._logger.debug('sym_items:', sym_items)

		signature = sym_items[0x00]
		raw_body = sym_items[0x01]
		self._logger.debug('signature: %s', signature)
		self._logger.debug('raw_body: %s', raw_body)

		# Signature Data
		hasher = hashes.Hash(hashes.SHA256())
		hasher.update(sym_key)
		hasher.update(raw_body)
		sign_token = hasher.finalize()
		self._logger.debug('sign_token: %s', sign_token.hex())

		mail.is_encrypted = False
		mail.is_new = True
		mail.verified = 'n'
		mail.sign_hash = b64encode(sign_token).decode()
		mail.sign = b64encode(signature).decode()
		mail.decode(raw_body)

		self._database.changed()

	def _verify_mail(self, mail: Mail, client: Client):
		self._logger.debug('_verify_mail()')
		self._logger.debug('mail: %s', mail)
		self._logger.debug('client: %s', client)

		self._logger.debug('sign_hash A: %s', mail.sign_hash)
		sign_hash = b64decode(mail.sign_hash)
		self._logger.debug('sign_hash B: %s', sign_hash)

		self._logger.debug('sign A: %s', mail.sign)
		sign = b64decode(mail.sign)
		self._logger.debug('sign B: %s', sign)

		try:
			client.public_key.verify(
				sign,
				sign_hash,
				padding.PSS(
					mgf=padding.MGF1(hashes.SHA256()),
					salt_length=padding.PSS.MAX_LENGTH
				),
				hashes.SHA256()
			)
		except InvalidSignature:
			self._logger.error('InvalidSignature')
			mail.verified = 'e'
		else:
			self._logger.debug('mail signature OK')
			mail.verified = 'y'
			mail.sign_hash = None
			mail.sign = None

		self._database.changed()

	def get_database(self) -> Optional[Database]:
		return self._database
