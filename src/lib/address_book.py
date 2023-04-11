
import datetime as dt
import os

from sty import fg
from lib.client import Client

import lib.overlay as overlay
from lib.helper import read_json_file, write_json_file

class AddressBook():
	_path: str
	_config: dict
	_ab_config: dict
	_clients_by_uuid: dict
	_clients_by_id: dict
	_changes: bool
	_clients_ttl: dt.timedelta

	def __init__(self, path: str, config: dict = None):
		print('-> AddressBook.__init__({})'.format(path))
		print(config)

		self._path = path
		self._config = config
		self._ab_config = self._config['address_book']
		self._clients_by_uuid = dict()
		self._clients_by_id = dict()
		self._changes = False

		if self._ab_config == None:
			self._clients_ttl = dt.timedelta(hours=1)
		else:
			self._clients_ttl = dt.timedelta(hours=self._ab_config['client_retention_time'])

	def load(self):
		_data = read_json_file(self._path, {})
		for client_uuid, row in _data.items():
			client = Client()
			client.uuid = client_uuid
			client.from_dict(row)

			print('-> load client: {}'.format(client))

			self._clients_by_uuid[client_uuid] = client
			if client.id != None:
				if client.id in self._clients_by_id:
					print('{}-> AddressBook.__init__(): Warning: Client ID already exists: {}{}'.format(fg.red, client.id, fg.rs))
				self._clients_by_id[client.id] = client

				key_file_path = os.path.join(self._config['keys_dir'], client.id + '.pem')
				print('-> key_file_path: {}'.format(key_file_path))
				if os.path.isfile(key_file_path):
					client.load_public_key_from_pem_file(key_file_path)

	def save(self) -> bool:
		print('-> AddressBook.save() -> {}'.format(self._changes))
		if not self._changes:
			return False

		_data = dict()
		for client_uuid, client in self._clients_by_uuid.items():
			print('-> save client: {}'.format(client))
			_data[client_uuid] = client.as_dict()

			if client.id != None:
				key_file_path = os.path.join(self._config['keys_dir'], client.id + '.pem')
				if not os.path.isfile(key_file_path):
					client.write_public_key_to_pem_file(key_file_path)

		write_json_file(self._path, _data)
		self._changes = False

		return True

	def get_clients(self) -> dict:
		# print('-> AddressBook.get_clients()')
		return self._clients_by_uuid

	def get_clients_len(self) -> int:
		# print('-> AddressBook.get_clients_len()')
		return len(self._clients_by_uuid)

	def get_bootstrap_clients(self) -> list:
		# print('-> AddressBook.get_bootstrap_clients()')

		ffunc = lambda _client: _client[1].is_bootstrap
		bootstrap_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		return bootstrap_clients

	def get_bootstrap_clients_len(self) -> int:
		# print('-> AddressBook.get_bootstrap_clients_len()')

		ffunc = lambda _client: _client[1].is_bootstrap
		bootstrap_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		return len(bootstrap_clients)

	def get_client(self, id: str) -> Client:
		# print('-> AddressBook.get_client({})'.format(id))

		if id in self._clients_by_uuid:
			return self._clients_by_uuid[id]

		if id in self._clients_by_id:
			return self._clients_by_id[id]

		return None

	def get_client_by_uuid(self, uuid: str) -> Client:
		print('-> AddressBook.get_client_by_uuid({})'.format(uuid))

		if uuid in self._clients_by_uuid:
			return self._clients_by_uuid[uuid]

		return None

	def get_client_by_id(self, id: str) -> Client:
		print('-> AddressBook.get_client_by_id({})'.format(id))

		if id in self._clients_by_id:
			return self._clients_by_id[id]

		return None

	def get_client_by_addr_port(self, addr: str, port: int):
		# print('-> AddressBook.get_client_by_addr_port({}, {})'.format(addr, port))

		ffunc = lambda _client: _client[1].address == addr and _client[1].port == port

		_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		print('-> _clients: {}'.format(_clients))

		if len(_clients) > 0:
			return _clients[0][1]

		return None

	def add_client(self, id: str = None, addr: str = None, port: int = None) -> Client:
		print('-> AddressBook.add_client({}, {}, {})'.format(id, addr, port))

		client = Client()

		if id != None:
			client.set_id(id)

		if addr != None:
			client.address = addr

		if port != None:
			client.port = port

		self._clients_by_uuid[client.uuid] = client
		if client.id != None:
			self._clients_by_id[client.id] = client
		self.changed()

		return client

	def remove_client(self, client: Client):
		# print('-> AddressBook.remove_client({})'.format(client))

		key_file_path = os.path.join(self._config['keys_dir'], client.id + '.pem')
		if os.path.isfile(key_file_path):
			os.remove(key_file_path)

		del self._clients_by_uuid[client.uuid]
		if client.id != None:
			del self._clients_by_id[client.id]
		self.changed()

	def add_bootstrap(self, file: str):
		# print('-> AddressBook.add_bootstrap({})'.format(file))

		_data = read_json_file(file, [])
		for row in _data:
			items = row.split(':')

			client = Client()
			client.address = items[0]
			client.port = int(items[1])
			client.is_bootstrap = True
			client.debug_add = 'bootstrap'

			self._clients_by_uuid[client.uuid] = client
			if client.id != None:
				self._clients_by_id[client.id] = client
			self.changed()

		write_json_file(file, [])

	def changed(self):
		# print('-> AddressBook.changed()')
		self._changes = True

	def hard_clean_up(self, local_id: str = None):
		# print('-> AddressBook.hard_clean_up({})'.format(local_id))

		# remove local_id
		if local_id != None and local_id in self._clients_by_id:
			del self._clients_by_id[local_id]

		_clients = list(self._clients_by_uuid.values())
		_clients_len = len(_clients)
		# print('-> clients: {}'.format(_clients_len))

		if _clients_len <= self._ab_config['max_clients']:
			return

		# remove bootstrap clients with no meetings
		_clients = list(filter(lambda _client: _client.is_bootstrap and _client.meetings == 0, _clients))
		for client in _clients:
			self.remove_client(client)
			_clients_len -= 1
			if _clients_len <= self._ab_config['max_clients']:
				return

		# remove out-of-date clients (invalid client_retention_time)
		_clients = list(self._clients_by_uuid.values())
		_clients = list(filter(lambda _client: dt.datetime.utcnow() - _client.used_at > self._clients_ttl, _clients))
		_clients.sort(key=lambda _client: _client.used_at)
		for client in _clients:
			# print('-> removing ttl client: {}'.format(client.uuid))
			self.remove_client(client)
			_clients_len -= 1
			if _clients_len <= self._ab_config['max_clients']:
				return

		# remove clients, sorted by meetings
		# print('-> clients: {}'.format(_clients_len))
		_clients = list(self._clients_by_uuid.values())
		_clients.sort(key=lambda _client: _client.meetings)
		# print('-> clients: {}'.format(_clients))

		for client in _clients:
			# print('-> removing client: {} {} {}'.format(client.uuid, client.meetings, client.seen_at))
			self.remove_client(client)
			_clients_len -= 1
			if _clients_len <= self._ab_config['max_clients']:
				return

	def soft_clean_up(self, local_id: str = None):
		print('-> AddressBook.soft_clean_up({})'.format(local_id))

		# remove local_id
		if local_id != None and local_id in self._clients_by_id:
			del self._clients_by_id[local_id]

		_clients = list(self._clients_by_uuid.values())
		_clients_len = len(_clients)

		# remove out-of-date clients (invalid client_retention_time)
		_clients = list(self._clients_by_uuid.values())
		_clients = list(filter(lambda _client: dt.datetime.utcnow() - _client.used_at > self._clients_ttl, _clients))
		_clients.sort(key=lambda _client: _client.used_at)
		for client in _clients:
			# print('-> removing ttl client: {}'.format(client.uuid))
			self.remove_client(client)
			_clients_len -= 1
			if _clients_len <= self._ab_config['max_clients']:
				return

	def get_nearest_to(self, node: overlay.Node, limit: int = 20, with_contact_infos: bool = None) -> list:
		_clients = list(self._clients_by_uuid.values())
		_clients.sort(key=lambda _client: _client.node.distance(node))

		if with_contact_infos:
			_clients = list(filter(lambda _client: with_contact_infos == _client.has_contact(), _clients))

		return _clients[:limit]
