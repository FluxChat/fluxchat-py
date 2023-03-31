
import datetime as dt

from lib.json_file import JsonFile
from lib.client import Client
import lib.overlay as overlay

class AddressBook(JsonFile):
	_path: str
	_config: dict
	_clients_by_uuid: dict
	_clients_by_id: dict
	_changes: bool
	_clients_ttl: dt.timedelta

	def __init__(self, path: str, config: dict = None):
		print('-> AddressBook.__init__({})'.format(path))
		# print(f'{config}')

		self._path = path
		self._config = config
		self._clients_by_uuid = dict()
		self._clients_by_id = dict()
		self._changes = False

		if self._config == None:
			self._clients_ttl = dt.timedelta(hours=1)
		else:
			self._clients_ttl = dt.timedelta(hours=self._config['client_retention_time'])

		_data = self._read_json_file(self._path, {})
		for client_uuid, row in _data.items():
			client = Client()
			client.uuid = client_uuid
			client.from_dict(row)

			self._clients_by_uuid[client_uuid] = client
			if client.id != None:
				self._clients_by_id[client.id] = client

	def __del__(self):
		print('-> AddressBook.__del__()')
		self.save()

	def save(self) -> bool:
		if not self._changes:
			return False

		_data = dict()
		for client_uuid, client in self._clients_by_uuid.items():
			_data[client_uuid] = client.as_dict()

		self._write_json_file(self._path, _data)

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

	def get_client(self, id: str):
		# print('-> AddressBook.get_client({})'.format(id))

		if id in self._clients_by_uuid:
			return self._clients_by_uuid[id]

		if id in self._clients_by_id:
			return self._clients_by_id[id]

		return None

	def get_client_by_addr_port(self, addr: str, port: int):
		print('-> AddressBook.get_client_by_addr_port({}, {})'.format(addr, port))

		ffunc = lambda _client: _client[1].address == addr and _client[1].port == port

		_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		print('-> _clients: {}'.format(_clients))

		if len(_clients) > 0:
			return _clients[0][1]

		return None

	def add_client(self, id: str = None, addr: str = None, port: int = None) -> Client:
		print('-> AddressBook.add_client({}, {}, {})'.format(id, addr, port))

		client = Client()
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
		print('-> AddressBook.remove_client({})'.format(client))

		del self._clients_by_uuid[client.uuid]
		if client.id != None:
			del self._clients_by_id[client.id]
		self.changed()

	def add_bootstrap(self, file: str):
		print('-> AddressBook.add_bootstrap({})'.format(file))

		_data = self._read_json_file(file, [])
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

		self._write_json_file(file, [])

	def changed(self):
		# print('-> AddressBook.changed()')
		self._changes = True

	def clean_up(self):
		print('-> AddressBook.clean_up()')

		_clients = list(self._clients_by_uuid.values())
		_clients_len = len(_clients)
		_bootstrap_len = len(list(filter(lambda _client: _client.is_bootstrap, _clients)))

		print('-> clients: {}'.format(_clients_len))
		print('-> bootstrap: {}'.format(_bootstrap_len))

		if _clients_len <= self._config['max_clients']:
			return

		# remove bootstrap clients with no meetings
		for client in filter(lambda _client: _client.is_bootstrap and _client.meetings == 0, _clients):
			print('-> removing bootstrap client: {}'.format(client.uuid))
			self.remove_client(client)

		_clients = list(self._clients_by_uuid.values())
		_clients_len = len(_clients)

		_clients.sort(key=lambda _client: _client.meetings, reverse=True)

		print('-> clients: {}'.format(_clients_len))
		n = 0
		for client in _clients:
			remove = n >= self._config['max_clients']
			print('-> client: {} {} {} {}'.format(remove, client.uuid, client.meetings, client.seen_at))
			if remove:
				self.remove_client(client)
			n += 1

	def get_nearest_to(self, node: overlay.Node) -> list:
		_clients = list(self._clients_by_uuid.values())
		_clients.sort(key=lambda _client: _client.node.distance(node))
		return _clients
