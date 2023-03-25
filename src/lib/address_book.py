
from lib.json_file import JsonFile
from lib.client import Client

class AddressBook(JsonFile):
	_path: str
	_clients_by_uuid: dict
	_clients_by_id: dict
	_changes: bool

	def __init__(self, path: str):
		print('-> AddressBook.__init__({})'.format(path))
		self._path = path
		self._clients_by_uuid = dict()
		self._clients_by_id = dict()
		self._changes = False

		_data = self._read_json_file(self._path, {})
		for client_uuid, row in _data.items():
			client = Client()
			client.from_dict(row)

			self._clients_by_uuid[client_uuid] = client
			if client.id != None:
				self._clients_by_id[client.id] = client

	def __del__(self):
		print('-> AddressBook.__del__()')

		if self._changes:
			_data = dict()
			for client_uuid, client in self._clients_by_uuid.items():
				_data[client_uuid] = client.as_dict()

			self._write_json_file(self._path, _data)

	def get_clients(self) -> dict:
		print('-> AddressBook.get_clients()')
		return self._clients_by_uuid

	def get_client(self, id: str):
		print('-> AddressBook.get_client({})'.format(id))

		if id in self._clients_by_uuid:
			return self._clients_by_uuid[id]

		if id in self._clients_by_id:
			return self._clients_by_id[id]

		return None

	def add_client(self, items: list):
		print('-> AddressBook.add_client({})'.format(items))

		client = Client()
		client.from_list(items)

		self._clients_by_uuid[client.uuid] = client

		if client.id != None:
			self._clients_by_id[client.id] = client

		self._changes = True

		return client

	def add_bootstrap(self, file: str):
		print('-> AddressBook.add_bootstrap({})'.format(file))

		_data = self._read_json_file(file, [])
		for row in _data:
			self.add_client(row.split(':'))

		self._write_json_file(file, [])
