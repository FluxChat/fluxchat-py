
from lib.json_file import JsonFile
from lib.client import Client

class AddressBook(JsonFile):
	_path: str
	_clients: dict
	_changes: bool

	def __init__(self, path: str):
		print('-> AddressBook.__init__({})'.format(path))
		self._path = path
		self._clients = dict()
		self._changes = False

		_data = self._read_json_file(self._path, {})
		for client_id, row in _data.items():
			client = Client()
			client.from_dict(row)

			self._clients[row['id']] = client

	def __del__(self):
		print('-> AddressBook.__del__()')

		if self._changes:
			_data = dict()
			for client_id, client in self._clients.items():
				_data[client_id] = client.as_dict()
				# print(_data[client_id])

			self._write_json_file(self._path, _data)

	def get_client(self, id: str):
		print('-> AddressBook.get_client({})'.format(id))

		#client = dict(filter(lambda item: item[1] > 200, self._clients.items()))

		if id in self._clients:
			return self._clients[id]
		else:
			return None

	def add_client(self, items: list):
		print('-> AddressBook.add_client({})'.format(items))

		client = Client()
		client.from_list(items)

		self._clients[client.id] = client
		self._changes = True

		return client
