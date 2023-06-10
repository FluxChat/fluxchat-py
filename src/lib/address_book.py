
import logging
import datetime as dt
import os

from sty import fg
from lib.client import Client

import lib.overlay as overlay
from lib.helper import read_json_file, write_json_file
from lib.contact import Contact

class AddressBook():
	_path: str
	_config: dict
	_ab_config: dict
	_clients_by_uuid: dict
	_clients_by_id: dict
	_changes: bool
	_clients_ttl: dt.timedelta

	def __init__(self, path: str, config: dict = None):
		self._path = path
		self._config = config
		self._ab_config = self._config['address_book']
		self._clients_by_uuid = dict()
		self._clients_by_id = dict()
		self._changes = False

		self._logger = logging.getLogger('address_book')
		self._logger.info('init()')

		if self._ab_config == None:
			self._clients_ttl = dt.timedelta(hours=1)
		else:
			self._clients_ttl = dt.timedelta(hours=self._ab_config['client_retention_time'])

		self._logger.info('clients_ttl %s', self._clients_ttl)

	def load(self):
		self._logger.debug('load()')

		_data = read_json_file(self._path, {})
		for client_uuid, row in _data.items():
			client = Client()
			client.uuid = client_uuid
			client.from_dict(row)

			self._logger.debug('load client: %s', client)

			self._clients_by_uuid[client_uuid] = client
			if client.id != None:
				if client.id in self._clients_by_id:
					self._logger.warning('Client ID already exists: %s', client.id)

				self._clients_by_id[client.id] = client

				key_file_path = os.path.join(self._config['keys_dir'], client.id + '.pem')
				if os.path.isfile(key_file_path):
					client.load_public_key_from_pem_file(key_file_path)

	def save(self) -> bool:
		self._logger.debug('save() changes=%s', self._changes)

		if not self._changes:
			return False

		_data = dict()
		for client_uuid, client in self._clients_by_uuid.items():
			self._logger.debug('save client: %s', client)

			_data[client_uuid] = client.as_dict()

			if client.id != None:
				key_file_path = os.path.join(self._config['keys_dir'], client.id + '.pem')
				if not os.path.isfile(key_file_path):
					client.write_public_key_to_pem_file(key_file_path)

		write_json_file(self._path, _data)
		self._changes = False

		return True

	def get_clients(self) -> dict:
		return self._clients_by_uuid

	def get_clients_len(self) -> int:
		return len(self._clients_by_uuid)

	def get_bootstrap_clients(self) -> list:
		ffunc = lambda _client: _client[1].is_bootstrap
		bootstrap_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		return bootstrap_clients

	def get_bootstrap_clients_len(self) -> int:
		ffunc = lambda _client: _client[1].is_bootstrap
		bootstrap_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		return len(bootstrap_clients)

	def get_client_by_id(self, id: str) -> Client:
		self._logger.debug('get_client_by_id(%s)', id)

		if id in self._clients_by_id:
			return self._clients_by_id[id]

		return None

	def get_client_by_uuid(self, uuid: str) -> Client:
		self._logger.debug('get_client_by_uuid(%s)', uuid)

		if uuid in self._clients_by_uuid:
			return self._clients_by_uuid[uuid]

		return None

	def get_client_by_addr_port(self, addr: str, port: int):
		ffunc = lambda _client: _client[1].address == addr and _client[1].port == port
		_clients = list(filter(ffunc, self._clients_by_uuid.items()))

		if len(_clients) > 0:
			return _clients[0][1]

		return None

	def add_client(self, id: str = None, addr: str = None, port: int = None) -> Client:
		self._logger.debug('add_client(%s, %s, %s)', id, addr, port)

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

	def append_client(self, client: Client):
		self._logger.debug('append_client(%s)', client)

		self._clients_by_uuid[client.uuid] = client
		if client.id != None:
			self._clients_by_id[client.id] = client

		self.changed()

	def remove_client(self, client: Client, force: bool = False) -> bool:
		self._logger.debug('remove_client(%s, %s)', client, force)

		if not force and client.is_trusted:
			return False

		key_file_path = os.path.join(self._config['keys_dir'], client.id + '.pem')
		if os.path.isfile(key_file_path):
			os.remove(key_file_path)

		del self._clients_by_uuid[client.uuid]
		if client.id != None:
			del self._clients_by_id[client.id]

		self.changed()

		return True

	def add_bootstrap(self, file_path: str):
		self._logger.debug('add_bootstrap(%s)', file_path)
		_data = read_json_file(file_path, [])
		for row in _data:
			contact = Contact.parse(row)

			_client = self.get_client_by_addr_port(contact.addr, contact.port)
			if _client != None:
				self._logger.debug('bootstrap client already exists: %s', _client)
				continue

			client = Client()
			client.address = contact.addr
			client.port = contact.port
			client.is_bootstrap = True
			client.debug_add = 'bootstrap'

			self._clients_by_uuid[client.uuid] = client
			if client.id != None:
				self._clients_by_id[client.id] = client

			self.changed()

		write_json_file(file_path, [])

	def changed(self):
		self._changes = True

	def hard_clean_up(self, local_id: str = None):
		self._logger.debug('hard_clean_up(%s)', local_id)

		# remove local_id
		if local_id != None and local_id in self._clients_by_id:
			del self._clients_by_id[local_id]

		_clients = list(self._clients_by_uuid.values())
		_clients_len = len(_clients)

		if _clients_len <= self._ab_config['max_clients']:
			return

		# remove bootstrap clients with no meetings
		_clients = list(filter(lambda _client: _client.is_bootstrap and _client.meetings == 0, _clients))
		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				if _clients_len <= self._ab_config['max_clients']:
					return

		# remove out-of-date clients (invalid client_retention_time)
		_clients = list(self._clients_by_uuid.values())
		_clients = list(filter(lambda _client: dt.datetime.utcnow() - _client.used_at > self._clients_ttl, _clients))
		_clients.sort(key=lambda _client: _client.used_at)
		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				if _clients_len <= self._ab_config['max_clients']:
					return

		# remove clients, sorted by meetings
		_clients = list(self._clients_by_uuid.values())
		_clients.sort(key=lambda _client: _client.meetings)

		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				if _clients_len <= self._ab_config['max_clients']:
					return

	def soft_clean_up(self, local_id: str = None):
		self._logger.debug('soft_clean_up(%s)', local_id)

		# remove local_id
		if local_id != None and local_id in self._clients_by_id:
			del self._clients_by_id[local_id]

		_clients = list(self._clients_by_uuid.values())
		_clients_len = len(_clients)

		# remove out-of-date clients (invalid client_retention_time)
		_clients = list(self._clients_by_uuid.values())
		_clients = list(filter(lambda _client: dt.datetime.utcnow() - _client.used_at > self._clients_ttl and _client.meetings == 0, _clients))
		_clients.sort(key=lambda _client: _client.used_at)
		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				if _clients_len <= self._ab_config['max_clients']:
					return

	def get_nearest_to(self, node: overlay.Node, limit: int = 20, with_contact_infos: bool = None) -> list:
		_clients = list(self._clients_by_uuid.values())
		_clients.sort(key=lambda _client: _client.node.distance(node))

		if with_contact_infos:
			_clients = list(filter(lambda _client: with_contact_infos == _client.has_contact(), _clients))

		return _clients[:limit]
