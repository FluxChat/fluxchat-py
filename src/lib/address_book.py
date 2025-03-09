
import datetime as dt
from os import path, remove
from logging import getLogger, Logger
from sty import fg
from lib.client import Client
from lib.helper import read_json_file, write_json_file


# class AddressBook():
# 	_path: str
# 	_config: dict
# 	_ab_config: dict
# 	_clients_by_uuid: dict[str, Client]
# 	_clients_by_id: dict[str, Client]
# 	_changes: bool
# 	_clients_ttl: dt.timedelta
# 	_logger: Logger

# 	def __init__(self, path: str, config: dict = None):
# 		self._path = path
# 		self._config = config
# 		self._ab_config = self._config['address_book']
# 		self._clients_by_uuid = dict()
# 		self._clients_by_id = dict()
# 		self._changes = False

# 		self._logger = getLogger('app.address_book')
# 		self._logger.info('init()')

# 		if self._ab_config is None:
# 			self._clients_ttl = dt.timedelta(hours=1)
# 		else:
# 			self._clients_ttl = dt.timedelta(hours=self._ab_config['client_retention_time'])

# 		self._logger.info('clients_ttl %s', self._clients_ttl)

# 	def load(self):
# 		self._logger.debug('load()')

# 		_data = read_json_file(self._path, {})
# 		for client_uuid, row in _data.items():
# 			client = Client()
# 			client.uuid = client_uuid
# 			client.from_dict(row)

# 			self._logger.debug('load client: %s', client)

# 			self._clients_by_uuid[client_uuid] = client
# 			if client.id is not None:
# 				if client.id in self._clients_by_id:
# 					self._logger.warning('Client ID already exists: %s', client.id)

# 				self._clients_by_id[client.id] = client

# 				key_file_path = path.join(self._config['keys_dir'], client.id + '.pem')
# 				if path.isfile(key_file_path):
# 					client.load_public_key_from_pem_file(key_file_path)

# 	def save(self) -> bool:
# 		self._logger.debug('save() changes=%s', self._changes)

# 		if not self._changes:
# 			return False

# 		_data = dict()
# 		for client_uuid, client in self._clients_by_uuid.items():
# 			self._logger.debug('save client: %s', client)

# 			_data[client_uuid] = client.as_dict()

# 			if client.id is not None:
# 				key_file_path = path.join(self._config['keys_dir'], client.id + '.pem')
# 				if not path.isfile(key_file_path):
# 					client.write_public_key_to_pem_file(key_file_path)

# 		write_json_file(self._path, _data)
# 		self._changes = False

# 		return True
