
import datetime as dt
from logging import getLogger, Logger
from sqlite3 import Connection, connect
from os import path, remove
from typing import Optional, cast
from lib.helper import read_json_file, write_json_file
from lib.client import Client
from lib.overlay import Node, Distance
from lib.contact import Contact
from lib.mail import Mail


class Database():
	_logger: Logger
	_config: dict
	_db_config: dict
	_mail_config: dict
	_max_clients: int
	_clients_by_uuid: dict[str, Client]
	_clients_by_id: dict[str, Client]
	_mails_by_uuid: dict[str, Mail]
	_queue_by_uuid: dict[str, Mail]
	_changes: bool
	_connection: Connection
	_clients_ttl: dt.timedelta
	_mail_retention_time: dt.timedelta

	def __init__(self, config: dict = None):
		self._logger = getLogger('app.database')
		self._logger.info('init()')

		self._config = config
		self._db_config = self._config['database']
		self._mail_config = self._config['mail']

		self._max_clients = self._db_config['max_clients']

		self._changes = False
		self._clients_by_uuid = dict()
		self._clients_by_id = dict()
		self._mails_by_uuid = dict()
		self._queue_by_uuid = dict()

		if self._db_config is None:
			self._clients_ttl = dt.timedelta(hours=1)
		else:
			self._clients_ttl = dt.timedelta(hours=self._db_config['client_retention_time'])
		self._logger.info('clients_ttl %s', self._clients_ttl)

		self._mail_retention_time = dt.timedelta(hours=self._mail_config['retention_time'])

		db_path = path.join(self._config['data_dir'], self._db_config['file_name'])
		self._connection = connect(str(db_path))
		self._cursor = self._connection.cursor()

	def __del__(self):
		self.save()
		self._connection.close()

	def changed(self):
		self._changes = True

	def load(self):
		self._logger.debug('load()')

		# TODO
		# _data = read_json_file(self._path, {})
		# for client_uuid, row in _data.items():
		# 	client = Client()
		# 	client.uuid = client_uuid
		# 	client.from_dict(row)

		# 	self._logger.debug('load client: %s', client)

		# 	self._clients_by_uuid[client_uuid] = client
		# 	if client.id is not None:
		# 		if client.id in self._clients_by_id:
		# 			self._logger.warning('Client ID already exists: %s', client.id)

		# 		self._clients_by_id[client.id] = client

		# 		key_file_path = path.join(self._config['keys_dir'], client.id + '.pem')
		# 		if path.isfile(key_file_path):
		# 			client.load_public_key_from_pem_file(key_file_path)

	def save(self) -> bool:
		self._logger.debug('save() changes=%s', self._changes)

		if not self._changes:
			return False

		# TODO
		# _data = dict()
		for client_uuid, client in self._clients_by_uuid.items():
			self._logger.debug('save client: %s', client)

			# _data[client_uuid] = client.as_dict()

			if client.id is not None:
				key_file_path = path.join(self._config['keys_dir'], client.id + '.pem')
				if not path.isfile(key_file_path):
					client.write_public_key_to_pem_file(key_file_path)

		# write_json_file(self._path, _data)
		self._changes = False

		# TODO
		#self._connection.commit()

		return True

	def create_tables(self):
		pass

	def get_clients(self) -> dict[str, Client]:
		return self._clients_by_uuid

	def get_clients_len(self) -> int:
		return len(self._clients_by_uuid)

	def get_bootstrap_clients(self) -> list:
		def ffunc(_client_t: tuple[str, Client]):
			client = _client_t[1]
			return client.is_bootstrap
		bootstrap_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		return bootstrap_clients

	def get_bootstrap_clients_len(self) -> int:
		def ffunc(_client_t: tuple[str, Client]):
			client = _client_t[1]
			return client.is_bootstrap
		bootstrap_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		return len(bootstrap_clients)

	def get_client_by_id(self, id: str) -> Optional[Client]:
		self._logger.debug('get_client_by_id(%s)', id)
		if id in self._clients_by_id:
			return self._clients_by_id[id]
		return None

	def get_client_by_uuid(self, uuid: str) -> Optional[Client]:
		self._logger.debug('get_client_by_uuid(%s)', uuid)
		if uuid in self._clients_by_uuid:
			return self._clients_by_uuid[uuid]
		return None

	def get_client_by_addr_port(self, addr: str, port: int) -> Optional[Client]:
		def ffunc(_client):
			return _client[1].address == addr and _client[1].port == port
		_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		if len(_clients) > 0:
			return _clients[0][1]
		return None

	def add_client(self, id: str = None, addr: str = None, port: int = None) -> Client:
		self._logger.debug('add_client(%s, %s, %s)', id, addr, port)

		client = Client()
		if id is not None:
			client.set_id(id)
		if addr is not None:
			client.address = addr
		if port is not None:
			client.port = port
		self._clients_by_uuid[client.uuid] = client
		if client.id is not None:
			self._clients_by_id[client.id] = client
		self.changed()
		return client

	def append_client(self, client: Client) -> None:
		self._logger.debug('append_client(%s)', client)
		self._clients_by_uuid[client.uuid] = client
		if client.id is not None:
			self._clients_by_id[client.id] = client
		self.changed()

	def remove_client(self, client: Client, force: bool = False) -> bool:
		self._logger.debug('remove_client(%s, %s)', client, force)
		if not force and client.is_trusted:
			return False
		key_file_path = path.join(self._config['keys_dir'], client.id + '.pem')
		if path.isfile(key_file_path):
			remove(key_file_path)
		del self._clients_by_uuid[client.uuid]
		if client.id is not None:
			del self._clients_by_id[client.id]
		self.changed()
		return True

	def add_bootstrap(self, file_path: str) -> None:
		self._logger.debug('add_bootstrap(%s)', file_path)
		_data = read_json_file(file_path, [])
		for row in _data:
			contact = Contact.parse(row)

			_client = self.get_client_by_addr_port(contact.addr, contact.port)
			if _client is not None:
				self._logger.debug('bootstrap client already exists: %s', _client)
				continue

			client = Client()
			client.address = contact.addr
			client.port = contact.port
			client.is_bootstrap = True
			client.debug_add = 'bootstrap'

			self._clients_by_uuid[client.uuid] = client

			if client.id is not None:
				self._clients_by_id[client.id] = client

			self.changed()

		write_json_file(file_path, [])

	def hard_clean_up(self, local_id: str = None) -> None:
		self._logger.debug('hard_clean_up(%s)', local_id)

		# remove local_id
		if local_id is not None and local_id in self._clients_by_id:
			del self._clients_by_id[local_id]

		_clients = list(self._clients_by_uuid.values())
		_clients_len = len(_clients)

		if _clients_len <= self._max_clients:
			return

		# remove bootstrap clients with no meetings
		_clients = list(filter(lambda _client: _client.is_bootstrap and _client.meetings == 0, _clients))
		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				if _clients_len <= self._max_clients:
					return

		# remove out-of-date clients (invalid client_retention_time)
		_clients = list(self._clients_by_uuid.values())
		_clients = list(filter(lambda _client: dt.datetime.now(dt.UTC) - _client.used_at > self._clients_ttl, _clients))
		_clients.sort(key=lambda _client: _client.used_at)
		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				if _clients_len <= self._max_clients:
					return

		# remove clients, sorted by meetings
		_clients = list(self._clients_by_uuid.values())
		_clients.sort(key=lambda _client: _client.meetings)

		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				if _clients_len <= self._max_clients:
					return

	def soft_clean_up(self, local_id: str = None) -> None:
		self._logger.debug('soft_clean_up(%s)', local_id)

		# remove local_id
		if local_id is not None and local_id in self._clients_by_id:
			del self._clients_by_id[local_id]

		_clients = list(self._clients_by_uuid.values())
		_clients_len = len(_clients)

		# remove out-of-date clients (invalid client_retention_time)
		_clients = list(self._clients_by_uuid.values())
		_clients = list(filter(lambda _client: dt.datetime.now(dt.UTC) - _client.used_at > self._clients_ttl and _client.meetings == 0, _clients))
		_clients.sort(key=lambda _client: _client.used_at)
		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				if _clients_len <= self._max_clients:
					return

	def get_nearest_to(self, node: Node, limit: int = 20, with_contact_infos: bool = None) -> list[Client]:
		def sort_key(_client: Client) -> Distance:
			print(f'-> sort_key client: {_client}')
			print(f'-> sort_key node: {_client.node}')
			return _client.node.distance(node)

		_clients = list(self._clients_by_uuid.values())
		_clients.sort(key=sort_key)

		if with_contact_infos:
			_clients = list(filter(lambda _client: with_contact_infos == _client.has_contact(), _clients))

		return _clients[:limit]

	def add_mail(self, mail: Mail) -> None:
		self._logger.debug('add_mail %s', mail)

		self._mails_by_uuid[mail.uuid] = mail
		self._changes = True

	def has_mail(self, mail_uuid: str) -> bool:
		self._logger.debug('has_mail %s', mail_uuid)
		return mail_uuid in self._mails_by_uuid

	def get_mails(self) -> dict[str, Mail]:
		return self._mails_by_uuid

	def get_mail(self, mail_uuid: str) -> Mail:
		self._logger.debug('get_mail %s', mail_uuid)
		self._logger.debug('_data %s', self._mails_by_uuid)

		try:
			return self._mails_by_uuid[mail_uuid]
		except KeyError:
			return None

	def add_queue_mail(self, mail: Mail) -> None:
		self._logger.debug('add_mail(%s)', mail)

		mail.valid_until = dt.datetime.now(dt.UTC) + self._mail_retention_time
		mail.changed()

		self._queue_by_uuid[mail.uuid] = mail
		self._changes = True

	def get_queue_mails(self) -> dict[str, Mail]:
		return self._queue_by_uuid

	def has_queue_mail(self, mail_uuid: str) -> bool:
		self._logger.debug('has_mail(%s)', mail_uuid)
		return mail_uuid in self._queue_by_uuid

	def clean_queue_up(self) -> None:
		self._logger.info('clean up')

		def ffunc(_mail_t: tuple[str, Mail]):
			_mail = cast(Mail, _mail_t[1])
			return _mail.valid_until is not None and dt.datetime.now(dt.UTC) >= _mail.valid_until
		old_mails = list(filter(ffunc, self._queue_by_uuid.items()))
		self._logger.debug('old mails A: %s', old_mails)

		for mail_uuid, mail in old_mails:
			self._logger.debug('remove mail: %s', mail)

			del self._queue_by_uuid[mail_uuid]
			self._changes = True
