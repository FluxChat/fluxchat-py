
import datetime as dt
from json import dumps
from logging import getLogger, Logger
from sqlite3 import Connection, Cursor, connect
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
	_new_clients: list[Client]
	_clients_by_uuid: dict[int, Client]
	_clients_by_pubid: dict[str, Client]
	_clients_to_remove: list[Client]
	_mails_by_uuid: dict[int, Mail]
	_new_queue_mails: list[Mail]
	_queue_by_uuid: dict[int, Mail]
	_queue_to_remove: list[Mail]
	_changes: bool
	_connection: Connection
	_cursor: Cursor
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
		self._connection = None
		self._cursor = None
		self._new_clients = []
		self._clients_by_uuid = dict()
		self._clients_by_pubid = dict()
		self._clients_to_remove = []
		self._mails_by_uuid = dict()
		self._new_queue_mails = []
		self._queue_by_uuid = dict()
		self._queue_to_remove = []

		if self._db_config is None:
			self._clients_ttl = dt.timedelta(hours=1)
		else:
			self._clients_ttl = dt.timedelta(hours=self._db_config['client_retention_time'])
		self._logger.info('clients_ttl %s', self._clients_ttl)

		self._mail_retention_time = dt.timedelta(hours=self._mail_config['retention_time'])

		# Init DB
		db_path = path.join(self._config['data_dir'], self._db_config['file_name'])
		if not path.isfile(db_path):
			run_create = True
		else:
			run_create = False
		self._connection = connect(str(db_path))
		self._cursor = self._connection.cursor()
		if run_create:
			self._create_tables()

	def __del__(self):
		self._logger.debug('__del__')
		self.save()

		if self._connection:
			self._connection.close()

	def changed(self):
		self._changes = True

	def load(self):
		# Load Nodes
		self._logger.debug('load nodes')
		nodes = self._cursor.execute('SELECT uuid, pubid, address, port, created_at, seen_at, used_at, meetings, is_bootstrap, is_trusted, debug_add FROM nodes;').fetchall()
		for node in nodes:
			self._logger.debug(f'load node: {node}')
			client = Client.from_db(node)

			self._logger.debug('load client: %s', client)

			if client.uuid is not None:
				if client.uuid in self._clients_by_uuid:
					self._logger.warning('Client UUID already exists: %s', client.uuid)
				self._clients_by_uuid[client.uuid] = client

			if client.pubid is not None:
				if client.pubid in self._clients_by_pubid:
					self._logger.warning('Client ID already exists: %s', client.pubid)

				self._clients_by_pubid[client.pubid] = client

				key_file_path = path.join(self._config['keys_dir'], client.pubid + '.pem')
				self._logger.debug(f'load node public key: {key_file_path}')
				if path.isfile(key_file_path):
					self._logger.debug(f'is file: {key_file_path}')
					client.load_public_key_from_pem_file(key_file_path)
				else:
					self._logger.debug(f'file not found: {key_file_path}')

		# Load Mails
		self._logger.debug('load queue')
		queued_mails = self._cursor.execute('SELECT uuid, pubid, receiver, body, is_encrypted, created_at, valid_until FROM queue').fetchall()
		for mail in queued_mails:
			self._logger.debug(f'load mail: {mail}')
			mail = Mail.from_queue_db(mail)

			self._queue_by_uuid[mail.uuid] = mail

		self._logger.debug('load mails')
		mails = self._cursor.execute('SELECT uuid, pubid, sender, receiver, subject, body, forwarded_to, is_encrypted, is_delivered, is_new, verified, sign_hash, sign, created_at, received_at, valid_until FROM mails').fetchall()
		for mail in mails:
			self._logger.debug(f'load mail: {mail}')
			mail = Mail.from_mail_db(mail)

			self._mails_by_uuid[mail.uuid] = mail

	def save(self) -> bool:
		self._logger.debug('save() changes=%s', self._changes)

		if not self._changes:
			return False
		self._changes = False

		self._logger.debug('save new clients len=%d', len(self._new_clients))
		for client in self._new_clients:
			self._logger.debug('new client: %s', client)
			# Insert Client
			sql = """
			INSERT INTO nodes (pubid, address, port, created_at, seen_at, used_at, meetings, is_bootstrap, is_trusted, debug_add)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
			"""
			self._cursor.execute(sql, (
				client.pubid,
				client.address, client.port,
				client.created_at,
				client.seen_at,
				client.used_at,
				client.meetings,
				client.is_bootstrap,
				client.is_trusted,
				client.debug_add))
			self._connection.commit()
			client.uuid = self._cursor.lastrowid

			self._clients_by_uuid[client.uuid] = client
			self._clients_by_pubid[client.pubid] = client
		self._new_clients = []

		self._logger.debug('save existing clients cbuuid=%d cbid=%d', len(self._clients_by_uuid), len(self._clients_by_pubid))
		for client_uuid, client in self._clients_by_uuid.items():
			self._logger.debug('save client: c=%s %s', client.has_changed, client)

			if not client.has_changed:
				continue

			if client.pubid is not None:
				key_file_path = path.join(self._config['keys_dir'], client.pubid + '.pem')
				if not path.isfile(key_file_path):
					client.write_public_key_to_pem_file(key_file_path)

			client.changed(False)

			self._logger.debug('update client: %s', client)
			# Update Client
			sql = """
			UPDATE nodes
			SET pubid =?,
				address = ?, port = ?,
				seen_at = ?,
				used_at = ?,
				meetings = ?,
				is_bootstrap = ?,
				is_trusted = ?,
				debug_add = ?
			WHERE uuid = ?;
			"""
			self._cursor.execute(sql, (
				client.pubid,
				client.address, client.port,
				client.seen_at,
				client.used_at,
				client.meetings,
				client.is_bootstrap,
				client.is_trusted,
				client.debug_add,
				client.uuid))

			self._connection.commit()

		self._logger.debug('clients to remove len=%d', len(self._clients_to_remove))
		for client in self._clients_to_remove:
			self._logger.debug('remove client: %s', client)
			# Remove Client
			sql = """DELETE FROM nodes WHERE uuid = ?;"""
			self._cursor.execute(sql, (client.uuid,))
			self._connection.commit()
		self._clients_to_remove = []

		### Queue
		self._logger.debug('save new queue mails len=%d', len(self._new_queue_mails))
		for mail in self._new_queue_mails:
			self._logger.debug('new queue mail: %s', mail)

			# Insert Mail
			sql = """
			INSERT INTO queue (pubid, receiver, body, is_encrypted, created_at, valid_until)
			VALUES (?, ?, ?, ?, ?, ?);
			"""
			self._cursor.execute(sql, (
				mail.pubid,
				mail.receiver,
				mail.body,
				mail.is_encrypted,
				mail.created_at,
				mail.valid_until))
			self._connection.commit()
			mail.uuid = self._cursor.lastrowid

			self._queue_by_uuid[mail.uuid] = mail
		self._new_queue_mails = []

		self._logger.debug('save existing queue mails len=%d', len(self._queue_by_uuid))
		for mail_uuid, mail in self._queue_by_uuid.items():
			sql = """
			UPDATE queue
			SET pubid = ?,
				receiver = ?,
				body = ?,
				is_encrypted = ?,
				created_at = ?,
				valid_until = ?
			WHERE uuid = ?;
			"""
			self._cursor.execute(sql, (
				mail.pubid,
				mail.receiver,
				mail.body,
				mail.is_encrypted,
				mail.created_at,
				mail.valid_until,
				mail.uuid))
			self._connection.commit()

		self._logger.debug('queue to remove len=%d', len(self._queue_to_remove))
		for mail in self._queue_to_remove:
			self._logger.debug('remove mail: %s', mail)
			# Remove Mail
			sql = """DELETE FROM queue WHERE uuid = ?;"""
			self._cursor.execute(sql, (mail.uuid,))
			self._connection.commit()
		self.queue_to_remove = []

		### Mails
		self._logger.debug('save mails len=%d', len(self._mails_by_uuid))
		for mail_uuid, mail in self._mails_by_uuid.items():
			self._logger.debug('save mail: %s', mail)

			forwarded_to = dumps(mail.forwarded_to, default=str)
			# Insert Mail
			if mail.uuid is None:
				sql = """
				INSERT INTO mails (pubid, sender, receiver, subject, body, forwarded_to, is_encrypted, is_delivered, is_new, verified, sign_hash, sign, created_at, received_at, valid_until)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
				"""
				self._cursor.execute(sql, (
					mail.pubid,
					mail.sender, mail.receiver,
					mail.subject, mail.body,
					forwarded_to,
					mail.is_encrypted,
					mail.is_delivered,
					mail.is_new,
					mail.verified,
					mail.sign_hash,
					mail.sign,
					mail.created_at,
					mail.received_at,
					mail.valid_until))
				self._connection.commit()
				mail.uuid = self._cursor.lastrowid
			else:
				# Update Mail
				sql = """
				UPDATE mails
				SET pubid = ?,
					sender = ?, receiver = ?,
					subject = ?, body = ?,
					forwarded_to = ?,
					is_encrypted = ?, is_delivered = ?, is_new = ?,
					verified = ?, sign_hash = ?, sign = ?,
					created_at = ?, received_at = ?, valid_until = ?
				WHERE uuid = ?
				"""
				self._cursor.execute(sql, (
					mail.pubid,
					mail.sender, mail.receiver,
					mail.subject, mail.body,
					forwarded_to,
					mail.is_encrypted,
					mail.is_delivered,
					mail.is_new,
					mail.verified,
					mail.sign_hash,
					mail.sign,
					mail.created_at,
					mail.received_at,
					mail.valid_until,
					mail.uuid))
				self._connection.commit()
			mail.changed(False)

		return True

	def _create_tables(self):
		sql = """
		CREATE TABLE IF NOT EXISTS nodes (
			uuid INTEGER PRIMARY KEY,
			pubid VARCHAR(255) NULL,
			address VARCHAR(15) NULL,
			port INTEGER NULL,
			meetings INTEGER NOT NULL DEFAULT 0,
			is_bootstrap BOOLEAN NOT NULL DEFAULT FALSE,
			is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
			debug_add VARCHAR(255) NULL,
			used_at TIMESTAMP NULL,
			seen_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL
		);
		"""
		self._cursor.execute(sql)
		self._connection.commit()

		sql = """
		CREATE TABLE IF NOT EXISTS queue (
			uuid INTEGER PRIMARY KEY,
			pubid VARCHAR(36) NULL,
			receiver VARCHAR(255) NULL,
			body TEXT NULL,
			is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL,
			valid_until TIMESTAMP NOT NULL
		);
		"""
		self._cursor.execute(sql)
		self._connection.commit()

		sql = """
		CREATE TABLE IF NOT EXISTS mails (
			uuid INTEGER PRIMARY KEY,
			pubid VARCHAR(36) NULL,
			sender VARCHAR(255) NULL,
			receiver VARCHAR(255) NULL,
			subject TEXT NULL,
			body TEXT NULL,
			forwarded_to TEXT NULL,
			is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
			is_delivered BOOLEAN NOT NULL DEFAULT FALSE,
			is_new BOOLEAN NOT NULL DEFAULT FALSE,
			verified TEXT NULL,
			sign_hash TEXT NULL,
			sign TEXT NULL,
			created_at TIMESTAMP NOT NULL,
			received_at TIMESTAMP NOT NULL,
			valid_until TIMESTAMP NOT NULL
		);
		"""
		self._cursor.execute(sql)
		self._connection.commit()

	def get_clients(self) -> dict[str, Client]:
		return self._clients_by_uuid

	def get_clients_len(self) -> int:
		return len(self._clients_by_uuid)

	def get_bootstrap_clients(self) -> list:
		def ffunc(_client_t: tuple[str, Client]):
			client = cast(Client, _client_t[1])
			return client.is_bootstrap
		bootstrap_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		return bootstrap_clients

	def get_bootstrap_clients_len(self) -> int:
		def ffunc(_client_t: tuple[str, Client]):
			client = cast(Client, _client_t[1])
			return client.is_bootstrap
		bootstrap_clients = list(filter(ffunc, self._clients_by_uuid.items()))
		return len(bootstrap_clients)

	def get_client_by_uuid(self, uuid: str) -> Optional[Client]:
		self._logger.debug('get_client_by_uuid(%s)', uuid)
		if uuid in self._clients_by_uuid:
			return self._clients_by_uuid[uuid]
		return None

	def get_client_by_pubid(self, pubid: str) -> Optional[Client]:
		self._logger.debug('get_client_by_pubid(%s)', pubid)
		if pubid in self._clients_by_pubid:
			return self._clients_by_pubid[pubid]
		return None

	def get_client_by_addr_port(self, addr: str, port: int) -> Optional[Client]:
		def ffunc(_client_t: tuple[str, Client]):
			_client = cast(Client, _client_t[1])
			return _client.address == addr and _client.port == port

		_clients = list(filter(ffunc, self._clients_by_uuid.items()))

		# print(f'get_client_by_addr_port _clients: {_clients}')
		if len(_clients) > 0:
			return _clients[0][1]
		return None

	def add_client(self, pubid: str = None, addr: str = None, port: int = None) -> Client:
		self._logger.debug('add_client(%s, %s, %s)', id, addr, port)
		if pubid in self._clients_by_pubid:
			self._logger.debug('client already exists: (%s, %s, %s)', pubid, addr, port)
			return self._clients_by_pubid[pubid]

		client = Client()
		if pubid is not None:
			client.set_pubid(pubid)
		if addr is not None:
			client.address = addr
		if port is not None:
			client.port = port

		# if client.pubid is not None:
		# 	self._clients_by_pubid[client.pubid] = client

		self._new_clients.append(client)

		self.changed()
		self.save()

		return client

	def append_client(self, client: Client) -> None:
		self._logger.debug('append_client(%s)', client)

		if client.pubid is not None:
			self._clients_by_pubid[client.pubid] = client

		self.changed()
		self.save()

	def remove_client(self, client: Client, force: bool = False) -> bool:
		self._logger.debug('remove_client(%s, %s)', client, force)

		if not force and client.is_trusted:
			return False

		key_file_path = path.join(self._config['keys_dir'], client.pubid + '.pem')
		if path.isfile(key_file_path):
			remove(key_file_path)

		if client.uuid is not None and client.uuid in self._clients_by_uuid:
			del self._clients_by_uuid[client.uuid]

		if client.pubid is not None:
			del self._clients_by_pubid[client.pubid]

		self._clients_to_remove.append(client)

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

			self._logger.debug('new bootstrap: %s:%s', contact.addr, contact.port)

			client = Client()
			client.address = contact.addr
			client.port = contact.port
			client.is_bootstrap = True
			client.debug_add = 'bootstrap'

			# self._clients_by_uuid[client.uuid] = client

			# if client.pubid is not None:
			# 	self._clients_by_pubid[client.pubid] = client

			self._new_clients.append(client)

			self.changed()

		self.save()

		write_json_file(file_path, [])

	def hard_clean_up(self, local_id: str = None) -> int:
		self._logger.debug('hard_clean_up(%s)', local_id)

		_clients_removed_c = 0
		_clients_len = len(self._clients_by_pubid)

		# remove local_id
		if local_id is not None and local_id in self._clients_by_pubid:
			del self._clients_by_pubid[local_id]

		if len(self._clients_by_pubid) <= self._max_clients:
			return _clients_removed_c

		# remove bootstrap clients with no meetings
		def ffunc1(_client: Client):
			# client = cast(Client, _client_t[1])
			return _client.is_bootstrap and _client.meetings == 0

		_clients = list(self._clients_by_pubid.values())
		_clients = list(filter(ffunc1, _clients))
		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				_clients_removed_c += 1
				if _clients_len <= self._max_clients:
					return _clients_removed_c

		# remove out-of-date clients (invalid client_retention_time)
		def ffunc2(_client: Client):
			return dt.datetime.now(dt.UTC) - _client.used_at > self._clients_ttl

		_clients = list(self._clients_by_pubid.values())
		_clients = list(filter(ffunc2, _clients))
		_clients.sort(key=lambda _client: _client.used_at)
		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				_clients_removed_c += 1
				if _clients_len <= self._max_clients:
					return _clients_removed_c

		# remove clients, sorted by meetings
		def sfunc(_client: Client):
			return _client.meetings

		_clients = list(self._clients_by_pubid.values())
		_clients.sort(key=sfunc)

		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				_clients_removed_c += 1
				if _clients_len <= self._max_clients:
					return _clients_removed_c

		return _clients_removed_c

	def soft_clean_up(self, local_id: str = None) -> int:
		self._logger.debug('soft_clean_up(%s)', local_id)

		_clients_removed_c = 0

		# remove local_id
		if local_id is not None and local_id in self._clients_by_pubid:
			del self._clients_by_pubid[local_id]

		_clients_len = len(self._clients_by_pubid)

		# remove out-of-date clients (invalid client_retention_time)
		_clients = list(self._clients_by_pubid.values())
		_clients = list(filter(lambda _client: dt.datetime.now(dt.UTC) - _client.used_at > self._clients_ttl and _client.meetings == 0, _clients))
		_clients.sort(key=lambda _client: _client.used_at)
		for client in _clients:
			if self.remove_client(client):
				_clients_len -= 1
				_clients_removed_c += 1
				if _clients_len <= self._max_clients:
					return _clients_removed_c

		return _clients_removed_c

	def get_nearest_to(self, node: Node, limit: int = 20, with_contact_infos: bool = None) -> list[Client]:
		self._logger.debug('get_nearest_to(%s)', node)

		def sort_key(_client: Client) -> Distance:
			print(f'-> sort_key client: {_client}')
			print(f'-> sort_key node: {_client.node}')
			return _client.node.distance(node)

		_clients = list(self._clients_by_pubid.values())
		_clients.sort(key=sort_key)

		if with_contact_infos:
			_clients = list(filter(lambda _client: with_contact_infos == _client.has_contact(), _clients))

		return _clients[:limit]

	### Mails

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

	### Queue

	def add_queue_mail(self, mail: Mail) -> int:
		self._logger.debug('add_mail(%s)', mail)
		self._logger.debug('_new_queue_mails=%d', len(self._new_queue_mails))

		mail.valid_until = dt.datetime.now(dt.UTC) + self._mail_retention_time
		mail.changed()

		self._new_queue_mails.append(mail)
		self._logger.debug('_new_queue_mails=%d', len(self._new_queue_mails)) # TODO remove

		self.changed()
		self.save()

		self._logger.debug('_new_queue_mails=%d', len(self._new_queue_mails)) # TODO remove

		return len(self._queue_by_uuid)

	def get_queue_mails(self) -> dict[str, Mail]:
		self._logger.debug('get_queue_mails() -> %d', len(self._new_queue_mails)) # TODO remove
		return self._queue_by_uuid

	def has_queue_mail(self, mail_uuid: str) -> bool:
		self._logger.debug('has_mail(%s)', mail_uuid)
		self._logger.debug('_new_queue_mails=%d', len(self._new_queue_mails)) # TODO remove
		return mail_uuid in self._queue_by_uuid

	def clean_queue_up(self) -> None:
		self._logger.info('clean queue up')

		def ffunc(_mail_t: tuple[str, Mail]):
			_mail = cast(Mail, _mail_t[1])
			return _mail.valid_until is not None \
				and dt.datetime.now(dt.UTC) >= _mail.valid_until

		old_mails = list(filter(ffunc, self._queue_by_uuid.items()))
		self._logger.debug('old mails A: %s', old_mails)

		for mail_uuid, mail in old_mails:
			self._logger.debug('remove mail: %s', mail)

			del self._queue_by_uuid[mail_uuid]
			self.changed()

			self._queue_to_remove.append(mail)

	def delete_queue_mails(self) -> int:
		old_len = len(self._queue_by_uuid)
		self._queue_by_uuid = dict()

		sql = """DELETE FROM queue;"""
		self._cursor.execute(sql)
		self._connection.commit()

		return old_len
