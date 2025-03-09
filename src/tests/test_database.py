
import datetime as dt
from os import path, remove
from typing import cast
from unittest import TestCase
from lib.client import Client
from lib.database import Database


BOOTSTRAP_PATH = 'tmp/tests/bootstrap.json'


class AddressBookTestCase(TestCase):
	def setUp(self) -> None:
		self.config = {
			'data_dir': 'tmp/tests',
			'keys_dir': 'tmp/tests/keys',
			'database': {
				'file_name': 'test.db',
				'max_clients': 2,
				'client_retention_time': 24,
			},
			'mail': {'retention_time': 24},
		}
		self.db_path = path.join(self.config['data_dir'], self.config['database']['file_name'])

	def test_save_load(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.is_bootstrap = True
		client1.meetings = 1
		database.append_client(client1)
		self.assertEqual(database.get_clients_len(), 1)

		database.add_client('FC_test2', 'localhost', 25002)
		database.save()
		self.assertEqual(database.get_clients_len(), 2)

		database = Database(self.config)
		database.load()
		self.assertEqual(database.get_clients_len(), 2)

		database.remove_client(client1)
		self.assertEqual(database.get_clients_len(), 1)

	def test_get_client_by_pid(self):
		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)

		client1b = database.get_client_by_pid('FC_test1')
		self.assertEqual(client1b.pid, 'FC_test1')

		client1c = database.get_client_by_pid('FC_test1')
		self.assertEqual(client1c.pid, 'FC_test1')

		client3 = database.get_client_by_pid('FC_test3')
		self.assertEqual(client3, None)

		client1e = database.get_client_by_addr_port('localhost', 25001)
		self.assertEqual(client1e.pid, 'FC_test1')

		client2 = database.get_client_by_addr_port('localhost', 25002)
		self.assertEqual(client2, None)

	def test_bootstrap(self):
		if path.exists(self.db_path):
			remove(self.db_path)
		if path.exists(BOOTSTRAP_PATH):
			remove(BOOTSTRAP_PATH)

		with open(BOOTSTRAP_PATH, 'w') as fh:
			fh.write('["localhost:25001", "localhost:25002"]')

		database = Database(self.config)
		database.add_bootstrap(BOOTSTRAP_PATH)
		self.assertEqual(database.get_bootstrap_clients_len(), 2)

	# clients < max_clients
	def test_hard_clean_up1(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)
		database.add_client('FC_test1', 'localhost', 25001)
		clients_removed = database.hard_clean_up()
		self.assertEqual(clients_removed, 0)
		self.assertEqual(database.get_clients_len(), 1)

	# remove bootstrap clients with no meetings
	def test_hard_clean_up2(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.is_bootstrap = True
		client1.meetings = 0

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.is_bootstrap = True
		client2.meetings = 0

		clients_removed = database.hard_clean_up()
		self.assertEqual(clients_removed, 0)
		self.assertEqual(database.get_clients_len(), 2)

	# remove bootstrap clients with no meetings
	def test_hard_clean_up3(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.is_bootstrap = True
		client1.meetings = 0

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.is_bootstrap = True
		client2.meetings = 0

		client3 = database.add_client('FC_test3', 'localhost', 25003)
		client3.is_bootstrap = False
		client3.meetings = 0

		clients_removed = database.hard_clean_up()
		self.assertEqual(clients_removed, 1)
		self.assertEqual(database.get_clients_len(), 2)

		def mfunc(_client: tuple[int, Client]) -> str:
			return _client[1].pid

		clients = list(map(mfunc, database.get_clients().items()))
		self.assertEqual(clients, ['FC_test2', 'FC_test3'])

	# remove clients with invalid client_retention_time
	def test_hard_clean_up4(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.meetings = 100
		client1.seen_at = dt.datetime.strptime('2001-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.meetings = 100
		client2.seen_at = dt.datetime.strptime('2001-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client3 = database.add_client('FC_test3', 'localhost', 25003)
		client3.meetings = 100
		client3.seen_at = dt.datetime.strptime('2001-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		clients_removed = database.hard_clean_up()
		self.assertEqual(clients_removed, 1)
		self.assertEqual(database.get_clients_len(), 2)

		def mfunc(_client_t: tuple[int, Client]) -> str:
			return _client_t[1].pid

		clients = list(map(mfunc, database.get_clients().items()))
		self.assertEqual(clients, ['FC_test2', 'FC_test3'])

	# remove clients with invalid client_retention_time, sorted by last_seen
	def test_hard_clean_up5(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.meetings = 100
		client1.seen_at = dt.datetime.strptime('2005-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.meetings = 100
		client2.seen_at = dt.datetime.strptime('2004-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client3 = database.add_client('FC_test3', 'localhost', 25003)
		client3.meetings = 100
		client3.seen_at = dt.datetime.strptime('2003-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		clients_removed = database.hard_clean_up()
		self.assertEqual(clients_removed, 1)
		self.assertEqual(database.get_clients_len(), 2)

		def mfunc(_client_t: tuple[int, Client]) -> str:
			return _client_t[1].pid

		clients = list(map(mfunc, database.get_clients().items()))
		self.assertEqual(clients, ['FC_test2', 'FC_test3'])

	# remove clients, sorted by meetings
	def test_hard_clean_up6(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.meetings = 100
		client1.seen_at = dt.datetime.strptime('3005-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.meetings = 100
		client2.seen_at = dt.datetime.strptime('3005-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client3 = database.add_client('FC_test3', 'localhost', 25003)
		client3.meetings = 10
		client3.seen_at = dt.datetime.strptime('3005-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		clients_removed = database.hard_clean_up('test6')
		self.assertEqual(clients_removed, 1)
		self.assertEqual(database.get_clients_len(), 2)

		def mfunc(_client_t: tuple[int, Client]) -> str:
			return _client_t[1].pid

		clients = list(map(mfunc, database.get_clients().items()))
		self.assertEqual(clients, ['FC_test1', 'FC_test2'])

	# clients < max_clients
	def test_soft_clean_up1(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)
		database.add_client('FC_test1', 'localhost', 25001)
		clients_removed = database.soft_clean_up()
		self.assertEqual(clients_removed, 0)
		self.assertEqual(database.get_clients_len(), 1)

	# remove bootstrap clients with no meetings
	def test_soft_clean_up2(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.is_bootstrap = True
		client1.meetings = 0

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.is_bootstrap = True
		client2.meetings = 0

		clients_removed = database.soft_clean_up()
		self.assertEqual(clients_removed, 0)
		self.assertEqual(database.get_clients_len(), 2)

	# remove bootstrap clients with no meetings
	def test_soft_clean_up3(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.is_bootstrap = True
		client1.meetings = 0

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.is_bootstrap = True
		client2.meetings = 0

		client3 = database.add_client('FC_test3', 'localhost', 25003)
		client3.is_bootstrap = False
		client3.meetings = 0

		clients_removed = database.soft_clean_up()
		self.assertEqual(clients_removed, 0)
		self.assertEqual(database.get_clients_len(), 3)

		def mfunc(_client: tuple[int, Client]) -> str:
			return _client[1].pid

		clients = list(map(mfunc, database.get_clients().items()))
		self.assertEqual(clients, ['FC_test1', 'FC_test2', 'FC_test3'])

	# remove clients with invalid client_retention_time
	def test_soft_clean_up4(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.meetings = 100
		client1.seen_at = dt.datetime.strptime('2001-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.meetings = 100
		client2.seen_at = dt.datetime.strptime('2001-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client3 = database.add_client('FC_test3', 'localhost', 25003)
		client3.meetings = 100
		client3.seen_at = dt.datetime.strptime('2001-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		clients_removed = database.soft_clean_up()
		self.assertEqual(clients_removed, 0)
		self.assertEqual(database.get_clients_len(), 3)

		def mfunc(_client_t: tuple[int, Client]) -> str:
			return _client_t[1].pid

		clients = list(map(mfunc, database.get_clients().items()))
		self.assertEqual(clients, ['FC_test1', 'FC_test2', 'FC_test3'])

	# remove clients with invalid client_retention_time, sorted by last_seen
	def test_soft_clean_up5(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.meetings = 100
		client1.seen_at = dt.datetime.strptime('2005-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.meetings = 100
		client2.seen_at = dt.datetime.strptime('2004-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client3 = database.add_client('FC_test3', 'localhost', 25003)
		client3.meetings = 100
		client3.seen_at = dt.datetime.strptime('2003-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		clients_removed = database.soft_clean_up()
		self.assertEqual(clients_removed, 0)
		self.assertEqual(database.get_clients_len(), 3)

		def mfunc(_client_t: tuple[int, Client]) -> str:
			return _client_t[1].pid

		clients = list(map(mfunc, database.get_clients().items()))
		self.assertEqual(clients, ['FC_test1', 'FC_test2', 'FC_test3'])

	# remove clients, sorted by meetings
	def test_soft_clean_up6(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		database = Database(self.config)

		client1 = database.add_client('FC_test1', 'localhost', 25001)
		client1.meetings = 100
		client1.seen_at = dt.datetime.strptime('3005-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client2 = database.add_client('FC_test2', 'localhost', 25002)
		client2.meetings = 100
		client2.seen_at = dt.datetime.strptime('3005-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		client3 = database.add_client('FC_test3', 'localhost', 25003)
		client3.meetings = 10
		client3.seen_at = dt.datetime.strptime('3005-01-01 00:00:00+0000', '%Y-%m-%d %H:%M:%S%z')

		clients_removed = database.soft_clean_up('test6')
		self.assertEqual(clients_removed, 0)
		self.assertEqual(database.get_clients_len(), 3)

		def mfunc(_client_t: tuple[int, Client]) -> str:
			return _client_t[1].pid

		clients = list(map(mfunc, database.get_clients().items()))
		self.assertEqual(clients, ['FC_test1', 'FC_test2', 'FC_test3'])
