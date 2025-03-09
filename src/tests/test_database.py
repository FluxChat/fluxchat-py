
# import os
from os import path, remove
from unittest import TestCase
from lib.address_book import AddressBook
from lib.database import Database


BOOTSTRAP_PATH = 'tmp/tests/bootstrap.json'


class AddressBookTestCase(TestCase):
	def setUp(self) -> None:
		self.config = {
			'data_dir': 'tmp/tests',
			# 'keys_dir': 'tmp/tests/keys',
			'database': {
				'file_name': 'test.db',
				'max_clients': 2,
				'client_retention_time': 24,
			},
		}
		self.db_path = path.join(self.config['data_dir'], self.config['database']['file_name'])

	def test_save_load(self):
		if path.exists(self.db_path):
			remove(self.db_path)

		address_book = Database(self.config)

		client1 = address_book.add_client('FC_test1', 'localhost', 25001)
		client1.is_bootstrap = True
		client1.meetings = 1

		address_book.add_client('FC_test2', 'localhost', 25002)
		address_book.save()
		self.assertEqual(address_book.get_clients_len(), 2)

		address_book = Database(self.config)
		address_book.load()
		self.assertEqual(address_book.get_clients_len(), 2)

		address_book.remove_client(client1)
		self.assertEqual(address_book.get_clients_len(), 1)

	def test_get_client_by_id(self):
		address_book = Database(self.config)

		client1 = address_book.add_client('FC_test1', 'localhost', 25001)

		client1b = address_book.get_client_by_id('FC_test1')
		self.assertEqual(client1b.id, 'FC_test1')

		client1c = address_book.get_client_by_id('FC_test1')
		self.assertEqual(client1c.id, 'FC_test1')

		client3 = address_book.get_client_by_id('FC_test3')
		self.assertEqual(client3, None)

		client1e = address_book.get_client_by_addr_port('localhost', 25001)
		self.assertEqual(client1e.id, 'FC_test1')

		client2 = address_book.get_client_by_addr_port('localhost', 25002)
		self.assertEqual(client2, None)

	def test_bootstrap(self):
		if path.exists(self.db_path):
			remove(self.db_path)
		if path.exists(BOOTSTRAP_PATH):
			remove(BOOTSTRAP_PATH)

		f = open(BOOTSTRAP_PATH, 'w')
		f.write('["localhost:25001", "localhost:25002"]')
		f.close()

		address_book = Database(self.config)
		address_book.add_bootstrap(BOOTSTRAP_PATH)
		self.assertEqual(address_book.get_bootstrap_clients_len(), 2)

	# TODO
	# # clients < max_clients
	# def test_hard_clean_up1(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.hard_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 1)

	# # remove bootstrap clients with no meetings
	# def test_hard_clean_up2(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.hard_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 2)

	# # remove bootstrap clients with no meetings
	# def test_hard_clean_up3(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.hard_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 2)

	# 	clients = list(map(lambda kv: kv[1].id, address_book.get_clients().items()))
	# 	self.assertEqual(clients, ['FC_test2', 'FC_test3'])

	# # remove clients with invalid client_retention_time
	# def test_hard_clean_up4(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.hard_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 2)

	# 	clients = list(map(lambda kv: kv[1].id, address_book.get_clients().items()))
	# 	self.assertEqual(clients, ['FC_test2', 'FC_test3'])

	# # remove clients with invalid client_retention_time, sorted by last_seen
	# def test_hard_clean_up5(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.hard_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 2)

	# 	clients = list(map(lambda kv: kv[1].id, address_book.get_clients().items()))
	# 	self.assertEqual(clients, ['FC_test1', 'FC_test2'])

	# # remove clients, sorted by meetings
	# def test_hard_clean_up6(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.hard_clean_up('test6')
	# 	# address_book.save()
	# 	self.assertEqual(address_book.get_clients_len(), 2)

	# 	clients = list(map(lambda kv: kv[1].id, address_book.get_clients().items()))
	# 	self.assertEqual(clients, ['FC_test1', 'FC_test2'])

	# def test_soft_clean_up1(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.soft_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 1)

	# def test_soft_clean_up2(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.soft_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 2)

	# def test_soft_clean_up3(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.soft_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 3)

	# def test_soft_clean_up4(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.soft_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 3)

	# 	client = address_book.get_client_by_addr_port('localhost', 25001)
	# 	self.assertNotEqual(client, None)

	# 	client = address_book.get_client_by_addr_port('localhost', 25002)
	# 	self.assertNotEqual(client, None)

	# 	client = address_book.get_client_by_addr_port('localhost', 25003)
	# 	self.assertNotEqual(client, None)

	# def test_soft_clean_up5(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.soft_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 3)

	# def test_soft_clean_up6(self):
	# 	address_book = Database(self.config)
	# 	address_book.load()
	# 	address_book.soft_clean_up()
	# 	self.assertEqual(address_book.get_clients_len(), 3)
