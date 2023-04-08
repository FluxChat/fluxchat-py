
import os
import unittest
from lib.address_book import AddressBook

ADDRESS_BOOK_PATH = 'tmp/tests/address_book.json'
BOOTSTRAP_PATH = 'tmp/tests/bootstrap.json'

class AddressBookTestCase(unittest.TestCase):
	def test_save_load(self):
		if os.path.exists(ADDRESS_BOOK_PATH):
			os.remove(ADDRESS_BOOK_PATH)

		address_book = AddressBook(ADDRESS_BOOK_PATH)

		client1 = address_book.add_client('FC_test1', 'localhost', 25001)
		client1.is_bootstrap = True
		client1.meetings = 1

		address_book.add_client('FC_test2', 'localhost', 25002)
		address_book.save()
		self.assertEqual(address_book.get_clients_len(), 2)

		address_book = AddressBook(ADDRESS_BOOK_PATH)
		self.assertEqual(address_book.get_clients_len(), 2)

		address_book.remove_client(client1)
		self.assertEqual(address_book.get_clients_len(), 1)

	def test_bootstrap(self):
		if os.path.exists(ADDRESS_BOOK_PATH):
			os.remove(ADDRESS_BOOK_PATH)
		if os.path.exists(BOOTSTRAP_PATH):
			os.remove(BOOTSTRAP_PATH)

		f = open(BOOTSTRAP_PATH, 'w')
		f.write('["localhost:25001", "localhost:25002"]')
		f.close()

		address_book = AddressBook(ADDRESS_BOOK_PATH)
		address_book.add_bootstrap(BOOTSTRAP_PATH)
		self.assertEqual(address_book.get_bootstrap_clients_len(), 2)

	# clients < max_clients
	def test_clean_up1(self):
		config = {'address_book': {
			'max_clients': 2,
			'client_retention_time': 24,
		}}
		address_book = AddressBook('resources/tests/ab1.json', config)
		address_book.clean_up()
		self.assertEqual(address_book.get_clients_len(), 1)

	# remove bootstrap clients with no meetings
	def test_clean_up2(self):
		config = {'address_book': {
			'max_clients': 2,
			'client_retention_time': 24,
		}}
		address_book = AddressBook('resources/tests/ab2.json', config)
		address_book.clean_up()
		self.assertEqual(address_book.get_clients_len(), 2)

	# remove bootstrap clients with no meetings
	def test_clean_up3(self):
		config = {'address_book': {
			'max_clients': 2,
			'client_retention_time': 24,
		}}
		address_book = AddressBook('resources/tests/ab3.json', config)
		address_book.clean_up()
		# address_book.save()
		self.assertEqual(address_book.get_clients_len(), 2)

		clients = list(map(lambda kv: kv[1].id, address_book.get_clients().items()))
		self.assertEqual(clients, ['FC_test2', 'FC_test3'])

	# remove clients with invalid client_retention_time
	def test_clean_up4(self):
		config = {'address_book': {
			'max_clients': 2,
			'client_retention_time': 24,
		}}
		address_book = AddressBook('resources/tests/ab4.json', config)
		address_book.clean_up()
		self.assertEqual(address_book.get_clients_len(), 2)

		clients = list(map(lambda kv: kv[1].id, address_book.get_clients().items()))
		self.assertEqual(clients, ['FC_test2', 'FC_test3'])

	# remove clients with invalid client_retention_time, sorted by last_seen
	def test_clean_up5(self):
		config = {'address_book': {
			'max_clients': 2,
			'client_retention_time': 24,
		}}
		address_book = AddressBook('resources/tests/ab5.json', config)
		address_book.clean_up()
		self.assertEqual(address_book.get_clients_len(), 2)

		clients = list(map(lambda kv: kv[1].id, address_book.get_clients().items()))
		self.assertEqual(clients, ['FC_test1', 'FC_test2'])

	# remove clients, sorted by meetings
	def test_clean_up6(self):
		config = {'address_book': {
			'max_clients': 2,
			'client_retention_time': 24,
		}}
		address_book = AddressBook('resources/tests/ab6.json', config)
		address_book.clean_up('test6')
		# address_book.save()
		self.assertEqual(address_book.get_clients_len(), 2)

		clients = list(map(lambda kv: kv[1].id, address_book.get_clients().items()))
		self.assertEqual(clients, ['FC_test1', 'FC_test2'])
