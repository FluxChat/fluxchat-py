
import unittest
from lib.server import Server
from lib.client import Client

SERVER_DATA_DIR = 'tmp/tests/data_custom'

class ServerTestCase(unittest.TestCase):
	def test_has_contact_false1(self):
		server = Server({
			'contact': 'private',
			'id': 'FC_test',
			'data_dir': SERVER_DATA_DIR,
		})
		self.assertFalse(server.has_contact())

	def test_has_contact_false2(self):
		server = Server({
			'contact': False,
			'id': 'FC_test',
			'data_dir': SERVER_DATA_DIR,
		})
		self.assertFalse(server.has_contact())

	def test_has_contact_public_no_port(self):
		server = Server({
			'port': 25001,
			'contact': 'public',
			'id': 'FC_test',
			'data_dir': SERVER_DATA_DIR,
		})
		self.assertEqual(server.get_contact(), 'public:25001')

	def test_has_contact_public_with_port(self):
		server = Server({
			'port': 25001,
			'contact': 'public:25002',
			'id': 'FC_test',
			'data_dir': SERVER_DATA_DIR,
		})
		self.assertEqual(server.get_contact(), 'public:25002')

	def test_client_actions(self):
		client1 = Client()
		client2 = Client()

		client1.add_action('test', 1)
		client2.add_action('test', 2)

		server = Server()
		server.add_client(client1)
		server.add_client(client2)

		self.assertTrue(server.client_actions())
