
from unittest import TestCase
from lib.server import Server

SERVER_DATA_DIR = 'tmp/tests/data_default'

class ServerTestCase(TestCase):
	def setUp(self):
		self.server = Server({
			'id': 'FC_test',
			'data_dir': SERVER_DATA_DIR,
			'discovery': {
				'enabled': False,
				'port': 26000,
			},
			'mail': {
				'retention_time': 24,
			}
		})

	def test_has_contact(self):
		self.assertFalse(self.server.has_contact())

	def test_get_contact(self):
		self.assertEqual(self.server.get_contact(), 'N/A')

	def test_handle_sockets(self):
		self.assertFalse(self.server.handle_sockets())

	def test_contact_address_book(self):
		self.assertTrue(self.server.contact_address_book())

	def test_handle_clients(self):
		self.assertTrue(self.server.handle_clients())

	def test_ping_clients(self):
		self.assertTrue(self.server.ping_clients())

	def test_save(self):
		self.assertTrue(self.server.save())

	def test_client_actions(self):
		self.assertFalse(self.server.client_actions())

	def test_is_bootstrap_phase(self):
		self.assertTrue(self.server.is_bootstrap_phase())
