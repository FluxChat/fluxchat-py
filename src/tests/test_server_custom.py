
import unittest
from lib.server import Server
from lib.client import Client

SERVER_DATA_DIR = 'tmp/tests/data_custom'

class ServerTestCase(unittest.TestCase):
	def setUp(self) -> None:
		self.config = {
			'id': 'FC_test',
			'data_dir': SERVER_DATA_DIR,
			'discovery': {
				'enabled': False,
				'port': 26000,
			},
			'mail': {
				'retention_time': 24
			}
		}

	def test_has_contact_false1(self):
		server = Server({
			'contact': 'private',
		} | self.config)
		self.assertFalse(server.has_contact())

	def test_has_contact_public_no_port(self):
		server = Server({
			'port': 25001,
			'contact': 'public',
		} | self.config)
		self.assertEqual(server.get_contact(), 'public:25001')

	def test_has_contact_public_with_port(self):
		server = Server({
			'port': 25001,
			'contact': 'public:25002',
		} | self.config)
		self.assertEqual(server.get_contact(), 'public:25002')
