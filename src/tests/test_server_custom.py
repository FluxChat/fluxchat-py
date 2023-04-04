
import unittest
from lib.server import Server

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
