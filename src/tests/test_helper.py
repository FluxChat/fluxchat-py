
import unittest
from lib.helper import generate_id_from_public_key_file, resolve_contact, is_valid_uuid

class HelperTestCase(unittest.TestCase):
	def test_generate_id_from_public_key_file(self):
		self.assertEqual(generate_id_from_public_key_file('resources/tests/public_key.pem'), 'FC_Da6bDVBD1wT84v3z3nTMB8uWwgUw1DSxsfsvToaVYr9m')

	def test_resolve_contact(self):
		data = [
			('', '192.168.10.10', [None, None, False]),
			('public', '192.168.10.10', ['192.168.10.10', None, False]),
			('public:', '192.168.10.10', ['192.168.10.10', None, False]),
			('public:25001', '192.168.10.10', ['192.168.10.10', 25001, True]),
			('192.168.10.10', '192.168.10.20', ['192.168.10.10', None, False]),
			('192.168.10.10:25001', '192.168.10.20', ['192.168.10.10', 25001, True]),
			('localhost.fluxchat.dev:25001', '192.168.10.20', [None, 25001, False]),
			('lan-host.fluxchat.dev:25001', '192.168.10.20', ['lan-host.fluxchat.dev', 25001, True]),
			('non-resolvable.fluxchat.dev:25001', '192.168.10.20', [None, 25001, False]),

			('', None, [None, None, False]),
			('public', None, [None, None, False]),
			('public:', None, [None, None, False]),
			('public:25001', None, [None, 25001, False]),
			('192.168.10.10', None, ['192.168.10.10', None, False]),
			('192.168.10.10:25001', None, ['192.168.10.10', 25001, True]),
			('localhost.fluxchat.dev:25001', None, [None, 25001, False]),
			('lan-host.fluxchat.dev:25001', None, ['lan-host.fluxchat.dev', 25001, True]),
			('non-resolvable.fluxchat.dev:25001', None, [None, 25001, False]),
		]
		for contact, raddr, expect in data:
			self.assertEqual(resolve_contact(contact, raddr), expect)

	def test_is_valid_uuid_v4(self):
		self.assertTrue(is_valid_uuid('642b8d3b-7b73-4941-bb11-c6ac13c18ba5'))
		self.assertFalse(is_valid_uuid('xyz'))
