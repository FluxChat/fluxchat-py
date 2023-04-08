
import unittest
from lib.helper import generate_id_from_public_key_file, resolve_contact

class HelperTestCase(unittest.TestCase):
	def test_generate_id_from_public_key_file(self):
		self.assertEqual(generate_id_from_public_key_file('resources/tests/pubkey.pem'), 'FC_3iB6UnLXWdPfi2eLVEfY1d5eEaMR')

	def test_resolve_contact(self):
		data = [
			('', '192.168.10.10', [None, None, False]),
			('public', '192.168.10.10', ['192.168.10.10', None, False]),
			('public:', '192.168.10.10', ['192.168.10.10', None, False]),
			('public:25001', '192.168.10.10', ['192.168.10.10', 25001, True]),
			('192.168.10.10', '192.168.10.20', ['192.168.10.10', None, False]),
			('192.168.10.10:25001', '192.168.10.20', ['192.168.10.10', 25001, True]),
			('localhost.pychat.fox21.at:25001', '192.168.10.20', [None, 25001, False]),
			('lan-host.pychat.fox21.at:25001', '192.168.10.20', ['lan-host.pychat.fox21.at', 25001, True]),
			('non-resolvable.pychat.fox21.at:25001', '192.168.10.20', [None, 25001, False]),

			('', None, [None, None, False]),
			('public', None, [None, None, False]),
			('public:', None, [None, None, False]),
			('public:25001', None, [None, 25001, False]),
			('192.168.10.10', None, ['192.168.10.10', None, False]),
			('192.168.10.10:25001', None, ['192.168.10.10', 25001, True]),
			('localhost.pychat.fox21.at:25001', None, [None, 25001, False]),
			('lan-host.pychat.fox21.at:25001', None, ['lan-host.pychat.fox21.at', 25001, True]),
			('non-resolvable.pychat.fox21.at:25001', None, [None, 25001, False]),
		]
		for contact, raddr, expect in data:
			self.assertEqual(resolve_contact(contact, raddr), expect)
