
import unittest
from lib.contact import Contact

class ContactTestCase(unittest.TestCase):
	def test_resolve_contact(self):
		data = [
			('', None, [None, None, False]),
			('', '192.168.10.10', [None, None, False]),

			('public', None, [None, None, False]),
			('public', '192.168.10.10', ['192.168.10.10', None, False]),

			('public:', None, [None, None, False]),
			('public:', '192.168.10.10', ['192.168.10.10', None, False]),

			('public:25001', None, [None, 25001, False]),
			('public:25001', '192.168.10.10', ['192.168.10.10', 25001, True]),

			('192.168.10.10', None, ['192.168.10.10', None, False]),
			('192.168.10.10', '192.168.10.20', ['192.168.10.10', None, False]),

			('192.168.10.10:25001', None, ['192.168.10.10', 25001, True]),
			('192.168.10.10:25001', '192.168.10.20', ['192.168.10.10', 25001, True]),

			('localhost.fluxchat.dev:25001', None, [None, 25001, False]),
			('localhost.fluxchat.dev:25001', '192.168.10.20', [None, 25001, False]),

			('lan-host.fluxchat.dev:25001', None, ['lan-host.fluxchat.dev', 25001, True]),
			('lan-host.fluxchat.dev:25001', '192.168.10.20', ['lan-host.fluxchat.dev', 25001, True]),

			('non-resolvable.fluxchat.dev:25001', None, [None, 25001, False]),
			('non-resolvable.fluxchat.dev:25001', '192.168.10.20', [None, 25001, False]),
		]
		for contact_s, raddr, expect_a in data:
			contact = Contact.resolve(contact_s, raddr)
			actual = [contact.addr, contact.port, contact.is_valid]

			self.assertEqual(actual, expect_a)
