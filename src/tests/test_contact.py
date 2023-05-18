
import unittest
from lib.contact import Contact

class ContactTestCase(unittest.TestCase):
	def test_resolve_contact(self):
		data = [
			# IPv4
			('', None, [None, None, False]),
			('', '192.168.10.10', [None, None, False]),

			('private', None, [None, None, False]),

			('public', None, ['public', None, False]),
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


			# IPv6
			# 2001:db8::/32 is reserved for documentation and example code.

			('2001:db8::1:25001', '2001:db8::2', ['2001:db8::1', 25001, True]),
			('[2001:db8::1]:25001', '2001:db8::2', ['2001:db8::1', 25001, True]),

			('test.ipv6.fluxchat.dev:25001', '2001:db8::2', ['test.ipv6.fluxchat.dev', 25001, True]),

			('non-resolvable.ipv6.fluxchat.dev:25001', '2001:db8::2', [None, 25001, False]),
		]
		for contact_s, raddr, expect_a in data:
			contact = Contact.resolve(contact_s, raddr)
			actual = [contact.addr, contact.port, contact.is_valid]

			self.assertEqual(actual, expect_a)
