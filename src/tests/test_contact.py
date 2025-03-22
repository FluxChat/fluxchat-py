
from unittest import TestCase
from lib.contact import Contact
from lib.types import PeerAddress


class ContactTestCase(TestCase):
	def test_parse_contact(self):
		data = [
			# IPv4
			('', ['private', None]),
			('private', ['private', None]),

			('public', ['public', None]),
			('public:', ['public', None]),
			('public:25001', ['public', 25001]),

			(':25001', ['private', 25001]),
			('192.168.10.10', ['192.168.10.10', None]),
			('192.168.10.10:25001', ['192.168.10.10', 25001]),
			('hostname.fluxchat.dev:25001', ['hostname.fluxchat.dev', 25001]),

			# IPv6
			('2001:db8::1:25001', ['2001:db8::1', 25001]),
			('[2001:db8::1]:25001', ['2001:db8::1', 25001]),
		]
		for contact_s, expect_a in data:
			contact = Contact.parse(contact_s)

			self.assertEqual(contact.addr, expect_a[0], 'addr')
			self.assertEqual(contact.port, expect_a[1], 'port')

	def test_resolve_contact(self):
		DPEER = ('192.168.10.10', 1337)

		data: list[tuple[str, PeerAddress, list]] = [
			# IPv4
			('', DPEER, [None, None, False]),
			('public', DPEER, ['192.168.10.10', 1337, True]),
			('private', DPEER, [None, None, False]),

			('192.168.10.10:25001', ('192.168.10.11', 1337), ['192.168.10.10', 25001, True]),

			('localhost.fluxchat.dev:25001', DPEER, [None, 25001, False]),
			('lan-host.fluxchat.dev:25001', DPEER, ['lan-host.fluxchat.dev', 25001, True]),
			('non-resolvable.fluxchat.dev:25001', DPEER, [None, 25001, False]),
		]
		for contact_s, raddr, expect_a in data:
			contact = Contact.resolve(contact_s, raddr)

			self.assertEqual(contact.addr, expect_a[0], 'addr')
			self.assertEqual(contact.port, expect_a[1], 'port')
			self.assertEqual(contact.is_valid, expect_a[2], 'is_valid')
