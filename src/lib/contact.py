
from typing import Optional
from socket import getaddrinfo, gaierror as SocketGaiError
from ipaddress import ip_address
from lib.types import PeerAddress


class Contact:
	def __init__(self) -> None:
		self.addr: Optional[str] = None
		self.port: Optional[int] = None
		self.is_valid: bool = False
		self.is_ipv6: bool = False

	def __str__(self) -> str:
		return f'{self.addr}:{self.port}'

	@staticmethod
	def parse(raw: str) -> 'Contact':
		contact = Contact()

		if '[' in raw and ']' in raw:
			# IPv6
			items = raw.split(']')
			items = [
				items[0][1:],
				int(items[1][1:]),
			]
		else:
			items = raw.split(':')

		items_len = len(items)

		if items_len == 1:
			contact.addr = items[0]
			contact.port = None
		elif items_len == 2:
			contact.addr = items[0]
			if items[1] == '':
				contact.port = None
			else:
				contact.port = int(items[1])
		elif items_len > 2:
			# IPv6
			contact.addr = ':'.join(items[0:-1])
			contact.port = int(items[-1])
			contact.is_ipv6 = True

		if contact.addr == '':
			contact.addr = 'private'

		return contact

	@staticmethod
	def resolve(raw: str, raddr: PeerAddress = None) -> 'Contact':
		contact = Contact.parse(raw)
		print(f'-> contact after parse: {contact}')

		if contact.addr == 'public':
			contact.addr = raddr[0]
			contact.port = raddr[1]
		elif contact.addr == 'private':
			contact.addr = None
			contact.port = None
		else:
			try:
				ip_add = str(ip_address(contact.addr))
				print(f'-> ip address: {ip_add}')
				if ip_add[0:4] == '127.' or ip_add[0:4] == '0.0.' or ip_add == '::1':
					print(f'-> localhost is invalid')
					# Localhost is invalid.
					contact.addr = None
			except ValueError:
				# Contact is hostname
				try:
					print(f'-> getaddrinfo({contact.addr})')
					results = getaddrinfo(contact.addr, None)
					for result in results:
						ip_add = result[4][0]
						print(f'-> getaddrinfo result: {ip_add}')
						if ip_add[0:4] == '127.' or ip_add[0:4] == '0.0.' or ip_add == '::1':
							# Localhost is invalid.
							contact.addr = None
							break
				except SocketGaiError:
					print('-> SocketGaiError')
					contact.addr = None

		contact.is_valid = contact.addr is not None and contact.port is not None
		return contact
