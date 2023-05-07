
import ipaddress
import socket

class Contact:
	addr: str = None
	port: int = None
	is_valid: bool = False

	def __init__(self) -> None:
		pass

	@staticmethod
	def resolve(raw: str, raddr: str = None):
		contact = Contact()

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

		if contact.addr == '':
			contact.addr = 'private'

		if contact.addr == 'public':
			contact.addr = raddr
		elif contact.addr == 'private':
			contact.addr = None
			contact.port = None
		else:
			try:
				ip_add = str(ipaddress.ip_address(contact.addr))
				if ip_add[0:4] == '127.':
					# Localhost is invalid.
					contact.addr = None
			except ValueError:
				# Contact is hostname
				try:
					results = socket.getaddrinfo(contact.addr, None)
					for result in results:
						ip_add = result[4][0]
						if ip_add[0:4] == '127.':
							# Localhost is invalid.
							contact.addr = None
							break
				except socket.gaierror:
					contact.addr = None

		contact.is_valid = contact.addr != None and contact.port != None
		return contact