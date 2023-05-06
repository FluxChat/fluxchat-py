
import secrets
import base58
import ipaddress
import socket
import json
import os
import uuid

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Generate ID from Public Key
def generate_id_from_public_key_file(file_path: str) -> str:
	f = open(file_path, 'rb')
	key_data = f.read()
	f.close()

	# print('generate_id_from_public_key_file', key_data)

	return generate_id_from_public_key_data(key_data)

# Generate ID from Public Key Data
def generate_id_from_public_key_data(key_data: bytes) -> str:
	public_key = serialization.load_pem_public_key(key_data)
	# print('-> public_key type', type(public_key))
	public_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)
	# print('-> public_bytes', type(public_bytes))

	return generate_id_from_public_key(public_bytes)

def generate_id_from_public_key(public_key_bytes: bytes) -> str:
	# print('public_key_bytes', public_key_bytes)

	hasher = hashes.Hash(hashes.SHA256())
	hasher.update(public_key_bytes)
	digest = hasher.finalize()

	# print('digest', digest.hex())

	base58_hash = base58.b58encode(digest).decode()
	return f'FC_{base58_hash}'

def generate_test_id() -> str: # pragma: no cover
	public_bytes = secrets.token_bytes(20)

	hasher = hashes.Hash(hashes.SHA256())
	hasher.update(public_bytes)
	digest = hasher.finalize()

	base58_hash = base58.b58encode(digest).decode()
	return f'FC_{base58_hash}'

def password_key_derivation(key_password: bytes) -> bytes:
	iterations = int(os.environ.get('FLUXCHAT_KEY_DERIVATION_ITERATIONS', 600000))

	salt = b'FluxChat_Static_Salt'
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=64,
		salt=salt,
		iterations=iterations,
	)
	return kdf.derive(key_password)

def resolve_contact(contact: str, raddr: str = None) -> list:
	items = contact.split(':')
	items_len = len(items)

	if items_len == 1:
		c_addr = items[0]
		c_port = None
	elif items_len == 2:
		c_addr = items[0]
		if items[1] == '':
			c_port = None
		else:
			c_port = int(items[1])

	if c_addr == '':
		c_addr = 'private'

	if c_addr == 'public':
		c_addr = raddr
	elif c_addr == 'private':
		c_addr = None
		c_port = None
	else:
		try:
			ipaddress.ip_address(c_addr)
		except ValueError:
			# Contact is hostname
			try:
				results = socket.getaddrinfo(c_addr, None)
				for result in results:
					ip_address = result[4][0]
					if ip_address[0:4] == '127.':
						# Localhost is invalid.
						c_addr = None
						break
			except socket.gaierror:
				c_addr = None

	return [c_addr, c_port, c_addr != None and c_port != None]

def write_json_file(path: str, data):
	with open(path, 'w') as write_file:
		json.dump(data, write_file, indent=4)

def read_json_file(path: str, default = None) -> dict:
	if not os.path.exists(path) and default != None:
		write_json_file(path, default)

	with open(path, 'r') as read_file:
		return json.load(read_file)

def is_valid_uuid(id: str):
	try:
		obj = uuid.UUID(id, version=4)
	except ValueError:
		return False
	return str(obj) == id

# key: data
def binary_encode(data: dict, max_len: int = 4) -> bytes:
	items = []
	for key, value in data.items():
		d_len = len(value)

		try:
			items.append(key.to_bytes(1, 'little'))
		except AttributeError as e:
			# print('type:', type(key))
			# print('key:', key)
			raise e

		items.append(d_len.to_bytes(max_len, 'little'))

		if isinstance(value, bytes):
			items.append(value)
		elif isinstance(value, str):
			items.append(value.encode())

	return b''.join(items)

def binary_decode(data: bytes, max_len: int = 4) -> dict:
	data_len = len(data)
	pos = 0
	items = {}
	while pos < data_len:
		item_t = int.from_bytes(data[pos:pos+1], 'little')
		pos += 1
		# print('item_t:', item_t)

		item_l = int.from_bytes(data[pos:pos+max_len], 'little')
		pos += max_len
		# print('item_l:', item_l)

		items[item_t] = data[pos:pos+item_l]
		# print('item:', items[item_t])

		pos += item_l

	return items
