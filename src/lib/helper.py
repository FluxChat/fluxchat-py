
import secrets
import base58
import base64
import json
import os
import uuid

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate ID from Public Key
def generate_id_from_public_key_file(file_path: str) -> str:
	f = open(file_path, 'rb')
	key_data = f.read()
	f.close()

	public_key = serialization.load_pem_public_key(key_data)

	return generate_id_from_public_key(public_key)

# Generate ID from Public Key Data
def generate_id_from_public_key(public_key: rsa.RSAPublicKey) -> str:
	# DER is binary representation of public key.
	public_bin = public_key.public_bytes(
		encoding=serialization.Encoding.DER,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	# print('public_bin:', public_bin)

	return generate_id_from_public_key_der(public_bin)

def generate_id_from_public_key_der(public_key_bytes: bytes) -> str:
	hasher = hashes.Hash(hashes.SHA256())
	hasher.update(public_key_bytes)
	digest = hasher.finalize()

	# print('digest:', digest.hex())

	base58_hash = base58.b58encode(digest).decode()
	return f'FC_{base58_hash}'

def generate_test_id() -> str: # pragma: no cover
	public_bytes = secrets.token_bytes(20)

	hasher = hashes.Hash(hashes.SHA256())
	hasher.update(public_bytes)
	digest = hasher.finalize()

	base58_hash = base58.b58encode(digest).decode()
	return f'FC_{base58_hash}'

def password_key_derivation(key_password: bytes) -> str:
	iterations = int(os.environ.get('FLUXCHAT_KEY_DERIVATION_ITERATIONS', 600000))

	salt = b'FluxChat_Static_Salt'
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=64,
		salt=salt,
		iterations=iterations,
	)
	kdf_b = kdf.derive(key_password)

	# base64
	kdf_b64 = base64.b64encode(kdf_b).decode()

	return kdf_b64

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
