
import hashlib
import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate ID from Public Key
def generate_id_from_public_key_file(file_path: str) -> str:
	f = open(file_path, 'rb')
	key_data = f.read()
	f.close()

	return generate_id_from_public_key_data(key_data)

# Generate ID from Public Key Data
def generate_id_from_public_key_data(key_data: bytes) -> str:
	public_key = serialization.load_pem_public_key(key_data)
	public_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.DER,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)

	hash_obj = hashlib.new('ripemd160')
	hash_obj.update(public_bytes)

	base58_hash = base58.b58encode(hash_obj.digest()).decode('utf-8')
	return f'FC_{base58_hash}'

def is_valid_id(id: str) -> bool:
	if len(id) != 31:
		return False

	id = id[3:]
	id = base58.b58decode(id)
	print('-> id: {} {}'.format(type(id), id))

	return len(id) == 20

def id_distance(id1: str, id2: str):
	id1 = id1[3:]
	id2 = id2[3:]

	id1 = base58.b58decode(id1)
	id2 = base58.b58decode(id2)

	diff = [a ^ b for a, b in zip(id1, id2)]
	return diff
