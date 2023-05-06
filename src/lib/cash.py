
import random
from cryptography.hazmat.primitives import hashes

class Cash():
	data: str
	bits: int
	proof: str
	nonce: int

	def __init__(self, data: str, bits: int):
		self.data = data.encode()
		self.bits = bits
		self.proof = None
		self.nonce = None

	def __str__(self): # pragma: no cover
		return 'Cash(b={})'.format(self.bits)

	def __repr__(self): # pragma: no cover
		return self.__str__()

	def mine(self) -> int:
		self.nonce = random.randint(0, 100000000)

		cycle = 0
		while True:
			cycle += 1

			input_data = b'FC:' + str(self.bits).encode() + b':' + self.data + b':' + str(self.nonce).encode()

			hasher = hashes.Hash(hashes.SHA256())
			hasher.update(input_data)
			digest = hasher.finalize()

			found_bits = 0
			for c in digest:
				if c & 0b10000000:
					break
				if c & 0b01000000:
					found_bits += 1
					break
				if c & 0b00100000:
					found_bits += 2
					break
				if c & 0b00010000:
					found_bits += 3
					break
				if c & 0b00001000:
					found_bits += 4
					break
				if c & 0b00000100:
					found_bits += 5
					break
				if c & 0b00000010:
					found_bits += 6
					break
				if c & 0b00000001:
					found_bits += 7
					break
				if c == 0:
					found_bits += 8

				if found_bits >= self.bits:
					break

			if found_bits >= self.bits:
				self.proof = digest.hex()
				break

			self.nonce += 1

		return cycle

	def verify(self, proof: str, nonce: int) -> bool:
		if len(proof) != 64:
			# print('verify, invalid length')
			return False

		full_bytes = self.bits % 4 == 0
		if full_bytes:
			if not proof.startswith('0' * (self.bits // 4)):
				# print('verify, startswith wrong')
				return False
		else:
			found_bits = 0
			for c in bytes.fromhex(proof):
				pos = bin(c)[2:].zfill(8).find('1')
				if pos == -1:
					found_bits += 8
					continue

				found_bits += pos
				break

			# print('verify, found_bits: {} {}'.format(found_bits, self.bits))
			if found_bits < self.bits:
				# print('verify, found_bits wrong')
				return False

		input_data = b'FC:' + str(self.bits).encode() + b':' + self.data + b':' + str(nonce).encode()

		hasher = hashes.Hash(hashes.SHA256())
		hasher.update(input_data)
		digest = hasher.finalize()

		return digest.hex() == proof
