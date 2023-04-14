
import hashlib
import random

class Cash():
	nonce: int
	proof: str

	def __init__(self, data: str, bits: int):
		self.nonce = None
		self.proof = None
		self.data = data.encode('utf-8')
		self.bits = bits

	def __str__(self):
		return 'Cash(b={})'.format(self.bits)

	def __repr__(self):
		return self.__str__()

	def mine(self) -> int:
		self.nonce = random.randint(0, 100000000)

		cycle = 0
		while True:
			cycle += 1

			input_data = b'FC:' + str(self.bits).encode('utf-8') + b':' + self.data + b':' + str(self.nonce).encode('utf-8')

			hashobj = hashlib.sha256(input_data)
			hash_output = hashobj.digest()

			found_bits = 0
			for c in hash_output:
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
				self.proof = hashobj.hexdigest()
				break

			self.nonce += 1

		return cycle

	def verify(self, proof: str, nonce: int) -> bool:
		input_data = b'FC:' + str(self.bits).encode('utf-8') + b':' + self.data + b':' + str(nonce).encode()
		return hashlib.sha256(input_data).hexdigest() == proof

class Database():
	pass # TODO
