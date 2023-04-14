
import hashlib
import random

class Cash():
	nonce: int
	proof: str

	def __init__(self):
		self.nonce = None
		self.proof = None

	def mine(self, data: bytes, bits: int) -> int:
		self.nonce = random.randint(0, 100000000)

		cycle = 0
		while True:
			input_data = b'FC_' + data + str(self.nonce).encode()

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

				if found_bits >= bits:
					break

			if found_bits >= bits:
				self.proof = hashobj.hexdigest()
				break

			self.nonce += 1
			cycle += 1

		return cycle
