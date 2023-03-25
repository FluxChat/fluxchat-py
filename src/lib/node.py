
import base58

class Node():
	id: str

	def __init__(self, id: str):
		self.id = id

	def decode(self) -> bytes:
		return base58.b58decode(self.id[3:])

	def has_valid_id(self) -> bool:
		if len(self.id) != 31:
			return False

		return len(self.decode()) == 20

	def parse(_id: str) -> 'Node':
		node = Node(_id)
		if not node.has_valid_id():
			raise ValueError('Invalid ID')

		return node

