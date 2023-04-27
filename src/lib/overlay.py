
import os
import base58

class Node():
	id: str

	def __init__(self, id: str):
		self.id = id

	def __str__(self):
		return 'Node({})'.format(self.id)

	def __repr__(self):
		return 'Node({})'.format(self.id)

	def __eq__(self, other):
		if isinstance(other, str):
			return self.id == other

		if not isinstance(other, Node):
			return False

		return self.id == other.id

	def decode(self) -> bytes:
		return base58.b58decode(self.id[3:])

	def has_valid_id(self) -> bool:
		if self.id[0:3] != 'FC_':
			return False

		return len(self.decode()) == 32

	def distance(self, other):
		return Distance(self, other)

	@staticmethod
	def parse(id: str):
		node = Node(id)
		if not os.environ.get('IS_UNITTEST') and not node.has_valid_id(): # pragma: no cover
			raise ValueError('Invalid ID')

		return node

class Distance():
	_distance: int

	def __init__(self, node1: Node = None, node2: Node = None):
		self._distance = 160

		if node1 != None and node2 != None:
			id1 = node1.decode()
			id2 = node2.decode()

			for a, b in zip(id1, id2):
				x = a ^ b
				if x == 0:
					self._distance -= 8
				else:
					self._distance -= bin(x)[2:].zfill(8).find('1')

	def __str__(self):
		return 'Distance({})'.format(self._distance)

	def __lt__(self, other):
		return self._distance < other._distance

	def __eq__(self, other):
		if isinstance(other, int):
			return self._distance == other

		if not isinstance(other, Distance):
			return False

		return self._distance == other._distance
