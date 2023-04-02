
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
		if not isinstance(other, Node):
			return False
		return self.id == other.id

	def decode(self) -> bytes:
		return base58.b58decode(self.id[3:])

	def has_valid_id(self) -> bool:
		if self.id[0:3] != 'FC_':
			print('-> Invalid ID')
			return False

		return len(self.decode()) == 20

	def distance(self, other) -> int:
		return Distance(self, other)

	def parse(_id: str):
		_node = Node(_id)
		if not _node.has_valid_id():
			raise ValueError('Invalid ID')

		return _node

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
		# print('-> Distance.__eq__')
		# print('-> self: {}'.format(self))
		# print('-> other: {}'.format(other))
		return self._distance < other._distance

	def __le__(self, other):
		raise NotImplementedError('Distance.__le__')

	def __eq__(self, other):
		# print('-> Distance.__eq__')
		if not isinstance(other, Distance):
			return False
		return self._distance == other._distance

	def __ne__(self, other):
		raise NotImplementedError('Distance.__ne__')

	def __gt__(self, other):
		raise NotImplementedError('Distance.__gt__')

	def __ge__(self, other):
		raise NotImplementedError('Distance.__ge__')
