
import socket
import uuid
import datetime as dt

import lib.overlay as overlay

class Client():
	uuid: str # Internal ID
	address: str
	port: int
	id: str
	seen_at: dt.datetime
	meetings: int
	is_bootstrap: bool

	# Unmapped
	node: overlay.Node
	sock: socket.socket

	# Connection Mode
	# 0 = DISCONNECTED
	# 1 = CONNECTED
	# 2 = AUTHENTICATED (has sent ID command and received ID command)
	conn_mode: int

	# Directory Mode
	# None, in, out
	dir_mode: str

	# Authenticated (Binary)
	# 0, 0 = Not Authenticated
	# 0, 1 = self send ID command
	# 1, 0 = self received ID command
	# 1, 1 = Authenticated both
	auth: int

	# is_new: bool

	def __init__(self):
		self.uuid = str(uuid.uuid4())
		print('-> Client.__init__({})'.format(self.uuid))
		self.address = None
		self.port = None
		self.id = None
		self.seen_at = None
		self.meetings = 0
		self.is_bootstrap = False

		# Unmapped
		self.node = None
		self.sock = None
		self.conn_mode = 0
		self.dir_mode = None
		self.auth = 0
		# self.is_new = False

	def __del__(self):
		print('-> Client.__del__({})'.format(self.uuid))

	def __str__(self):
		return 'Client({},addr={},p={},ID={},c={},d={},a={})'.format(self.uuid, self.address, self.port, self.id, self.conn_mode, self.dir_mode, self.auth)

	def __repr__(self):
		return 'Client({})'.format(self.uuid)

	def as_dict(self) -> dict:
		d = dict()
		if self.address != None:
			d['address'] = self.address
		if self.port != None:
			d['port'] = self.port
		if self.id != None:
			d['id'] = self.id
		if self.seen_at != None:
			d['seen_at'] = self.seen_at.strftime('%Y-%m-%d %H:%M:%S')
		if self.meetings != None:
			d['meetings'] = self.meetings
		if self.is_bootstrap:
			d['is_bootstrap'] = self.is_bootstrap

		return d

	def from_dict(self, data: dict):
		print('-> Client.from_dict({})'.format(self.uuid))

		if 'address' in data:
			self.address = data['address']
		if 'port' in data:
			self.port = int(data['port'])
		if 'id' in data:
			self.set_id(data['id'])
		if 'seen_at' in data:
			self.seen_at = dt.datetime.strptime(data['seen_at'], '%Y-%m-%d %H:%M:%S')
		if 'meetings' in data:
			self.meetings = int(data['meetings'])
		if 'is_bootstrap' in data:
			self.is_bootstrap = data['is_bootstrap']

	def from_list(self, data: list):
		print('-> Client.from_list({})'.format(data))
		l = len(data)

		self.id = data[0]

		if l >= 3:
			self.address = data[1]
			self.port = int(data[2])

	def refresh_seen_at(self):
		self.seen_at = dt.datetime.utcnow()

	def inc_meetings(self):
		self.meetings += 1

	def set_id(self, id: str):
		self.id = id
		self.node = overlay.Node.parse(id)

	def distance(self, node: overlay.Node) -> int:
		print('-> Client.distance()')
		print('-> self: {}'.format(self))
		print('-> node: {}'.format(node))

		if self.node == None:
			return 160

		return self.node.distance(node)
