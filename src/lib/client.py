
#import socket
import uuid
import datetime as dt

class Client():
	uuid: str # Internal ID
	address: str
	port: int
	id: str
	seen_at: dt.datetime
	is_bootstrap: bool

	# Data Mode
	# t = TEXT
	# b = BINARY
	data_mode: str

	# Connection Mode
	# 0 = DISCONNECTED
	# 1 = CONNECTED
	# 2 = AUTHENTICATED (has sent ID command)
	conn_mode: int

	# Directory Mode
	# None, in, out
	dir_mode: str

	def __init__(self):
		self.uuid = str(uuid.uuid4())
		print('-> Client.__init__({})'.format(self.uuid))
		self.address = None
		self.port = None
		self.id = None
		self.seen_at = None
		self.data_mode = 'b' # Default binary mode
		self.conn_mode = 0
		self.dir_mode = None

	def __del__(self):
		print('-> Client.__del__({})'.format(self.uuid))

	def __str__(self):
		return 'Client({},{},{},{})'.format(self.uuid, self.address, self.port, self.id)

	def as_dict(self) -> dict:
		d = {
			#'uuid': self.uuid,
		}
		if self.address != None:
			d['address'] = self.address
		if self.port != None:
			d['port'] = self.port
		if self.id != None:
			d['id'] = self.id
		if self.seen_at != None:
			d['seen_at'] = self.seen_at

		return d

	def from_dict(self, data: dict):
		# print('-> Client.from_dict()')
		# if 'uuid' in data:
		# 	self.uuid = data['uuid']
		if 'address' in data:
			self.address = data['address']
		if 'port' in data:
			self.port = int(data['port'])
		if 'id' in data:
			self.id = data['id']
		if 'seen_at' in data:
			self.seen_at = data['seen_at']

	def from_list(self, data: list):
		print('-> Client.from_list({})'.format(data))
		l = len(data)
		self.address = data[0]
		self.port = int(data[1])
		if l >= 3:
			self.id = data[2]

	def refresh_seen_at(self):
		self.seen_at = dt.datetime.now()
