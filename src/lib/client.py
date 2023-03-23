
#import socket
import uuid
import datetime as dt

class Client():
	rt: str
	address: str
	port: int
	id: str
	seen_at: dt.datetime
	#sock: socket.socket

	# Data Mode
	# t = TEXT
	# b = BINARY
	data_mode: str

	# Connection Mode
	# 0 = DISCONNECTED
	# 1 = CONNECTED
	# 2 = AUTHENTICATED
	conn_mode: int

	# Directory Mode
	# None, in, out
	dir_mode: str

	def __init__(self):
		self.rt = str(uuid.uuid4())
		print('-> Client.__init__({})'.format(self.rt))
		self.address = None
		self.port = None
		self.id = None
		self.data_mode = 't'
		self.conn_mode = 0
		self.dir_mode = None

	def __del__(self):
		print('-> Client.__del__({})'.format(self.rt))

	def __str__(self):
		return 'Client({},{},{})'.format(self.id, self.address, self.port)

	def as_dict(self) -> dict:
		return {
			'address': self.address,
			'port': int(self.port),
			'id': self.id,
		}

	def from_dict(self, data: dict):
		print('-> Client.from_dict()')
		# print(data)
		# print()

		self.address = data['address']
		self.port = int(data['port'])
		self.id = data['id']

	def from_list(self, data: list):
		self.address = data[0]
		self.port = int(data[1])
		self.id = data[2]
