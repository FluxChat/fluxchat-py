
import socket
import uuid

class Client():
	_address: str
	_port: int
	_id: str

	def __init__(self):
		print('-> Client.__init__()')

	def __del__(self):
		print('-> Client.__del__()')

	def as_dict(self) -> dict:
		return {
			'address': self._address,
			'port': self._port,
			'id': self._id,
		}

	def from_dict(self, data: dict):
		print('-> Client.from_dict()')
		print(data)
		print()

		self._address = data['address']
		self._port = data['port']
		self._id = data['id']

	def from_list(self, data: list):
		self._address = data[0]
		self._port = data[1]
		self._id = data[2]

	def get_address(self) -> str:
		return self._address

	def get_port(self) -> int:
		return self._port

	def get_id(self) -> str:
		return self._id
