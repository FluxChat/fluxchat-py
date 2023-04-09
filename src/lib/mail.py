
import datetime as dt
import uuid

from lib.json_file import JsonFile
import lib.overlay as overlay

class Message(JsonFile):
	uuid: str
	to: str
	target: overlay.Node
	body: str
	received_at: dt.datetime
	forwarded_to: list
	is_encrypted: bool

	def __init__(self, to: str = None, body: str = None):
		self.uuid = str(uuid.uuid4())
		self.to = to
		self.body = body
		self.received_at = dt.datetime.now()
		self.forwarded_to = []
		self.is_encrypted = False

		if self.to == None:
			self.target = None
		else:
			try:
				self.target = overlay.Node.parse(self.to)
			except:
				self.target = None

	def __str__(self):
		return 'Message({},t={})'.format(self.uuid, self.to)

	def __repr__(self):
		return self.__str__()

	def as_dict(self) -> dict:
		data = dict()
		if self.to != None:
			data['to'] = self.to
		if self.body != None:
			data['body'] = self.body
		if self.received_at != None:
			data['received_at'] = self.received_at.isoformat()
		if self.forwarded_to != None:
			data['forwarded_to'] = self.forwarded_to
		if self.is_encrypted != None:
			data['is_encrypted'] = self.is_encrypted
		return data

	def from_dict(self, data: dict):
		if 'to' in data:
			self.to = data['to']
			try:
				self.target = overlay.Node.parse(self.to)
			except:
				self.target = None
		if 'body' in data:
			self.body = data['body']
		if 'received_at' in data:
			self.received_at = dt.datetime.fromisoformat(data['received_at'])
		if 'forwarded_to' in data:
			self.forwarded_to = data['forwarded_to']
		if 'is_encrypted' in data:
			self.is_encrypted = data['is_encrypted']

class Queue(JsonFile):
	_path: str
	_config: dict
	_mail_config: dict
	_messages_by_uuid: dict
	_changes: bool

	def __init__(self, path: str, config: dict = None):
		print('-> Queue.__init__({})'.format(path))

		self._path = path
		self._config = config
		self._mail_config = self._config['mail']
		self._messages_by_uuid = dict()
		self._changes = False

	def load(self):
		_data = self._read_json_file(self._path, {})
		for message_uuid, row in _data.items():
			message = Message()
			message.uuid = message_uuid
			message.from_dict(row)

			print('-> load message: {}'.format(message))

			self._messages_by_uuid[message_uuid] = message

	def save(self) -> bool:
		print('-> Queue.save() -> {}'.format(self._changes))
		if not self._changes:
			return False

		_data = dict()
		for message_uuid, message in self._messages_by_uuid.items():
			_data[message_uuid] = message.as_dict()

		self._write_json_file(self._path, _data)
		self._changes = False

		return True

	def add_message(self, message: Message):
		print('-> Queue.add_message({})'.format(message))
		self._messages_by_uuid[message.uuid] = message
		print(self._messages_by_uuid)
		self._changes = True

	def get_messages(self) -> dict:
		print('-> Queue.get_messages()')
		return self._messages_by_uuid.items()

	def changed(self):
		self._changes = True

	def clean_up(self):
		print('-> Queue.clean_up()')

		ffunc = lambda _message: _message[1].received_at < dt.datetime.now() - dt.timedelta(hours=self._mail_config['message_retention_time'])
		old_messages = list(filter(ffunc, self._messages_by_uuid.items()))
		print('-> old_messages: {}'.format(old_messages))

		# remove old messages
		for message_uuid, message in old_messages:
			print('-> remove message: {}'.format(message))
			del self._messages_by_uuid[message_uuid]
			self._changes = True
