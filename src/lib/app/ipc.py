
import logging
import socket
import base64
import time
import selectors
import datetime as dt

from lib.network import Network, SocketReadStatus
from lib.helper import read_json_file
from lib.mail import Mail
from lib.scheduler import Scheduler

class IpcCommand():
	_logger: logging.Logger
	type: str
	def __init__(self):
		self._logger = logging.getLogger('ipc_command')
		self._logger.info('init()')

		self.data = None

class IpcApp(Network):
	_config_file: str
	_config: dict
	_ipc_config: dict
	_selectors: selectors.DefaultSelector
	_logger: logging.Logger
	_commands: list
	_scheduler: Scheduler
	_client_socket: socket.socket

	def __init__(self, config_file: str = None):
		self._config_file = config_file
		self._selectors = selectors.DefaultSelector()
		self._commands = []
		self._scheduler = None
		self._client_socket = None

		self._logger = logging.getLogger('ipc.app')
		self._logger.info('init()')

	def __del__(self):
		self._logger.info('__del__()')
		self._selectors.close()

	def start(self): # pragma: no cover
		self._load_config()

		if not self._ipc_config['enabled']:
			raise Exception('IPC is not enabled')

		logConfig = {
			'level': logging.DEBUG,
			'format': '%(asctime)s %(process)d %(levelname)-8s %(name)-13s %(message)s',
		}
		logging.basicConfig(**logConfig)

		command = IpcCommand()
		command.type = '_client_connect'
		self._commands.append(command)

		self._scheduler = Scheduler()
		self._scheduler.add_task(self.handle_sockets, dt.timedelta(milliseconds=100))
		self._scheduler.add_task(self.handle_commands, dt.timedelta(milliseconds=100))

	def run(self):
		self._logger.info('run()')
		self._scheduler.run()
		self._logger.info('run finished')

	def shutdown(self, reason: str = None):
		self._logger.info('shutdown(%s)', reason)
		self._scheduler.shutdown(reason)

	def stop(self):
		self._logger.info('stop()')

		command = IpcCommand()
		command.type = '_stop'
		self._commands.append(command)

	def _load_config(self):
		self._config = read_json_file(self._config_file)
		self._ipc_config = self._config['ipc']

	def handle_commands(self):
		self._logger.info('handle_commands() -> %d', len(self._commands))

		commands = self._commands
		self._commands = []

		for command in commands:
			self._logger.info('command: %s', command.type)

			if command.type == '_client_connect':
				self._client_socket = self._client_connect()

			elif command.type == '_client_disconnect':
				self._client_disconnect(self._client_socket)

			elif command.type == '_stop':
				self._scheduler.shutdown('stop')

			elif command.type == 'send_mail':
				self._logger.info('command data: %s', command.data)
				self._client_send_send_mail(self._client_socket, command.data['target'], command.data['raw'])

			elif command.type == 'list_mails':
				self._client_send_list_mails(self._client_socket, command.data['only_new'])

			elif command.type == 'read_mail':
				self._client_send_read_mail(self._client_socket)

			elif command.type == 'save':
				self._client_send_save(self._client_socket)

	def send_mail_command(self, target: str, subject: str, body: str) -> bool:
		self._logger.info('send_mail_command(%s, %s)', target, subject)

		mail = Mail()
		mail.sender = self._config['id']
		mail.receiver = target
		mail.subject = subject
		mail.body = body

		raw = mail.encode()

		command = IpcCommand()
		command.type = 'send_mail'
		command.data = {
			'target': target,
			'raw': raw,
		}
		self._commands.append(command)

	def list_mails_command(self, only_new: bool = False) -> bool:
		self._logger.info('list_mails_command(%s)', only_new)

		command = IpcCommand()
		command.type = 'list_mails'
		command.data = {
			'only_new': only_new,
		}
		self._commands.append(command)

	def read_mail_command(self, m_uuid: str) -> bool:
		self._logger.info('read_mail_command(%s)', m_uuid)

	def save_command(self):
		self._logger.info('save_command()')

		command = IpcCommand()
		command.type = 'save'

		self._commands.append(command)

	def handle_sockets(self):
		self._logger.debug('handle_sockets()')

		events = self._selectors.select(timeout=0)
		for key, mask in events:
			self._logger.debug('socket event: %s %d', key, mask)

			if key.data['type'] == 'client':
				status = self._client_read(key.fileobj)

				if status.disconnect:
					self._logger.debug('client disconnect')
					# TODO
					raise Exception('client disconnect not implemented')

				self._client_commands(key.fileobj, status.commands)

	def _client_commands(self, sock: socket.socket, commands: list):
		self._logger.debug('_handle_client(%s)', sock)
		self._logger.debug('commands: %s', commands)

		for command_raw in commands:
			group_i, command_i, payload = command_raw
			payload_len = len(payload)

			self._logger.debug('group: %d, command %d', group_i, command_i)
			self._logger.debug('payload: %s', payload)

			if group_i == 1:
				if command_i == 0:
					chunks_len, chunk_num = payload[0:2]
					chunks_len_i = int.from_bytes(chunks_len.encode(), 'little')
					chunk_num_i = int.from_bytes(chunk_num.encode(), 'little')

					self._logger.debug('chunks_len: %s', chunks_len)
					self._logger.debug('chunk_num: %s', chunk_num)
					self._logger.debug('chunks_len_i: %s', chunks_len_i)
					self._logger.debug('chunk_num_i: %s', chunk_num_i)

					mails_encoded = payload[2:]
					self._logger.debug('mails_encoded: %s', mails_encoded)

					for mail_encoded in mails_encoded:
						self._logger.debug('mail_encoded: "%s"', mail_encoded)

						mail = Mail()
						mail.ipc_decode(mail_encoded.encode())

						self._logger.debug('mail: %s', mail)

	def _client_connect(self): # pragma: no cover
		self._logger.info('_client_connect()')

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(2)
		try:
			self._logger.debug('sock.connect to %s:%s', self._ipc_config['address'], self._ipc_config['port'])
			sock.connect((self._ipc_config['address'], self._ipc_config['port']))
			self._logger.debug('sock.connect done')
		except ConnectionRefusedError as e:
			self._logger.error('ConnectionRefusedError: %s', e)
			return False
		except TimeoutError as e:
			self._logger.error('TimeoutError: %s', e)
			return False
		except socket.timeout as e:
			self._logger.error('socket.timeout: %s', e)
			return False
		sock.settimeout(None)
		sock.setblocking(False)

		self._selectors.register(sock, selectors.EVENT_READ, data={'type': 'client'})

		return sock

	def _client_send_ok(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_send_mail(self, sock: socket.socket, target: str, raw: str): # pragma: no cover
		self._logger.debug('_client_send_send_mail()')
		self._logger.debug('sock: %s', sock)
		self._logger.debug('target: %s', target)
		self._logger.debug('raw: %s', raw)

		self._client_write(sock, 1, 0, [target, raw])

	def _client_send_list_mails(self, sock: socket.socket, only_new: bool = False): # pragma: no cover
		self._logger.debug('_client_send_list_mails()')
		self._logger.debug('sock: %s', sock)
		self._logger.debug('only_new: %s', only_new)

		flags = 0
		if only_new:
			flags |= 1

		data = [
			flags,
		]

		self._client_write(sock, 1, 1, data)

	def _client_send_read_mail(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_client_send_read_mail()')
		self._logger.debug('sock: %s', sock)

		data = [
		]

		self._client_write(sock, 1, 2, data)

	def _client_send_save(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_client_send_save()')
		self._client_write(sock, 2, 0)

	def _client_disconnect(self, sock: socket.socket): # pragma: no cover
		self._logger.info('_client_disconnect()')
		self._client_send_ok(sock)
		sock.close()
