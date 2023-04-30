
import logging
import socket
import base64
import time
import selectors

from lib.network import Network
from lib.helper import read_json_file
from lib.mail import Mail

class IpcApp(Network):
	_config_file: str
	_config: dict
	_ipc_config: dict
	_selectors: selectors.DefaultSelector

	def __init__(self, config_file: str = None):
		self._config_file = config_file
		self._selectors = selectors.DefaultSelector()

	def start(self): # pragma: no cover
		self._load_config()

		if not self._ipc_config['enabled']:
			raise Exception('IPC is not enabled')

		logConfig = {
			'level': logging.DEBUG,
			'format': '%(asctime)s %(process)d %(levelname)-8s %(name)-13s %(message)s',
		}
		logging.basicConfig(**logConfig)

		self._logger = logging.getLogger('ipc')
		self._logger.info('start')

	def _load_config(self):
		self._config = read_json_file(self._config_file)
		self._ipc_config = self._config['ipc']

	def send_mail(self, target: str, subject: str, body: str) -> bool:
		self._logger.info('send_mail(%s, %s)', target, subject)

		sock = self._client_connect()
		if not sock:
			return False

		mail = Mail()
		mail.sender = self._config['id']
		mail.receiver = target
		mail.subject = subject
		mail.body = body

		raw = mail.encode()

		self._client_send_mail(sock, target, raw)
		time.sleep(0.1) # TODO replace with selectors
		sock.close()

		return True

	def save(self):
		self._logger.info('save()')

		sock = self._client_connect()
		if not sock:
			return False

		self._client_send_save(sock)
		time.sleep(0.1) # TODO replace with selectors
		sock.close()

	def _client_connect(self):
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

		return sock

	def _client_send_ok(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_mail(self, sock: socket.socket, target: str, raw: str): # pragma: no cover
		self._logger.debug('_client_send_mail()')
		self._client_write(sock, 1, 0, [target, raw])

	def _client_send_save(self, sock: socket.socket): # pragma: no cover
		self._logger.debug('_client_send_save()')
		self._client_write(sock, 2, 0)
