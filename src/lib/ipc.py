
import socket
import base64
import time

from lib.json_file import JsonFile

class Ipc(JsonFile):
	_config_file: str
	_config: dict
	_ipc_config: dict

	def __init__(self, config_file: str = None):
		print('-> Ipc.__init__()')

		self._config_file = config_file

	def start(self): # pragma: no cover
		# Init
		self._load_config()

		if not self._ipc_config['enabled']:
			raise Exception('IPC is not enabled')

	def _load_config(self):
		print('-> Ipc._load_config()')
		self._config = self._read_json_file(self._config_file)
		self._ipc_config = self._config['ipc']

	def send(self, target: str, subject: str, message: str) -> bool:
		print('-> Ipc.send()')
		print('-> target:', target)
		print('-> subject:', subject)
		print('-> message:', message)

		raw = "\n".join([self._config['id'], subject, message])
		print('-> raw:', raw)
		# encode raw to base64
		raw = base64.b64encode(raw.encode('utf-8')).decode('utf-8')
		print('-> raw:', type(raw))
		print('-> raw:', raw)

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(2)
		try:
			print('-> sock.connect to')
			sock.connect((self._ipc_config['address'], self._ipc_config['port']))
			print('-> sock.connect done')
		except ConnectionRefusedError as e:
			print('-> ConnectionRefusedError', e)
			return False
		except TimeoutError as e:
			print('-> TimeoutError', e)
			return False
		except socket.timeout as e:
			print('-> socket.timeout', e)
			return False

		sock.settimeout(None)
		self._client_send_message(sock, target, raw)
		time.sleep(0.1)
		sock.close()

	def _client_write(self, sock: socket.socket, group: int, command: int, data: list = []): # pragma: no cover
		print('-> Server._client_write()')
		payload_l = []
		for item in data:
			payload_l.append(chr(len(item)))
			payload_l.append(item)
		payload = ''.join(payload_l)

		cmd_grp = (chr(group) + chr(command)).encode('utf-8')
		len_payload = len(payload).to_bytes(4, byteorder='little')

		raw = cmd_grp + len_payload + (payload + chr(0)).encode('utf-8')

		sock.sendall(raw)

	def _client_send_ok(self, sock: socket.socket): # pragma: no cover
		print('-> Server._client_send_ok()')
		self._client_write(sock, 0, 0)

	def _client_send_message(self, sock: socket.socket, target: str, raw: str): # pragma: no cover
		print('-> Server._client_send_message()')
		self._client_write(sock, 1, 0, [target, raw])
