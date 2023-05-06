
import socket
import ssl
import datetime as dt
import select

CLIENT_READ_SIZE = 2048

class SslHandshakeError(Exception):
	pass

class SocketReadStatus(): # pragma: no cover
	def __init__(self) -> None:
		self.disconnect = False
		self.commands = []
		self.msg = None

class Network():
	def _client_read(self, sock: socket.socket) -> SocketReadStatus:
		self._logger.debug('_client_read(%s)', sock)

		status = SocketReadStatus()

		raw_total = b''

		reading = True
		while reading:
			raw_len = 0
			try:
				raw = sock.recv(CLIENT_READ_SIZE)
				raw_len = len(raw)
				self._logger.debug('recv raw A: %d %s', raw_len, raw)

				raw_total += raw
			except TimeoutError as e:
				self._logger.debug('TimeoutError: %s', e)

				status.disconnect = True
				reading = False
			except ConnectionResetError as e:
				self._logger.debug('ConnectionResetError: %s', e)

				status.disconnect = True
				reading = False
			except ssl.SSLWantReadError as e:
				self._logger.debug('SSLWantReadError: %s', e)

				status.disconnect = True
				reading = False
			else:
				if raw_len >= CLIENT_READ_SIZE:
					self._logger.debug('raw_len(%d) >= CLIENT_READ_SIZE(%d)', raw_len, CLIENT_READ_SIZE)

					reading = True
				elif raw_len > 0:
					self._logger.debug('raw_len(%d) > 0', raw_len)

					reading = False
				else:
					self._logger.debug('raw_len(%d) < CLIENT_READ_SIZE(%d)', raw_len, CLIENT_READ_SIZE)

					reading = False
					status.disconnect = True

		raw_total_len = len(raw_total)
		if raw_total_len > 0:
			self._logger.debug('recv raw B: %d %s', raw_total_len, raw_total)

			raw_pos = 0
			while raw_pos < raw_total_len:
				try:
					flags_i = raw_total[raw_pos]
					raw_pos += 1

					group = raw_total[raw_pos]
					raw_pos += 1

					command = raw_total[raw_pos]
					raw_pos += 1
				except IndexError as e:
					self._logger.debug('IndexError: %s', e)

					status.disconnect = True
					status.msg = 'array index out of range'
					return

				lengths_are_4_bytes = flags_i & 1 != 0

				try:
					length = int.from_bytes(raw_total[raw_pos:raw_pos + 4], 'little')
					raw_pos += 4
				except struct.error as e:
					self._logger.debug('struct.error: %s', e)

					status.disconnect = True
					status.msg = 'unpack error'
					return

				payload_raw = raw_total[raw_pos:]
				payload_items = []

				self._logger.debug('group: %d', group)
				self._logger.debug('command: %d', command)
				self._logger.debug('length: %d %s', length, type(length))

				pos = 0
				while pos < length:
					if lengths_are_4_bytes:
						item_len = int.from_bytes(payload_raw[pos:pos + 4], 'little')
						pos += 3
					else:
						item_len = payload_raw[pos]
					pos += 1

					# self._logger.debug('item len: %d %s', item_len, type(item_len))

					item = payload_raw[pos:pos + item_len]
					# self._logger.debug('item content: %s', item)

					payload_items.append(item.decode())
					pos += item_len

				status.commands.append([group, command, payload_items])
				raw_pos += length + 1
				# self._logger.debug('raw_pos: %d', raw_pos)

		return status

	def _client_write(self, sock: socket.socket, group: int, command: int, data: list = []):
		self._logger.debug('_client_write(%d, %d, %s)', group, command, data)

		flag_lengths_are_4_bytes = False

		for item in data:
			#self._logger.debug('data item: %s %s', type(item), item)

			if isinstance(item, int):
				continue

			item_content_len = len(item)
			if item_content_len > 255:
				flag_lengths_are_4_bytes = True

		self._logger.debug('flag_lengths_are_4_bytes: %s', flag_lengths_are_4_bytes)

		payload_len_i = 0
		payload_items = []
		for item in data:
			enconded_item = None
			if isinstance(item, str):
				enconded_item = item.encode()
			elif isinstance(item, bytes):
				enconded_item = item
			elif isinstance(item, int):
				enconded_item = item.to_bytes(4, 'little')

			item_content_len = len(enconded_item)
			payload_len_i += item_content_len
			self._logger.debug('item: l=%d t=%s i=%s', item_content_len, type(item), item)

			if flag_lengths_are_4_bytes:
				payload_items.append(item_content_len.to_bytes(4, 'little'))
				payload_len_i += 3
			else:
				self._logger.debug('item_content_len: %s', item_content_len.to_bytes(1, 'little'))
				payload_items.append(item_content_len.to_bytes(1, 'little'))

			payload_len_i += 1
			payload_items.append(enconded_item)

		self._logger.debug('payload_len_i: %d', payload_len_i)
		self._logger.debug('payload_items: %s', payload_items)

		payload = b''.join(payload_items)

		flags_i = 0
		if flag_lengths_are_4_bytes: # LENs are 4 bytes
			flags_i |= 1

		flags_b = flags_i.to_bytes(1, 'little')
		group_b = group.to_bytes(1, 'little')
		command_b = command.to_bytes(1, 'little')
		payload_len_b = payload_len_i.to_bytes(4, 'little')

		raw = flags_b + group_b + command_b + payload_len_b + payload + b'\x00'

		self._logger.debug('sock: %s', sock)
		self._logger.debug('send raw: %d %s', len(raw), raw)

		sock.sendall(raw)

	def _ssl_handshake(self, socket_ssl: ssl.SSLObject) -> None:
		self._logger.debug('_ssl_handshake(%s)', socket_ssl)

		start = dt.datetime.now()
		tries = 0
		while True:
			try:
				self._logger.debug('ssl handshake: %d', tries)
				socket_ssl.do_handshake()
				break
			except ssl.SSLWantReadError as e:
				pass
				# self._logger.debug('ssl.SSLWantReadError: %s', e)
				select.select([socket_ssl], [], [], 0.3)
			except ssl.SSLWantWriteError as e:
				pass
				# self._logger.debug('ssl.SSLWantWriteError: %s', e)
				select.select([], [socket_ssl], [], 0.3)
			except ssl.SSLError as e:
				self._logger.error('ssl.SSLError: %s', e)
				raise SslHandshakeError(e)

			now = dt.datetime.now()
			if now - start >= self._ssl_handshake_timeout:
				raise SslHandshakeError('ssl handshake timeout')

			tries += 1

		self._logger.debug('ssl handshake done: %d', tries)
