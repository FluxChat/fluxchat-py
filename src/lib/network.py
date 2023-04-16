
import socket

class Network(): # pragma: no cover
	def _client_write(self, sock: socket.socket, group: int, command: int, data: list = []):
		self._logger.debug('_client_write()')

		flag_lengths_are_4_bytes = False

		for item in data:
			# self._logger.debug('-> item: %s', type(item))
			item_content_len = len(item)
			if item_content_len > 255:
				flag_lengths_are_4_bytes = True

		payload_len_i = 0
		payload_items = []
		for item in data:
			# self._logger.debug('-> item: %s', type(item))
			item_content_len = len(item)
			payload_len_i += item_content_len

			if flag_lengths_are_4_bytes:
				payload_items.append(item_content_len.to_bytes(4, byteorder='little'))
				payload_len_i += 3
			else:
				payload_items.append(chr(item_content_len).encode('utf-8'))

			payload_len_i += 1
			payload_items.append(item.encode('utf-8'))

		# self._logger.debug('-> payload_len_i: %d', payload_len_i)
		# self._logger.debug('-> payload_items: %s', payload_items)

		payload = b''.join(payload_items)

		flags_i = 0
		if flag_lengths_are_4_bytes: # LENs are 4 bytes
			flags_i |= 1

		flags_b = chr(flags_i).encode('utf-8')
		cmd_grp = (chr(group) + chr(command)).encode('utf-8')
		payload_len_b = payload_len_i.to_bytes(4, byteorder='little')

		raw = flags_b + cmd_grp + payload_len_b + payload + b'\x00'

		self._logger.debug('send raw %s', raw)

		sock.sendall(raw)
