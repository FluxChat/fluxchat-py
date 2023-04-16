
import socket

class Network(): # pragma: no cover
	def _client_write(self, sock: socket.socket, group: int, command: int, data: list = []):
		self._logger.debug('_client_write(%d, %d, %s)', group, command, data)

		flag_lengths_are_4_bytes = False

		for item in data:
			#self._logger.debug('data item: %s %s', type(item), item)
			item_content_len = len(item)
			if item_content_len > 255:
				flag_lengths_are_4_bytes = True

		self._logger.debug('flag_lengths_are_4_bytes: %s', flag_lengths_are_4_bytes)

		payload_len_i = 0
		payload_items = []
		for item in data:
			item_content_len = len(item)
			payload_len_i += item_content_len
			self._logger.debug('item: l=%d t=%s i=%s', item_content_len, type(item), item)

			if flag_lengths_are_4_bytes:
				payload_items.append(item_content_len.to_bytes(4, 'little'))
				payload_len_i += 3
			else:
				self._logger.debug('item_content_len: %s', item_content_len.to_bytes(1, 'little'))
				payload_items.append(item_content_len.to_bytes(1, 'little'))

			payload_len_i += 1
			payload_items.append(item.encode('utf-8'))

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

		self._logger.debug('send raw: %s', raw)

		sock.sendall(raw)
