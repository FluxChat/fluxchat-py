
import os
import json

from sty import fg

class PyChat():
	_config_file: str
	_config: dict

	def __init__(self, config_file: str = None):
		print('-> PyChat.__init__()')

		self._config_file = config_file

		# Init
		self._load_config()

	def __del__(self):
		print('-> PyChat.__del__()')

	def _load_config(self):
		print('-> PyChat._load_config()')

		self._config = self._read_json_file(self._config_file)

	def _read_json_file(self, file_path: str) -> dict:
		with open(file_path, 'r') as read_file:
			return json.load(read_file)

	def _write_json_file(self, file_path: str, data: dict):
		with open(file_path, 'w') as write_file:
			json.dump(data, write_file, indent=4)

	def run(self, is_watch: bool = False) -> list:
		print('-> PyChat.run()')
