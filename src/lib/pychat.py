
import os
import json

from sty import fg
from lib.json_file import JsonFile

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

	def run(self, is_watch: bool = False) -> list:
		print('-> PyChat.run()')
