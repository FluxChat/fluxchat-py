
import os
import json

class JsonFile():
	def _read_json_file(self, path: str, default = None) -> dict:
		print('-> JsonFile._read_json_file({})'.format(path))
		if not os.path.exists(path) and default != None:
			self._write_json_file(path, default)

		with open(path, 'r') as read_file:
			return json.load(read_file)

	def _write_json_file(self, path: str, data):
		print('-> JsonFile._write_json_file({})'.format(path))
		with open(path, 'w') as write_file:
			json.dump(data, write_file, indent=4)
