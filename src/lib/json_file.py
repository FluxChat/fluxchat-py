
import json

class JsonFile():
	def _read_json_file(self, file_path: str) -> dict:
		with open(file_path, 'r') as read_file:
			return json.load(read_file)

	def _write_json_file(self, file_path: str, data: dict):
		with open(file_path, 'w') as write_file:
			json.dump(data, write_file, indent=4)
