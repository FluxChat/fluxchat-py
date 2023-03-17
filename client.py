import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	try:
		s.connect(('127.0.0.1', 65432))
	except ConnectionRefusedError as e:
		print(e)
		exit(1)
	s.sendall(b"Hello, world")
	data = s.recv(1024)

print(f"Received {data!r}")
