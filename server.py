import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	print('-> bind')
	s.bind(('127.0.0.1', 65432))

	print('-> listen')
	s.listen()

	print('-> accept')
	conn, addr = s.accept()

	print('-> conn', conn)
	print('-> addr', addr)

	with conn:
		print(f"Connected by {addr}")
		while True:
			data = conn.recv(1024)
			if not data:
				break
			conn.sendall(data)
