#!/usr/bin/env python3
"""Serve the NETWORK-INFO directory to devices on the local network.

On the Raspberry Pi, downloadwith:

	wget -r -np -nH --reject "index.html*" http://192.168.1.190:1234/

"""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


HOST = "0.0.0.0"
PORT = 1234
DIRECTORY = Path(__file__).resolve().parent


def main() -> None:
	handler = partial(SimpleHTTPRequestHandler, directory=str(DIRECTORY))
	server = ThreadingHTTPServer((HOST, PORT), handler)
	print(f"Serving {DIRECTORY} on http://{HOST}:{PORT}/")
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		print("\nStopping server.")
	finally:
		server.server_close()


if __name__ == "__main__":
	main()
