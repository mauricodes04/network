#!/usr/bin/env python3
"""LAN listener that exposes a desktop's local Ollama instance.

Run this on the desktop that has the models:
	OLLAMA_PROXY_TOKEN='shared-secret' python3 server_ollama.py

The listener accepts Ollama-compatible /api/chat requests and forwards them to
the Ollama service on the same desktop. Set OLLAMA_PROXY_TOKEN on both sides
when the listener is reachable beyond a trusted private network.
"""
import argparse
import os

import requests
from flask import Flask, jsonify, request
from werkzeug.serving import make_server


DEFAULT_UPSTREAM = "http://127.0.0.1:11434"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 11435
UPSTREAM_TIMEOUT = 600

app = Flask(__name__)
upstream_url = DEFAULT_UPSTREAM
proxy_token = ""


def authorized():
	return not proxy_token or request.headers.get("Authorization") == f"Bearer {proxy_token}"


@app.get("/health")
def health():
	if not authorized():
		return jsonify(error="Unauthorized"), 401
	return jsonify(status="ok", upstream=upstream_url)


@app.post("/api/chat")
def chat():
	if not authorized():
		return jsonify(error="Unauthorized"), 401

	body = request.get_json(silent=True)
	if not isinstance(body, dict):
		return jsonify(error="Expected a JSON object"), 400

	try:
		response = requests.post(
			f"{upstream_url}/api/chat",
			json=body,
			headers={"Accept": "application/json"},
			timeout=UPSTREAM_TIMEOUT,
		)
	except requests.RequestException as exc:
		return jsonify(error=f"Desktop Ollama unreachable: {exc.__class__.__name__}"), 502

	return response.content, response.status_code, {
		"Content-Type": response.headers.get("Content-Type", "application/json")
	}


def main():
	global proxy_token, upstream_url

	parser = argparse.ArgumentParser(description="LAN listener for desktop Ollama")
	parser.add_argument("--host", default=os.environ.get("OLLAMA_PROXY_HOST", DEFAULT_HOST))
	parser.add_argument("--port", type=int, default=int(os.environ.get("OLLAMA_PROXY_PORT", DEFAULT_PORT)))
	parser.add_argument("--upstream", default=os.environ.get("OLLAMA_UPSTREAM", DEFAULT_UPSTREAM),
						help="Ollama URL on this machine, without /api/chat")
	args = parser.parse_args()

	upstream_url = args.upstream.rstrip("/")
	proxy_token = os.environ.get("OLLAMA_PROXY_TOKEN", "")
	server = make_server(args.host, args.port, app, threaded=True)
	print(f"Ollama listener: http://{args.host}:{args.port}")
	print(f"Forwarding to: {upstream_url}/api/chat")
	if not proxy_token:
		print("Warning: no OLLAMA_PROXY_TOKEN set; requests are unauthenticated")
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		pass
	finally:
		server.server_close()


if __name__ == "__main__":
	main()
