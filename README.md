# Network Monitor

## Quick start

```bash
conda create -n network python=3.13 -y
conda activate network
pip install -r requirements.txt
./run.sh
```

## Desktop Ollama listener

On device
```bash
export OLLAMA_FALLBACK_URL=http://<AI DESKTOP IP>:11435/api/chat
unset OLLAMA_PROXY_TOKEN
./run.sh
```

on AI Desktop
```bash
#Run `server_ollama.py` on the desktop that has the models installed:
python server_ollama.py --host 0.0.0.0 --port 11435
```

