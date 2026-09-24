#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-${CONDA_PREFIX:-}/bin/python}"

if [[ ! -x "$PYTHON" ]]; then
    PYTHON="$(command -v python3 || command -v python)"
fi
if [[ -z "${PYTHON:-}" || ! -x "$PYTHON" ]]; then
    echo "Python interpreter not found. Activate the network environment first." >&2
    exit 1
fi

PYTHON_REAL="$(readlink -f "$PYTHON")"
CAPABILITIES="$(getcap "$PYTHON_REAL" 2>/dev/null || true)"
if [[ "$CAPABILITIES" != *cap_net_raw* ]]; then
    if ! command -v setcap >/dev/null 2>&1; then
        echo "setcap is required. Install libcap2-bin, then run this script again." >&2
        exit 1
    fi
    echo "Granting packet-capture capability to $PYTHON_REAL"
    sudo setcap cap_net_raw,cap_net_admin+eip "$PYTHON_REAL"
fi

exec "$PYTHON" "$SCRIPT_DIR/main.py" "$@"
