#!/usr/bin/env bash
# Pull a model and refuse to continue unless its digest matches the pin in models.env.
set -euo pipefail
MODEL=$1
HERE=$(cd "$(dirname "$0")" && pwd)
WANT=$(grep -E "^${MODEL//./\\.}=" "$HERE/models.env" | cut -d= -f2)
[ -n "$WANT" ] || { echo "no pinned digest for $MODEL in models.env" >&2; exit 1; }
OLLAMA=${OLLAMA_BIN:-ollama}
"$OLLAMA" pull "$MODEL"
GOT=$(curl -fsS http://127.0.0.1:11434/api/tags | python3 -c "
import json,sys
for m in json.load(sys.stdin)['models']:
    if m['name']=='$MODEL': print(m['digest'])")
if [ "$GOT" != "$WANT" ]; then
  echo "digest mismatch for $MODEL: pinned $WANT, pulled $GOT" >&2
  exit 1
fi
echo "$MODEL digest $GOT matches the pin"
