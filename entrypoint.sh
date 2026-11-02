#!/bin/sh
set -eu
if [ ! -s "$CAT_DB_PATH" ]; then
  cp /app/seed/carta_auto_testes_seed.db "$CAT_DB_PATH"
fi
exec python -m server
