#!/bin/sh
# Startet als root nur, um dem Datenordner die richtigen Rechte zu geben (Volumes vieler Hoster gehören root),
# und führt die App danach als unprivilegierter Nutzer "node" aus.
set -e
DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"
if [ "$(id -u)" = "0" ]; then
  chown -R node:node "$DATA_DIR" || echo "Warnung: Rechte für $DATA_DIR konnten nicht gesetzt werden."
  exec setpriv --reuid=node --regid=node --init-groups node server.js
fi
exec node server.js
