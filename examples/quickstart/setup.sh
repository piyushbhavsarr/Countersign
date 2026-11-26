#!/bin/sh
# Creates a throwaway demo: a git workspace, a SQLite "production" database, a config.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
DEMO=${1:-/tmp/undolayer-demo}
rm -rf "$DEMO" && mkdir -p "$DEMO/ws"
echo "building undolayer..."
(cd "$ROOT" && go build -o "$ROOT/bin/undolayer" ./cmd/undolayer)
cd "$DEMO/ws"
printf "print('v1')\n" > app.py
printf "DATABASE_URL=postgres://admin:hunter2-prod@db/app\n" > .env
printf ".env\n" > .gitignore
git init -q -b main && git -c user.email=demo@x -c user.name=demo add -A && git -c user.email=demo@x -c user.name=demo commit -qm init
python3 - "$DEMO/app.db" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE customers(id INTEGER PRIMARY KEY, email TEXT, plan TEXT)")
c.executemany("INSERT INTO customers(email, plan) VALUES (?, ?)", [(f"c{i}@shop.example", "free") for i in range(1, 101)])
c.commit()
PY
cat > "$DEMO/undolayer.toml" <<TOML
state_dir = "$DEMO/state"
[workspace]
root = "ws"
[sql]
dsn = "app.db"
[approvals]
wait = "2m"
TOML
echo
echo "demo ready in $DEMO"
echo "  binary: $ROOT/bin/undolayer"
echo "  config: $DEMO/undolayer.toml"
