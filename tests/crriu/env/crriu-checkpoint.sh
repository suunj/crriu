
#!/usr/bin/env bash
# usage: crriu-checkpoint.sh HOST_PID SNAPSHOT_ID
set -euo pipefail

P=$1
ID=$2

E=$(cd "$(dirname "$0")" && pwd)
. "$E/common.sh"

case "$ID" in
  ''|*[!a-zA-Z0-9_-]*)
    echo "invalid snapshot id: $ID" >&2
    exit 2 ;;
esac

test -d "/proc/$P" || {
  echo "process not found: $P" >&2
  exit 1
}

IMG="$CRRIU_IMG/$ID"
test ! -e "$IMG" || {
  echo "snapshot already exists: $IMG" >&2
  exit 1
}

mkdir -p "$IMG"

NSPID=$(awk '/^NSpid:/ {print $NF}' "/proc/$P/status")

echo "checkpoint: host=$P ns=$NSPID image=$IMG"

if ! nsenter -t "$P" -p -m \
    criu dump \
      -t "$NSPID" \
      -D "$IMG" \
      --shell-job \
      --ext-unix-sk \
      --leave-stopped \
      -v4 \
      -o dump.log; then
  echo "checkpoint failed: $IMG/dump.log" >&2
  exit 1
fi

echo "checkpoint complete: $IMG"
echo "original process remains stopped"

