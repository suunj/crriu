#!/usr/bin/env bash
# usage: crriu-branch.sh SNAPSHOT_ID INSTANCE_ID
set -euo pipefail

E=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
. "$E/common.sh"

if (( $# != 2 )); then
  echo "usage: $0 SNAPSHOT_ID INSTANCE_ID" >&2
  exit 2
fi
SNAP=$1
INSTANCE=$2
for value in "$SNAP" "$INSTANCE"; do
  [[ $value =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "invalid id: $value" >&2; exit 2; }
done

for tool in criu crit jq flock unshare python3; do
  command -v "$tool" >/dev/null || { echo "missing command: $tool" >&2; exit 1; }
done

SRC="$CRRIU_IMG/$SNAP"
DST="$CRRIU_IMG/instance-$INSTANCE"
BR="$CRRIU_BR"
INPUT="$BR/instance-$INSTANCE.stdin"
OUTPUT="$BR/instance-$INSTANCE.log"
LOCK="$CRRIU_IMG/.restore.lock"

[[ -f "$SRC/inventory.img" && -f "$SRC/files.img" ]] || { echo "invalid snapshot: $SRC" >&2; exit 1; }
[[ ! -e "$DST" && ! -e "$INPUT" && ! -e "$OUTPUT" ]] || {
  echo "instance already exists: $INSTANCE" >&2; exit 1;
}
mkdir -p "$BR" "$DST"
cp -a "$SRC/." "$DST/"

# Identify the target file objects by tracing fdinfo-2.img's fd 0/1/2.
crit decode -i "$DST/fdinfo-2.img" --pretty > "$DST/.fdinfo.json"
crit decode -i "$DST/files.img" --pretty > "$DST/.files.json"

python3 - "$DST/.fdinfo.json" "$DST/.files.json" "$INPUT" "$OUTPUT" "$DST/.files-new.json" <<'PY'
import json, sys
fd_path, files_path, inp, out, dest = sys.argv[1:]
with open(fd_path) as f: fd = json.load(f)
with open(files_path) as f: files = json.load(f)
fd_ids = {}
for entry in fd.get('entries', []):
    if entry.get('fd') in (0, 1, 2):
        fd_ids[entry['fd']] = entry['id']
if not all(x in fd_ids for x in (0, 1, 2)):
    raise SystemExit('fdinfo-2.img does not contain fd 0/1/2; inspect image manually')

objects = {e['id']: e for e in files.get('entries', [])}
def resolve(fid):
    obj = objects.get(fid)
    if not obj:
        raise SystemExit(f'missing files.img object {fid}')
    if obj.get('type') == 'REG':
        return obj
    if obj.get('type') == 'FIFO':
        regid = obj.get('fifo', {}).get('regf_id')
        reg = objects.get(regid)
        if reg and reg.get('type') == 'REG':
            return reg
    raise SystemExit(f'unsupported fd object {fid}: {obj.get("type")}')

inobj = resolve(fd_ids[0])
outobj = resolve(fd_ids[1])
err_obj = resolve(fd_ids[2])
if inobj['id'] in (outobj['id'], err_obj['id']):
    raise SystemExit('stdin shares file object with stdout/stderr; cannot remap independently')
if outobj['id'] != err_obj['id']:
    raise SystemExit('stdout and stderr use different file objects; not supported yet')
if not inobj['reg']['name'].endswith('.stdin') or not outobj['reg']['name'].endswith('.log'):
    raise SystemExit('unexpected stdio path types; inspect files.img before proceeding')
print(f"stdin: object {inobj['id']}: {inobj['reg']['name']} -> {inp}")
print(f"stdout/stderr: object {outobj['id']}: {outobj['reg']['name']} -> {out}")
inobj['reg']['name'] = inp
outobj['reg']['name'] = out
with open(dest, 'w') as f: json.dump(files, f)
PY
crit encode -i "$DST/.files-new.json" -o "$DST/files.img"

mkfifo -m 600 "$INPUT"
install -m 644 /dev/null "$OUTPUT"

# Serialize CRIU restore's ghost-file setup/cleanup; keep guest processes concurrent.
(
  flock -x 9
  unshare -pf --mount-proc \
    criu restore -D "$DST" --shell-job --ext-unix-sk \
      --skip-file-rwx-check --pidfile "$DST/restored.pid" \
      -v4 -o restore.log \
    >"$DST/restore.out" 2>&1 </dev/null 9>&- &
  UPID=$!
  echo "$UPID" > "$DST/unshare.hostpid"
  # CRIU's restore process remains running as a parent after successful restore.
  for ((i=0; i<200; i++)); do
    if grep -q 'Restore finished successfully' "$DST/restore.log" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$UPID" 2>/dev/null; then
      echo "restore exited unexpectedly; see $DST/restore.log and restore.out" >&2
      exit 1
    fi
    sleep 0.1
  done
  grep -q 'Restore finished successfully' "$DST/restore.log" 2>/dev/null || {
    echo "restore timed out; see $DST/restore.log" >&2
    exit 1
  }
  # Find the QEMU child within this specific unshare -> criu -> tracee tree.
  CPID=$(pgrep -P "$UPID" -x criu | head -n1 || true)
  [[ -n "$CPID" ]] || { echo "cannot locate CRIU child of $UPID" >&2; exit 1; }
  RPID=$(pgrep -P "$CPID" | head -n1 || true)
  [[ -n "$RPID" ]] || { echo "cannot locate restored process child of $CPID" >&2; exit 1; }
  echo "$RPID" > "$DST/host.pid"
  printf 'restored snapshot=%s instance=%s host_pid=%s\nstdin=%s\nstdout=%s\n' \
    "$SNAP" "$INSTANCE" "$RPID" "$INPUT" "$OUTPUT"
) 9>"$LOCK"

