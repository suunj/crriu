# Shared settings for the crriu harness. Override with environment variables.
: "${CRRIU_RR:=$(cd "$(dirname "$0")/../../.." && pwd)/build/bin/rr}"
: "${CRRIU_CWD:=$PWD}"              # --cwd given to rr detach
: "${CRRIU_STDIN:=/tmp/qemu-stdin}" # fifo handed to the tracee as stdin
: "${CRRIU_LOG:=/tmp/detach.log}"
: "${CRRIU_IMG:=/tmp/crriu-img}"
[ -p "$CRRIU_STDIN" ] || { rm -f "$CRRIU_STDIN"; mkfifo "$CRRIU_STDIN"; }
