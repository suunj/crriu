# Shared settings for the crriu harness. Override with environment variables.
: "${CRRIU_RR:=$(cd "$(dirname "$0")/../../.." && pwd)/build/bin/rr}"
: "${CRRIU_CWD:=$PWD}"              # --cwd given to rr detach
: "${CRRIU_LOG:=/tmp/detach.log}"   # rr's own stdout/stderr (replay echo, "detached pid" lines)
: "${CRRIU_IMG:=/tmp/crriu-img}"    # criu images: $CRRIU_IMG/<branch>
: "${CRRIU_BR:=/tmp/crriu-br}"      # per-branch stdio: branch-K.stdin (FIFO), branch-K.log
mkdir -p "$CRRIU_BR"
