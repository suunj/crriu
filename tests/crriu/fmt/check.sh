#!/bin/sh
# Runs every case in fmt/cases through crriu-cycle.sh and checks the expected
# output. The expectation is the oracle: the restored process must produce
# what the recording would have (or what the injected input asks for).
D=$(cd "$(dirname "$0")" && pwd)
fail=0
grep -v '^#' "$D/cases" | while IFS='|' read -r name trace sel nspid inject expect wait; do
  name=$(echo $name); trace=$(echo $trace); sel=$(echo $sel | sed 's/^ *//;s/ *$//')
  nspid=$(echo $nspid); inject=$(echo $inject | sed 's/^ *//;s/ *$//'); expect=$(echo $expect | sed 's/^ *//;s/ *$//')
  pkill -f 'bin/rr detach' 2>/dev/null; pkill -KILL -f '^rr:' 2>/dev/null; sleep 1
  wait=$(echo $wait)
  if INJECT="$inject" INJECT_WAIT="${wait:-8}" "$D/../env/crriu-cycle.sh" "$trace" "$sel" "$nspid" >/tmp/crriu-check-$name.log 2>&1 \
     && grep -qE "$expect" /tmp/crriu-check-$name.log; then
    echo "PASS $name"
  else
    echo "FAIL $name  (see /tmp/crriu-check-$name.log)"; fail=1
  fi
done
pkill -f 'bin/rr detach' 2>/dev/null; pkill -KILL -f '^rr:' 2>/dev/null
exit $fail
