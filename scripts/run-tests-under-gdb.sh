#!/bin/sh
# Run the test binary under gdb so a crash OR a hang leaves all-thread
# backtraces in the CI log (issue #83).
#
#   scripts/run-tests-under-gdb.sh <test-binary> [iterations] [timeout-seconds]
#
# Each iteration runs the binary to completion under `gdb -batch`:
#
#   * a clean exit ends gdb with the binary's own exit code, so a failing
#     assertion still fails the step;
#   * a fatal signal (SIGSEGV, SIGABRT, ...) stops the binary inside gdb, which
#     prints `info threads` + `thread apply all bt` and exits 99;
#   * a hang is interrupted by `timeout -s INT` BEFORE ctest's / the job's own
#     limit would kill everything silently: gdb stops the binary on the SIGINT,
#     prints the same backtraces, and timeout reports 124. `-k 30` hard-kills gdb
#     itself if it ever wedges.
#
# Iterations stop at the first failure, whose code becomes this script's exit
# code. Looping is the point: the failures this exists for are intermittent.
set -u

bin=${1:?usage: run-tests-under-gdb.sh <test-binary> [iterations] [timeout-seconds]}
iterations=${2:-3}
limit=${3:-300}
here=$(cd "$(dirname "$0")" && pwd)

i=1
while [ "$i" -le "$iterations" ]; do
    echo "=== $bin under gdb: iteration $i/$iterations (timeout ${limit}s) ==="
    timeout -s INT -k 30 "$limit" \
        gdb -q -batch -nx -x "$here/run-tests-under-gdb.gdb" --args "$bin"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        case "$rc" in
            124) echo "::error::$bin hung (no exit within ${limit}s); all-thread backtraces above" ;;
            99) echo "::error::$bin died on a signal; all-thread backtraces above" ;;
            *) echo "::error::$bin exited $rc" ;;
        esac
        exit "$rc"
    fi
    i=$((i + 1))
done
echo "=== $iterations clean iteration(s) ==="
