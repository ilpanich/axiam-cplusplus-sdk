# gdb command file for scripts/run-tests-under-gdb.sh (issue #83).
set pagination off
set confirm off
set print thread-events off
# Inside a container gdb may not be allowed to turn ASLR off; do not try.
set disable-randomization off
# The loopback test servers can see a peer vanish; that is not what we are here for.
handle SIGPIPE nostop noprint pass
run
if $_isvoid($_exitcode)
  echo \n=== the test binary did not exit (crash, or interrupted on timeout): all-thread backtraces ===\n
  info threads
  thread apply all bt
  kill
  quit 99
else
  quit $_exitcode
end
