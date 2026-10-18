#!/bin/sh
# Oracle: the kernel. Nothing here adjudicates whether a syscall was
# permitted; the filter is installed, the call is made, and the process
# lives or dies. The result is read out of wait4 status.
set -u
cd "$(dirname "$0")/.."

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
nok() { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"
        [ $# -gt 1 ] && printf '        %s\n' "$2"; return 0; }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else nok "$1" "want [$2] got [$3]"; fi; }

# Built here rather than by the Makefile because it is a test fixture
# and not part of the program. The program under test is NOT compiled
# here: make test depends on all, so an edit cannot be tested against
# a stale binary by running this script directly.
if [ profiled.c -nt profiled ]; then
	echo "FAIL  profiled.c is newer than profiled: run make test, not t/run.sh" >&2
	exit 1
fi
cc -std=c11 -O1 -Wall -Wextra -o t/waitstat t/waitstat.c || exit 1

# ------------------------------------------------- the rig checks itself
# Three facts, and the suite is worthless without all three.
#
# A filter that kills everything would pass the "denied call dies" check
# while meaning nothing, so the allowed call has to be shown to survive.
# And waitstat has to be shown to distinguish a signal from an exit
# status, because the shell does not: $? is 159 for both SIGSYS and a
# program returning 159.

# getpid is 39 and getuid is 102 on x86-64. Named here rather than
# looked up, because a wrong number would make the test pass for the
# wrong reason and the suite checks the numbers below.
GETPID=39
GETUID=102

got=$(./t/waitstat sh -c 'exit 7')
eq "waitstat reports an ordinary exit" "exit 7" "$got"

got=$(./t/waitstat sh -c 'kill -TERM $$')
eq "waitstat reports a signal, not 128 plus it" "signal 15" "$got"

# The numbers themselves, against the kernel's own header rather than
# against memory. A wrong number here would deny something harmless and
# the kill test would still pass.
# The header moved between distributions: Fedora has it under
# /usr/include/asm, Debian under /usr/include/x86_64-linux-gnu/asm.
# Checked in both rather than skipped on one.
hdr=
for c in /usr/include/asm/unistd_64.h \
         /usr/include/x86_64-linux-gnu/asm/unistd_64.h; do
	[ -r "$c" ] && { hdr=$c; break; }
done
if [ -n "$hdr" ]; then
	eq "getpid is $GETPID in the kernel header" \
	   "$GETPID" "$(awk '$2 == "__NR_getpid" { print $3 }' "$hdr")"
	eq "getuid is $GETUID in the kernel header" \
	   "$GETUID" "$(awk '$2 == "__NR_getuid" { print $3 }' "$hdr")"
else
	echo "SKIP  no unistd_64.h found, so the syscall numbers are unchecked"
fi

# ------------------------------------------------------- the kernel bites
# SIGSYS is 31. Written out rather than taken from the shell's own
# table, so the expected value does not come from the same place as the
# observed one.
got=$(./t/waitstat -q ./profiled probe "$GETPID" "$GETPID" 2>/dev/null)
eq "a denied syscall is killed by the kernel, SIGSYS" "signal 31" "$got"

got=$(./t/waitstat -q ./profiled probe "$GETPID" "$GETUID" 2>/dev/null)
eq "a permitted syscall returns, under the same filter" "exit 0" "$got"

# The permitted call must also produce its answer, not merely survive.
# A filter that turned every call into a silent no-op would pass the
# line above.
out=$(./profiled probe "$GETPID" "$GETUID" 2>/dev/null)
case "$out" in
	"returned "[0-9]*" errno 0") ok "the permitted syscall actually ran: $out" ;;
	*) nok "the permitted syscall actually ran" "got [$out]" ;;
esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
