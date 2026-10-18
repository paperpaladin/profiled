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

# ------------------------------------------------------------- record
# The syscall set of one run, and then the same run watched by strace.
# A recorder checked against itself proves nothing: this is the first
# point where an outside observer can disagree.
#
# strace -o and not strace -c. The summary is the obvious choice and is
# wrong here for exactly the syscall a sandbox cannot afford to miss:
# -c counts calls that returned, exit_group never returns, and so it is
# absent from every summary strace prints. A profile built from that
# view kills the program at the moment it tries to exit cleanly.
TMP=t/tmp.$$
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT INT TERM

# The recording must not land on the program's stdout. Recording
# /bin/echo once produced a profile with "hi" in it, because the traced
# program inherits these streams.
"$PWD/profiled" record -o "$TMP/p" -- /bin/echo marker > "$TMP/out" 2>&1
eq "the program's own output does not reach the profile" \
   "marker" "$(cat "$TMP/out")"
if grep -qv '^[0-9][0-9]*$' "$TMP/p"; then
	nok "the profile is numbers only" "$(grep -v '^[0-9][0-9]*$' "$TMP/p" | head -2 | tr '\n' ' ')"
else
	ok "the profile is numbers only"
fi

# exit_group, 231, is the specific case the strace summary loses. Named
# here so that a regression says which syscall rather than "the sets
# differ".
if grep -qx 231 "$TMP/p"; then
	ok "exit_group is in the profile, which strace -c would have lost"
else
	nok "exit_group is in the profile" "231 is absent"
fi

# A syscall number outside the recorded range has to be reported, not
# dropped: a profile missing one syscall is a profile that kills the
# program. No workload here reaches 1024, so the branch is unreachable
# as built and a mutation that deletes it survives. Reached by building
# a second binary with a table too small for ordinary syscalls, which
# is the same move as planting a defect and requiring the gate to see
# it.
cc -std=c11 -O1 -w -DNR_MAX=40 -o "$TMP/small" profiled.c || exit 1
if "$TMP/small" record -o "$TMP/sp" -- /bin/true > /dev/null 2>"$TMP/se"; then
	nok "a syscall outside the table is reported" "it was accepted"
elif grep -q 'outside the recorded range' "$TMP/se"; then
	ok "a syscall outside the table is reported, not dropped"
else
	nok "a syscall outside the table is reported" "$(head -1 "$TMP/se")"
fi

# A program that makes another process. The recorder does not follow
# it, so the profile covers the parent only and saying so is the whole
# point: a profile that silently omits a child's syscalls kills the
# program under apply, for reasons the recording never showed.
#
# This case is here because the warning survived a mutation that
# deleted it. Nothing in the suite forked, so the check was a line of
# code no test could reach.
if timeout 30 "$PWD/profiled" record -o "$TMP/f" -- \
     /bin/sh -c '/bin/echo a | /bin/cat' > "$TMP/fo" 2> "$TMP/fe"; then
	nok "a forking program is reported as incomplete" "it was accepted"
elif grep -q 'created another process' "$TMP/fe"; then
	ok "a forking program is reported as incomplete, by name"
else
	nok "a forking program is reported as incomplete" "$(head -1 "$TMP/fe")"
fi

# The hang this found is worth its own case. A tracer that drops the
# signals it did not cause swallows the SIGCHLD a parent is waiting
# for, and `timeout 5 true` never returns: nothing crashes, nothing
# prints, the process simply stays. A timeout here rather than a
# wedged suite.
if timeout 30 "$PWD/profiled" record -o "$TMP/t" -- \
     /usr/bin/timeout 5 /bin/true > /dev/null 2>&1; then
	nok "a program waiting on a child does not hang" "expected the spawn warning"
else
	st=$?
	if [ "$st" -eq 124 ]; then
		nok "a program waiting on a child does not hang" "it hung"
	else
		ok "a program waiting on a child does not hang (exit $st)"
	fi
fi

if command -v strace >/dev/null 2>&1; then
	for w in "/bin/true" "/bin/echo hi" "/bin/cat /etc/hostname" \
	         "/usr/bin/head -1 /etc/hosts"; do
		# shellcheck disable=SC2086
		out=$(python3 t/strace_cmp.py "$PWD/profiled" "$TMP/sc" $w 2>&1)
		st=$?
		case "$out" in
			SKIP*) printf 'SKIP  %s: %s\n' "$w" "$out" ;;
			*) if [ "$st" -eq 0 ]; then
			     ok "strace agrees on [$w]: $(printf '%s' "$out" | tr -d '\n' | sed 's/^ *//')"
			   else
			     nok "strace disagrees on [$w]"
			     printf '%s\n' "$out" | head -6 | sed 's/^/        /'
			   fi ;;
		esac
	done
else
	echo "SKIP  strace is not installed, so the recorder has no second observer"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
