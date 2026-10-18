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
# A header naming the format and the ABI, then nothing but numbers.
eq "the profile names its format" "profiled 1" "$(sed -n 1p "$TMP/p")"
eq "the profile names its ABI" "arch 0xc000003e" "$(sed -n 2p "$TMP/p")"
if tail -n +3 "$TMP/p" | grep -qv '^[0-9][0-9]*$'; then
	nok "the rest of the profile is numbers only" \
	    "$(tail -n +3 "$TMP/p" | grep -v '^[0-9][0-9]*$' | head -2 | tr '\n' ' ')"
else
	ok "the rest of the profile is numbers only"
fi

# exit_group, 231, is the specific case the strace summary loses. Named
# here so that a regression says which syscall rather than "the sets
# differ".
if tail -n +3 "$TMP/p" | grep -qx 231; then
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

# -------------------------------------------------------------- apply
# The first half of the claim: under its own profile the program must
# behave identically. Not "exits 0": stdout, stderr and exit status
# compared byte for byte against the unconfined run, because a sandbox
# that quietly breaks the workload is not a tighter sandbox.
for w in "/bin/echo hello" "/bin/cat /etc/hostname" "/usr/bin/head -2 /etc/hosts"; do
	# shellcheck disable=SC2086
	set -- $w
	"$@" > "$TMP/free.out" 2> "$TMP/free.err"; free_st=$?
	# Recorded with its output going to the same kind of place as the
	# runs it is compared against. That is not a tidiness point: cat
	# uses copy_file_range to a regular file and a read/write loop to
	# a pipe, so recording with stdout elsewhere produces a profile
	# that kills it here. See the case below, which demonstrates it.
	if ! "$PWD/profiled" record -o "$TMP/p" -- "$@" \
	     > "$TMP/rec.out" 2> "$TMP/rec.err"; then
		nok "record [$w]" "$(head -1 "$TMP/rec.err")"
		continue
	fi
	"$PWD/profiled" apply "$TMP/p" -- "$@" > "$TMP/jail.out" 2> "$TMP/jail.err"
	jail_st=$?
	if [ "$free_st" != "$jail_st" ]; then
		nok "[$w] runs identically under its own profile" \
		    "exit $free_st free, $jail_st confined: $(head -1 "$TMP/jail.err")"
	elif ! cmp -s "$TMP/free.out" "$TMP/jail.out"; then
		nok "[$w] runs identically under its own profile" "stdout differs"
	elif ! cmp -s "$TMP/free.err" "$TMP/jail.err"; then
		nok "[$w] runs identically under its own profile" "stderr differs"
	else
		ok "[$w] runs identically under its own profile"
	fi
done

# A profile from one program applied to another has to kill it. This is
# not the tightness check, which comes next and is sharper, but it is
# the cheap version of it: if this passed by allowing everything, the
# whole project would be decoration.
"$PWD/profiled" record -o "$TMP/echo.p" -- /bin/echo hi > /dev/null 2>&1
got=$(./t/waitstat -q "$PWD/profiled" apply "$TMP/echo.p" -- /bin/cat /etc/hostname 2>/dev/null)
eq "another program under that profile is killed" "signal 31" "$got"

# The coverage problem, in its least obvious form. A profile is not a
# property of the program: it is a property of the program AND the
# environment it ran in. cat writes to a regular file with
# copy_file_range and to a pipe with read and write, so the same
# command line produces two different syscall sets depending on where
# stdout points, and a profile from one kills it under the other.
#
# This is demonstrated rather than worked around, because it is the
# thing a user of this program most needs to know.
"$PWD/profiled" record -o "$TMP/pipe.p" -- /bin/cat /etc/hostname \
	> /dev/null 2>&1
got=$(./t/waitstat "$PWD/profiled" apply "$TMP/pipe.p" -- \
      /bin/cat /etc/hostname > "$TMP/cfr.out" 2>/dev/null)
if [ "$got" = "signal 31" ]; then
	ok "a profile recorded with stdout elsewhere kills the same command"
else
	# Not a failure of the program: it means this cat no longer takes
	# a different path, and the warning in the README needs a new
	# example rather than deleting.
	printf 'SKIP  cat no longer varies by output type here (got %s)\n' "$got"
fi

# ----------------------------------------------- the profile is read strictly
# Every line is understood or refused. A reader that skips what it does
# not recognise turns a typo into a policy permitting less than the
# file says, and the program then dies somewhere else with no hint that
# the file was the problem.
refuses() { # name, how to build the bad file, expected substring
	eval "$2"
	out=$("$PWD/profiled" apply "$TMP/bad" -- /bin/true 2>&1)
	if [ $? -eq 0 ]; then
		nok "refuses $1" "it was accepted"
	elif printf '%s' "$out" | grep -q "$3"; then
		ok "refuses $1, by name"
	else
		nok "refuses $1" "message did not mention $3: $out"
	fi
}
refuses "a file that is not a profile" \
	'printf "hello\n1\n" > "$TMP/bad"' "not a version 1 profile"
refuses "a profile for another architecture" \
	'sed "s/^arch .*/arch 0x40000028/" "$TMP/echo.p" > "$TMP/bad"' "arch"
refuses "a profile with no arch line" \
	'grep -v "^arch " "$TMP/echo.p" > "$TMP/bad"' "no arch line"
refuses "an out-of-order profile" \
	'{ head -2 "$TMP/echo.p"; echo 300; echo 10; } > "$TMP/bad"' "out of order"
refuses "a repeated syscall" \
	'{ head -2 "$TMP/echo.p"; echo 10; echo 10; } > "$TMP/bad"' "out of order or repeated"
refuses "a line that is not a number" \
	'{ head -2 "$TMP/echo.p"; echo "read"; } > "$TMP/bad"' "cannot read"
refuses "a syscall number out of range" \
	'{ head -2 "$TMP/echo.p"; echo 99999; } > "$TMP/bad"' "cannot read"
refuses "an empty file" \
	': > "$TMP/bad"' "not a profile"
refuses "a profile permitting nothing" \
	'head -2 "$TMP/echo.p" > "$TMP/bad"' "permits no syscalls"

# Two recordings of the same workload must produce the same bytes, or
# a profile cannot be reviewed in a diff.
"$PWD/profiled" record -o "$TMP/a.p" -- /bin/echo hi > /dev/null 2>&1
"$PWD/profiled" record -o "$TMP/b.p" -- /bin/echo hi > /dev/null 2>&1
if cmp -s "$TMP/a.p" "$TMP/b.p"; then
	ok "two recordings of the same workload are byte-identical"
else
	nok "two recordings of the same workload are byte-identical" \
	    "$(diff "$TMP/a.p" "$TMP/b.p" | head -3 | tr '\n' ' ')"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
