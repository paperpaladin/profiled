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

# Every record call is wrapped in a timeout. A tracer that loses a
# stop waits forever, and the first version of the signal handling did
# exactly that: a suite that hangs reports nothing at all, which is
# worse than one that fails.
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
timeout 60 "$PWD/profiled" record -o "$TMP/p" -- /bin/echo marker > "$TMP/out" 2>&1
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

# ------------------------------------------------- where the program starts
# The boundary between the recorder's syscalls and the program's, and
# it is not where it first looks.
#
# execve BELONGS to the program and must be in the profile: `apply`
# installs the filter and then execs, so a profile without it kills
# the program before it has run an instruction. Everything the child
# does before that (ptrace(TRACEME), and the raise(SIGSTOP) that lets
# the parent set its options) must not be, and is not, because the
# parent's first waitpid returns only after that stop. That ordering
# is by construction rather than by luck, which is why it is not a
# flaky test.
#
# The tracer's own calls must be absent too. They would be, since the
# tracer is a different process, but a recorder that read the wrong
# pid would put them there and every id in the profile would still
# look plausible.
timeout 60 "$PWD/profiled" record -o "$TMP/b.p" -- /bin/true > /dev/null 2>&1
if tail -n +3 "$TMP/b.p" | grep -qx 59; then
	ok "execve is in the profile, because apply has to exec under it"
else
	nok "execve is in the profile" "59 is absent, so apply would die at exec"
fi
leaked=
for pair in "101 ptrace" "61 wait4" "62 kill" "57 fork"; do
	n=${pair%% *}
	tail -n +3 "$TMP/b.p" | grep -qx "$n" && leaked="$leaked ${pair#* }"
done
if [ -z "$leaked" ]; then
	ok "no syscall only the recorder makes is in the profile"
else
	nok "no syscall only the recorder makes is in the profile" "found:$leaked"
fi

# And the whole thing has to survive the round trip it exists for: the
# profile recorded from /bin/true must let /bin/true run.
/bin/true; want=$?
"$PWD/profiled" apply "$TMP/b.p" -- /bin/true; got=$?
eq "the recorded program runs under its own profile" "$want" "$got"

# -------------------------------------------------------------- apply
# The first half of the claim: under its own profile the program must
# behave identically. Not "exits 0": stdout, stderr and exit status
# compared byte for byte against the unconfined run, because a sandbox
# that quietly breaks the workload is not a tighter sandbox.
# The first three are small and similar on purpose: they are where a
# mistake is easiest to read. The last two are the point of item 08.
# python3 makes 34 syscalls to echo's 20, with dynamic loading, a pile
# of stat and openat, and signal setup that none of the others reach;
# sort allocates and uses a temporary. A profile derived from a
# four-syscall program proves very little about one that does real
# work.
#
# Both are skipped rather than failed when absent, because they are
# two workloads among five and the suite still means something
# without them.
WORKLOADS="/bin/echo hello
/bin/cat /etc/hostname
/usr/bin/head -2 /etc/hosts"
for extra in "/usr/bin/python3 -c pass" "/usr/bin/sort /etc/hosts"; do
	if [ -x "${extra%% *}" ]; then
		WORKLOADS="$WORKLOADS
$extra"
	else
		printf 'SKIP  %s is not installed\n' "${extra%% *}"
	fi
done

# Fed by a here-document and not a pipe: a pipe runs the loop in a
# subshell and every pass and fail it counts is discarded when the
# subshell exits. The suite would report fewer tests than it ran and
# a failure in here would not be a failure at all.
while read -r w; do
	# shellcheck disable=SC2086
	set -- $w
	"$@" > "$TMP/free.out" 2> "$TMP/free.err"; free_st=$?
	# Recorded with its output going to the same kind of place as the
	# runs it is compared against. That is not a tidiness point: cat
	# uses copy_file_range to a regular file and a read/write loop to
	# a pipe, so recording with stdout elsewhere produces a profile
	# that kills it here. See the case below, which demonstrates it.
	if ! timeout 60 "$PWD/profiled" record -o "$TMP/p" -- "$@" \
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

	# And the profile it produced has to be tight, not just
	# sufficient. A bigger workload permits more syscalls, which is
	# exactly when a filter builder with a wrong jump offset starts
	# to matter.
	out=$("$PWD/profiled" check "$TMP/p" 2>&1)
	if [ $? -eq 0 ] && printf '%s' "$out" | grep -q '0 wrong'; then
		ok "[$w] its profile is tight"
	else
		nok "[$w] its profile is tight"
		printf '%s\n' "$out" | head -4 | sed 's/^/        /'
	fi
done <<WORKLOAD_LIST
$WORKLOADS
WORKLOAD_LIST

# A profile from one program applied to another has to kill it. This is
# not the tightness check, which comes next and is sharper, but it is
# the cheap version of it: if this passed by allowing everything, the
# whole project would be decoration.
timeout 60 "$PWD/profiled" record -o "$TMP/echo.p" -- /bin/echo hi > /dev/null 2>&1
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
timeout 60 "$PWD/profiled" record -o "$TMP/pipe.p" -- /bin/cat /etc/hostname \
	> /dev/null 2>&1
# -o and not a shell redirect: cat has to be writing to a REGULAR
# file for copy_file_range to be the path it takes, and an outer
# redirect would capture waitstat's verdict along with it.
got=$(./t/waitstat -o "$TMP/cfr.out" "$PWD/profiled" apply "$TMP/pipe.p" -- \
      /bin/cat /etc/hostname 2>/dev/null)
if [ "$got" = "signal 31" ]; then
	ok "a profile recorded with stdout elsewhere kills the same command"
elif [ -z "$got" ]; then
	# An empty verdict is this harness being wrong, not cat having
	# changed, and it must not take the skip branch. It did, for as
	# long as this case existed, because an outer redirect was
	# swallowing the verdict: the case printed SKIP every run and a
	# SKIP is not a failure, so nothing said so.
	nok "a profile recorded with stdout elsewhere kills the same command" \
	    "waitstat said nothing, so this case measured nothing"
else
	# A real skip: cat no longer takes a different path by output
	# type, and the warning in the README needs a new example rather
	# than deleting.
	printf 'SKIP  cat no longer varies by output type here (got %s)\n' "$got"
fi

# -------------------------------------------------------------- check
# The second half, and the one that is easy to fake. A profile is
# tight only if a syscall it omits is actually killed, and nothing so
# far has asked for that directly: "another program is killed" is
# suggestive, not a measurement of this profile.
#
# The probes are pure syscalls, and the reason is the check itself. It
# confirms a denied call is stopped before it runs; if the filter is
# wrong, the call runs. Issuing an arbitrary syscall in a process
# whose filter might be broken is precisely the thing not to do.
out=$("$PWD/profiled" check "$TMP/echo.p" 2>&1)
if [ $? -eq 0 ] && printf '%s' "$out" | grep -q '0 wrong'; then
	ok "check: $(printf '%s' "$out" | tail -1 | sed 's/^check: //')"
else
	nok "check reports the profile is tight"
	printf '%s\n' "$out" | head -5 | sed 's/^/        /'
fi

# Both directions in one profile: permitted probes must return and
# omitted ones must die. A check that only ever saw one side would
# pass with a filter that killed everything.
{ head -2 "$TMP/echo.p"
  { tail -n +3 "$TMP/echo.p"; echo 39; } | sort -n | uniq
} > "$TMP/one.p"
out=$("$PWD/profiled" check "$TMP/one.p" 2>&1)
case "$out" in
	*"9 denied as expected, 1 permitted as expected, 0 wrong"*)
		ok "check sees both directions: getpid permitted, the rest denied" ;;
	*) nok "check sees both directions" "$out" ;;
esac

# check tests install_allow, not the profile, so the two can only
# disagree when the filter builder is wrong. Which means nothing in
# this suite had ever seen check report a wrong answer: a mutation
# making it always say "tight" passed everything.
#
# So the defect is planted. A copy of the source whose filter permits
# one syscall the profile does not, built and run, and check has to
# notice. Without this the tightness check is a function that has only
# ever been asked easy questions.
# The defect has to keep the instruction count the same, or the
# assertion in install_allow catches it first and check never gets a
# chance to be wrong. So it is a mis-aimed comparison rather than an
# extra one: the filter permits getpid in place of write.
sed 's/(unsigned)i, (unsigned char)to_allow/(unsigned)(i == 1 ? 39 : i), (unsigned char)to_allow/' \
    profiled.c > "$TMP/leaky.c"
if cmp -s profiled.c "$TMP/leaky.c"; then
	nok "the planted leak was planted" "the sed matched nothing"
else
	cc -std=c11 -O1 -w -o "$TMP/leaky" "$TMP/leaky.c" || exit 1
	out=$("$TMP/leaky" check "$TMP/echo.p" 2>&1)
	if [ $? -eq 0 ]; then
		nok "check notices a filter that permits more than the profile" \
		    "it reported success: $(printf '%s' "$out" | tail -1)"
	elif printf '%s' "$out" | grep -q 'getpid *returned'; then
		ok "check notices a filter that permits more than the profile"
	else
		nok "check notices a filter that permits more than the profile" "$out"
	fi
fi

# Three more planted defects, because each of these branches is
# unreachable while the program is correct, and a branch no test can
# reach is a branch no test is checking. Each sed must keep the
# instruction count: the assertion in build_filter catches a change in
# length before any of this gets a chance to be wrong.
plant() { # name, sed expression, expected substring
	sed "$2" profiled.c > "$TMP/pl.c"
	if cmp -s profiled.c "$TMP/pl.c"; then
		nok "planted: $1" "the sed matched nothing"
		return
	fi
	cc -std=c11 -O1 -w -o "$TMP/pl" "$TMP/pl.c" || { nok "planted: $1" "did not build"; return; }
	out=$("$TMP/pl" check "$TMP/echo.p" 2>&1)
	if [ $? -eq 0 ]; then
		nok "check notices $1" "it reported success"
	elif printf '%s' "$out" | grep -q "$3"; then
		ok "check notices $1"
	else
		nok "check notices $1" "$(printf '%s' "$out" | tail -2 | tr '\n' ' ')"
	fi
}

# An instruction the interpreter does not model. It must say so rather
# than shrug: an interpreter that treats what it cannot read as a
# no-op reports a verdict on a filter it never understood.
plant "a filter instruction it cannot model" \
      's/seccomp_data, nr));/seccomp_data, args[0]));/' \
      "does not model"

# An opcode outside the three this interpreter models at all, as
# opposed to a field it does not know. Different branch, and the one
# that decides whether an unreadable filter is reported or shrugged
# at: with this plant nothing else goes wrong, so the exit status
# rests entirely on the unmodelled count being counted.
plant "an opcode outside the three it models" \
      's/case BPF_LD | BPF_W | BPF_ABS:/case BPF_LD | BPF_W | BPF_IND:/' \
      "does not model"

# The architecture guard removed. Another ABI reaches the same kernel
# through different numbers, so every one of them has to be killed
# rather than judged against a table that does not apply.
plant "an architecture guard that does not guard" \
      's/AUDIT_ARCH_X86_64, 1, 0);/AUDIT_ARCH_X86_64, 1, 1);/' \
      "wrong ABI"

# The interpreter itself wrong. Caught by the exhaustive pass rather
# than by any comparison against the kernel: a model that misreads the
# syscall number disagrees with the profile on 29 of 1024.
plant "an interpreter that misreads the syscall number" \
      's/seccomp_data, nr)) A = nr;/seccomp_data, nr)) A = nr + 1;/' \
      "disagree with the profile"

# A check that happened to probe only permitted syscalls would report
# success having tested nothing about denial. It refuses.
{ head -2 "$TMP/echo.p"
  { tail -n +3 "$TMP/echo.p"
    printf '24\n39\n96\n102\n104\n107\n108\n110\n186\n201\n'
  } | sort -n | uniq
} > "$TMP/all.p"
out=$("$PWD/profiled" check "$TMP/all.p" 2>&1)
if [ $? -eq 0 ]; then
	nok "a check that tests no denial refuses" "it reported success"
elif printf '%s' "$out" | grep -q 'nothing about denial'; then
	ok "a check that tests no denial refuses, by name"
else
	nok "a check that tests no denial refuses" "$out"
fi

# ------------------------------------- mutating the profile, both ways
# The source mutations above ask whether the code is right. These ask
# whether the checks would notice a profile that is wrong, which is a
# different question and has a less comfortable answer.
#
# Too small is caught, and caught hard. Remove write(1) from echo's
# profile and the program dies at the first thing it tries to print.
grep -vx 1 "$TMP/echo.p" > "$TMP/small.p"
if cmp -s "$TMP/echo.p" "$TMP/small.p"; then
	nok "planted: a profile missing a syscall the program uses" \
	    "write(1) was not in the profile to begin with"
else
	got=$(./t/waitstat -q "$PWD/profiled" apply "$TMP/small.p" -- \
	      /bin/echo hi 2>/dev/null)
	eq "a profile missing one syscall kills the program" "signal 31" "$got"
fi

# Too large is caught by nothing here, and that is worth stating
# rather than leaving for someone to discover. "Tight" in this program
# means the installed filter matches the profile. It does not mean the
# profile is the smallest one that works. Add kill(62), which echo
# never calls: check still reports 0 wrong, because the filter does
# faithfully deny everything the profile omits, and apply still runs
# the program.
#
# The property that does catch it is minimality against a recording,
# and it is a comparison rather than a check: record the same workload
# again and require the profile to contain nothing the recording did
# not produce.
{ head -2 "$TMP/echo.p"
  { tail -n +3 "$TMP/echo.p"; echo 62; } | sort -n | uniq
} > "$TMP/big.p"

out=$("$PWD/profiled" check "$TMP/big.p" 2>&1)
if [ $? -eq 0 ] && printf '%s' "$out" | grep -q '0 wrong'; then
	ok "check calls an over-wide profile tight, which is what tight means here"
else
	nok "check calls an over-wide profile tight" \
	    "it reported a problem, so the README paragraph about this is now wrong"
fi

timeout 60 "$PWD/profiled" record -o "$TMP/fresh.p" -- /bin/echo hi \
	> /dev/null 2>&1
# Plain files and not process substitution: this suite runs under
# /bin/sh, where <(...) is a syntax error rather than a feature.
tail -n +3 "$TMP/big.p"   | sort > "$TMP/big.sorted"
tail -n +3 "$TMP/fresh.p" | sort > "$TMP/fresh.sorted"
extra=$(comm -23 "$TMP/big.sorted" "$TMP/fresh.sorted" | tr '\n' ' ')
if [ "$(printf '%s' "$extra" | tr -d ' ')" = "62" ]; then
	ok "a fresh recording names the syscall the profile did not need: $extra"
else
	nok "a fresh recording names the unneeded syscall" "found [$extra]"
fi

# And the honest other half of that comparison: the real profile must
# have nothing extra in it, or the check above would pass for the
# wrong reason.
tail -n +3 "$TMP/echo.p" | sort > "$TMP/echo.sorted"
extra=$(comm -23 "$TMP/echo.sorted" "$TMP/fresh.sorted" | tr '\n' ' ')
if [ -z "$(printf '%s' "$extra" | tr -d ' ')" ]; then
	ok "the recorded profile itself is minimal against a fresh recording"
else
	nok "the recorded profile itself is minimal" "extra:$extra"
fi

# ------------------------------------------------- kill or errno
# Two policies with two different failure modes, so neither is the
# silent default.
#
# kill stops the program at the offending call. errno fails the call
# and lets it carry on, which is the gentler option only for a
# program that checks its return values.
#
# cat is not such a program here, and the contrast is the case. Under
# the echo profile with --deny kill it dies of SIGSYS. With --deny
# errno it exits 0 and prints 47000-odd bytes of whatever was in the
# buffer, where the correct output is one byte. Neither is a bug in
# profiled: it is what choosing errno means, demonstrated rather than
# described.
got=$(./t/waitstat -q "$PWD/profiled" apply "$TMP/echo.p" -- \
      /bin/cat /etc/hostname 2>/dev/null)
eq "--deny kill: the program dies at the denied call" "signal 31" "$got"

"$PWD/profiled" apply --deny errno "$TMP/echo.p" -- /bin/cat /etc/hostname \
	> "$TMP/errno.out" 2>/dev/null
st=$?
if [ "$st" -ne 0 ]; then
	nok "--deny errno: the program survives the denied call" "it exited $st"
elif cmp -s "$TMP/errno.out" /etc/hostname; then
	nok "--deny errno: the program survives and its output is wrong" \
	    "the output was correct, so this case no longer shows anything"
else
	ok "--deny errno: the program survives, exits 0, and prints the wrong thing"
fi

# check has to follow the mode. In errno mode a denied probe returns
# EPERM instead of dying, so a check that only looked for SIGSYS would
# report every syscall wrongly permitted.
out=$("$PWD/profiled" check --deny errno "$TMP/echo.p" 2>&1)
if [ $? -eq 0 ] && printf '%s' "$out" | grep -q '0 wrong'; then
	ok "check under --deny errno: $(printf '%s' "$out" | tail -1 | sed 's/^check: //' | cut -c1-54)"
else
	nok "check follows --deny errno"
	printf '%s\n' "$out" | head -4 | sed 's/^/        /'
fi

out=$("$PWD/profiled" apply --deny shout "$TMP/echo.p" -- /bin/true 2>&1)
if [ $? -eq 0 ]; then
	nok "an unknown --deny value is refused" "it was accepted"
elif printf '%s' "$out" | grep -q 'kill or errno'; then
	ok "an unknown --deny value is refused, by name"
else
	nok "an unknown --deny value is refused" "$out"
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
timeout 60 "$PWD/profiled" record -o "$TMP/a.p" -- /bin/echo hi > /dev/null 2>&1
timeout 60 "$PWD/profiled" record -o "$TMP/b.p" -- /bin/echo hi > /dev/null 2>&1
if cmp -s "$TMP/a.p" "$TMP/b.p"; then
	ok "two recordings of the same workload are byte-identical"
else
	nok "two recordings of the same workload are byte-identical" \
	    "$(diff "$TMP/a.p" "$TMP/b.p" | head -3 | tr '\n' ' ')"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
