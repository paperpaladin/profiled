# profiled

Watch a program run, derive the smallest seccomp-bpf policy that still
lets it run, install that policy, and prove both halves of the claim.

**Seven commits in.** `record`, `apply` and `check` all work: a program
can be watched, run under a policy built from what it did, and the
policy shown to deny what it omits, for all 1024 syscall numbers and
a second ABI.

```
$ profiled record -o echo.p -- /bin/echo hi
$ cat echo.p
profiled 1
arch 0xc000003e
0
1
3
...
$ profiled apply echo.p -- /bin/echo hi
hi
$ profiled apply echo.p -- /bin/cat /etc/hostname
Bad system call (core dumped)
$ profiled check echo.p
check: 10 denied as expected, 0 permitted as expected, 0 wrong; 1024 numbers and a second ABI checked against the installed filter
```

```
$ make test
...
ok    a denied syscall is killed by the kernel, SIGSYS
ok    strace agrees on [/bin/cat /etc/hostname]: 20 syscalls, both observers agree
ok    [/bin/echo hello] runs identically under its own profile
ok    [/bin/cat /etc/hostname] runs identically under its own profile
ok    another program under that profile is killed
ok    a profile recorded with stdout elsewhere kills the same command
ok    check: 10 denied as expected, 0 permitted as expected, 0 wrong
ok    check notices a filter that permits more than the profile
ok    refuses a profile for another architecture, by name
ok    execve is in the profile, because apply has to exec under it
ok    no syscall only the recorder makes is in the profile
ok    two recordings of the same workload are byte-identical

48 passed, 0 failed
```



## The oracle is the kernel

Nothing here decides whether a syscall was permitted. The filter is
installed, the call is made, and the process lives or dies. The result
is read out of `wait4` status.

That distinction is why `t/waitstat.c` exists. The shell cannot make
it: `$?` is 128+n for a signal, which is the same number a program
exiting 159 produces, and the claim being tested is "the kernel killed
it" rather than "the program returned something odd". A harness that
cannot tell those apart is not testing the claim.

Three checks guard the three ways this could pass while meaning
nothing. A filter that killed everything would satisfy "the denied
call dies", so the permitted call is required to survive. A filter
that turned every call into a no-op would satisfy that, so the
permitted call is required to produce its answer. And `waitstat`
itself is required to report `signal 15` for a `kill -TERM` and
`exit 7` for an exit, because an oracle that reports the same thing
for both is not reading anything.

The syscall numbers are checked against `asm/unistd_64.h` rather than
remembered. A wrong number would deny something harmless, and the kill
test would still pass.

Five mutations, all caught: invert the match so the filter allows what
it should deny, make it kill everything, skip `PR_SET_NO_NEW_PRIVS`,
skip the `seccomp` call entirely, and drop the architecture check.

## Why the architecture check is in the first commit

`seccomp_data.nr` is an index into one ABI's table. A filter that does
not pin the ABI can be walked around on a kernel offering more than
one, because x32 reaches the same kernel code through different
numbers. The filter kills on a mismatch rather than allowing it.

## Two observers, and what the second one found

A recorder checked against itself proves nothing, so the same run is
watched by `strace` and the two must name the same syscalls. Seventeen
to twenty syscalls per workload, four workloads, exact agreement.

It reads `strace -o`, the trace, and not `strace -c`, the summary. The
summary is the obvious choice and it is wrong here, for precisely the
syscall a sandbox cannot afford to miss. `-c` counts calls that
returned; `exit_group` never returns; so it appears in no summary
strace prints. A profile built from that view kills the program at the
moment it tries to exit cleanly. There is a named test for 231 being
present, so a regression says which syscall rather than "the sets
differ".

Three bugs came out of building the second observer, and none of them
would have been found by reading the code.

**The recorder shared stdout with the program it recorded.** Recording
`/bin/echo hi` produced a profile containing `hi`. The profile goes to
a file now and never to stdout, which is the program's.

**Dropping signals hung the tracee.** `timeout 5 true` never returned.
`timeout` forks, the child exits, `SIGCHLD` stops the tracee, and the
loop saw a stop that was not a syscall stop and resumed it with signal
0. The signal was swallowed, `timeout` waited forever for a `SIGCHLD`
that never came, and its child stayed a zombie. Nothing crashed and
nothing printed. A tracer has to hand back the signals it did not
cause.

**Handing back all of them killed every program instead.** The
`SIGTRAP` that follows `execve` is ptrace's own, and re-injecting it
terminates the tracee: every traced program died before reaching
`main`, having recorded four syscalls. `PTRACE_O_TRACEEXEC` is set so
that stop carries an event code and can be told apart from a `SIGTRAP`
the program raised itself.

The two fixes are a pair, and the suite shows it: removing
`TRACEEXEC` is caught, and so is dropping the re-injection, while the
`event == 0` guard on its own is an equivalent mutant as long as
`TRACEEXEC` stays set.

## The half that is easy to fake

`apply` running the program proves the policy is sufficient. It says
nothing about whether the policy is tight, and a policy that permits
everything is sufficient for every program.

So `check` issues syscalls the profile omits and requires the kernel
to kill the process with `SIGSYS`, and issues ones it permits and
requires them to return. Both directions, because a filter that
killed everything would satisfy the first on its own.

The probes are ten pure syscalls rather than all 1024 numbers, and
the reason is the check itself. It confirms that a denied call is
stopped *before it runs*; if the filter is wrong, the call runs.
Issuing an arbitrary syscall in a process whose filter might be
broken is precisely the thing not to do. So every probe reads a
number the kernel already knows and changes nothing.

The other thousand are covered by interpreting the filter directly,
over the exact bytes handed to the kernel: there is one builder, and
`check` runs the interpreter on what `apply` installs. Every number
must come out `ALLOW` if the profile lists it and `KILL` if it does
not, and every number under a second ABI must come out `KILL`,
because another ABI reaches the same kernel through different numbers
and judging them against a table that does not apply is the bypass
the arch guard exists to prevent.

An instruction the interpreter cannot model is reported, not
shrugged at. An interpreter that treats what it cannot read as a
no-op returns a verdict on a filter it never understood.

### Two routes that do not work

`PTRACE_SECCOMP_GET_FILTER` would read the filter back out of the
kernel rather than rebuilding it, which is a better oracle. It
requires `CAP_SYS_ADMIN` and returns `EACCES` to an ordinary user, so
a check built on it would skip on every machine this runs on.

Probing all 1024 numbers under a tracer that neutralises anything
dangerous does not work either, and the reason is worth knowing. The
kernel runs the ptrace syscall-entry stop **before** seccomp,
deliberately, so that a tracer's changes are what the filter judges.
Measured here rather than assumed: with the tracer writing -1 over
`orig_rax`, a call the filter denies survives, and with the write
removed the same call dies of `SIGSYS`. So a tracer cannot both
neutralise a syscall and find out what the filter would have done
with it. The substituted number is the number the filter sees.

### Why the two halves are enough together

The interpreter agrees with the profile for every number. The kernel
agrees with the profile on ten. Those two facts imply the interpreter
agrees with the kernel on those ten, which is what ties the exhaustive
half to the real one.

There was an explicit cross-check asserting exactly that, and it was
deleted: by the argument above it cannot fail while the other two
checks run, and a check that reads well and cannot go red is the thing
this project is about not writing.

A check that happened to probe only permitted syscalls would report
success having tested nothing about denial, so it refuses instead.

### What this one got wrong

`check` tests the filter builder, not the profile, so the two can
only disagree when the builder is wrong, which means nothing in the
suite had ever seen `check` report a wrong answer. A mutation making
it always say "tight" passed everything.

The fix is a planted defect: a copy of the source whose filter
permits `getpid` in place of `write`, built and run, and `check` has
to notice. The first attempt planted an *extra* permitted syscall and
was caught by the instruction-count assertion before `check` could be
wrong at all, which is the assertion working and the test not. It is
a mis-aimed comparison now, so the count is unchanged.

There are five planted defects in all, one per branch that cannot be
reached while the program is correct: a filter permitting more than
the profile, a load from a field the interpreter does not model, an
opcode outside the three it models, an architecture guard that does
not guard, and an interpreter that misreads the syscall number.

## Where the program starts

`execve` belongs to the program and is in the profile. That is worth
saying because it looks like the tracer's: `apply` installs the
filter and then execs, so a profile without `execve` kills the
program before it has run an instruction.

Everything the child does before that, `ptrace(TRACEME)` and the
`raise(SIGSTOP)` that lets the parent set its options, is outside the
profile, and by construction rather than by luck: the parent's first
`waitpid` returns only after that stop. The tracer's own calls are
outside too, which they would be anyway, but a recorder reading the
wrong pid would put them in and every id would still look plausible.
Both are cases, and both mutations are caught.

## A profile is not a property of a program

It is a property of the program **and the environment it ran in**, and
the sharpest demonstration of that is also the least obvious.

`cat` copies to a regular file with `copy_file_range`, and to a pipe
with a `read`/`write` loop. So `cat /etc/hostname` makes a different
set of syscalls depending on where stdout points, and a profile
recorded with output going to `/dev/null` kills the identical command
line when its output goes to a file. Two syscalls separate them:
`copy_file_range` and the `uname` that decides whether to try it.

This is a test rather than a warning in prose. It records one way,
applies the other, and requires the kill. If a future `cat` stops
varying, the case says SKIP and asks for a new example rather than
being deleted, because the hazard will not have gone away.

It is also what the suite got wrong first. The sufficiency check
recorded with stdout inherited and applied with stdout to a file, and
`cat` died under what looked like its own profile.

## kill, or errno

A denied call can stop the program or fail. Neither is the silent
default: `--deny kill` and `--deny errno`, on both `apply` and
`check`.

The contrast is best shown by a program that gets it wrong. Under the
`echo` profile, `cat /etc/hostname`:

```
$ profiled apply --deny kill  echo.p -- /bin/cat /etc/hostname
Bad system call (core dumped)
$ profiled apply --deny errno echo.p -- /bin/cat /etc/hostname | wc -c
47594
```

The correct output is one byte. `cat` does not check the return of
the call that was denied, so it carries on and prints whatever was in
the buffer, and exits 0 while doing it. That is not a bug here. It is
what choosing `errno` means, and it is why the choice is a flag with
both sides tested rather than a default nobody reads.

`check` follows the mode, and has to: in `errno` mode a denied probe
returns `EPERM` instead of dying, so a check that only looked for
`SIGSYS` would report every syscall wrongly permitted. That mutation
is caught.

The architecture mismatch always kills, in both modes. Softening it
would let a process on another ABI carry on while its syscall numbers
mean something this profile never judged.

## Reading a profile strictly

Nine refusals, each with the real file and one thing changed: not a
profile, another architecture, no `arch` line, out of order, a
repeated number, a line that is not a number, a number out of range,
empty, and one that permits nothing at all.

A reader that skipped what it did not recognise would turn a typo into
a policy permitting less than the file says, and the program would
then die somewhere else with no hint that the file was the problem.
The `arch` line matters most: a syscall number indexes one ABI's
table, so the same file is a different policy on another machine, and
the failure is permitting the wrong calls rather than failing to
parse.

Two recordings of the same workload are byte-identical, which is what
makes a profile reviewable in a diff.

## Survivors, written down

Two mutations survive and both are genuinely equivalent rather than
untested:

- Counting unmodelled instructions towards the exit status. Every
  filter that reaches that branch also trips the probe check or the
  arch check, so the counter never decides anything. It is kept
  because the message it accompanies says the verdict is
  *incomplete*, and exiting 0 on an incomplete verdict would be this
  project's cardinal sin.
- Returning an error when the interpreter runs off the end of a
  program. `build_filter` always ends in a `RET`.
- Requiring `SIGSYS` specifically rather than any signal in `check`.
  The only way a probe child dies here is `SIGSYS`, so the
  specificity is defensive.
- Treating an unreadable probe result as a pass. The next branch
  catches it anyway, since -1 matches neither expected answer.
- Recording both halves of each syscall stop instead of the entry.
  `orig_rax` holds the same value at both, and the second write lands
  on the same bit of a set. The entry-only toggle is kept because a
  syscall's arguments are only meaningful at entry, which is what the
  profile format needs next.
- Re-injecting ptrace's own event stops, as above, while
  `TRACEEXEC` is set.

A third survived until the test for it existed: no workload here makes
a syscall numbered above 1024, so the out-of-range branch was
unreachable. It is reached now by building a second binary with
`-DNR_MAX=40`, which is the same move as planting a defect and
requiring the gate to see it.

## What does not work

Everything else. In the order it is planned:

- The exhaustive half interprets a filter this program built rather
  than one read back from the kernel. The kernel's own copy needs
  `CAP_SYS_ADMIN` to retrieve, so what ties the two together is the
  ten concrete probes and the argument above, not a direct read.
- Filtering on arguments. The policy is syscall numbers only, so
  `openat` is permitted or not, never permitted for one path.
- `SECCOMP_RET_ERRNO`. A denied call kills the process and there is
  no option to fail it instead, which is a different policy with
  different failure modes.
- **Child processes.** The recorder does not follow them, so a
  program that forks gets a profile covering the parent only. It
  refuses rather than writing a profile that would kill the program
  later: `PTRACE_O_TRACEFORK` is the fix and it is not done.
- Job control. A group-stop is resumed like any other
  signal-delivery-stop, so a program that stops itself with `SIGTSTP`
  is silently continued. `PTRACE_GETSIGINFO` and `PTRACE_LISTEN` are
  the correct handling.
- **The coverage problem, which no amount of code fixes.** A profile
  derived from one run covers the paths that run took. It is not a
  safe policy for paths that did not, and this will be the first
  sentence of this README when there is a profile to derive. Saying
  it now so it does not arrive as a footnote later.
- Landlock path policy, which is `jail`'s job, and syscall decoding,
  which is `trace`'s. This is the syscall-permission layer only.
- Architectures other than x86-64.

GPL-3.0-or-later.
