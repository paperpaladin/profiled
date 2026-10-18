# profiled

Watch a program run, derive the smallest seccomp-bpf policy that still
lets it run, install that policy, and prove both halves of the claim.

**Two commits in.** There is a seccomp filter the kernel has been seen
to enforce, and a recorder that watches a program run and writes down
the syscalls it made. There is no profile format, no `apply` and no
`check`.

```
$ make test
...
ok    a denied syscall is killed by the kernel, SIGSYS
ok    a permitted syscall returns, under the same filter
ok    a syscall outside the table is reported, not dropped
ok    a forking program is reported as incomplete, by name
ok    a program waiting on a child does not hang (exit 1)
ok    strace agrees on [/bin/true]: 17 syscalls, both observers agree
ok    strace agrees on [/bin/cat /etc/hostname]: 20 syscalls, both observers agree

17 passed, 0 failed
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

## Survivors, written down

Two mutations survive and both are genuinely equivalent rather than
untested:

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

- The profile file, `apply`, and `check`. `record` writes a sorted
  list of numbers and nothing reads it yet.
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
