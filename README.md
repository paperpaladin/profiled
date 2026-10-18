# profiled

Watch a program run, derive the smallest seccomp-bpf policy that still
lets it run, install that policy, and prove both halves of the claim.

**One commit in. Only the rig exists.** There is no recorder, no
profile format and no `apply`. What is here is the thing everything
else will rest on: a seccomp filter, and a test that has watched the
kernel kill a process for using a syscall the filter denies.

```
$ make test
ok    waitstat reports an ordinary exit
ok    waitstat reports a signal, not 128 plus it
ok    getpid is 39 in the kernel header
ok    getuid is 102 in the kernel header
ok    a denied syscall is killed by the kernel, SIGSYS
ok    a permitted syscall returns, under the same filter
ok    the permitted syscall actually ran: returned 1000 errno 0

7 passed, 0 failed
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

## What does not work

Everything else. In the order it is planned:

- Recording a program's syscall set. Nothing observes a program yet.
- The profile file, `apply`, and `check`.
- **The coverage problem, which no amount of code fixes.** A profile
  derived from one run covers the paths that run took. It is not a
  safe policy for paths that did not, and this will be the first
  sentence of this README when there is a profile to derive. Saying
  it now so it does not arrive as a footnote later.
- Landlock path policy, which is `jail`'s job, and syscall decoding,
  which is `trace`'s. This is the syscall-permission layer only.
- Architectures other than x86-64.

GPL-3.0-or-later.
