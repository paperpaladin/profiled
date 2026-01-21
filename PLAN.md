# profiled

## Contract

Watch a program run, derive the smallest seccomp-bpf policy that still
lets it run, install that policy, and prove both halves of the claim.

```
$ profiled record -o prof.json -- ./server --once
$ profiled apply prof.json -- ./server --once      # runs, identically
$ profiled check prof.json -- ./server --once      # proves it is tight
```

Three subcommands and one file between them. The file is text, because
a policy nobody can read is a policy nobody will review.

## Hard invariant

**A syscall absent from the profile is killed by the kernel, and the
kernel is the one that says so.**

Not "our filter would reject it". The check subcommand makes the
process issue a syscall the profile omits and requires the process to
die of `SIGSYS`, read from `wait4` status. If the profile is not
actually enforced, that call returns normally and the check fails.

The mirror of it, equally load-bearing: under the profile the program
must produce byte-identical stdout, stderr and exit status to the same
program unconfined. A sandbox that breaks the workload is not a
tighter sandbox, it is a broken one.

## Oracle

Ranked by how little we control them.

1. **The kernel.** `seccomp(2)` decides whether a call is permitted.
   Nothing here adjudicates: the policy is installed and the process
   lives or dies. A `SIGSYS` in `wait4` status is the whole result.
2. **`strace`**, as an independent observer of the syscall set. Our
   recorder and strace watch the same run and must name the same
   syscalls. Two tracers disagreeing means one of them is wrong, and
   it is a different question from whether the policy works.
3. **The program itself.** Its stdout, stderr and exit status,
   unconfined and confined, compared byte for byte.
4. **`seccomp-tools` or `libseccomp`'s disassembler**, where present,
   to read back the installed filter. A loud skip when absent: it is
   one oracle among four here, not the only one.

## Non-goals

- Landlock path policy. `jail` does that and does it better than a
  first attempt here would. This is the syscall layer only, and the
  two compose at the command line rather than in one program.
- A general-purpose tracer. `trace` is that. The recorder here needs
  the syscall numbers and nothing else, so it is a few hundred lines
  of `PTRACE_SYSCALL` and not a decoder.
- Reporting what a running process can do. `confine` is that.
- Guessing. A profile covers the paths that were executed. It is not
  a safe policy for paths that were not, and the README says so
  before it says anything else.
- Architectures other than x86-64. Syscall numbers are per-ABI and a
  profile that silently means something different on another machine
  is worse than one that refuses to load.

## Commit sequence

- [x] 01 the rig, and a seccomp filter that is known to bite
      why: everything here rests on "the kernel killed it", so that
           has to be demonstrated before anything is built on top.
           The first commit installs a filter denying one syscall,
           calls it, and requires SIGSYS in wait4 status. A harness
           that cannot observe the kill cannot test any of the rest,
           and this is the collection's standing lesson: a gate
           nobody has seen fail may be checking nothing.
- [x] 02 record: the syscall set of one run, via PTRACE_SYSCALL
      why: the input to everything else. Numbers only, no decoding.
- [x] 03 the same run under strace, and the two sets compared
      why: a recorder checked against itself proves nothing. This is
           the first point where an outside observer can disagree.
      done: committed together with 02, because the comparison is what
           made 02 correct rather than what confirmed it. Three bugs,
           all found by strace and none visible in the code: the
           recorder wrote the profile to the stdout the program was
           using, dropping signals hung any tracee waiting on a child,
           and handing every signal back killed every tracee at exec.
           Also: strace -c is the wrong view, because it counts calls
           that returned and exit_group never does.
- [x] 04 the profile file: text, sorted, with the ABI named in it
      why: sorted so two recordings of the same workload produce the
           same bytes, and the ABI named so a profile cannot be
           loaded on a machine where the numbers mean something else.
- [x] 05 apply: install the filter, exec the program
      why: the first half of the claim. Compared against the
           unconfined run byte for byte, not just by exit status.
      done: and the byte-for-byte part earned itself immediately. The
           suite recorded with stdout inherited and applied with
           stdout to a file, and cat died under what looked like its
           own profile: it uses copy_file_range to a regular file and
           read/write to a pipe. A profile is a property of the
           program AND the environment it ran in. That is now a test
           which records one way, applies the other, and requires the
           kill.
           Also: the filter length was computed as 2 per syscall while
           the code emits 1, so every jump offset was wrong and the
           kernel said EINVAL without naming a cause. There is an
           assertion that the emitted count matches the computed one.
           Nine mutations across the reader and the filter, all
           caught.
- [ ] 06 check: prove the profile is tight
      why: the second half, and the one that is easy to fake. A
           syscall outside the profile has to be issued and the
           process has to die of SIGSYS. Without this, "minimal
           profile" is an adjective.
- [ ] 07 the recorder's own syscalls must not leak into the profile
      why: ptrace sees the tracee, but exec, mmap and the dynamic
           loader run before main and belong to the program. The
           boundary has to be decided and stated, because getting it
           wrong produces a profile that works only under ptrace.
- [ ] 08 a second workload with a different shape
      why: one program is one data point, and a profile derived from
           a short-lived process will not exercise the paths a
           long-lived one does.
- [ ] 09 what happens on a denied call: kill, or errno
      why: SECCOMP_RET_KILL_PROCESS and SECCOMP_RET_ERRNO are
           different policies with different failure modes, and
           picking one silently is the kind of choice that should be
           a flag with both tested.
- [ ] 10 mutation testing of the whole gate
      why: plant a syscall in the profile that the program never
           made and require the tightness check to notice; remove
           one it did make and require the sufficiency check to
           notice. Both directions, both seen failing.
- [ ] 11 README with the measured numbers and the coverage caveat
      why: last, so the numbers are the ones the suite prints, and
           the caveat is first in the document rather than last.
