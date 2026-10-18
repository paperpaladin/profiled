// profiled -- derive a seccomp policy by watching a program run, then
// prove both halves of the claim: that the program still works under
// the policy, and that a syscall outside it is killed by the kernel.
//
// So far: the filter builder and the probe subcommand the suite drives
// to show that an installed filter actually bites, and `record`, which
// is the input to everything else.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

// glibc has no wrapper for seccomp(2) on every version we might meet,
// and the raw call is three arguments. Going through syscall() also
// keeps the one place that installs a filter visible in a grep.
static int sys_seccomp(unsigned op, unsigned flags, void *args) {
  return (int)syscall(__NR_seccomp, op, flags, args);
}

// A filter that kills the process on one named syscall and allows
// everything else. Inverted from what the finished program will
// install, deliberately: it is the smallest filter whose effect is
// unambiguous, so a test using it cannot pass by accident.
//
// The architecture check is not optional. seccomp_data.nr is an index
// into the ABI's table, so a filter that does not pin the ABI can be
// bypassed on a kernel that offers more than one: the x32 ABI reaches
// the same kernel with different numbers. Kill on a mismatch rather
// than allow.
static int install_deny_one(int nr) {
  struct sock_filter prog[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (unsigned)offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (unsigned)offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog fprog = {
    .len = (unsigned short)(sizeof prog / sizeof *prog),
    .filter = prog,
  };

  // Without no_new_privs an unprivileged process cannot install a
  // filter at all, and the error is EACCES from seccomp() rather than
  // from here, which reads like a permissions problem with the binary.
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    fprintf(stderr, "profiled: PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
    return -1;
  }
  if (sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, &fprog) < 0) {
    fprintf(stderr, "profiled: seccomp: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}

// ---------------------------------------------------------------- record

// x86-64 is at 460-odd syscalls and the table only grows, so 1024 has
// room without being a guess that quietly truncates: a number outside
// it is reported rather than dropped. A profile missing one syscall is
// a profile that kills the program.
#ifndef NR_MAX
#define NR_MAX 1024
#endif
static unsigned char seen[NR_MAX];

// Syscalls that make another process. ptrace follows only what it is
// told to follow, and without PTRACE_O_TRACEFORK a child runs
// unobserved: its syscalls are missing from the profile and the
// program dies under `apply` for reasons the recording never showed.
// Not implemented yet, so it is detected and said out loud rather than
// left to be discovered later.
static int is_spawn(long nr) {
  return nr == SYS_clone || nr == SYS_fork || nr == SYS_vfork
#ifdef SYS_clone3
         || nr == SYS_clone3
#endif
      ;
}

static int record(const char *outpath, char **argv) {
  pid_t pid = fork();
  if (pid < 0) { perror("profiled: fork"); return 2; }

  if (pid == 0) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("profiled: traceme"); _exit(127); }
    // Stop here so the parent can set its options before the first
    // syscall of execvp. Without this the exec itself races the
    // parent's PTRACE_SETOPTIONS and its syscalls can be missed.
    raise(SIGSTOP);
    execvp(argv[0], argv);
    perror(argv[0]);
    _exit(127);
  }

  int st;
  if (waitpid(pid, &st, 0) < 0) { perror("profiled: waitpid"); return 2; }
  // EXITKILL so a crash here does not leave the tracee stopped forever.
  if (ptrace(PTRACE_SETOPTIONS, pid, 0,
             (void *)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                      PTRACE_O_TRACEEXEC)) < 0) {
    perror("profiled: setoptions");
    return 2;
  }

  int in_call = 0;          // syscall stops arrive in entry/exit pairs
  int spawned = 0;
  long out_of_range = -1;

  // A signal the tracer did not cause has to be handed back, and the
  // first version of this loop dropped every one of them. Tracing
  // `timeout 5 true` hung forever: timeout forks, the child exits,
  // SIGCHLD stops the tracee, the loop saw a stop that was not a
  // syscall stop and resumed with signal 0. The signal was swallowed,
  // timeout waited for a SIGCHLD that never arrived, and its child
  // stayed a zombie. Nothing printed, nothing crashed.
  //
  // shortcut: group-stop is resumed like any other signal-delivery-
  // stop, which is not quite right. A correct tracer distinguishes
  // them with PTRACE_GETSIGINFO and uses PTRACE_LISTEN, so a program
  // that stops itself with SIGTSTP is not silently continued here.
  // Upgrade when a workload needs job control.
  int sig = 0;
  for (;;) {
    if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)(long)sig) < 0) break;
    sig = 0;
    if (waitpid(pid, &st, 0) < 0) break;
    if (WIFEXITED(st) || WIFSIGNALED(st)) break;

    // TRACESYSGOOD makes a syscall stop SIGTRAP|0x80, which is how it
    // is told apart from a SIGTRAP the program raised itself.
    if (!(WIFSTOPPED(st) && WSTOPSIG(st) == (SIGTRAP | 0x80))) {
      // Only a signal the program would have received anyway goes
      // back. ptrace's own stops arrive as SIGTRAP with an event code
      // in the high bits, and handing one of those to the tracee
      // kills it: the first version of this re-injected the SIGTRAP
      // that follows execve and every traced program died before
      // reaching main, having recorded four syscalls and printed
      // nothing. TRACEEXEC is set so that stop carries an event code
      // and can be told apart from a SIGTRAP the program raised.
      int event = st >> 16;
      if (WIFSTOPPED(st) && event == 0) sig = WSTOPSIG(st);
      continue;
    }

    // Entry only. For a set of numbers this is not observable, since
    // orig_rax holds the same value at both stops and the second write
    // lands on the same bit: a mutation that records both halves
    // survives, and that is recorded in the README rather than hidden.
    // It is kept because a syscall's arguments are only meaningful at
    // entry, and reading them is what the profile format needs next.
    in_call = !in_call;
    if (!in_call) continue;                       // the exit half

    errno = 0;
    long nr = ptrace(PTRACE_PEEKUSER, pid,
                     (void *)offsetof(struct user_regs_struct, orig_rax), 0);
    if (nr == -1 && errno) { perror("profiled: peekuser"); return 2; }
    if (nr < 0 || nr >= NR_MAX) { out_of_range = nr; continue; }
    seen[nr] = 1;
    if (is_spawn(nr)) spawned = 1;
  }

  if (out_of_range >= 0) {
    fprintf(stderr, "profiled: syscall %ld is outside the recorded range, "
            "so this profile is incomplete\n", out_of_range);
    return 1;
  }
  if (spawned) {
    fprintf(stderr, "profiled: the program created another process, which "
            "this recorder does not follow, so this profile is incomplete\n");
    return 1;
  }

  // Never stdout. The traced program inherits this process's streams,
  // so a profile written to stdout is interleaved with whatever the
  // program printed: recording /bin/echo produced a profile with "hi"
  // in it. The file is the only output.
  FILE *f = fopen(outpath, "w");
  if (!f) { fprintf(stderr, "profiled: %s: %s\n", outpath, strerror(errno)); return 2; }
  for (int i = 0; i < NR_MAX; i++)
    if (seen[i]) fprintf(f, "%d\n", i);
  if (fclose(f) != 0) {
    fprintf(stderr, "profiled: %s: %s\n", outpath, strerror(errno));
    return 2;
  }
  return 0;
}

static void usage(void) {
  fputs("usage: profiled probe DENY_NR CALL_NR\n"
        "  installs a filter killing DENY_NR, then makes syscall CALL_NR.\n"
        "  Exits 0 if the call returned. The kernel decides the other case.\n"
        "usage: profiled record -o FILE -- CMD [ARG...]\n"
        "  writes the syscall numbers CMD made to FILE, one per line,\n"
        "  sorted. Never to stdout: the traced program has that one.\n",
        stderr);
}

int main(int argc, char **argv) {
  if (argc == 4 && !strcmp(argv[1], "probe")) {
    int deny = atoi(argv[2]);
    int call = atoi(argv[3]);
    if (install_deny_one(deny) < 0) return 2;

    // Flush before the call. If the kernel kills the process here,
    // anything still sitting in stdio's buffer is lost, and a test
    // reading output to decide what happened would see the same empty
    // stream for "killed" and for "wrote nothing".
    fflush(NULL);
    long r = syscall(call);
    printf("returned %ld errno %d\n", r, r < 0 ? errno : 0);
    fflush(NULL);
    return 0;
  }
  if (argc >= 5 && !strcmp(argv[1], "record") && !strcmp(argv[2], "-o")) {
    int i = 4;
    if (!strcmp(argv[i - 1], "--")) { usage(); return 2; }
    if (!strcmp(argv[i], "--")) i++;
    if (i >= argc) { usage(); return 2; }
    return record(argv[3], argv + i);
  }
  usage();
  return 2;
}
