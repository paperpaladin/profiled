// profiled -- derive a seccomp policy by watching a program run, then
// prove both halves of the claim: that the program still works under
// the policy, and that a syscall outside it is killed by the kernel.
//
// So far: the filter builder and the probe subcommand the suite drives
// to show that an installed filter actually bites, `record`, the
// profile file, `apply`, and `check`.
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
#include <sys/resource.h>
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

// x86-64 is at 460-odd syscalls and the table only grows, so 1024 has
// room without being a guess that quietly truncates: a number outside
// it is reported rather than dropped. A profile missing one syscall is
// a profile that kills the program.
#ifndef NR_MAX
#define NR_MAX 1024
#endif
static unsigned char seen[NR_MAX];

// ------------------------------------------------------- the profile

// Version 1. Text, one syscall number per line, sorted, with the ABI
// named at the top.
//
// The ABI line is not decoration. A syscall number is an index into
// one ABI's table, so the same file means something different on
// another machine, and the difference is a policy that permits the
// wrong calls rather than a file that fails to parse. It is checked on
// load and the load fails if it does not match.
#define PROFILE_MAGIC "profiled 1"

static int write_profile(const char *path, const unsigned char *set) {
  FILE *f = fopen(path, "w");
  if (!f) { fprintf(stderr, "profiled: %s: %s\n", path, strerror(errno)); return 2; }
  fprintf(f, "%s\n", PROFILE_MAGIC);
  fprintf(f, "arch 0x%x\n", (unsigned)AUDIT_ARCH_X86_64);
  for (int i = 0; i < NR_MAX; i++)
    if (set[i]) fprintf(f, "%d\n", i);
  if (fclose(f) != 0) {
    fprintf(stderr, "profiled: %s: %s\n", path, strerror(errno));
    return 2;
  }
  return 0;
}

// Fills `set` and returns the count, or -1 with a message.
//
// Every line is either understood or refused. A profile reader that
// skips what it does not recognise turns a typo into a policy that
// permits less than the file says, and the program dies somewhere else
// entirely with no hint that the file was the problem.
static int read_profile(const char *path, unsigned char *set) {
  FILE *f = fopen(path, "r");
  if (!f) { fprintf(stderr, "profiled: %s: %s\n", path, strerror(errno)); return -1; }

  char line[256];
  int lineno = 0, n = 0, have_magic = 0, have_arch = 0, last = -1;
  while (fgets(line, sizeof line, f)) {
    lineno++;
    size_t len = strlen(line);
    if (len && line[len - 1] == '\n') line[--len] = 0;
    else if (!feof(f)) {
      fprintf(stderr, "profiled: %s:%d: line is longer than %zu bytes\n",
              path, lineno, sizeof line - 1);
      fclose(f); return -1;
    }
    if (!len) continue;

    if (lineno == 1) {
      if (strcmp(line, PROFILE_MAGIC)) {
        fprintf(stderr, "profiled: %s: not a version 1 profile "
                "(first line is \"%s\")\n", path, line);
        fclose(f); return -1;
      }
      have_magic = 1;
      continue;
    }
    if (!strncmp(line, "arch ", 5)) {
      unsigned long a = strtoul(line + 5, NULL, 0);
      if (a != (unsigned long)AUDIT_ARCH_X86_64) {
        fprintf(stderr, "profiled: %s: profile is for arch 0x%lx, this is "
                "0x%x. Syscall numbers mean different things on the two.\n",
                path, a, (unsigned)AUDIT_ARCH_X86_64);
        fclose(f); return -1;
      }
      have_arch = 1;
      continue;
    }

    char *end;
    long v = strtol(line, &end, 10);
    if (*end || end == line || v < 0 || v >= NR_MAX) {
      fprintf(stderr, "profiled: %s:%d: cannot read \"%s\" as a syscall "
              "number\n", path, lineno, line);
      fclose(f); return -1;
    }
    // Sorted and distinct, enforced rather than assumed. An unsorted
    // or duplicated file still builds a working filter, so this is
    // about the file being canonical: two recordings of the same
    // workload have to produce the same bytes.
    if ((int)v <= last) {
      fprintf(stderr, "profiled: %s:%d: %ld is out of order or repeated\n",
              path, lineno, v);
      fclose(f); return -1;
    }
    last = (int)v;
    set[v] = 1;
    n++;
  }
  fclose(f);

  if (!have_magic) {
    fprintf(stderr, "profiled: %s: empty, so it is not a profile\n", path);
    return -1;
  }
  if (!have_arch) {
    fprintf(stderr, "profiled: %s: no arch line, so the syscall numbers "
            "cannot be trusted\n", path);
    return -1;
  }
  if (!n) {
    fprintf(stderr, "profiled: %s: permits no syscalls at all, which would "
            "kill the program at its first instruction\n", path);
    return -1;
  }
  return n;
}

// ---------------------------------------------------------------- record


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
  // Never stdout. The traced program inherits this process's streams,
  // so a profile written to stdout is interleaved with whatever the
  // program printed: recording /bin/echo produced a profile with "hi"
  // in it. The file is the only output.
  return write_profile(outpath, seen);
}

// ---------------------------------------------------------------- apply

// Allow the listed syscalls, kill on anything else. The architecture
// check is the same one the probe filter uses and for the same reason.
static int install_allow(const unsigned char *set, int n) {
  // Four for the preamble (load arch, compare, kill, load nr), one
  // comparison per permitted syscall, then kill and allow. The first
  // version of this said "2 per syscall", counting a load that happens
  // once, so every jump offset was computed against a length that was
  // too large and the kernel returned EINVAL. The assertion below is
  // why that is a one-time mistake.
  int len = 4 + n + 2;
  struct sock_filter *prog = calloc((size_t)len, sizeof *prog);
  if (!prog) { fputs("profiled: out of memory\n", stderr); return -1; }

  int k = 0;
  struct sock_filter ld_arch =
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               (unsigned)offsetof(struct seccomp_data, arch));
  struct sock_filter jeq_arch =
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
  struct sock_filter kill =
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  struct sock_filter ld_nr =
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               (unsigned)offsetof(struct seccomp_data, nr));
  struct sock_filter allow = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  prog[k++] = ld_arch;
  prog[k++] = jeq_arch;
  prog[k++] = kill;
  prog[k++] = ld_nr;
  for (int i = 0; i < NR_MAX; i++) {
    if (!set[i]) continue;
    // Jump over the remaining comparisons straight to the allow, which
    // is the last instruction. Computed from where we are rather than
    // counted up front, so adding an instruction above cannot silently
    // make every jump land one short.
    int here = k;
    int to_allow = (len - 1) - (here + 1);
    struct sock_filter j =
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)i, (unsigned char)to_allow, 0);
    if (to_allow > 255) {
      fputs("profiled: too many syscalls for a flat filter\n", stderr);
      free(prog);
      return -1;
    }
    prog[k++] = j;
  }
  prog[k++] = kill;
  prog[k++] = allow;

  // The jump offsets above are computed from `len`, so a `len` that
  // does not match what was emitted sends every jump somewhere wrong.
  // The kernel says EINVAL, which does not name the cause.
  if (k != len) {
    fprintf(stderr, "profiled: filter is %d instructions, expected %d\n", k, len);
    free(prog);
    return -1;
  }

  struct sock_fprog fprog = { .len = (unsigned short)k, .filter = prog };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    fprintf(stderr, "profiled: PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
    free(prog);
    return -1;
  }
  if (sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, &fprog) < 0) {
    fprintf(stderr, "profiled: seccomp: %s\n", strerror(errno));
    free(prog);
    return -1;
  }
  free(prog);
  return 0;
}

static int apply(const char *path, char **argv) {
  static unsigned char set[NR_MAX];
  int n = read_profile(path, set);
  if (n < 0) return 2;
  if (install_allow(set, n) < 0) return 2;
  execvp(argv[0], argv);
  fprintf(stderr, "profiled: %s: %s\n", argv[0], strerror(errno));
  return 127;
}

// ---------------------------------------------------------------- check

// Syscalls safe to issue in a process whose filter might be broken.
//
// That caveat is the whole reason this list exists rather than a loop
// over all 1024 numbers. The point of the check is to confirm a
// denied call is killed before it runs; if the filter is wrong, the
// call runs. Issuing an arbitrary syscall under those conditions is
// precisely the thing not to do, so every probe here is pure: it
// reads a number the kernel already knows and changes nothing, with
// no arguments to get wrong.
static const struct { int nr; const char *name; } PROBES[] = {
  {  24, "sched_yield" },
  {  39, "getpid"      },
  {  96, "gettimeofday"},
  { 102, "getuid"      },
  { 104, "getgid"      },
  { 107, "geteuid"     },
  { 108, "getegid"     },
  { 110, "getppid"     },
  { 186, "gettid"      },
  { 201, "time"        },
};
#define PROBES_N ((int)(sizeof PROBES / sizeof *PROBES))

// Runs one probe in a child under the filter. Returns 1 if the kernel
// killed it with SIGSYS, 0 if the call returned, -1 if something else
// happened and the result cannot be read.
static int probe_under(const unsigned char *set, int n, int nr) {
  fflush(NULL);
  pid_t pid = fork();
  if (pid < 0) { perror("profiled: fork"); return -1; }
  if (pid == 0) {
    struct rlimit no_core = { 0, 0 };
    setrlimit(RLIMIT_CORE, &no_core);
    if (install_allow(set, n) < 0) _exit(2);
    syscall(nr);
    _exit(0);
  }
  int st;
  if (waitpid(pid, &st, 0) < 0) { perror("profiled: waitpid"); return -1; }
  if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS) return 1;
  if (WIFEXITED(st) && WEXITSTATUS(st) == 0) return 0;
  return -1;
}

static int check(const char *path) {
  static unsigned char set[NR_MAX];
  int n = read_profile(path, set);
  if (n < 0) return 2;

  int denied = 0, permitted = 0, bad = 0;
  for (int i = 0; i < PROBES_N; i++) {
    int nr = PROBES[i].nr;
    int want_kill = !set[nr];
    int got = probe_under(set, n, nr);
    if (got < 0) {
      printf("  %-13s could not be read\n", PROBES[i].name);
      bad++;
    } else if (got != want_kill) {
      printf("  %-13s %s, and the profile says it should %s\n",
             PROBES[i].name,
             got ? "was killed" : "returned",
             want_kill ? "be denied" : "be permitted");
      bad++;
    } else if (want_kill) {
      denied++;
    } else {
      permitted++;
    }
  }

  // A check that happened to probe only permitted syscalls would
  // report success having tested nothing about denial, which is the
  // half of the claim that matters. It refuses instead.
  if (!denied && !bad) {
    fprintf(stderr, "profiled: every probe is permitted by this profile, so "
            "nothing about denial was tested\n");
    return 2;
  }
  printf("check: %d denied as expected, %d permitted as expected, %d wrong\n",
         denied, permitted, bad);
  return bad ? 1 : 0;
}

static void usage(void) {
  fputs("usage: profiled probe DENY_NR CALL_NR\n"
        "  installs a filter killing DENY_NR, then makes syscall CALL_NR.\n"
        "  Exits 0 if the call returned. The kernel decides the other case.\n"
        "usage: profiled record -o FILE -- CMD [ARG...]\n"
        "  writes the syscall numbers CMD made to FILE, one per line,\n"
        "  sorted. Never to stdout: the traced program has that one.\n"
        "usage: profiled apply FILE -- CMD [ARG...]\n"
        "  installs FILE as a seccomp policy, then runs CMD under it.\n"
        "usage: profiled check FILE\n"
        "  issues syscalls FILE omits and requires the kernel to kill.\n",
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
  if (argc >= 4 && !strcmp(argv[1], "apply")) {
    int i = 3;
    if (!strcmp(argv[i], "--")) i++;
    if (i >= argc) { usage(); return 2; }
    return apply(argv[2], argv + i);
  }
  if (argc == 3 && !strcmp(argv[1], "check")) return check(argv[2]);
  usage();
  return 2;
}
