// profiled -- derive a seccomp policy by watching a program run, then
// prove both halves of the claim: that the program still works under
// the policy, and that a syscall outside it is killed by the kernel.
//
// This file is the first commit and contains only what the rig needs:
// the filter builder, and a probe subcommand the suite drives to show
// that an installed filter actually bites. Everything here rests on
// "the kernel killed it", so that has to be demonstrated before
// anything is built on top of it.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
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

static void usage(void) {
  fputs("usage: profiled probe DENY_NR CALL_NR\n"
        "  installs a filter killing DENY_NR, then makes syscall CALL_NR.\n"
        "  Exits 0 if the call returned. The kernel decides the other case.\n",
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
  usage();
  return 2;
}
