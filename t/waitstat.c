// Run a command and say how it ended, distinguishing a signal from an
// exit status.
//
// The shell cannot. $? is 128+n for a signal, which is the same number
// a program exiting 159 produces, and the whole claim here is "the
// kernel killed it" rather than "the program returned something odd".
// A test that cannot tell those apart is not testing the claim.
//
// Prints exactly one line: "signal N" or "exit N".
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
  // -q sends the child's stdout to /dev/null. Without it the child's
  // own output and this program's one-line verdict arrive on the same
  // stream and a caller reading $(...) gets both.
  int quiet = 0;
  if (argc > 1 && !strcmp(argv[1], "-q")) { quiet = 1; argc--; argv++; }
  if (argc < 2) { fputs("usage: waitstat [-q] CMD [ARG...]\n", stderr); return 2; }

  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return 2; }
  if (pid == 0) {
    // A probe that is supposed to die of SIGSYS dies several times per
    // run, and each one would drop a core file in whatever directory
    // the suite happens to be in.
    struct rlimit no_core = { 0, 0 };
    setrlimit(RLIMIT_CORE, &no_core);
    if (quiet) {
      int fd = open("/dev/null", O_WRONLY);
      if (fd >= 0) { dup2(fd, 1); close(fd); }
    }
    execvp(argv[1], argv + 1);
    perror(argv[1]);
    _exit(127);
  }

  int st;
  if (waitpid(pid, &st, 0) < 0) { perror("waitpid"); return 2; }
  if (WIFSIGNALED(st)) printf("signal %d\n", WTERMSIG(st));
  else if (WIFEXITED(st)) printf("exit %d\n", WEXITSTATUS(st));
  else { puts("neither"); return 2; }
  return 0;
}
