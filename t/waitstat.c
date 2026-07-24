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
  // -q sends the child's stdout to /dev/null; -o FILE sends it to a
  // file. Both exist so the child's output and this program's verdict
  // do not share a stream. -o rather than an outer shell redirect
  // because an outer one captures the verdict too: the case that
  // needed cat writing to a REGULAR file reported an empty verdict
  // for as long as it existed, and an empty verdict took the "this no
  // longer reproduces" branch, so it printed SKIP every run and
  // nobody read it.
  int quiet = 0;
  const char *outfile = NULL;
  while (argc > 1 && argv[1][0] == '-') {
    if (!strcmp(argv[1], "-q")) { quiet = 1; argc--; argv++; }
    else if (!strcmp(argv[1], "-o") && argc > 2) {
      outfile = argv[2]; argc -= 2; argv += 2;
    } else break;
  }
  if (argc < 2) {
    fputs("usage: waitstat [-q] [-o FILE] CMD [ARG...]\n", stderr);
    return 2;
  }

  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return 2; }
  if (pid == 0) {
    // A probe that is supposed to die of SIGSYS dies several times per
    // run, and each one would drop a core file in whatever directory
    // the suite happens to be in.
    struct rlimit no_core = { 0, 0 };
    setrlimit(RLIMIT_CORE, &no_core);
    if (quiet || outfile) {
      int fd = outfile ? open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600)
                       : open("/dev/null", O_WRONLY);
      if (fd < 0) { perror(outfile ? outfile : "/dev/null"); _exit(127); }
      dup2(fd, 1);
      close(fd);
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
