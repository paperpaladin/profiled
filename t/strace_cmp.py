#!/usr/bin/env python3
"""Compare profiled's recorded syscall set against strace's, per workload.

A recorder checked against itself proves nothing, so this is the first
point where an outside observer can disagree. Both watch the same
program and must name the same syscalls.

It reads `strace -o`, the trace, and not `strace -c`, the summary. The
summary is the obvious choice and it is wrong here, for exactly the
syscall that matters most to a sandbox: `-c` counts calls that
returned, and `exit_group` never returns, so it is missing from every
summary strace prints. A profile derived from that view kills the
program at the moment it tries to exit cleanly.

Names are mapped to numbers through asm/unistd_64.h rather than a
table written here. The point of comparing against strace is to use a
source we do not control, and a hand-written name-to-number map would
put one back in the middle.
"""
import re
import subprocess
import sys

HEADERS = ("/usr/include/asm/unistd_64.h",
           "/usr/include/x86_64-linux-gnu/asm/unistd_64.h")


def numbers():
    for h in HEADERS:
        try:
            text = open(h).read()
        except OSError:
            continue
        out = {}
        for m in re.finditer(r"#define __NR_(\w+)\s+(\d+)", text):
            out[m.group(1)] = int(m.group(2))
        if out:
            return out
    sys.exit("SKIP: no asm/unistd_64.h, so names cannot be mapped to numbers")


def strace_set(cmd, num, tmp):
    r = subprocess.run(["strace", "-qq", "-f", "-o", tmp] + cmd,
                       capture_output=True)
    if r.returncode != 0 and not open(tmp).read():
        sys.exit("SKIP: strace could not run (%s)"
                 % r.stderr.decode()[:120].strip())
    names = set()
    for line in open(tmp):
        # "PID name(args)", "name(args)", and the two halves of a call
        # split by a signal: "<unfinished ...>" and "<... name resumed>".
        m = (re.match(r"^(?:\d+\s+)?(\w+)\(", line)
             or re.match(r"^(?:\d+\s+)?<\.\.\.\s+(\w+)\s+resumed", line))
        if m:
            names.add(m.group(1))
    unknown = sorted(n for n in names if n not in num)
    return {num[n] for n in names if n in num}, unknown


def main():
    if len(sys.argv) < 4:
        sys.exit("usage: strace_cmp.py PROFILED TMPFILE CMD [ARG...]")
    binary, tmp, cmd = sys.argv[1], sys.argv[2], sys.argv[3:]

    num = numbers()
    rev = {v: k for k, v in num.items()}

    theirs, unknown = strace_set(cmd, num, tmp)
    prof = tmp + ".prof"
    r = subprocess.run([binary, "record", "-o", prof, "--"] + cmd,
                       capture_output=True)
    if r.returncode != 0:
        print("  record failed: %s" % r.stderr.decode().strip()[:160])
        return 1
    # Skip the two header lines: the format is a magic line, an arch
    # line, then one number per line.
    ours = {int(x) for x in open(prof).read().split("\n")[2:] if x.strip()}

    # strace prints "syscall" for a number it has no name for, and the
    # header has no entry for that. Reported rather than dropped: it
    # means the two sides are looking at different kernels.
    if unknown:
        print("  strace named syscalls the header does not define: %s"
              % ", ".join(unknown))
        return 1

    only_them = sorted(theirs - ours)
    only_us = sorted(ours - theirs)
    if only_them or only_us:
        for n in only_them:
            print("  strace saw %d (%s) and we did not" % (n, rev.get(n, "?")))
        for n in only_us:
            print("  we saw %d (%s) and strace did not" % (n, rev.get(n, "?")))
        return 1

    print("  %d syscalls, both observers agree" % len(ours))
    return 0


sys.exit(main())
