"""Drive the issue 15 terminal prompter smoke program on a real pty.

Build and run from the repository root:

    go build -tags issue15 -o /tmp/prompter ./ad_hoc/issue-15/smoke/
    python3 ad_hoc/issue-15/smoke/pty_smoke.py /tmp/prompter

It answers a secret, a text, and a confirm prompt, declines a second secret
with Ctrl-C, and reports whether the terminal was raw while prompting,
whether the secret or text was echoed, and whether the mode was restored.
"""

import os, pty, sys, time, termios, select

binary = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.execv(binary, [binary])

before = termios.tcgetattr(fd)
out = b""

def read_until(marker, timeout=15):
    global out
    end = time.time() + timeout
    while marker not in out:
        r, _, _ = select.select([fd], [], [], max(0, end - time.time()))
        if not r:
            raise SystemExit(f"timeout waiting for {marker!r}; got {out!r}")
        out += os.read(fd, 4096)

def lflag():
    return termios.tcgetattr(fd)[3]

read_until(b"secret?")
time.sleep(0.2)
raw_during = not (lflag() & termios.ECHO) and not (lflag() & termios.ICANON)
os.write(fd, b"hunter 2\r")
read_until(b"RESULT kind=secret")
read_until(b"text?")
time.sleep(0.2)
os.write(fd, b"123456\r")
read_until(b"RESULT kind=text")
read_until(b"confirm?")
time.sleep(0.2)
os.write(fd, b"s\r")
read_until(b"RESULT kind=confirm")
read_until(b"secret?")
time.sleep(0.2)
os.write(fd, b"\x03")
read_until(b"DONE")
time.sleep(0.2)
after_lflag = before[3]
try:
    after_lflag = lflag()
except OSError:
    pass
os.waitpid(pid, 0)

text = out.decode(errors="replace")
print(text)
print("---")
print("raw while prompting:", raw_during)
print("secret echoed:", "hunter" in text.split("RESULT kind=secret")[0])
print("text echoed:", "123456" in text.split("RESULT kind=text")[0])
print("lflag restored:", after_lflag == before[3])
