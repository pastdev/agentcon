"""Smoke the startup Bitwarden prompt at an interactive `bouncer serve`.

Build and run from the repository root:

    go build -o /tmp/agentcon ./cmd/agentcon
    python3 ad_hoc/issue-15/smoke/serve_bitwarden.py /tmp/agentcon

A fake Bitwarden server accepts prelogin and rejects every password. The
script starts `agentcon bouncer serve` on a pty, types a wrong password at
the startup prompt, expects a retry prompt, declines it with Ctrl-C, then
stops serve with Ctrl-C and checks the terminal mode was restored.
"""

import http.server
import json
import os
import pty
import select
import signal
import socket
import sys
import tempfile
import termios
import threading
import time


class FakeBitwarden(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/identity/accounts/prelogin":
            self.reply(200, {"kdf": 0, "kdfIterations": 1000})
        elif self.path == "/identity/connect/token":
            self.reply(400, {"error": "invalid_grant", "error_description": "invalid_username_or_password"})
        else:
            self.reply(404, {})

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


binary = sys.argv[1]
server = http.server.HTTPServer(("127.0.0.1", 0), FakeBitwarden)
threading.Thread(target=server.serve_forever, daemon=True).start()
work = tempfile.mkdtemp(prefix="issue15-serve-")
config = os.path.join(work, "bouncer.yaml")
with open(config, "w") as f:
    f.write(f"""listen: 127.0.0.1:{free_port()}
ssh_listen: 127.0.0.1:{free_port()}
default_profile: p
prompts: {{notify: false}}
profiles:
  p: {{}}
credentials:
  bw:
    token:
      source: bitwarden
      email: user@example.com
      server: http://127.0.0.1:{server.server_address[1]}
      item: GitLab
      path: $.login.password
""")

pid, fd = pty.fork()
if pid == 0:
    os.execv(binary, [binary, "bouncer", "--file", config, "--state-dir", os.path.join(work, "state"), "serve"])

before = termios.tcgetattr(fd)
out = b""


def read_until(marker, timeout=30):
    global out
    end = time.time() + timeout
    while marker not in out:
        r, _, _ = select.select([fd], [], [], max(0, end - time.time()))
        if not r:
            raise SystemExit(f"timeout waiting for {marker!r}; got {out!r}")
        out += os.read(fd, 4096)


read_until(b"Bitwarden master password")
time.sleep(0.2)
os.write(fd, b"wrong password\r")
read_until(b"attempt 2 of 3")
time.sleep(0.2)
os.write(fd, b"\x03")
read_until(b"declined")
read_until(b"preparing credentials")
time.sleep(0.5)
restored = termios.tcgetattr(fd)[3] == before[3]
os.write(fd, b"\x03")
_, code = os.waitpid(pid, 0)

text = out.decode(errors="replace")
print(text)
print("---")
print("password echoed:", "wrong password" in text)
print("lflag restored after decline:", restored)
print("serve exit status:", os.waitstatus_to_exitcode(code))
