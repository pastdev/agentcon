"""Smoke `agentcon bouncer answer` on a pty against a serve with no terminal.

Build and run from the repository root:

    go build -o /tmp/agentcon ./cmd/agentcon
    python3 ad_hoc/issue-15/smoke/answer_cli.py /tmp/agentcon

`bouncer serve` runs without a terminal, so its startup Bitwarden prompt can
only be answered through the control API. A fake Bitwarden server rejects
every password. The script answers the first prompt with a wrong password
through `agentcon bouncer answer` on a pty, declines the retry prompt with
Ctrl-C, and checks that the password was not echoed and that serve reports
the decline.
"""

import http.server
import json
import os
import pty
import select
import socket
import subprocess
import sys
import tempfile
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
work = tempfile.mkdtemp(prefix="issue15-answer-")
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
cli = [binary, "bouncer", "--file", config, "--state-dir", os.path.join(work, "state")]
serve_log = open(os.path.join(work, "serve.log"), "w+")
serve = subprocess.Popen(cli + ["serve"], stdin=subprocess.DEVNULL, stdout=serve_log, stderr=serve_log)


def pending(message):
    end = time.time() + 30
    while time.time() < end:
        out = subprocess.run(cli + ["prompts"], capture_output=True, text=True).stdout
        for line in out.splitlines()[1:]:
            if message in line:
                return line.split()[0]
        time.sleep(0.2)
    raise SystemExit(f"no pending prompt matching {message!r}")


def answer(prompt_id, keys):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(binary, cli + ["answer", prompt_id])
    out = b""
    end = time.time() + 30
    while b"decline" not in out:
        r, _, _ = select.select([fd], [], [], max(0, end - time.time()))
        if not r:
            raise SystemExit(f"no prompt shown; got {out!r}")
        out += os.read(fd, 4096)
    time.sleep(0.2)
    os.write(fd, keys)
    while True:
        r, _, _ = select.select([fd], [], [], 5)
        if not r:
            break
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    _, code = os.waitpid(pid, 0)
    return out.decode(errors="replace"), os.waitstatus_to_exitcode(code)


first = pending("Bitwarden master password")
text1, code1 = answer(first, b"wrong password\r")
retry = pending("attempt 2 of 3")
text2, code2 = answer(retry, b"\x03")
time.sleep(0.5)
serve.terminate()
serve.wait()
serve_log.seek(0)
log = serve_log.read()

print("--- answer 1 (exit %d)\n%s" % (code1, text1))
print("--- answer 2 (exit %d)\n%s" % (code2, text2))
print("--- serve log\n%s" % log)
print("---")
print("password echoed:", "wrong password" in text1)
print("ctrl-c declined:", "declined" in text2)
print("serve saw decline:", "prompt declined" in log)
