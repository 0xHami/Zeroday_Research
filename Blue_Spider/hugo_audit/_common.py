"""
Shared helpers for the Hugo v0.167.0-DEV (commit c7f9999) stage-10 exploits.

Hugo is a static-site generator: its exploitable surface is (A) the `hugo server`
dev server running live at http://localhost:37230/ and (B) the *build pipeline*
(Markdown/templates/shortcodes/resource transforms/data funcs), which is exercised
by feeding a throwaway site to the `hugo` binary.

This module provides:
  * log()/banner()      — colored-for-tty, plain-for-file status output (CLAUDE.md rule)
  * run_hugo()          — build a throwaway site in the target's own container image,
                          isolated from the live dev server (its own temp dir, its own
                          --network / --memory). Returns (rc, combined_output, public_dir).
  * OOBListener         — a host HTTP listener that records the requests it receives,
                          reachable from a `--network host` build container as
                          http://127.0.0.1:<port>/ (used to prove SSRF / header-forward /
                          unbounded-body / cache-collision findings).

Every exploit imports this; nothing here targets anything but localhost / the local
target container image.
"""
import http.server
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading

# ── Target facts (from claude_audit/hugo/hugo_summary.md) ────────────────────
IMAGE = os.environ.get("HUGO_IMAGE", "cvehunterlab_hugo_app:latest")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:37230")
# The lab's host user == the container's hugo user (uid 999 / gid 986), so a
# bind-mounted site is writable by the build with no permission juggling.
UID = os.environ.get("HUGO_UID", "999")
GID = os.environ.get("HUGO_GID", "986")

# ── Colored, report-grade output (gated on tty + NO_COLOR) ───────────────────
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}


def log(tag: str, msg: str) -> None:
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}", flush=True)
    else:
        print(f"[{tag}] {msg}", flush=True)


def banner(vuln_id: str, title: str, info: str = "", target: str = BASE_URL) -> None:
    line = "=" * 78
    print(line, flush=True)
    print(f"{vuln_id}: {title}", flush=True)
    print(f"target: {target}", flush=True)
    if info:
        log("INFO", info)
    print(line, flush=True)


def rand(prefix: str = "") -> str:
    """Random suffix so re-runs never collide with orphaned state."""
    s = secrets.token_hex(4)
    return f"{prefix}{s}" if prefix else s


# ── Throwaway build harness ──────────────────────────────────────────────────
def _site_dir(automation_file: str, name: str = "buildsite") -> str:
    """Fresh site dir next to the exploit's automation.py (inspectable evidence)."""
    d = os.path.join(os.path.dirname(os.path.abspath(automation_file)), name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    os.makedirs(d)
    return d


def write_site(root: str, files: dict) -> None:
    """files: {relative/path: text-or-bytes}. Creates parent dirs."""
    for rel, content in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        mode = "wb" if isinstance(content, (bytes, bytearray)) else "w"
        with open(p, mode) as fh:
            fh.write(content)


def make_site(automation_file: str, files: dict, name: str = "buildsite") -> str:
    """Create a fresh throwaway site dir with `files` and return its path."""
    root = _site_dir(automation_file, name)
    write_site(root, files)
    return root


def run_hugo(site_dir: str, args=None, network: str = "none", memory: str = "2g",
             timeout: int = 120, render_to_memory: bool = True, cpus: str | None = None,
             extra_docker=None, image: str | None = None):
    """
    Run a one-off `hugo` build against `site_dir` in the target's own image,
    fully isolated from the live dev server.

    Returns (returncode, combined_output_str, public_dir_or_None).
      * returncode 124  -> timed out (we killed the container)
      * returncode 137  -> OOM / SIGKILL (memory cap hit) — the DoS proof for the bomb findings
    """
    args = args or []
    extra_docker = extra_docker or []
    name = "hugobuild_" + rand()
    cmd = [
        "docker", "run", "--rm", "--name", name,
        "--user", f"{UID}:{GID}",
        "-e", "HOME=/tmp", "-e", "HUGO_CACHEDIR=/tmp/hugocache",
        "-v", f"{site_dir}:/site", "-w", "/site",
        f"--memory={memory}", f"--network={network}",
    ]
    if cpus:
        cmd.append(f"--cpus={cpus}")
    cmd += extra_docker
    cmd += [image or IMAGE, "--source=/site"]
    if render_to_memory:
        cmd.append("--renderToMemory")
    cmd += list(args)

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        rc, out = p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        out = ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")) \
            + ((e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""))
        rc = 124
    public = os.path.join(site_dir, "public")
    return rc, out, (public if (not render_to_memory and os.path.isdir(public)) else None)


def docker_run(image: str, args, network: str = "none", memory: str = "2g",
               timeout: int = 120, user=None, mounts=None, workdir=None,
               entrypoint=None, env=None):
    """Generic one-off container (used for external-tool images: pandoc/asciidoctor/…)."""
    name = "hugost10_" + rand()
    cmd = ["docker", "run", "--rm", "--name", name, f"--memory={memory}", f"--network={network}"]
    if user:
        cmd += ["--user", user]
    for m in (mounts or []):
        cmd += ["-v", m]
    if workdir:
        cmd += ["-w", workdir]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    if entrypoint is not None:
        cmd += ["--entrypoint", entrypoint]
    cmd += [image] + list(args)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return 124, "[timed out]"


# ── Out-of-band HTTP listener (host side; reachable via --network host) ───────
class OOBListener:
    """
    Minimal HTTP server on the host that records every request it receives
    (path, method, headers, and body length actually read). A build container
    started with `--network host` reaches it at http://127.0.0.1:<port>/.

    Optional behaviours:
      * redirect_to: 302 every request to this Location (open-redirect emulation)
      * body_bytes:  stream this many bytes as the response body (unbounded-body DoS)
      * payload:     fixed response body (bytes)
    """
    def __init__(self, redirect_to=None, body_bytes=None, payload=b"OOB-CANARY\n",
                 content_type="text/plain", host="127.0.0.1", port=0):
        self.records = []
        self.redirect_to = redirect_to
        self.body_bytes = body_bytes
        self.payload = payload
        self.content_type = content_type
        self._host = host
        rec = self.records
        red = self  # closure

        class H(http.server.BaseHTTPRequestHandler):
            def _handle(self):
                clen = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(clen) if clen else b""
                rec.append({
                    "path": self.path, "method": self.command,
                    "headers": {k: v for k, v in self.headers.items()},
                    "body_len": len(body),
                })
                if red.redirect_to is not None:
                    self.send_response(302)
                    self.send_header("Location", red.redirect_to)
                    self.end_headers()
                    return
                if red.body_bytes is not None:
                    self.send_response(200)
                    self.send_header("Content-Type", red.content_type)
                    self.send_header("Content-Length", str(red.body_bytes))
                    self.end_headers()
                    chunk = b"A" * 65536
                    sent = 0
                    try:
                        while sent < red.body_bytes:
                            n = min(len(chunk), red.body_bytes - sent)
                            self.wfile.write(chunk[:n])
                            sent += n
                    except Exception:
                        pass
                    return
                self.send_response(200)
                self.send_header("Content-Type", red.content_type)
                self.send_header("Content-Length", str(len(red.payload)))
                self.end_headers()
                self.wfile.write(red.payload)

            do_GET = _handle
            do_POST = _handle
            do_HEAD = _handle

            def log_message(self, *a):
                pass

        self._server = http.server.ThreadingHTTPServer((host, port), H)
        self.port = self._server.server_address[1]

    def __enter__(self):
        self._t = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *a):
        self._server.shutdown()

    @property
    def url(self):
        return f"http://{self._host}:{self.port}"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ── Dedicated `hugo server` under test (isolated from the live lab) ───────────
import subprocess as _sp  # noqa: E402
import time as _time      # noqa: E402
import urllib.request as _u  # noqa: E402


class HugoServer:
    """
    Start a throwaway `hugo server` in the target's own image on a free host port,
    bound to 127.0.0.1, serving `site_dir`. Fully separate from the live lab
    (its own container, port and site). Yields self; `.base_url` is the URL.
    """
    def __init__(self, site_dir: str, extra_args=None, memory: str = "1g",
                 ready_timeout: int = 30, env=None, publish=None, render_to_memory=True):
        self.site_dir = site_dir
        self.extra_args = extra_args or []
        self.memory = memory
        self.ready_timeout = ready_timeout
        self.env = env or {}
        self.publish = publish or []   # extra "-p host:cont" mappings (e.g. pprof 8080)
        self.render_to_memory = render_to_memory
        self.port = free_port()
        self.name = "cvehunterlab_hugo_st10srv_" + rand()
        self.base_url = f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        env_flags = []
        for k, v in self.env.items():
            env_flags += ["-e", f"{k}={v}"]
        pub_flags = []
        for p in self.publish:
            pub_flags += ["-p", p]
        cmd = [
            "docker", "run", "-d", "--rm", "--name", self.name,
            "--user", f"{UID}:{GID}",
            "-e", "HOME=/tmp", "-e", "HUGO_CACHEDIR=/tmp/hugocache",
        ] + env_flags + [
            "-v", f"{self.site_dir}:/project", "-w", "/project",
            "-p", f"127.0.0.1:{self.port}:{self.port}",
        ] + pub_flags + [
            f"--memory={self.memory}", "--network=bridge",
            IMAGE, "server", "--source=/project", "--bind=0.0.0.0",
            f"--port={self.port}", f"--baseURL=http://localhost:{self.port}/",
            "--appendPort=false", "--poll=1s",
        ] + (["--renderToMemory"] if self.render_to_memory else []) + list(self.extra_args)
        r = _sp.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"failed to start hugo server: {r.stderr or r.stdout}")
        self.cid = r.stdout.strip()
        deadline = _time.time() + self.ready_timeout
        last = ""
        while _time.time() < deadline:
            try:
                with _u.urlopen(self.base_url + "/", timeout=3) as resp:
                    if resp.status in (200, 301, 302, 307, 404):
                        return self
            except Exception as e:  # noqa
                last = str(e)
            _time.sleep(0.5)
        logs = _sp.run(["docker", "logs", self.name], capture_output=True, text=True)
        self.__exit__(None, None, None)
        raise RuntimeError(f"hugo server not ready in {self.ready_timeout}s ({last})\n{logs.stderr[-800:]}")

    def logs(self) -> str:
        return _sp.run(["docker", "logs", self.name], capture_output=True, text=True).stdout \
            + _sp.run(["docker", "logs", self.name], capture_output=True, text=True).stderr

    def __exit__(self, *a):
        _sp.run(["docker", "rm", "-f", self.name], capture_output=True)


def raw_http(host: str, port: int, raw: bytes, timeout: float = 5.0) -> bytes:
    """Send a raw HTTP request over a socket (no client-side path normalization)."""
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(raw)
        s.settimeout(timeout)
        chunks = []
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
            if len(b"".join(chunks)) > 2_000_000:
                break
        return b"".join(chunks)
    finally:
        s.close()
