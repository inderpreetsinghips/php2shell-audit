#!/usr/bin/env python3
"""
mock_vuln_target.py — fake PHP targets for validating php2shell_audit
===================================================================

This is a TEST FIXTURE, not a vulnerable application. It is a plain Python
HTTP server that *advertises* a chosen PHP version in its `Server` /
`X-Powered-By` headers (and, optionally, a fake phpinfo page). It runs no PHP,
contains no vulnerability, and cannot be exploited — its only job is to give
the scanner something to fingerprint so you can confirm detection works.

Use it to exercise `host` and `fleet` modes end to end.

Examples
--------
# One vulnerable target on :8801
python3 testlab/mock_vuln_target.py --port 8801 --php-version 8.3.12 --sapi apache

# A target that also serves a fake phpinfo page at /info.php
python3 testlab/mock_vuln_target.py --port 8801 --php-version 8.3.12 --phpinfo

# A hidden-version target (no PHP header) — scanner should say "not disclosed"
python3 testlab/mock_vuln_target.py --port 8801 --sapi hidden

# Spin up a whole lab (4 profiles) in one process and print a hosts file:
python3 testlab/mock_vuln_target.py --lab
"""
from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Preset lab profiles: (port, php_version, sapi, serve_phpinfo, label)
LAB_PROFILES = [
    (8801, "8.3.12", "apache", True,  "vulnerable (below 8.3.36) + mod_php"),
    (8802, "8.1.20", "fpm",    False, "no-upstream-fix branch (8.1)"),
    (8803, "8.3.36", "fpm",    False, "fixed (8.3.36)"),
    (8804, None,     "hidden", False, "version hidden (no PHP header)"),
]

_FAKE_PHPINFO = """<!DOCTYPE html>
<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version {ver}</h1>
<table><tr><td>System</td><td>Linux testlab</td></tr>
<tr><td>Server API</td><td>{sapi}</td></tr></table>
<p>This is a MOCK phpinfo page for scanner testing. No PHP is running.</p>
</body></html>
"""


def make_handler(php_version, sapi, serve_phpinfo):
    server_hdr = {
        "apache": "Apache/2.4.58 (Unix)",
        "fpm": "nginx/1.25.3",
        "nginx": "nginx/1.25.3",
        "hidden": "nginx",
    }.get(sapi, "Apache/2.4.58 (Unix)")

    class Handler(BaseHTTPRequestHandler):
        server_version = server_hdr
        sys_version = ""  # don't append Python/x.y to the Server header

        def _send(self, body: str, ctype="text/html"):
            data = body.encode()
            self.send_response(200)
            self.send_header("Server", server_hdr)
            # Only expose X-Powered-By for non-hidden PHP SAPIs.
            if php_version and sapi != "hidden":
                self.send_header("X-Powered-By", f"PHP/{php_version}")
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if serve_phpinfo and self.path.rstrip("/") in ("/info.php",
                                                           "/phpinfo.php"):
                self._send(_FAKE_PHPINFO.format(
                    ver=php_version or "unknown",
                    sapi=f"{sapi} (mock)"))
            else:
                self._send("<html><body>mock target OK</body></html>")

        def log_message(self, fmt, *args):
            print(f"    [:{self.server.server_address[1]}] "
                  f"{self.address_string()} {fmt % args}")

    return Handler


def serve(bind, port, php_version, sapi, serve_phpinfo, block=True):
    httpd = HTTPServer((bind, port),
                       make_handler(php_version, sapi, serve_phpinfo))
    disp = php_version or "(hidden)"
    print(f"  serving mock PHP {disp} [{sapi}] on http://{bind}:{port}"
          + ("  (+/info.php)" if serve_phpinfo else ""))
    if block:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nshutting down")
            httpd.shutdown()
    else:
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return httpd


def run_lab(bind: str):
    print("Starting PHP2Shell detection test lab "
          "(mock targets — no real PHP, not exploitable):\n")
    for port, ver, sapi, pinfo, label in LAB_PROFILES:
        serve(bind, port, ver, sapi, pinfo, block=False)
        print(f"      -> {label}")
    hosts_path = "testlab/lab_hosts.txt"
    with open(hosts_path, "w") as fh:
        fh.write("# Generated mock lab targets for php2shell_audit fleet mode\n")
        for port, *_ in LAB_PROFILES:
            fh.write(f"{bind}:{port}\n")
    print(f"\nWrote {hosts_path}. Now, in another terminal:\n")
    print("  python3 php2shell_audit.py fleet testlab/lab_hosts.txt "
          "--authorized")
    print("  python3 php2shell_audit.py host "
          f"{bind}:8801 --authorized --phpinfo /info.php\n")
    print("Expected: :8801 CRITICAL, :8802 HIGH, :8803 INFO(fixed), "
          ":8804 LOW(hidden). Ctrl-C to stop.\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nlab stopped")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bind", default="127.0.0.1",
                   help="Bind address (default 127.0.0.1 — keep it local).")
    p.add_argument("--port", type=int, default=8801)
    p.add_argument("--php-version", default="8.3.12",
                   help="Version to advertise (e.g. 8.3.12, 8.1.20, 8.3.36).")
    p.add_argument("--sapi", choices=["apache", "fpm", "nginx", "hidden"],
                   default="apache")
    p.add_argument("--phpinfo", action="store_true",
                   help="Also serve a fake phpinfo page at /info.php.")
    p.add_argument("--lab", action="store_true",
                   help="Start a 4-target lab and write testlab/lab_hosts.txt.")
    ns = p.parse_args()

    if ns.bind not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: binding to {ns.bind} exposes the mock beyond "
              f"localhost. Use only on an isolated test network.")

    if ns.lab:
        run_lab(ns.bind)
    else:
        php = None if ns.sapi == "hidden" else ns.php_version
        serve(ns.bind, ns.port, php, ns.sapi, ns.phpinfo, block=True)


if __name__ == "__main__":
    main()
