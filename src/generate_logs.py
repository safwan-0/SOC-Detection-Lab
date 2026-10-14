#!/usr/bin/env python3
"""Generate synthetic Linux/web/firewall logs: normal noise + injected attacks.

All attacker IPs come from RFC 5737 documentation ranges (203.0.113.0/24,
198.51.100.0/24, 192.0.2.0/24), so they can never belong to a real host.
A ground_truth.json is written so the detector can be scored objectively.
"""
import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

HOST, FW = "web01", "fw01"
USERS = ["alice", "bob", "carol", "dave"]
INTERNAL = [f"10.0.0.{i}" for i in range(10, 40)]
PATHS = ["/", "/index.html", "/login", "/api/v1/items", "/static/app.js", "/about", "/contact"]
UAS = ["Mozilla/5.0 (X11; Linux x86_64) Firefox/118.0", "Mozilla/5.0 (Windows NT 10.0) Chrome/118.0"]
WORDLIST = ["admin", "backup", "config", "test", "old", "dev", "uploads", "private", "db", "api",
            "login", "panel", "secret", "tmp", "staging", "files", "logs", "data", "web", "site"]


def generate(out_dir, seed=42, start=None):
    rng = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    start = start or datetime.now().replace(hour=8, minute=0, second=0, microsecond=0)
    auth, web, fw, truth = [], [], [], []

    def at(minutes, secs=0.0):
        return start + timedelta(minutes=minutes, seconds=secs)

    def a_line(ts, proc, msg, pid=True):
        tag = f"{proc}[{rng.randint(1000, 9999)}]" if pid else proc
        auth.append((ts, f"{ts:%b %d %H:%M:%S} {HOST} {tag}: {msg}"))

    def w_line(ts, ip, method, path, status, ua):
        web.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S +0000}] "{method} {path} HTTP/1.1" '
                        f'{status} {rng.randint(120, 5000)} "-" "{ua}"'))

    def f_line(ts, src, dport):
        fw.append((ts, f"{ts:%b %d %H:%M:%S} {FW} kernel: [UFW BLOCK] IN=eth0 OUT= SRC={src} "
                       f"DST=10.0.0.5 LEN=60 PROTO=TCP SPT={rng.randint(30000, 60000)} DPT={dport} SYN"))

    def expect(scenario, rule, entity):
        truth.append({"scenario": scenario, "expected_rule": rule, "entity": entity})

    # ---------- normal background noise ----------
    for _ in range(120):
        ts, u, ip = at(rng.uniform(0, 480)), rng.choice(USERS), rng.choice(INTERNAL)
        if rng.random() < 0.1:  # typo, then success
            a_line(ts, "sshd", f"Failed password for {u} from {ip} port {rng.randint(30000, 60000)} ssh2")
            ts += timedelta(seconds=5)
        a_line(ts, "sshd", f"Accepted password for {u} from {ip} port {rng.randint(30000, 60000)} ssh2")
    for _ in range(25):
        ts, u = at(rng.uniform(0, 480)), rng.choice(USERS)
        cmd = rng.choice(["/usr/bin/apt update", "/usr/bin/systemctl status nginx", "/usr/bin/journalctl -u sshd"])
        a_line(ts, "sudo", f"{u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND={cmd}", pid=False)
    pool = [f"10.0.1.{i}" for i in range(1, 31)]
    for _ in range(500):
        ts = at(rng.uniform(0, 480))
        status = 404 if rng.random() < 0.03 else 200
        w_line(ts, rng.choice(pool), "GET", rng.choice(PATHS), status, rng.choice(UAS))

    # ---------- attack 1: SSH brute force (T1110.001) ----------
    ip = "203.0.113.50"
    for i in range(40):
        ts, u = at(60, i * 3), rng.choice(["root", "admin", "ubuntu", "test"])
        inv = "" if u == "root" else "invalid user "
        a_line(ts, "sshd", f"Failed password for {inv}{u} from {ip} port {rng.randint(30000, 60000)} ssh2")
    expect("ssh_brute_force", "ssh_brute_force", ip)

    # ---------- attack 2: password spraying (T1110.003) ----------
    ip = "198.51.100.23"
    victims = ["alice", "bob", "carol", "dave", "admin", "root", "ubuntu", "deploy", "git", "oracle"]
    for i, u in enumerate(victims):
        inv = "" if u in USERS + ["root"] else "invalid user "
        a_line(at(120, i * 45), "sshd", f"Failed password for {inv}{u} from {ip} port {rng.randint(30000, 60000)} ssh2")
    expect("password_spraying", "password_spraying", ip)

    # ---------- attack 3: low-and-slow brute force -> compromise -> privesc ----------
    ip = "203.0.113.77"
    for i in range(12):
        a_line(at(200, i * 8), "sshd", f"Failed password for bob from {ip} port {rng.randint(30000, 60000)} ssh2")
    a_line(at(200, 100), "sshd", f"Accepted password for bob from {ip} port {rng.randint(30000, 60000)} ssh2")
    for i, cmd in enumerate(["/usr/bin/id", "/bin/cat /etc/shadow", "/bin/bash"]):
        a_line(at(203, i * 20), "sudo",
               f"bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND={cmd}", pid=False)
    a_line(at(206), "useradd", "new user: name=svc_backup, UID=0, GID=0, home=/home/svc_backup, shell=/bin/bash")
    a_line(at(207), "usermod", "add 'bob' to group 'sudo'")
    a_line(at(208), "sudo", "bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash", pid=False)
    expect("compromise_chain", "brute_force_success", ip)
    expect("compromise_chain", "sudo_denied", "bob")
    expect("compromise_chain", "new_uid0_account", "svc_backup")
    expect("compromise_chain", "sudo_group_add", "bob")
    expect("compromise_chain", "root_shell", "bob")

    # ---------- attack 4: port scan (T1046) ----------
    ip = "192.0.2.99"
    for i, port in enumerate(rng.sample(range(1, 1025), 100)):
        f_line(at(300, i * 0.2), ip, port)
    expect("port_scan", "port_scan", ip)

    # ---------- attack 5: web recon / directory brute force (T1595) ----------
    ip = "203.0.113.9"
    for i in range(60):
        path = "/" + WORDLIST[i % len(WORDLIST)] + ("" if i < len(WORDLIST) else ".php")
        status = 301 if path == "/admin" else 404
        w_line(at(360, i), ip, "GET", path, status, "gobuster/3.6")
    expect("web_recon", "web_scan_404", ip)
    expect("web_recon", "scanner_user_agent", ip)

    # ---------- write files (sorted by time, like real logs) ----------
    for name, lines in (("auth.log", auth), ("access.log", web), ("firewall.log", fw)):
        (out / name).write_text("\n".join(l for _, l in sorted(lines, key=lambda x: x[0])) + "\n")
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2))
    return truth


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", default="data")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    t = generate(args.out, args.seed)
    print(f"Generated logs in {args.out}/ with {len(t)} injected attack indicators.")
