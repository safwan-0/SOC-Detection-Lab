#!/usr/bin/env python3
"""Rule-based detection engine: parse logs -> apply rules.yaml -> alerts + report."""
import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

import yaml

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RE_SYSLOG = re.compile(r"^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) (.*)$")
RE_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+")
RE_OK = re.compile(r"Accepted password for (\S+) from (\S+) port \d+")
RE_DENIED = re.compile(r"sudo: +(\S+) : user NOT in sudoers")
RE_SUDO = re.compile(r"sudo: +(\S+) : TTY=\S+ ; PWD=\S+ ; USER=root ; COMMAND=(.+)$")
RE_USERADD = re.compile(r"useradd\[\d+\]: new user: name=(\S+?), UID=(\d+)")
RE_USERMOD = re.compile(r"usermod\[\d+\]: add '(\S+)' to group '(sudo|wheel|admin)'")
RE_FW = re.compile(r"SRC=(\S+) DST=\S+ .*?DPT=(\d+)")
RE_WEB = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')


@dataclass
class Alert:
    rule: str
    severity: str
    mitre: str
    entity: str
    first_seen: str
    last_seen: str
    count: int
    description: str
    response: str


# ---------------------------------------------------------------- parsing
def load_events(logs_dir, year):
    logs = Path(logs_dir)
    ev = defaultdict(list)

    for line in (logs / "auth.log").read_text().splitlines():
        m = RE_SYSLOG.match(line)
        if not m:
            continue
        ts = datetime.strptime(f"{year} {m[1]}", "%Y %b %d %H:%M:%S")
        rest = m[3]
        if x := RE_FAIL.search(rest):
            ev["ssh_fail"].append({"ts": ts, "user": x[1], "ip": x[2]})
        elif x := RE_OK.search(rest):
            ev["ssh_ok"].append({"ts": ts, "user": x[1], "ip": x[2]})
        elif x := RE_DENIED.search(rest):
            ev["sudo_denied"].append({"ts": ts, "user": x[1]})
        elif x := RE_SUDO.search(rest):
            ev["sudo_cmd"].append({"ts": ts, "user": x[1], "cmd": x[2].strip()})
        elif x := RE_USERADD.search(rest):
            ev["user_added"].append({"ts": ts, "user": x[1], "uid": int(x[2])})
        elif x := RE_USERMOD.search(rest):
            ev["group_added"].append({"ts": ts, "user": x[1], "group": x[2]})

    fw_path = logs / "firewall.log"
    if fw_path.exists():
        for line in fw_path.read_text().splitlines():
            m = RE_SYSLOG.match(line)
            x = RE_FW.search(line)
            if m and x:
                ts = datetime.strptime(f"{year} {m[1]}", "%Y %b %d %H:%M:%S")
                ev["fw_block"].append({"ts": ts, "ip": x[1], "dport": int(x[2])})

    web_path = logs / "access.log"
    if web_path.exists():
        for line in web_path.read_text().splitlines():
            if x := RE_WEB.match(line):
                ts = datetime.strptime(x[2], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
                ev["http"].append({"ts": ts, "ip": x[1], "path": x[4], "status": int(x[5]), "ua": x[6]})
    return ev


# ---------------------------------------------------------------- helpers
def best_window(items, window, distinct=False):
    """Sliding window over (timestamp, value). Returns (metric, first_ts, last_ts)
    for the window with the most events (or most distinct values)."""
    items = sorted(items, key=lambda x: x[0])
    counts, left, best = Counter(), 0, (0, None, None)
    for right, (ts, val) in enumerate(items):
        counts[val] += 1
        while (ts - items[left][0]).total_seconds() > window:
            old = items[left][1]
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
            left += 1
        metric = len(counts) if distinct else right - left + 1
        if metric > best[0]:
            best = (metric, items[left][0], ts)
    return best


def mk(rule, cfg, entity, first, last, count, desc):
    return Alert(rule, cfg["severity"], cfg["mitre"], entity, first.isoformat(), last.isoformat(),
                 count, desc, cfg["response"])


def burst_rule(rule, cfg, groups, distinct, label):
    out = []
    for entity, items in groups.items():
        n, a, b = best_window(items, cfg["window_seconds"], distinct)
        if n >= cfg["threshold"]:
            out.append(mk(rule, cfg, entity, a, b, n, f"{n} {label} from {entity} within {cfg['window_seconds']}s"))
    return out


def group(events, key, val):
    g = defaultdict(list)
    for e in events:
        g[key(e)].append((e["ts"], val(e)))
    return g


# ---------------------------------------------------------------- rules
def rule_ssh_brute_force(ev, cfg):
    g = group(ev["ssh_fail"], lambda e: e["ip"], lambda e: e["user"])
    return burst_rule("ssh_brute_force", cfg, g, False, "failed SSH logins")


def rule_password_spraying(ev, cfg):
    g = group(ev["ssh_fail"], lambda e: e["ip"], lambda e: e["user"])
    return burst_rule("password_spraying", cfg, g, True, "distinct usernames tried")


def rule_brute_force_success(ev, cfg):
    fails = defaultdict(list)
    for e in ev["ssh_fail"]:
        fails[(e["ip"], e["user"])].append(e["ts"])
    seen, out = set(), []
    for ok in ev["ssh_ok"]:
        start = ok["ts"] - timedelta(seconds=cfg["window_seconds"])
        prior = [t for t in fails.get((ok["ip"], ok["user"]), []) if start <= t <= ok["ts"]]
        if len(prior) >= cfg["threshold"] and ok["ip"] not in seen:
            seen.add(ok["ip"])
            out.append(mk("brute_force_success", cfg, ok["ip"], min(prior), ok["ts"], len(prior) + 1,
                          f"{len(prior)} failed logins for '{ok['user']}' then SUCCESS from {ok['ip']}"))
    return out


def rule_sudo_denied(ev, cfg):
    g = group(ev["sudo_denied"], lambda e: e["user"], lambda e: 1)
    return burst_rule("sudo_denied", cfg, g, False, "denied sudo attempts by")


def _per_entity(rule, cfg, events, key, desc):
    g = defaultdict(list)
    for e in events:
        g[key(e)].append(e["ts"])
    return [mk(rule, cfg, ent, min(ts), max(ts), len(ts), desc.format(ent=ent)) for ent, ts in g.items()]


def rule_root_shell(ev, cfg):
    hits = [e for e in ev["sudo_cmd"] if e["cmd"] in cfg["shells"]]
    return _per_entity("root_shell", cfg, hits, lambda e: e["user"], "{ent} opened a root shell via sudo")


def rule_sudo_group_add(ev, cfg):
    return _per_entity("sudo_group_add", cfg, ev["group_added"], lambda e: e["user"],
                       "{ent} was added to a privileged group")


def rule_new_uid0(ev, cfg):
    hits = [e for e in ev["user_added"] if e["uid"] == 0]
    return _per_entity("new_uid0_account", cfg, hits, lambda e: e["user"],
                       "New account '{ent}' created with UID 0 (root-equivalent)")


def rule_port_scan(ev, cfg):
    g = group(ev["fw_block"], lambda e: e["ip"], lambda e: e["dport"])
    return burst_rule("port_scan", cfg, g, True, "distinct ports probed")


def rule_web_scan_404(ev, cfg):
    g = group([e for e in ev["http"] if e["status"] == 404], lambda e: e["ip"], lambda e: e["path"])
    return burst_rule("web_scan_404", cfg, g, False, "HTTP 404 responses")


def rule_scanner_ua(ev, cfg):
    agents = [a.lower() for a in cfg["agents"]]
    hits = [e for e in ev["http"] if any(a in e["ua"].lower() for a in agents)]
    return _per_entity("scanner_user_agent", cfg, hits, lambda e: e["ip"],
                       "Known scanner user-agent seen from {ent}")


RULES = {
    "ssh_brute_force": rule_ssh_brute_force, "password_spraying": rule_password_spraying,
    "brute_force_success": rule_brute_force_success, "sudo_denied": rule_sudo_denied,
    "root_shell": rule_root_shell, "sudo_group_add": rule_sudo_group_add,
    "new_uid0_account": rule_new_uid0, "port_scan": rule_port_scan,
    "web_scan_404": rule_web_scan_404, "scanner_user_agent": rule_scanner_ua,
}


# ---------------------------------------------------------------- engine
def run(logs_dir, rules_path, year):
    cfg = yaml.safe_load(Path(rules_path).read_text())
    ev = load_events(logs_dir, year)
    alerts = []
    for name, fn in RULES.items():
        if name in cfg:
            alerts += fn(ev, cfg[name])
    return sorted(alerts, key=lambda a: (SEV_ORDER[a.severity], a.first_seen))


def evaluate(alerts, truth):
    expected = {(t["expected_rule"], t["entity"]) for t in truth}
    got = {(a.rule, a.entity) for a in alerts}
    tp, missed, fps = expected & got, expected - got, got - expected
    return {
        "true_positives": len(tp), "missed": sorted(missed), "false_positives": sorted(fps),
        "precision": round(len(tp) / len(got), 2) if got else 0.0,
        "recall": round(len(tp) / len(expected), 2) if expected else 0.0,
    }


def write_report(alerts, metrics, path):
    lines = ["# SOC Detection Report", "", f"Generated: {datetime.now():%Y-%m-%d %H:%M}", ""]
    sev = Counter(a.severity for a in alerts)
    lines += ["## Summary", "", "| Severity | Alerts |", "|---|---|"]
    lines += [f"| {s} | {sev[s]} |" for s in SEV_ORDER if sev[s]]
    lines += ["", "## Alerts", ""]
    for i, a in enumerate(alerts, 1):
        lines += [f"### {i}. [{a.severity.upper()}] {a.rule} — `{a.entity}`", "",
                  f"- **What happened:** {a.description}",
                  f"- **MITRE ATT&CK:** {a.mitre}",
                  f"- **Time:** {a.first_seen} → {a.last_seen}",
                  f"- **Recommended response:** {a.response}", ""]
    if metrics:
        lines += ["## Detection quality (vs. ground truth)", "",
                  f"- Precision: **{metrics['precision']}**  Recall: **{metrics['recall']}**",
                  f"- Missed: {metrics['missed'] or 'none'}",
                  f"- False positives: {metrics['false_positives'] or 'none'}", ""]
    Path(path).write_text("\n".join(lines))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--logs", default="data")
    p.add_argument("--rules", default="config/rules.yaml")
    p.add_argument("--out", default="output")
    p.add_argument("--year", type=int, default=datetime.now().year)
    args = p.parse_args()

    alerts = run(args.logs, args.rules, args.year)
    truth_path = Path(args.logs) / "ground_truth.json"
    metrics = evaluate(alerts, json.loads(truth_path.read_text())) if truth_path.exists() else None

    out = Path(args.out)
    out.mkdir(exist_ok=True)
    (out / "alerts.json").write_text(json.dumps([asdict(a) for a in alerts], indent=2))
    write_report(alerts, metrics, out / "report.md")

    print(f"{'SEVERITY':<9} {'RULE':<22} {'ENTITY':<16} COUNT")
    for a in alerts:
        print(f"{a.severity.upper():<9} {a.rule:<22} {a.entity:<16} {a.count}")
    if metrics:
        print(f"\nPrecision={metrics['precision']} Recall={metrics['recall']} "
              f"Missed={metrics['missed']} FP={metrics['false_positives']}")
    print(f"\nWrote {out}/alerts.json and {out}/report.md")


if __name__ == "__main__":
    main()
