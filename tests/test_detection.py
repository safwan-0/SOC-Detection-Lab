from datetime import datetime, timedelta

from detect import best_window, evaluate, run
from generate_logs import generate

START = datetime(2026, 10, 14, 8, 0, 0)


def test_best_window_counts_and_distinct():
    t0 = datetime(2026, 1, 1)
    items = [(t0 + timedelta(seconds=i), i % 2) for i in range(10)]
    assert best_window(items, 60)[0] == 10
    assert best_window(items, 60, distinct=True)[0] == 2
    assert best_window(items, 2)[0] == 3  # events at 0s, 1s, 2s


def test_all_attacks_detected_without_false_positives(tmp_path):
    truth = generate(tmp_path, seed=1, start=START)
    alerts = run(tmp_path, "config/rules.yaml", 2026)
    result = evaluate(alerts, truth)
    assert result["missed"] == []
    assert result["false_positives"] == []


def test_clean_traffic_has_no_alerts(tmp_path):
    generate(tmp_path, seed=7, start=START)
    # keep only the normal-looking lines (drop every attacker IP / victim marker)
    for name in ("auth.log", "access.log", "firewall.log"):
        p = tmp_path / name
        keep = [l for l in p.read_text().splitlines()
                if "203.0.113" not in l and "198.51.100" not in l and "192.0.2" not in l
                and "bob" not in l and "svc_backup" not in l]
        p.write_text("\n".join(keep) + "\n")
    assert run(tmp_path, "config/rules.yaml", 2026) == []
