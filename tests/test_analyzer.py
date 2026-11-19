"""Tests for the Brute-Force Log Analyzer. Run: pytest -q"""

import io
import os
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import (  # noqa: E402
    MAX_LOG_SIZE,
    analyze_log,
    is_valid_ipv4,
    max_in_window,
    parse_line,
    parse_log,
    verdict_for_score,
)

import app as app_module  # noqa: E402

BASE = datetime(2026, 11, 19, 2, 10, 0)
EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "examples")
ATTACKER = "203.0.113.45"


def fmt(dt):
    return dt.strftime("%b %d %H:%M:%S")


def failed(ip, user, dt, invalid=False):
    who = "invalid user " + user if invalid else user
    return (f"{fmt(dt)} server sshd[3001]: Failed password for {who} "
            f"from {ip} port 51234 ssh2")


def accepted(ip, user, dt, method="password"):
    return (f"{fmt(dt)} server sshd[3001]: Accepted {method} for {user} "
            f"from {ip} port 51234 ssh2: RSA SHA256:xyz")


def fails(ip, user, count, start=BASE, step_seconds=30):
    return [failed(ip, user, start + timedelta(seconds=i * step_seconds),
                   invalid=False) for i in range(count)]


def findings_by_rule(result, rule_id):
    return [f for f in result["findings"] if f["rule_id"] == rule_id]


def read_example(name):
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------ parsing

def test_parse_failed_password():
    ev = parse_line(failed(ATTACKER, "root", BASE), 1)
    assert ev["outcome"] == "failed"
    assert ev["user"] == "root"
    assert ev["ip"] == ATTACKER
    assert ev["port"] == 51234
    assert ev["invalid_user"] is False
    assert ev["timestamp"].year == datetime.now().year
    assert ev["timestamp"].month == 11 and ev["timestamp"].day == 19


def test_parse_failed_invalid_user():
    ev = parse_line(failed(ATTACKER, "test", BASE, invalid=True), 1)
    assert ev["outcome"] == "failed"
    assert ev["user"] == "test"
    assert ev["invalid_user"] is True


def test_parse_accepted_password():
    ev = parse_line(accepted(ATTACKER, "raihan", BASE), 1)
    assert ev["outcome"] == "success"
    assert ev["user"] == "raihan"
    assert ev["method"] == "password"


def test_parse_accepted_publickey():
    ev = parse_line(accepted("192.168.1.10", "dina", BASE, "publickey"), 1)
    assert ev["outcome"] == "success"
    assert ev["method"] == "publickey"


def test_parse_invalid_user_line():
    ev = parse_line(
        f"{fmt(BASE)} server sshd[3001]: Invalid user nosuch from "
        f"{ATTACKER} port 51234", 1)
    assert ev is not None
    assert ev["outcome"] == "invalid"
    assert ev["user"] == "nosuch"
    assert ev["invalid_user"] is True


def test_parse_connection_closed():
    ev = parse_line(
        f"{fmt(BASE)} server sshd[3001]: Connection closed by {ATTACKER} "
        f"port 51234 [preauth]", 1)
    assert ev is not None
    assert ev["outcome"] == "other"
    assert ev["ip"] == ATTACKER


def test_parse_disconnected():
    ev = parse_line(
        f"{fmt(BASE)} server sshd[3001]: Disconnected from authenticating "
        f"user root {ATTACKER} port 51234 [preauth]", 1)
    assert ev is not None
    assert ev["outcome"] == "other"
    assert ev["user"] == "root"


def test_parse_generic_failed_fallback():
    ev = parse_line(
        f"{fmt(BASE)} server sshd[3001]: Failed login for raihan from "
        f"{ATTACKER} port 22", 1)
    assert ev is not None
    assert ev["outcome"] == "failed"
    assert ev["user"] == "raihan"


def test_unparsed_line_counted_not_crashed():
    events, unparsed = parse_log(
        failed(ATTACKER, "root", BASE) + "\n"
        "this is not a log line at all\n"
        "Nov 19 02:10:05 server kernel: something unrelated\n")
    assert len(events) == 1
    assert len(unparsed) == 2
    assert unparsed[0]["line_no"] == 2


def test_blank_lines_ignored():
    events, unparsed = parse_log("\n\n" + failed(ATTACKER, "root", BASE) + "\n\n")
    assert len(events) == 1
    assert unparsed == []


def test_invalid_ipv4_rejected():
    line = (f"{fmt(BASE)} server sshd[3001]: Failed password for root "
            f"from 999.1.2.3 port 51234 ssh2")
    assert parse_line(line, 1) is None
    assert parse_line("garbage", 1) is None
    assert parse_line("", 1) is None


def test_is_valid_ipv4():
    assert is_valid_ipv4("203.0.113.45") is True
    assert is_valid_ipv4("0.0.0.0") is True
    assert is_valid_ipv4("255.255.255.255") is True
    assert is_valid_ipv4("256.1.1.1") is False
    assert is_valid_ipv4("999.1.2.3") is False
    assert is_valid_ipv4("1.2.3") is False
    assert is_valid_ipv4("1.2.3.4.5") is False


def test_line_without_timestamp_still_parses():
    ev = parse_line(
        "sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2", 1)
    assert ev is not None
    assert ev["timestamp"] is None
    assert ev["outcome"] == "failed"


# ------------------------------------------------------------------ windows

def test_max_in_window_basic():
    stamps = [BASE + timedelta(seconds=s) for s in (0, 30, 59, 61, 120)]
    assert max_in_window(stamps, 60) == 3  # 0, 30, 59
    assert max_in_window(stamps, 10 * 60) == 5
    assert max_in_window([], 60) == 0


def test_sliding_window_spread_over_10_minutes_is_not_a_burst():
    # 5 failures at 0, 3, 6, 9, 12 minutes: at most 4 in any 10-min window.
    lines = [failed(ATTACKER, "raihan", BASE + timedelta(minutes=m))
             for m in (0, 3, 6, 9, 12)]
    result = analyze_log("\n".join(lines))
    assert findings_by_rule(result, "BRUTE-01") == []


def test_sliding_window_one_minute_spread_is_not_fast():
    lines = [failed(ATTACKER, "raihan", BASE + timedelta(seconds=s))
             for s in (0, 20, 40, 61, 80, 100, 130, 160, 190, 220)]
    result = analyze_log("\n".join(lines))
    assert findings_by_rule(result, "BRUTE-07") == []


# ------------------------------------------------------------------ BRUTE-01

def test_brute01_below_threshold_no_finding():
    result = analyze_log("\n".join(fails(ATTACKER, "raihan", 4)))
    assert findings_by_rule(result, "BRUTE-01") == []


def test_brute01_at_threshold_high():
    result = analyze_log("\n".join(fails(ATTACKER, "raihan", 5)))
    found = findings_by_rule(result, "BRUTE-01")
    assert len(found) == 1
    assert found[0]["severity"] == "high"


def test_brute01_critical_20_in_10_minutes():
    result = analyze_log("\n".join(fails(ATTACKER, "raihan", 20, step_seconds=27)))
    found = findings_by_rule(result, "BRUTE-01")
    assert len(found) == 1
    assert found[0]["severity"] == "critical"


def test_brute01_critical_50_total_even_when_spread_out():
    lines = [failed(ATTACKER, "raihan", BASE + timedelta(minutes=11 * i))
             for i in range(50)]
    result = analyze_log("\n".join(lines))
    found = findings_by_rule(result, "BRUTE-01")
    assert len(found) == 1
    assert found[0]["severity"] == "critical"


# ------------------------------------------------------------------ BRUTE-07

def test_brute07_below_threshold():
    result = analyze_log("\n".join(fails(ATTACKER, "raihan", 9, step_seconds=5)))
    assert findings_by_rule(result, "BRUTE-07") == []


def test_brute07_at_threshold_high():
    result = analyze_log("\n".join(fails(ATTACKER, "raihan", 10, step_seconds=5)))
    found = findings_by_rule(result, "BRUTE-07")
    assert len(found) == 1
    assert found[0]["severity"] == "high"


# ------------------------------------------------------------------ BRUTE-02 / 03

def test_brute02_below_threshold():
    users = ["root", "admin", "test", "user"]
    lines = [failed(ATTACKER, u, BASE + timedelta(minutes=15 * i))
             for i, u in enumerate(users)]
    assert findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-02") == []


def test_brute02_five_usernames_medium():
    users = ["root", "admin", "test", "user", "guest"]
    lines = [failed(ATTACKER, u, BASE + timedelta(minutes=15 * i))
             for i, u in enumerate(users)]
    found = findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-02")
    assert len(found) == 1
    assert found[0]["severity"] == "medium"
    assert found[0]["count"] == 5


def test_brute02_ten_usernames_high():
    users = [f"user{i}" for i in range(10)]
    lines = [failed(ATTACKER, u, BASE + timedelta(minutes=15 * i))
             for i, u in enumerate(users)]
    found = findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-02")
    assert len(found) == 1
    assert found[0]["severity"] == "high"


def test_brute03_five_ips_medium():
    lines = [failed(f"203.0.113.{i}", "raihan", BASE + timedelta(minutes=i))
             for i in range(1, 6)]
    found = findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-03")
    assert len(found) == 1
    assert found[0]["severity"] == "medium"
    assert found[0]["user"] == "raihan"


def test_brute03_ten_ips_high():
    lines = [failed(f"203.0.113.{i}", "raihan", BASE + timedelta(minutes=i))
             for i in range(1, 11)]
    found = findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-03")
    assert len(found) == 1
    assert found[0]["severity"] == "high"


def test_brute03_below_threshold():
    lines = [failed(f"203.0.113.{i}", "raihan", BASE + timedelta(minutes=i))
             for i in range(1, 5)]
    assert findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-03") == []


# ------------------------------------------------------------------ BRUTE-04

def test_brute04_success_without_failures_no_finding():
    result = analyze_log(accepted(ATTACKER, "raihan", BASE))
    assert findings_by_rule(result, "BRUTE-04") == []


def test_brute04_success_after_4_failures_no_finding():
    lines = fails(ATTACKER, "raihan", 4, step_seconds=660)
    lines.append(accepted(ATTACKER, "raihan", BASE + timedelta(minutes=60)))
    assert findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-04") == []


def test_brute04_success_after_5_failures_critical():
    lines = fails(ATTACKER, "raihan", 5, step_seconds=660)
    lines.append(accepted(ATTACKER, "raihan", BASE + timedelta(minutes=60)))
    found = findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-04")
    assert len(found) == 1
    assert found[0]["severity"] == "critical"
    assert found[0]["ip"] == ATTACKER


def test_brute04_failures_from_other_ip_do_not_count():
    lines = fails("198.51.100.23", "raihan", 5, step_seconds=660)
    lines.append(accepted(ATTACKER, "raihan", BASE + timedelta(minutes=60)))
    assert findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-04") == []


# ------------------------------------------------------------------ BRUTE-05 / 06

def test_brute05_below_threshold():
    lines = [f"{fmt(BASE + timedelta(minutes=i))} server sshd[1]: "
             f"Invalid user no{i} from {ATTACKER} port 51234"
             for i in range(2)]
    assert findings_by_rule(analyze_log("\n".join(lines)), "BRUTE-05") == []


def test_brute05_three_low_ten_medium():
    def invalid_lines(n):
        return [f"{fmt(BASE + timedelta(minutes=i))} server sshd[1]: "
                f"Invalid user no{i} from {ATTACKER} port 51234"
                for i in range(n)]
    assert findings_by_rule(
        analyze_log("\n".join(invalid_lines(3))), "BRUTE-05")[0]["severity"] == "low"
    assert findings_by_rule(
        analyze_log("\n".join(invalid_lines(10))), "BRUTE-05")[0]["severity"] == "medium"


def test_brute06_root_below_threshold():
    result = analyze_log("\n".join(fails(ATTACKER, "root", 4, step_seconds=660)))
    assert findings_by_rule(result, "BRUTE-06") == []


def test_brute06_root_at_threshold_medium():
    result = analyze_log("\n".join(fails(ATTACKER, "root", 5, step_seconds=660)))
    found = findings_by_rule(result, "BRUTE-06")
    assert len(found) == 1
    assert found[0]["severity"] == "medium"


# ------------------------------------------------------------------ scoring / verdict

def test_verdict_boundaries():
    assert verdict_for_score(0) == "Safe"
    assert verdict_for_score(9) == "Safe"
    assert verdict_for_score(10) == "Suspicious"
    assert verdict_for_score(29) == "Suspicious"
    assert verdict_for_score(30) == "High Risk"
    assert verdict_for_score(49) == "High Risk"
    assert verdict_for_score(50) == "Malicious"
    assert verdict_for_score(100) == "Malicious"


def test_critical_forces_at_least_high_risk():
    # Only a critical BRUTE-04 (25 pts): score alone would be Suspicious.
    lines = fails(ATTACKER, "raihan", 5, step_seconds=660)
    lines.append(accepted(ATTACKER, "raihan", BASE + timedelta(minutes=60)))
    result = analyze_log("\n".join(lines))
    assert result["score"] == 25
    assert result["has_critical"] is True
    assert result["verdict"] == "High Risk"


def test_score_capped_at_100():
    result = analyze_log(read_example("attack.log"))
    assert result["score"] == 100
    assert result["verdict"] == "Malicious"


def test_summary_counts():
    lines = fails(ATTACKER, "raihan", 2) + [accepted("192.168.1.10", "dina", BASE)]
    result = analyze_log("\n".join(lines) + "\nnot a log line\n")
    assert result["summary"]["total_lines"] == 4
    assert result["summary"]["failed"] == 2
    assert result["summary"]["successful"] == 1
    assert result["summary"]["unparsed_lines"] == 1
    assert result["summary"]["unique_ips"] == 2


def test_timeline_per_hour():
    lines = ([failed(ATTACKER, "raihan", BASE + timedelta(minutes=i))
              for i in (0, 10, 20)]
             + [failed(ATTACKER, "raihan", BASE + timedelta(hours=1))])
    result = analyze_log("\n".join(lines))
    by_hour = {b["hour"]: b for b in result["timeline"]}
    assert len(result["timeline"]) == 2
    assert by_hour[BASE.strftime("%Y-%m-%d %H:00")]["failed"] == 3


def test_top_ips_sorted_and_scored():
    result = analyze_log(read_example("attack.log"))
    top = result["top_ips"]
    assert top[0]["ip"] == ATTACKER
    assert top[0]["failed"] == 28
    assert top[0]["successful"] == 1
    assert top[0]["verdict"] == "Malicious"
    assert top[0]["score"] > top[1]["score"]
    assert "root" in top[0]["usernames"]


def test_recommendations_are_text_only():
    result = analyze_log(read_example("attack.log"))
    assert result["recommendations"]
    assert any("fail2ban" in r for r in result["recommendations"])
    assert any("compromis" in r for r in result["recommendations"])


# ------------------------------------------------------------------ examples

def test_example_benign_is_safe():
    result = analyze_log(read_example("benign.log"))
    assert result["score"] <= 9
    assert result["verdict"] == "Safe"
    assert result["summary"]["successful"] >= 2


def test_example_attack_is_malicious_with_brute04():
    result = analyze_log(read_example("attack.log"))
    assert result["score"] >= 50
    assert result["verdict"] == "Malicious"
    found = findings_by_rule(result, "BRUTE-04")
    assert len(found) == 1
    assert found[0]["severity"] == "critical"


def test_analyze_empty_log_rejected():
    with pytest.raises(ValueError, match="empty"):
        analyze_log("")
    with pytest.raises(ValueError, match="empty"):
        analyze_log("   \n  ")


def test_analyze_oversized_log_rejected():
    with pytest.raises(ValueError, match="too large"):
        analyze_log("x" * (MAX_LOG_SIZE + 1))


# ------------------------------------------------------------------ offline

def test_no_network_imports_in_analyzer_or_app():
    for filename in ("analyzer.py", "app.py"):
        path = os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))), filename)
        with open(path, encoding="utf-8") as f:
            source = f.read()
        for banned in ("import socket", "import requests", "import urllib",
                       "from urllib", "import http.client"):
            assert banned not in source, f"{banned} found in {filename}"


# ------------------------------------------------------------------ Flask

@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_index_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Brute-Force Log Analyzer" in resp.data


def test_analyze_log_text(client):
    resp = client.post("/analyze", data={"log_text": read_example("attack.log")})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["verdict"] == "Malicious"
    assert body["score"] == 100


def test_analyze_upload_file(client):
    resp = client.post("/analyze", data={
        "log_file": (io.BytesIO(read_example("benign.log").encode("utf-8")),
                     "benign.log")}, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert resp.get_json()["verdict"] == "Safe"


def test_analyze_empty_rejected_with_clear_message(client):
    resp = client.post("/analyze", data={"log_text": ""})
    assert resp.status_code == 400
    assert "empty" in resp.get_json()["error"].lower()


def test_analyze_empty_file_rejected(client):
    resp = client.post("/analyze", data={
        "log_file": (io.BytesIO(b""), "empty.log")},
        content_type="multipart/form-data")
    assert resp.status_code == 400
    assert resp.get_json()["error"]


def test_analyze_file_too_large_rejected(client):
    resp = client.post("/analyze", data={
        "log_file": (io.BytesIO(b"x" * (MAX_LOG_SIZE + 10)), "big.log")},
        content_type="multipart/form-data")
    assert resp.status_code in (400, 413)
    assert "too large" in resp.get_json()["error"].lower()


def test_example_endpoint(client):
    resp = client.get("/api/example/attack.log")
    assert resp.status_code == 200
    assert "Failed password" in resp.get_json()["log_text"]
    assert client.get("/api/example/nope.log").status_code == 404
