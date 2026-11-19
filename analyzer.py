"""Brute-Force Log Analyzer — analyse SSH auth logs, offline.

Defensive / educational tool only. It reads a pasted or uploaded auth log
(typically ``/var/log/auth.log`` from OpenSSH sshd), parses each line, and
explains what it found: which IPs tried to brute-force passwords, which
usernames they tried, whether any of them got in, and what to do about it.

It never executes anything from the log, never blocks an IP by itself,
and makes no network requests at all — it only reads the text you give it.

A verdict is NOT proof of compromise: a "Malicious" log means the pattern
looks like an attack; a "Safe" log means nothing suspicious was found by
these checks, not that the server is safe. Always review the findings.

Scoring (same convention as the other scanners in this portfolio):
critical 25, high 15, medium 8, low 3, info 0; total capped at 100.
Verdict: Safe 0-9, Suspicious 10-29, High Risk 30-49, Malicious 50-100.
Any single critical finding forces the verdict to at least High Risk.

Limits: log lines carry no year in syslog format, so timestamps are
assumed to be in the current year. Lines in a different format are
counted as unparsed instead of being silently dropped.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime

MAX_LOG_SIZE = 2 * 1024 * 1024  # 2 MB

SEVERITY_POINTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Timestamps in syslog lines look like "Nov 19 02:10:11" (no year).
_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\b"
)
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

_FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from "
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (\d+)"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (password|publickey) for (\S+) from "
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (\d+)"
)
_INVALID_RE = re.compile(
    r"Invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?: port (\d+))?"
)
_CLOSED_RE = re.compile(
    r"(?:Connection closed|Disconnected).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
_GENERIC_FAILED_RE = re.compile(
    r"Failed .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)

PRIVILEGED_USERS = {"root", "admin"}


def is_valid_ipv4(ip):
    """True only for a dotted-quad with every octet in 0-255."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not part:
            return False
        # Reject leading-zero oddities such as "01" only if they are not
        # a plain zero; "0" itself is fine. Keep it simple: int() check.
        if int(part) > 255:
            return False
    return True


def parse_timestamp(text):
    """Parse a syslog "Nov 19 02:10:11" prefix; None if absent/invalid.

    Syslog carries no year, so the current year is assumed.
    """
    match = _TS_RE.match(text)
    if not match:
        return None
    month = MONTHS.get(match.group("mon"))
    if month is None:
        return None
    try:
        return datetime(
            datetime.now().year, month, int(match.group("day")),
            int(match.group("hour")), int(match.group("min")),
            int(match.group("sec")),
        )
    except ValueError:
        return None


def parse_line(line, line_no=0):
    """Parse one log line.

    Returns a dict event, or None when the line cannot be parsed (the
    caller counts it as unparsed). A line whose IP fails validation is
    also unparsed — a bogus IP is never counted as an attack.
    """
    if not line or not line.strip():
        return None
    text = line.strip()
    timestamp = parse_timestamp(text)

    match = _FAILED_RE.search(text)
    if match:
        user, ip, port = match.groups()
        if not is_valid_ipv4(ip):
            return None
        return {
            "line_no": line_no, "raw": text, "timestamp": timestamp,
            "user": user, "ip": ip, "port": int(port),
            "method": None, "outcome": "failed",
            "invalid_user": "invalid user" in text,
        }

    match = _ACCEPTED_RE.search(text)
    if match:
        method, user, ip, port = match.groups()
        if not is_valid_ipv4(ip):
            return None
        return {
            "line_no": line_no, "raw": text, "timestamp": timestamp,
            "user": user, "ip": ip, "port": int(port),
            "method": method, "outcome": "success",
            "invalid_user": False,
        }

    match = _INVALID_RE.search(text)
    if match:
        user, ip, port = match.groups()
        if not is_valid_ipv4(ip):
            return None
        return {
            "line_no": line_no, "raw": text, "timestamp": timestamp,
            "user": user, "ip": ip, "port": int(port) if port else None,
            "method": None, "outcome": "invalid",
            "invalid_user": True,
        }

    match = _CLOSED_RE.search(text)
    if match:
        ip = match.group(1)
        if not is_valid_ipv4(ip):
            return None
        user_match = re.search(r"user (\S+)", text)
        return {
            "line_no": line_no, "raw": text, "timestamp": timestamp,
            "user": user_match.group(1) if user_match else None,
            "ip": ip, "port": None, "method": None,
            "outcome": "other", "invalid_user": False,
        }

    match = _GENERIC_FAILED_RE.search(text)
    if match:
        ip = match.group(1)
        if not is_valid_ipv4(ip):
            return None
        user_match = re.search(r"for (\S+) from", text)
        return {
            "line_no": line_no, "raw": text, "timestamp": timestamp,
            "user": user_match.group(1) if user_match else None,
            "ip": ip, "port": None, "method": None,
            "outcome": "failed", "invalid_user": False,
        }

    return None


def parse_log(text):
    """Parse a whole log. Returns (events, unparsed) where unparsed is a
    list of {"line_no": int, "raw": str} for lines that could not be
    parsed — including blank lines, which are skipped, not counted."""
    events = []
    unparsed = []
    for i, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        event = parse_line(line, line_no=i)
        if event is None:
            unparsed.append({"line_no": i, "raw": line.strip()[:200]})
        else:
            events.append(event)
    return events, unparsed


def max_in_window(timestamps, window_seconds):
    """Largest number of timestamps inside any sliding window.

    Correct sliding window (two pointers), not fixed buckets: events
    spread over more than the window do not count as one burst.
    """
    times = sorted(t for t in timestamps if t is not None)
    best = 0
    start = 0
    for end in range(len(times)):
        while (times[end] - times[start]).total_seconds() > window_seconds:
            start += 1
        best = max(best, end - start + 1)
    return best


def verdict_for_score(score, has_critical=False):
    """Verdict for a score. A critical finding forces at least High Risk,
    even when the points alone would only reach Suspicious."""
    if score >= 50:
        return "Malicious"
    if score >= 30 or has_critical:
        return "High Risk"
    if score >= 10:
        return "Suspicious"
    return "Safe"


def _fmt_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else None


def _finding(rule_id, severity, title, detail, ip=None, user=None,
             evidence=None, count=None):
    return {
        "rule_id": rule_id, "severity": severity, "title": title,
        "detail": detail, "ip": ip, "user": user,
        "evidence": evidence or [], "count": count,
        "points": SEVERITY_POINTS[severity],
    }


def analyze_log(text):
    """Analyse a log and return a JSON-serialisable result dict."""
    if text is None:
        raise ValueError("No log text supplied.")
    if len(text.encode("utf-8", errors="ignore")) > MAX_LOG_SIZE:
        raise ValueError("Log too large: limit is 2 MB.")
    if not text.strip():
        raise ValueError("Log is empty. Paste log text or upload a .log/.txt file.")

    events, unparsed = parse_log(text)
    total_lines = len([ln for ln in text.splitlines() if ln.strip()])

    failed = [e for e in events if e["outcome"] == "failed"]
    successful = [e for e in events if e["outcome"] == "success"]
    invalid_events = [e for e in events if e["invalid_user"]]
    other = [e for e in events if e["outcome"] == "other"]

    by_ip = defaultdict(list)
    by_user = defaultdict(list)
    for event in events:
        by_ip[event["ip"]].append(event)
        if event["user"]:
            by_user[event["user"]].append(event)

    failed_by_ip = defaultdict(list)
    for event in failed:
        failed_by_ip[event["ip"]].append(event)

    timed = [e["timestamp"] for e in events if e["timestamp"]]
    first_seen = min(timed) if timed else None
    last_seen = max(timed) if timed else None

    findings = []

    # ---- BRUTE-01: many failures from one IP in a short window ----
    for ip, evs in sorted(failed_by_ip.items()):
        stamps = [e["timestamp"] for e in evs]
        burst10 = max_in_window(stamps, 10 * 60)
        if burst10 >= 20 or len(evs) >= 50:
            findings.append(_finding(
                "BRUTE-01", "critical",
                "Brute-force burst from one IP",
                f"{ip} failed {len(evs)} times, with {burst10} failures "
                f"inside a single 10-minute window.",
                ip=ip, evidence=[e["raw"] for e in evs[:3]], count=len(evs)))
        elif burst10 >= 5:
            findings.append(_finding(
                "BRUTE-01", "high",
                "Many failures from one IP in 10 minutes",
                f"{ip} failed {burst10} times inside a single 10-minute "
                f"window ({len(evs)} failures in total).",
                ip=ip, evidence=[e["raw"] for e in evs[:3]], count=burst10))

    # ---- BRUTE-07: very fast failures from one IP (automated tool) ----
    for ip, evs in sorted(failed_by_ip.items()):
        burst1 = max_in_window([e["timestamp"] for e in evs], 60)
        if burst1 >= 10:
            findings.append(_finding(
                "BRUTE-07", "high",
                "Automated-speed failures from one IP",
                f"{ip} failed {burst1} times inside a single minute — "
                f"too fast for a human typing passwords.",
                ip=ip, evidence=[e["raw"] for e in evs[:3]], count=burst1))

    # ---- BRUTE-02: one IP tries many different usernames ----
    for ip, evs in sorted(by_ip.items()):
        tried = {e["user"] for e in evs
                 if e["outcome"] in ("failed", "invalid") and e["user"]}
        if len(tried) >= 10:
            findings.append(_finding(
                "BRUTE-02", "high",
                "One IP tried many different usernames",
                f"{ip} tried {len(tried)} different usernames — "
                f"credential stuffing or user enumeration.",
                ip=ip, evidence=sorted(tried)[:10], count=len(tried)))
        elif len(tried) >= 5:
            findings.append(_finding(
                "BRUTE-02", "medium",
                "One IP tried several different usernames",
                f"{ip} tried {len(tried)} different usernames.",
                ip=ip, evidence=sorted(tried)[:10], count=len(tried)))

    # ---- BRUTE-03: many IPs target one username ----
    for user, evs in sorted(by_user.items()):
        ips = {e["ip"] for e in evs if e["outcome"] in ("failed", "invalid")}
        if len(ips) >= 10:
            findings.append(_finding(
                "BRUTE-03", "high",
                "Many IPs target one username",
                f"{len(ips)} different IPs tried to log in as '{user}' — "
                f"password spraying or a distributed attack.",
                user=user, evidence=sorted(ips)[:10], count=len(ips)))
        elif len(ips) >= 5:
            findings.append(_finding(
                "BRUTE-03", "medium",
                "Several IPs target one username",
                f"{len(ips)} different IPs tried to log in as '{user}'.",
                user=user, evidence=sorted(ips)[:10], count=len(ips)))

    # ---- BRUTE-04: success after many failures from the same IP ----
    for ip, evs in sorted(by_ip.items()):
        fails_before = 0
        for event in sorted(evs, key=lambda e: (
                e["timestamp"] is None, e["timestamp"] or datetime.min,
                e["line_no"])):
            if event["outcome"] == "failed":
                fails_before += 1
            elif event["outcome"] == "success" and fails_before >= 5:
                findings.append(_finding(
                    "BRUTE-04", "critical",
                    "Login succeeded after many failures — possible compromise",
                    f"{ip} logged in as '{event['user']}' after "
                    f"{fails_before} failed attempts from the same IP. "
                    f"Treat this account as possibly compromised.",
                    ip=ip, user=event["user"],
                    evidence=[event["raw"]], count=fails_before))
                break

    # ---- BRUTE-05: invalid-user attempts ----
    if invalid_events:
        count = len(invalid_events)
        users = sorted({e["user"] for e in invalid_events if e["user"]})
        if count >= 10:
            findings.append(_finding(
                "BRUTE-05", "medium",
                "Many attempts with usernames that do not exist",
                f"{count} attempts used usernames that do not exist "
                f"({', '.join(users[:5])}) — the attacker is guessing "
                f"which accounts exist.",
                evidence=[e["raw"] for e in invalid_events[:3]], count=count))
        elif count >= 3:
            findings.append(_finding(
                "BRUTE-05", "low",
                "Some attempts with usernames that do not exist",
                f"{count} attempts used usernames that do not exist.",
                evidence=[e["raw"] for e in invalid_events[:3]], count=count))

    # ---- BRUTE-06: privileged users (root / admin) targeted ----
    privileged_fails = [e for e in failed if e["user"] in PRIVILEGED_USERS]
    if len(privileged_fails) >= 5:
        targets = sorted({e["user"] for e in privileged_fails})
        findings.append(_finding(
            "BRUTE-06", "medium",
            "Privileged account targeted",
            f"{len(privileged_fails)} failed logins targeted privileged "
            f"account(s): {', '.join(targets)} — root/admin are the "
            f"first accounts attackers try.",
            user=", ".join(targets),
            evidence=[e["raw"] for e in privileged_fails[:3]],
            count=len(privileged_fails)))

    # ---- Score, verdict, summary (BRUTE-08) ----
    total_points = sum(f["points"] for f in findings)
    score = min(total_points, 100)
    has_critical = any(f["severity"] == "critical" for f in findings)
    verdict = verdict_for_score(score, has_critical)

    summary = {
        "total_lines": total_lines,
        "parsed_lines": len(events),
        "unparsed_lines": len(unparsed),
        "failed": len(failed),
        "successful": len(successful),
        "invalid_user_attempts": len(invalid_events),
        "other_lines": len(other),
        "unique_ips": len(by_ip),
        "unique_users": len({e["user"] for e in events if e["user"]}),
        "first_seen": _fmt_ts(first_seen),
        "last_seen": _fmt_ts(last_seen),
    }
    findings.append(_finding(
        "BRUTE-08", "info", "Log summary",
        f"{total_lines} lines: {len(failed)} failed, {len(successful)} "
        f"successful, {len(invalid_events)} invalid-user attempts, "
        f"{len(by_ip)} unique IPs, {len(unparsed)} unparsed lines.",
        evidence=[], count=total_lines))

    # ---- Top IPs ----
    top_ips = []
    for ip, evs in by_ip.items():
        ip_fails = [e for e in evs if e["outcome"] == "failed"]
        ip_success = [e for e in evs if e["outcome"] == "success"]
        ip_stamps = [e["timestamp"] for e in evs if e["timestamp"]]
        burst10 = max_in_window([e["timestamp"] for e in ip_fails], 10 * 60)
        burst1 = max_in_window([e["timestamp"] for e in ip_fails], 60)
        tried = {e["user"] for e in evs
                 if e["outcome"] in ("failed", "invalid") and e["user"]}
        ip_score = 0
        ip_critical = False
        if burst10 >= 20 or len(ip_fails) >= 50:
            ip_score += 25
            ip_critical = True
        elif burst10 >= 5:
            ip_score += 15
        if burst1 >= 10:
            ip_score += 15
        if len(tried) >= 10:
            ip_score += 15
        elif len(tried) >= 5:
            ip_score += 8
        fails_before_success = 0
        for event in sorted(evs, key=lambda e: (
                e["timestamp"] is None, e["timestamp"] or datetime.min,
                e["line_no"])):
            if event["outcome"] == "failed":
                fails_before_success += 1
            elif event["outcome"] == "success" and fails_before_success >= 5:
                ip_score += 25
                ip_critical = True
                break
        ip_invalid = sum(1 for e in evs if e["invalid_user"])
        if ip_invalid >= 10:
            ip_score += 8
        elif ip_invalid >= 3:
            ip_score += 3
        if sum(1 for e in ip_fails if e["user"] in PRIVILEGED_USERS) >= 5:
            ip_score += 8
        ip_score = min(ip_score, 100)
        top_ips.append({
            "ip": ip,
            "failed": len(ip_fails),
            "successful": len(ip_success),
            "usernames": sorted(tried),
            "first_seen": _fmt_ts(min(ip_stamps)) if ip_stamps else None,
            "last_seen": _fmt_ts(max(ip_stamps)) if ip_stamps else None,
            "score": ip_score,
            "verdict": verdict_for_score(ip_score, ip_critical),
        })
    top_ips.sort(key=lambda row: (-row["score"], -row["failed"], row["ip"]))

    # ---- Timeline per hour (failed per hour) ----
    buckets = {}
    for event in events:
        if event["timestamp"] is None:
            continue
        key = event["timestamp"].strftime("%Y-%m-%d %H:00")
        bucket = buckets.setdefault(key, {"hour": key, "failed": 0,
                                          "successful": 0, "total": 0})
        bucket["total"] += 1
        if event["outcome"] == "failed":
            bucket["failed"] += 1
        elif event["outcome"] == "success":
            bucket["successful"] += 1
    timeline = [buckets[key] for key in sorted(buckets)]

    # ---- Recommendations (text only — nothing here is executed) ----
    recommendations = []
    if any(f["rule_id"] == "BRUTE-04" for f in findings):
        recommendations.append(
            "URGENT: an IP logged in after many failed attempts. Assume "
            "that account may be compromised: change its password, check "
            "what that account did afterwards, and revoke any keys or "
            "sessions you do not recognise.")
    if any(f["rule_id"] in ("BRUTE-01", "BRUTE-07") for f in findings):
        recommendations.append(
            "Block the attacking IPs at the firewall and consider "
            "fail2ban so repeated failures are banned automatically — "
            "this tool only analyses logs, it does not block anything.")
    if privileged_fails:
        recommendations.append(
            "Disable direct root login (PermitRootLogin no) and use a "
            "normal user with sudo instead.")
    if failed:
        recommendations.append(
            "Prefer SSH key authentication and disable password "
            "authentication (PasswordAuthentication no) where possible; "
            "at minimum, enforce long, unique passwords.")
        recommendations.append(
            "Rate-limit SSH (for example with fail2ban or a firewall "
            "rule) and, if the server does not need to be public, "
            "restrict SSH to known IPs or a VPN.")
    if invalid_events:
        recommendations.append(
            "Invalid-user attempts mean attackers are guessing account "
            "names. Do not confirm whether a username exists in login "
            "error messages, and remove unused accounts.")
    if not recommendations:
        recommendations.append(
            "Nothing suspicious was found in this log. Keep monitoring: "
            "review auth logs regularly and keep fail2ban or equivalent "
            "protection running.")
    recommendations.append(
        "Keep logs and review them regularly — an attack that is not "
        "in the log window you pasted will not show up here.")

    return {
        "score": score,
        "verdict": verdict,
        "has_critical": has_critical,
        "summary": summary,
        "findings": findings,
        "top_ips": top_ips,
        "timeline": timeline,
        "recommendations": recommendations,
        "unparsed": unparsed[:20],
    }
