# Brute-Force Log Analyzer

Paste an SSH auth log and find out whether someone tried to brute-force
their way into the server — and whether they got in.

Someone (or something) hammering `sshd` with password guesses leaves a
very recognisable trail in `/var/log/auth.log`: the same IP failing over
and over, trying username after username, sometimes succeeding after
dozens of failures. This tool reads that log, explains the pattern in
plain language, and shows the evidence — which IP, which usernames, how
fast, and in what time window — plus what to do about it.

It is the log-analysis companion to
[soc-dashboard-network-intrusion-detector](https://github.com/RaihanPratama-cyber/soc-dashboard-network-intrusion-detector):
that project watches live network attacks, this one reads the
authentication log after the fact.

Built as a portfolio project by **Raihan Pratama** (Politeknik Caltex Riau,
Teknologi Rekayasa Komputer, 3 TRK A).

> ⚠️ **A verdict is a pattern assessment, not proof.** "Malicious" means
> the log looks like a brute-force attack. "Safe" means nothing suspicious
> was found by these checks, not that the server is safe. This tool only
> reads logs — it does not block any IP, and it is not a replacement for
> fail2ban or an IDS.

## What it checks

| Rule | What it looks for |
| --- | --- |
| BRUTE-01 | Many failures from one IP in a short window: ≥5 in 10 minutes = high; ≥20 in 10 minutes or ≥50 total = critical (true sliding window, not fixed buckets) |
| BRUTE-02 | One IP tries many different usernames: ≥5 = medium, ≥10 = high (credential stuffing / user enumeration) |
| BRUTE-03 | Many different IPs target one username: ≥5 = medium, ≥10 = high (password spraying / distributed attack) |
| BRUTE-04 | Login succeeds after many failures from the same IP: success after ≥5 failures = **critical**, possible compromise — the most important finding |
| BRUTE-05 | Attempts with usernames that do not exist: ≥3 = low, ≥10 = medium |
| BRUTE-06 | Privileged accounts targeted: ≥5 failed logins to `root` / `admin` = medium |
| BRUTE-07 | Automated speed: ≥10 failures in one minute from one IP = high |
| BRUTE-08 | Log summary (info): total lines, failures, successes, unique IPs/users, time range, unparsed lines |

## How scoring works

Each finding adds points by severity: critical 25, high 15, medium 8,
low 3, info 0. The total is capped at 100.

| Score | Verdict |
| --- | --- |
| 0–9 | Safe |
| 10–29 | Suspicious |
| 30–49 | High Risk |
| 50–100 | Malicious |

Any single critical finding forces the verdict to at least High Risk,
even if the points alone would only reach Suspicious. Every IP also gets
its own score and verdict in the Top IPs table, using the same scale.

## How to run it

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

## How to use it

1. Paste log text into the textarea, or upload a `.log` / `.txt` file
   (max 2 MB — larger files are rejected with a clear message).
2. Or click **Load attack example** / **Load normal example** to try it
   without a real log.
3. Read the verdict, then the findings — each one shows the evidence
   (example log lines, counts, time window) and the Top IPs table shows
   who attacked, how often, and what they tried.
4. Follow the recommendations (block the IP, set up fail2ban, disable
   password auth / root login). The recommendations are text only —
   nothing here executes them for you.

## Examples

- `data/examples/benign.log` — a normal morning: three users logging in
  successfully, two mistyped passwords. Scans **Safe, score 0**.
- `data/examples/attack.log` — a realistic brute-force attack from
  several IPs; the main attacker tries 28 passwords (including `root`)
  in under 10 minutes and then logs in as `root`. Scans **Malicious,
  score 100**, with a critical BRUTE-04 finding.

Both examples are fictional: the dates are made up and the attacker IPs
are from the documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`,
`192.0.2.0/24`), which are reserved for examples and never belong to a
real machine. The normal log uses private LAN addresses
(`192.168.1.x`).

## Supported log format

OpenSSH `sshd` syslog lines, for example:

```
Nov 19 02:10:02 server sshd[3001]: Failed password for root from 203.0.113.45 port 51234 ssh2
Nov 19 02:10:02 server sshd[3001]: Failed password for invalid user test from 203.0.113.45 port 51234 ssh2
Nov 19 02:19:41 server sshd[3029]: Accepted password for root from 203.0.113.45 port 51234 ssh2
Nov 19 02:19:41 server sshd[3029]: Accepted publickey for dina from 192.168.1.12 port 53120 ssh2
Nov 19 02:10:02 server sshd[3001]: Invalid user nosuch from 203.0.113.45 port 51234
Nov 19 02:10:02 server sshd[3001]: Connection closed by 203.0.113.45 port 51234 [preauth]
```

A generic `Failed ... from <IP>` line is also recognised as a fallback.
Lines that cannot be parsed are counted as unparsed (and shown, up to
20 of them) — never silently dropped, never a crash.

## Tests

```bash
pytest -q
```

56 tests, covering: parsing of every line format, invalid IPv4
rejection, every rule at and below its exact threshold, the 10-minute
and 1-minute sliding windows (failures spread beyond the window do not
count as a burst), BRUTE-04 with and without prior failures, scoring,
the 100-point cap, critical forcing High Risk, all verdict boundaries,
both example logs, the Flask endpoints, and an offline check (no
`socket` / `requests` / `urllib` imports anywhere in `analyzer.py` or
`app.py`).

## Safety design

- The log is **only read as text**: nothing in it is executed, no file
  is written, and no IP is blocked.
- It makes **no network requests**: no reputation lookup, no external
  service. The analysis is 100% offline (the core module uses only the
  Python standard library).
- The UI renders all results with `textContent` / `createElement`
  only — `innerHTML` is never used, so a hostile log line cannot inject
  HTML or script into the page.
- No CDN, no external JavaScript library, no request from the browser
  to anywhere except this app itself.

## Limits (read this before trusting a verdict)

- Static log analysis only: it reads a log you paste, it does not watch
  a live server, block IPs, or replace fail2ban / an IDS.
- Syslog lines carry no year, so timestamps are assumed to be in the
  current year. Logs in a different format may be partly unparsed —
  check the unparsed count before trusting a Safe verdict.
- A successful login after failures can also have an innocent
  explanation (a user mistyping, then remembering the password). The
  tool flags the pattern; a human decides whether the account is
  compromised.
- An attack outside the log window you pasted will not show up here.
- A Safe verdict means "nothing suspicious was found by these checks",
  not "this server is safe".
