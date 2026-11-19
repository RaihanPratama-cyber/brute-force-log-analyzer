// Brute-Force Log Analyzer — UI rendering.
// All content is inserted with textContent / createElement only.
// Raw HTML insertion is never used: log lines are untrusted input.
(function () {
  "use strict";

  var form = document.getElementById("analyze-form");
  var logText = document.getElementById("log-text");
  var logFile = document.getElementById("log-file");
  var errorBox = document.getElementById("error");
  var resultBox = document.getElementById("result");

  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
    resultBox.hidden = true;
  }

  function row(table, cells) {
    var tr = document.createElement("tr");
    cells.forEach(function (value) {
      tr.appendChild(el("td", value));
    });
    table.appendChild(tr);
  }

  function headerRow(table, cells) {
    var tr = document.createElement("tr");
    cells.forEach(function (value) {
      tr.appendChild(el("th", value));
    });
    table.appendChild(tr);
  }

  function render(result) {
    errorBox.hidden = true;
    resultBox.hidden = false;

    var verdict = document.getElementById("verdict");
    clear(verdict);
    verdict.appendChild(el("span", result.verdict + " — score " + result.score + " / 100"));

    document.getElementById("score-line").textContent =
      "Verdict is based on the findings below. Any critical finding forces at least High Risk.";

    var summary = document.getElementById("summary-table");
    clear(summary);
    var s = result.summary;
    headerRow(summary, ["Measure", "Value"]);
    row(summary, ["Total lines", String(s.total_lines)]);
    row(summary, ["Parsed lines", String(s.parsed_lines)]);
    row(summary, ["Unparsed lines", String(s.unparsed_lines)]);
    row(summary, ["Failed logins", String(s.failed)]);
    row(summary, ["Successful logins", String(s.successful)]);
    row(summary, ["Invalid-user attempts", String(s.invalid_user_attempts)]);
    row(summary, ["Unique IPs", String(s.unique_ips)]);
    row(summary, ["Unique usernames", String(s.unique_users)]);
    row(summary, ["First seen", s.first_seen || "-"]);
    row(summary, ["Last seen", s.last_seen || "-"]);

    var findings = document.getElementById("findings");
    clear(findings);
    result.findings.forEach(function (f) {
      var li = document.createElement("li");
      var badge = el("span", f.severity.toUpperCase(), "badge " + f.severity);
      li.appendChild(badge);
      li.appendChild(document.createTextNode(" " + f.rule_id + " — " + f.title + " (" + f.points + " pts). "));
      li.appendChild(document.createTextNode(f.detail));
      if (f.evidence && f.evidence.length) {
        var sub = document.createElement("ul");
        f.evidence.slice(0, 3).forEach(function (line) {
          sub.appendChild(el("li", line));
        });
        li.appendChild(sub);
      }
      findings.appendChild(li);
    });

    var topIps = document.getElementById("top-ips-table");
    clear(topIps);
    headerRow(topIps, ["IP", "Failed", "Successful", "Usernames tried", "First seen", "Last seen", "Score", "Verdict"]);
    result.top_ips.forEach(function (t) {
      row(topIps, [t.ip, String(t.failed), String(t.successful),
        t.usernames.join(", ") || "-", t.first_seen || "-",
        t.last_seen || "-", String(t.score), t.verdict]);
    });

    var timeline = document.getElementById("timeline-table");
    clear(timeline);
    headerRow(timeline, ["Hour", "Failed", "Successful", "Total"]);
    result.timeline.forEach(function (b) {
      row(timeline, [b.hour, String(b.failed), String(b.successful), String(b.total)]);
    });

    var bars = document.getElementById("timeline-bars");
    clear(bars);
    var maxFailed = 0;
    result.timeline.forEach(function (b) { if (b.failed > maxFailed) maxFailed = b.failed; });
    result.timeline.forEach(function (b) {
      var line = document.createElement("div");
      line.className = "bar-row";
      line.appendChild(el("span", b.hour + " — " + b.failed + " failed", "bar-label"));
      var bar = document.createElement("div");
      bar.className = "bar";
      bar.style.width = (maxFailed ? (b.failed / maxFailed) * 220 : 0) + "px";
      line.appendChild(bar);
      bars.appendChild(line);
    });

    var recs = document.getElementById("recommendations");
    clear(recs);
    result.recommendations.forEach(function (r) {
      recs.appendChild(el("li", r));
    });

    document.getElementById("unparsed-note").textContent =
      result.summary.unparsed_lines + " line(s) could not be parsed and were counted, not dropped.";
    var unparsed = document.getElementById("unparsed");
    clear(unparsed);
    result.unparsed.forEach(function (u) {
      unparsed.appendChild(el("li", "Line " + u.line_no + ": " + u.raw));
    });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var data = new FormData();
    if (logFile.files.length) {
      data.append("log_file", logFile.files[0]);
    } else {
      data.append("log_text", logText.value);
    }
    fetch("/analyze", { method: "POST", body: data })
      .then(function (resp) { return resp.json().then(function (body) { return { ok: resp.ok, body: body }; }); })
      .then(function (pair) {
        if (!pair.ok) { showError(pair.body.error || "Analysis failed."); return; }
        render(pair.body);
      })
      .catch(function () { showError("Could not reach the analyzer. Is the app running?"); });
  });

  document.querySelectorAll(".example-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      fetch("/api/example/" + btn.getAttribute("data-name"))
        .then(function (resp) { return resp.json(); })
        .then(function (body) {
          logText.value = body.log_text || "";
          logFile.value = "";
          errorBox.hidden = true;
        })
        .catch(function () { showError("Could not load the example."); });
    });
  });
})();
