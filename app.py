"""Brute-Force Log Analyzer — Flask web app.

Paste an SSH auth log (or upload a .log/.txt file, max 2 MB) and get a
verdict, findings with evidence, top attacker IPs, and a per-hour
timeline. The log is only read as text: nothing in it is executed, and
no network request is made during analysis.
"""

import os

from flask import Flask, jsonify, render_template, request

from analyzer import MAX_LOG_SIZE, analyze_log

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_LOG_SIZE + 1024

EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "data", "examples")
ALLOWED_EXAMPLES = {"benign.log", "attack.log"}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/example/<name>")
def example(name):
    if name not in ALLOWED_EXAMPLES:
        return jsonify({"error": "Unknown example."}), 404
    path = os.path.join(EXAMPLES_DIR, name)
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return jsonify({"error": "Example not available."}), 404
    return jsonify({"name": name, "log_text": text})


@app.route("/analyze", methods=["POST"])
def analyze():
    text = ""
    uploaded = request.files.get("log_file")
    if uploaded is not None and uploaded.filename:
        data = uploaded.read(MAX_LOG_SIZE + 1)
        if len(data) > MAX_LOG_SIZE:
            return jsonify(
                {"error": "File too large: limit is 2 MB."}), 413
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return jsonify(
                {"error": "File is not valid UTF-8 text."}), 400
    elif request.form.get("log_text"):
        text = request.form["log_text"]
    elif request.is_json and request.get_json(silent=True):
        text = request.get_json().get("log_text", "") or ""
    if not text or not text.strip():
        return jsonify({"error": "Log is empty. Paste log text or upload "
                                 "a .log/.txt file."}), 400
    try:
        result = analyze_log(text)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(result)


@app.errorhandler(413)
def too_large(_exc):
    return jsonify({"error": "File too large: limit is 2 MB."}), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
