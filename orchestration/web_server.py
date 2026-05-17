#!/usr/bin/env python3
# ============================================================
# NEURO-MESH : SANITIZED WEB API
# ============================================================
from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
import json
import os
import subprocess
import secrets

app = Flask(__name__)
CORS(app)

API_TOKEN = os.environ.get("NEURO_API_TOKEN", secrets.token_hex(32))


@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")


@app.route("/<path:path>")
def static_files(path):
    safe_path = os.path.normpath(path)
    if safe_path.startswith("..") or os.path.isabs(safe_path):
        return jsonify({"error": "forbidden"}), 403
    return send_from_directory("dashboard", safe_path)


@app.route("/api/data")
def api_data():
    try:
        with open("api.json", "r") as f:
            return jsonify(json.load(f))
    except Exception:
        return jsonify({"active_nodes": []})


# Uses explicit Python module invocation instead of shell=True.
@app.route("/api/attack", methods=["POST"])
def api_attack():
    token = request.headers.get("X-Neuro-Token", "")
    if not token or not secrets.compare_digest(token, API_TOKEN):
        return jsonify({"status": "unauthorized"}), 401
    try:
        subprocess.run(["python3", "neuro_ctl.py", "inject"], check=True)
        return jsonify(
            {"status": "attack_launched", "message": "Simulated event in progress"}
        )
    except subprocess.CalledProcessError:
        return jsonify({"status": "error", "message": "Failed to launch attack."}), 500


@app.route("/api/logs")
def api_logs():
    try:
        with open("api.json", "r") as f:
            data = json.load(f)
            return jsonify(data.get("logs", []))
    except Exception:
        return jsonify([])


@app.route("/api/status")
def api_status():
    return jsonify(
        {
            "c2_online": os.path.exists("api.json"),
            "websocket_port": 8081,
            "dashboard_version": "4.0",
        }
    )


if __name__ == "__main__":
    print("Neuro-Mesh Web Server started")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
