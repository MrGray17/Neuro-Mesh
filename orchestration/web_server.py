#!/usr/bin/env python3
# ============================================================
# NEURO-MESH : SANITIZED WEB API
# ============================================================
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
import json
import os
import subprocess

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

@app.route('/api/data')
def api_data():
    try:
        with open('api.json', 'r') as f:
            return jsonify(json.load(f))
    except:
        return jsonify({"active_nodes": []})

# WHY: Eradicated shell=True and Popen vulnerabilities. 
# We explicitly call the hardened python module.
@app.route('/api/attack', methods=['POST'])
def api_attack():
    try:
        # Strictly executing the Python binary without invoking a bash shell
        subprocess.run(["python3", "neuro_ctl.py", "inject"], check=True)
        return jsonify({"status": "attack_launched", "message": "🔥 Attaque simulée en cours"})
    except subprocess.CalledProcessError:
        return jsonify({"status": "error", "message": "Failed to launch attack."}), 500

@app.route('/api/logs')
def api_logs():
    try:
        with open('api.json', 'r') as f:
            data = json.load(f)
            return jsonify(data.get('logs', []))
    except:
        return jsonify([])

@app.route('/api/status')
def api_status():
    return jsonify({
        "c2_online": os.path.exists('api.json'),
        "websocket_port": 8081,
        "dashboard_version": "4.0_SOVEREIGN"
    })

if __name__ == '__main__':
    print("🚀 NEURO-MESH Web Server démarré (Sanitized)")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
