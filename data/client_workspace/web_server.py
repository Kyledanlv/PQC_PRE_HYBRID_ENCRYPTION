import os
import time
from flask import Flask, render_template_string, jsonify
import subprocess
import threading

from proxy_edge import start_pqc_proxy
from backend_storage import start_backend_storage

app = Flask(__name__)
app.config['VAULT_FOLDER'] = '/app/data'

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PQC Vault - Server Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <meta http-equiv="refresh" content="5">
</head>
<body class="bg-dark text-light" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
    <div class="container mt-5">
        <h2 class="text-center text-success mb-4">🖥️ Server Vault Dashboard</h2>
        
        <div class="card bg-secondary text-light shadow-lg border-0">
            <div class="card-body">
                <h5 class="card-title border-bottom pb-2">📂 Protected Data (/app/data)</h5>
                <table class="table table-dark table-hover mt-3">
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Size (Bytes)</th>
                            <th>Crypto Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in files %}
                        <tr>
                            <td><strong>{{ file.name }}</strong></td>
                            <td>{{ file.size }}</td>
                            <td><span class="badge bg-success">🔒 Locked (Encrypted)</span></td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="3" class="text-center text-muted py-4">
                                <em>Vault is empty. Waiting for data from Client...</em>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="mt-4 text-center text-muted">
            <small>System auto-refreshes every 5 seconds.</small>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def dashboard():
    files_info = []
    if os.path.exists(app.config['VAULT_FOLDER']):
        for filename in os.listdir(app.config['VAULT_FOLDER']):
            if filename != "traffic_benchmark.csv":
                filepath = os.path.join(app.config['VAULT_FOLDER'], filename)
                if os.path.isfile(filepath):
                    files_info.append({
                        "name": filename,
                        "size": f"{os.path.getsize(filepath):,}"
                    })
    
    return render_template_string(HTML_TEMPLATE, files=files_info)

@app.route('/api/files', methods=['GET'])
def api_files():
    files_info = []
    if os.path.exists(app.config['VAULT_FOLDER']):
        for filename in os.listdir(app.config['VAULT_FOLDER']):
            if filename != "traffic_benchmark.csv":
                filepath = os.path.join(app.config['VAULT_FOLDER'], filename)
                if os.path.isfile(filepath):
                    files_info.append({
                        "name": filename,
                        "size": os.path.getsize(filepath)
                    })
    return jsonify(files_info)

def run_backend():
    print("[*] Start Vault Backend (Port 5002)...")
    start_backend_storage(listen_host="127.0.0.1", listen_port=5002, storage_dir="/app/data")

def run_proxy():
    print("[*] Start PQC Edge Proxy (Port 5000)...")
    time.sleep(2) 
    start_pqc_proxy(listen_host="0.0.0.0", listen_port=5000, backend_host="127.0.0.1", backend_port=5002)

if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        threading.Thread(target=run_backend, daemon=True).start()
        threading.Thread(target=run_proxy, daemon=True).start()

    app.run(host='0.0.0.0', port=5001, debug=True)
