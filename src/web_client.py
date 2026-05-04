import os
import requests
from flask import Flask, request, render_template_string, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from client import execute_vault_command

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = '/app/data'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PQC Vault - Enterprise Client</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .vault-card { margin: 15px auto; padding: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .crypto-panel { background-color: #212529; color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .log-box { background-color: #212529; color: #20c997; padding: 15px; border-radius: 5px; font-family: monospace; height: 130px; overflow-y: auto; }
        .table-wrapper { max-height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <h2 class="text-center mb-4">Post-Quantum Vault System</h2>

        <div class="crypto-panel d-flex justify-content-between align-items-center">
            <div>
                <h5 class="mb-0">Crypto-Agility Framework</h5>
                <small class="text-secondary">Real-time security protocol switching</small>
            </div>
            <select id="cryptoMode" class="form-select w-auto bg-dark text-white border-secondary">
                <option value="pqc">Post-Quantum</option>
                <option value="classical">Classical</option>
                <option value="hybrid">Hybrid</option>
            </select>
        </div>

        <div class="row">
            <div class="col-md-5">
                <div class="card vault-card h-100">
                    <h5>Upload to Vault</h5>
                    <hr>
                    <form id="uploadForm">
                        <div class="mb-3">
                            <label class="form-label">Select files:</label>
                            <input class="form-control" type="file" id="fileInput" multiple required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100" id="submitBtn">Encrypt & Upload</button>
                    </form>
                    <div class="mt-4">
                        <h6>Protocol Log:</h6>
                        <div class="log-box" id="statusLog">[System] Ready...<br></div>
                    </div>
                </div>
            </div>

            <div class="col-md-7">
                <div class="card vault-card h-100">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <h5>Explore Vault</h5>
                        <button class="btn btn-sm btn-outline-secondary" onclick="fetchFiles()"> Explore </button>
                    </div>

                    <div class="row mb-3">
                        <div class="col-md-7">
                            <input type="text" id="searchInput" class="form-control" placeholder="Enter filename..." onkeyup="renderTable()">
                        </div>
                        <div class="col-md-5">
                            <select id="sortSelect" class="form-select" onchange="renderTable()">
                                <option value="name_asc">Name (A-Z)</option>
                                <option value="size_desc">Largest first</option>
                            </select>
                        </div>
                    </div>

                    <div class="table-wrapper">
                        <table class="table table-hover align-middle">
                            <thead class="table-dark">
                                <tr>
                                    <th>Filename</th>
                                    <th>Size</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="fileTableBody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let serverFiles = [];

        async function fetchFiles() {
            try {
                const res = await fetch('/api/server_files');
                serverFiles = await res.json();
                renderTable();
            } catch (e) { console.error(e); }
        }

        function renderTable() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const sortBy = document.getElementById('sortSelect').value;
            let filtered = serverFiles.filter(f => f.name.toLowerCase().includes(query));
            filtered.sort((a, b) => sortBy === 'name_asc' ? a.name.localeCompare(b.name) : b.size - a.size);

            const tbody = document.getElementById('fileTableBody');
            tbody.innerHTML = '';
            filtered.forEach(f => {
                const sizeKB = (f.size / 1024).toFixed(2);
                tbody.innerHTML += `
                    <tr>
                        <td><strong>${f.name}</strong></td>
                        <td>${sizeKB} KB</td>
                        <td>
                            <button class="btn btn-sm btn-success" onclick="downloadFile('${f.name}')">⬇ Download</button>
                        </td>
                    </tr>
                `;
            });
        }

        async function downloadFile(filename) {
            const logBox = document.getElementById('statusLog');
            const mode = document.getElementById('cryptoMode').value;
            logBox.innerHTML += `[*] Initializing Download (${mode.toUpperCase()})...<br>`;
            logBox.scrollTop = logBox.scrollHeight;

            try {
                const res = await fetch('/api/download', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filename: filename, crypto_mode: mode })
                });
                const result = await res.json();

                if(res.ok) {
                    logBox.innerHTML += `<span style="color: #198754">[+] Decryption successful!</span><br>`;
                    window.location.href = '/download_to_windows/' + result.saved_as;
                } else {
                    logBox.innerHTML += `<span style="color: #dc3545">[!] Error: ${result.message}</span><br>`;
                }
            } catch (e) {}
        }

        document.getElementById('uploadForm').onsubmit = async function(e) {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const logBox = document.getElementById('statusLog');
            const mode = document.getElementById('cryptoMode').value;

            const files = document.getElementById('fileInput').files; 

            btn.disabled = true;
            btn.innerText = 'Processing...';
            logBox.innerHTML += `<br>[*] Start uploading (${files.length} files) - Mode: ${mode.toUpperCase()}<br>`;

            for (let i = 0;i < files.length; i++) {
                let file = files[i]
                let formData = new FormData();
                formData.append("file", file);
                formData.append("crypto_mode", mode);

                logBox.innerHTML += `>> Processing [${i+1}/${files.length}]: ${file.name}...<br>`;
                logBox.scrollTop = logBox.scrollHeight;

                try {
                    const res = await fetch('/api/upload', { method: "POST", body: formData });
                    if(res.ok) {
                        logBox.innerHTML += `<span style="color: #198754">[+] Success: ${file.name}</span><br>`;
                    } else {
                        const result = await res.json();
                        logBox.innerHTML += `<span style="color: #dc3545">[!] Error ${file.name}: ${result.message}</span><br>`;
                    }
                } catch (error) {
                    logBox.innerHTML += `<span style="color: #dc3545">[!] Network error while uploading ${file.name}</span><br>`;
                }
            }
            logBox.innerHTML += `<span style="color: #0dcaf0">[*] Upload complete!</span><br>`;
            logBox.scrollTop = logBox.scrollHeight;

            btn.disabled = false;
            btn.innerText = "Encrypt & Upload";
        };

    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/server_files', methods=['GET'])
def get_server_files():
    try:
        resp = requests.get('http://pqc_proxy:8090/api/files', timeout=5)
        return jsonify(resp.json())
    except Exception:
        return jsonify([])

@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files: return jsonify({"error": "No file"}), 400
    file = request.files['file']
    crypto_mode = request.form.get('crypto_mode', 'pqc')

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        execute_vault_command("pqc_proxy", 8080, "upload", filename, app.config['UPLOAD_FOLDER'], crypto_mode)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/download', methods=['POST'])
def api_download():
    data = request.json
    filename = data.get('filename')
    crypto_mode = data.get('crypto_mode', 'pqc')

    try:
        execute_vault_command("pqc_proxy", 8080, "download", filename, app.config['UPLOAD_FOLDER'], crypto_mode)
        return jsonify({"status": "success", "saved_as": filename})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/download_to_windows/<filename>')
def serve_file_to_windows(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
