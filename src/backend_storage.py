import socket, struct, argparse, os, sys, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from pqc_core import PQCKEM, PQCDSA
except ImportError:
    print("[!] Critical Error: 'pqc_core' module not found.")
    sys.exit(1)

def send_msg(sock, msg):
    sock.sendall(struct.pack('>I', len(msg)) + msg)

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data.extend(packet)
    return bytes(data)

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen: return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def start_backend_storage(listen_host="127.0.0.1", listen_port=5002, storage_dir="/app/data"):
    os.makedirs(storage_dir, exist_ok=True)
    
    print("[*] Initializing Backend Vault Static Keys...")
    vault_kem = PQCKEM()
    vault_pub_kem, vault_priv_kem = vault_kem.generate_keypair()

    vault_dsa = PQCDSA()
    vault_verify_key, vault_sign_key = vault_dsa.generate_sig_keypair()

    backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend_socket.bind((listen_host, listen_port))
    backend_socket.listen(5)
    print(f"[+] Backend Storage Engine active on {listen_host}:{listen_port}")

    while True:
        proxy_conn, addr = backend_socket.accept()
        try:
            header_bytes = recv_msg(proxy_conn)
            if not header_bytes: continue
            header = json.loads(header_bytes.decode('utf-8'))
            action, filename = header['action'].upper(), header['filename']
            filepath = os.path.join(storage_dir, filename)

            if action == "UPLOAD":
                plaintext_data = recv_msg(proxy_conn)

                # --- DATA-AT-REST ---
                # Use KEM of Vault to generate a AES key
                encapsulated_aes_key, aes_key = vault_kem.encapsulate_secret(vault_pub_kem)

                # Encrypt file with AES key
                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                encrypted_file = aesgcm.encrypt(nonce, plaintext_data, None)

                # Sign ML-DSA on encrypted file
                payload_to_sign = nonce + encrypted_file + encapsulated_aes_key
                digital_signature = vault_dsa.sign_message(payload_to_sign)

                # Write down to disk
                with open(filepath, 'wb') as f:
                    f.write(struct.pack('>I', len(digital_signature)))
                    f.write(digital_signature)
                    f.write(struct.pack('>I', len(encapsulated_aes_key)))
                    f.write(encapsulated_aes_key)
                    f.write(nonce)
                    f.write(encrypted_file)

                print(f"[#] STORAGE SECURED: '{filename}' wrapped in Quantum Envelope.")

            elif action == "DOWNLOAD":
                if not os.path.exists(filepath):
                    send_msg(proxy_conn, b"ERROR")
                else:
                    with open(filepath, 'rb') as f:
                        file_data = f.read()

                    # --- DECRYPT THE VAULT DATA ---
                    # Seperate fle structure
                    sig_len = struct.unpack('>I', file_data[:4])[0]
                    offset = 4
                    digital_signature = file_data[offset:offset+sig_len]
                    offset += sig_len

                    kem_len = struct.unpack('>I', file_data[offset:offset+4])[0]
                    offset += 4
                    encapsulated_aes_key = file_data[offset:offset+kem_len]
                    offset += kem_len

                    nonce = file_data[offset:offset+12]
                    offset += 12
                    encrypted_file = file_data[offset:]

                    # Check Integrity
                    payload_to_verify = nonce + encrypted_file + encapsulated_aes_key
                    if not vault_dsa.verify_signature(payload_to_verify, digital_signature, vault_verify_key):
                        print(f"[!] CRITICAL: Khóa file '{filename}' đã bị can thiệp!")
                        send_msg(proxy_conn, b"ERROR")
                        continue

                    # Unlock KEM take the AES Key and decrypt
                    aes_key = vault_kem.decapsulate_secret(encapsulated_aes_key)
                    aesgcm = AESGCM(aes_key)
                    plaintext_data = aesgcm.decrypt(nonce, encrypted_file, None)

                    send_msg(proxy_conn, b"SUCCESS")
                    send_msg(proxy_conn, plaintext_data)
                    print(f"[#] STORAGE RETRIEVED: '{filename}' successfully unwrapped.")

        except Exception as e:
            print(f"[!] Backend Processing Error: {e}")
        finally:
            proxy_conn.close()

if __name__ == "__main__":
    start_backend_storage(listen_host="0.0.0.0", listen_port=5000)
