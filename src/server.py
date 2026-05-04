import socket
import struct
import argparse
import os
import sys
import time
import json
import tracemalloc
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from benmark_logger import TransactionLogger
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from pqc_core import PQCKEM, HybridEncryption, PQCDSA
except ImportError:
    print("[!] Critical Error: 'pqc_core' module not found.")
    sys.exit(1)

def send_msg(sock, msg):
    sock.sendall(struct.pack('>I', len(msg)) + msg)

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def start_server(host, port, storage_dir):
    if not os.path.exists(storage_dir):
        os.makedirs(storage_dir)
    logger = TransactionLogger()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"[+] PQC Vault Daemon is listening on {host}:{port}")
        print(f"[+] Vault Directory: {storage_dir}")
    except Exception as e:
        print(f"[!] Socket initialization error: {e}")
        sys.exit(1)

    print("[*] Initializing Server Identity Key (ML-DSA)...")
    dsa_server = PQCDSA()
    server_verify_key, server_sign_key = dsa_server.generate_sig_keypair()
    print("[#] Server Identity Key is ready.")

    while True:
        conn, addr = server_socket.accept()
        tracemalloc.start()

        try:
            header_bytes = recv_msg(conn)
            if not header_bytes: continue
            header = json.loads(header_bytes.decode('utf-8'))

            action = header['action'].upper()
            filename = header['filename']
            crypto_mode = header.get('crypto_mode', 'pqc')
            filepath = os.path.join(storage_dir, filename)

            print(f"\n[{addr[0]}] Request: {action} '{filename}' | Mode: {crypto_mode.upper()}")

            t_keygen_ms, t_handshake_ms, t_enc_ms, t_dec_ms = 0.0, 0.0, 0.0, 0.0
            pub_key_size, sig_size, ciphertext_expansion, file_size = 0, 0, 0, 0
            suite_name, security_level = "", ""
            shared_secret = b''

            t_handshake_start = time.perf_counter()

            if crypto_mode == "classical":
                suite_name = "Classical"
                security_level = "128-bit"

                client_pk_bytes = recv_msg(conn)
                t_keygen_start = time.perf_counter()
                server_private_key = X25519PrivateKey.generate()
                server_public_key = server_private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
                )
                t_keygen_ms = (time.perf_counter() - t_keygen_start) * 1000
                pub_key_size = len(server_public_key)

                send_msg(conn, server_public_key)
                shared_secret = server_private_key.exchange(X25519PublicKey.from_public_bytes(client_pk_bytes))
            elif crypto_mode == "hybrid":
                suite_name = "Hybrid (X25519 + ML-KEM)"
                security_level = "Defense-in-Depth (Classical + Quantum-Safe)"

                client_pub_x25519_bytes = recv_msg(conn)
                client_pub_kem = recv_msg(conn)

                t_keygen_start = time.perf_counter()

                server_priv_x25519 = X25519PrivateKey.generate()
                server_pub_x25519 = server_priv_x25519.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
                )

                kem_server = PQCKEM()
                ciphertext_kem, ss_pqc = kem_server.encapsulate_secret(client_pub_kem)
                kem_server.free()
                t_keygen_ms = (time.perf_counter() - t_keygen_start) * 1000

                client_pub_x25519 = X25519PublicKey.from_public_bytes(client_pub_x25519_bytes)
                ss_classical = server_priv_x25519.exchange(client_pub_x25519)

                hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-vault-key")
                shared_secret = hkdf.derive(ss_classical + ss_pqc)

                signed_data = server_pub_x25519 + ciphertext_kem
                signature = dsa_server.sign_message(signed_data)

                sig_size = len(signature)
                pub_key_size = len(server_pub_x25519) + len(ciphertext_kem)

                send_msg(conn, server_pub_x25519)
                send_msg(conn, ciphertext_kem)
                send_msg(conn, server_verify_key)
                send_msg(conn, signature)
            else:
                suite_name = "PQC"
                security_level = "NIST Level 3"

                kem_pk_client = recv_msg(conn)
                kem_server = PQCKEM()

                t_keygen_start = time.perf_counter()
                ciphertext_kem, shared_secret = kem_server.encapsulate_secret(kem_pk_client)
                t_keygen_ms = (time.perf_counter() - t_keygen_start) * 1000
                kem_server.free()

                signature = dsa_server.sign_message(ciphertext_kem)
                sig_size = len(signature)
                pub_key_size = len(ciphertext_kem)

                send_msg(conn, server_verify_key)
                send_msg(conn, signature)
                send_msg(conn, ciphertext_kem)

            cipher = HybridEncryption(shared_secret)
            if action == "UPLOAD":
                print(f"[*] UPLOAD Command: Receiving ciphertext for '{filename}'...")
                payload = recv_msg(conn)
                nonce = payload[:12]
                encrypted_data = payload[12:]
                ciphertext_expansion = 28

                t_dec_start = time.perf_counter()
                decrypted_data = cipher.decrypt_data(nonce, encrypted_data)
                t_dec_ms = (time.perf_counter() - t_dec_start) * 1000

                file_size = len(decrypted_data)
                with open(filepath, 'wb') as f:
                    f.write(decrypted_data)
                print(f"[#] Data Integrity: VERIFIED. Saved to Vault.")

            elif action == "DOWNLOAD":
                print(f"[*] DOWNLOAD Command: Requesting access to '{filename}'...")
                if not os.path.exists(filepath):
                    send_msg(conn, b"ERROR|FILE_NOT_FOUND")
                else:
                    with open(filepath, 'rb') as f: raw_data = f.read()
                    file_size = len(raw_data)

                    t_enc_start = time.perf_counter()
                    nonce, encrypted_data = cipher.encrypt_data(raw_data)
                    t_enc_ms = (time.perf_counter() - t_enc_start) * 1000

                    payload = nonce + encrypted_data
                    ciphertext_expansion = len(payload) - file_size

                    send_msg(conn, b"SUCCESS")
                    send_msg(conn, payload)
                    print(f"[#] Quantum-resistant data exported ({len(payload)} bytes).")

            current_ram, peak_ram = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            logger.log_transaction(
                action=action, filename=filename, file_size=file_size,
                suite=suite_name, security_level=security_level,
                pub_key_size=pub_key_size, sig_size=sig_size, ciphertext_expansion=ciphertext_expansion,
                key_gen_time=t_keygen_ms, handshake_time=t_handshake_ms,
                enc_time=t_enc_ms, dec_time=t_dec_ms, peak_ram=(peak_ram / 1024)
            )

        except Exception as e:
            print(f"[!] Stream drop / Cryptography processing error: {e}")
            tracemalloc.stop()
        finally:
            conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Vault Server Daemon")
    parser.add_argument("--host", default="0.0.0.0", help="IP Interface")
    parser.add_argument("--port", type=int, default=5000, help="TCP Port")
    parser.add_argument("--storage", default="/app/data", help="Vault Storage Path")
    args = parser.parse_args()

    start_server(args.host, args.port, args.storage)
