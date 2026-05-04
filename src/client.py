import socket
import struct
import argparse
import os
import sys
import json
import time
import tracemalloc
from benmark_logger import TransactionLogger
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
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

def execute_vault_command(target_host, target_port, action, filename, data_dir, crypto_mode="pqc"):
    logger = TransactionLogger()
    tracemalloc.start()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        print(f"[*] Initializing connection to {target_host}:{target_port}...")
        client_socket.connect((target_host, target_port))
        header = json.dumps({"action": action, "filename": filename, "crypto_mode": crypto_mode}).encode('utf-8')
        send_msg(client_socket, header)

        t_keygen_ms = 0.0
        t_handshake_ms = 0.0
        t_enc_ms = 0.0
        t_dec_ms = 0.0
        pub_key_size = 0
        sig_size = 0
        ciphertext_expansion = 0
        security_level = ""
        suite_name = ""
        shared_secret = b''

        t_handshake_start = time.perf_counter()

        if crypto_mode == "classical":
            suite_name = "Classical"
            security_level = "128-bit"
            
            t_keygen_start = time.perf_counter()
            client_private_key = X25519PrivateKey.generate()
            client_public_key = client_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
            t_keygen_ms = (time.perf_counter() - t_keygen_start) * 1000

            pub_key_size = len(client_public_key)
            send_msg(client_socket, client_public_key)

            server_public_key_bytes = recv_msg(client_socket)
            server_public_key = X25519PublicKey.from_public_bytes(server_public_key_bytes)
            shared_secret = client_private_key.exchange(server_public_key)

        elif crypto_mode == "hybrid":
            suite_name = "Hybrid"
            security_level = "Defense-in-Depth"

            t_keygen_start = time.perf_counter()

            client_priv_x25519 = X25519PrivateKey.generate()
            client_pub_x25519 = client_priv_x25519.public_key().public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
            kem_client = PQCKEM()
            client_pub_kem, _ = kem_client.generate_keypair()
            t_keygen_ms = (time.perf_counter() - t_keygen_start) * 1000

            pub_key_size = len(client_pub_x25519) + len(client_pub_kem)

            send_msg(client_socket, client_pub_x25519)
            send_msg(client_socket, client_pub_kem)

            server_pub_x25519_bytes = recv_msg(client_socket)
            ciphertext_kem = recv_msg(client_socket)
            server_verify_key = recv_msg(client_socket) 
            signature = recv_msg(client_socket)
            sig_size = len(signature)

            dsa_verifier = PQCDSA()
            signed_data = server_pub_x25519_bytes + ciphertext_kem
            is_valid = dsa_verifier.verify_signature(signed_data, signature, server_verify_key)
            dsa_verifier.free()
            if not is_valid: raise ConnectionError("INVALID HYBRID SIGNATURE!")

            server_pub_x25519 = X25519PublicKey.from_public_bytes(server_pub_x25519_bytes)
            ss_classical = client_priv_x25519.exchange(server_pub_x25519)
            ss_pqc = kem_client.decapsulate_secret(ciphertext_kem)
            kem_client.free()

            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-vault-key")
            shared_secret = hkdf.derive(ss_classical + ss_pqc)

        else: 
            suite_name = "PQC"
            security_level = "NIST Level 3"
            
            t_keygen_start = time.perf_counter()
            kem_client = PQCKEM()
            public_key_kem, _ = kem_client.generate_keypair()
            t_keygen_ms = (time.perf_counter() - t_keygen_start) * 1000
            
            pub_key_size = len(public_key_kem)
            send_msg(client_socket, public_key_kem)

            server_verify_key = recv_msg(client_socket)
            signature = recv_msg(client_socket)
            ciphertext_kem = recv_msg(client_socket)
            sig_size = len(signature)

            dsa_verifier = PQCDSA()
            is_valid = dsa_verifier.verify_signature(ciphertext_kem, signature, server_verify_key)
            dsa_verifier.free()

            if not is_valid: raise ConnectionError("INVALID PQC SIGNATURE!")
            shared_secret = kem_client.decapsulate_secret(ciphertext_kem)
            kem_client.free()

        t_handshake_ms = (time.perf_counter() - t_handshake_start) * 1000
        print(f"[#] Handshake success ({suite_name}).")

        cipher = HybridEncryption(shared_secret)
        filepath = os.path.join(data_dir, filename)
        file_size = 0

        if action == "upload":
            if not os.path.exists(filepath): return
            file_size = os.path.getsize(filepath)
            with open(filepath, 'rb') as f: raw_data = f.read()

            t_enc_start = time.perf_counter()
            nonce, encrypted_data = cipher.encrypt_data(raw_data)
            t_enc_ms = (time.perf_counter() - t_enc_start) * 1000

            payload = nonce + encrypted_data
            ciphertext_expansion = len(payload) - file_size
            send_msg(client_socket, payload)
            print(f"[#] Upload: File {file_size} bytes encryption - {t_enc_ms:.2f} ms")

        elif action == "download":
            status = recv_msg(client_socket).decode('utf-8')
            if "ERROR" in status: return
            
            payload = recv_msg(client_socket)
            nonce = payload[:12]
            encrypted_file_data = payload[12:]
            ciphertext_expansion = 28

            t_dec_start = time.perf_counter()
            decrypted_data = cipher.decrypt_data(nonce, encrypted_file_data)
            t_dec_ms = (time.perf_counter() - t_dec_start) * 1000
            
            file_size = len(decrypted_data)
            with open(filepath, 'wb') as f: f.write(decrypted_data)
            print(f"[#] Download: File {file_size} bytes decryption - {t_dec_ms:.2f} ms")

        current_ram, peak_ram = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        logger.log_transaction(
            action=action, filename=filename, file_size=file_size,
            suite=suite_name, security_level=security_level,
            pub_key_size=pub_key_size, sig_size=sig_size, ciphertext_expansion=ciphertext_expansion,
            key_gen_time=t_keygen_ms, handshake_time=t_handshake_ms,
            enc_time=t_enc_ms, dec_time=t_dec_ms, peak_ram=(peak_ram / 1024)
        )
    except ConnectionRefusedError:
        print(f"[!] Network Error: Unable to connect to {target_host}:{target_port}.")
    except Exception as e:
        print(f"[!] Unknown process error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Vault Client Interface")
    parser.add_argument("--action", choices=['upload', 'download'], required=True,
                        help="Action: send (Upload) or receive (Download)")
    parser.add_argument("--target", required=True,
                        help="IP:Port of HAProxy or Server (e.g., pqc_proxy:8080)")
    parser.add_argument("--file", required=True, help="Filename")
    parser.add_argument("--dir", default="/app/data", help="Local working directory")

    args = parser.parse_args()

    try:
        host, port_str = args.target.split(':')
        port = int(port_str)
    except ValueError:
        print("[!] Error: --target parameter must be in HOST:PORT format")
        sys.exit(1)

    execute_vault_command(host, port, args.action, args.file, args.dir)
