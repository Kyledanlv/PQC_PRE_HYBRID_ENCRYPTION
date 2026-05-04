import socket, struct, argparse, os, sys, json, time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
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
        if not packet: return None
        data.extend(packet)
    return bytes(data)

def recv_msg(sock):
    raw_msglen = recvall(sock, 4)
    if not raw_msglen: return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def start_pqc_proxy(listen_host="0.0.0.0", listen_port=5000, backend_host="127.0.0.1", backend_port=5002):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((listen_host, listen_port))
    proxy_socket.listen(5)

    print("[*] Initializing Proxy Edge Identity Key (ML-DSA)...")
    dsa_proxy = PQCDSA()
    proxy_verify_key, proxy_sign_key = dsa_proxy.generate_sig_keypair()
    print(f"[+] PQC Proxy Offloader active on {listen_host}:{listen_port}")

    while True:
        client_conn, addr = proxy_socket.accept()
        try:
            # Receive packet from client
            header_bytes = recv_msg(client_conn)
            if not header_bytes: continue
            header = json.loads(header_bytes.decode('utf-8'))
            action, filename, crypto_mode = header['action'].upper(), header['filename'], header.get('crypto_mode', 'pqc')
            print(f"\n[{addr[0]}] Edge Routing: {action} '{filename}' | Crypto-Agility: {crypto_mode.upper()}")

            # Key transfer
            shared_secret = b''

            if crypto_mode == "classical":
                client_pk_bytes = recv_msg(client_conn)
                proxy_priv_x = X25519PrivateKey.generate()
                proxy_pub_x = proxy_priv_x.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                send_msg(client_conn, proxy_pub_x)
                shared_secret = proxy_priv_x.exchange(X25519PublicKey.from_public_bytes(client_pk_bytes))

            elif crypto_mode == "hybrid":
                client_pub_x = recv_msg(client_conn)
                client_pub_kem = recv_msg(client_conn)

                proxy_priv_x = X25519PrivateKey.generate()
                proxy_pub_x = proxy_priv_x.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

                kem_proxy = PQCKEM()
                proxy_ct_kem, ss_pqc = kem_proxy.encapsulate_secret(client_pub_kem)
                kem_proxy.free()

                ss_classical = proxy_priv_x.exchange(X25519PublicKey.from_public_bytes(client_pub_x))
                shared_secret = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-vault-key").derive(ss_classical + ss_pqc)

                signed_data = proxy_pub_x + proxy_ct_kem
                signature = dsa_proxy.sign_message(signed_data)

                send_msg(client_conn, proxy_pub_x)
                send_msg(client_conn, proxy_ct_kem)
                send_msg(client_conn, proxy_verify_key)
                send_msg(client_conn, signature)

            else:
                kem_pk_client = recv_msg(client_conn)
                kem_proxy = PQCKEM()
                proxy_ct_kem, shared_secret = kem_proxy.encapsulate_secret(kem_pk_client)
                kem_proxy.free()

                signature = dsa_proxy.sign_message(proxy_ct_kem)
                send_msg(client_conn, proxy_verify_key)
                send_msg(client_conn, signature)
                send_msg(client_conn, proxy_ct_kem)

            # Connect to backend and deal with plaintext
            cipher = HybridEncryption(shared_secret)
            backend_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_conn.connect((backend_host, backend_port))

            if action == "UPLOAD":
                # Receive Ciphertext -> Decrypt and push plaintext -> Backend
                payload = recv_msg(client_conn)
                nonce, enc_data = payload[:12], payload[12:]
                plaintext_data = cipher.decrypt_data(nonce, enc_data)

                send_msg(backend_conn, header_bytes)
                send_msg(backend_conn, plaintext_data)
                print(f"[*] Proxy Offloading: Decrypted & Forwarded '{filename}' to Backend.")

            elif action == "DOWNLOAD":
                # Backend -> Nhận Plaintext -> Mã hóa PQC -> Trả Client
                send_msg(backend_conn, header_bytes)
                status_from_backend = recv_msg(backend_conn).decode('utf-8')

                if status_from_backend == "SUCCESS":
                    plaintext_data = recv_msg(backend_conn)
                    nonce, enc_data = cipher.encrypt_data(plaintext_data)
                    send_msg(client_conn, b"SUCCESS")
                    send_msg(client_conn, nonce + enc_data)
                    print(f"[*] Proxy Offloading: Encrypted Backend response for '{filename}'.")
                else:
                    send_msg(client_conn, b"ERROR|FILE_NOT_FOUND")

            backend_conn.close()

        except Exception as e:
            print(f"[!] Proxy Stream Error: {e}")
        finally:
            client_conn.close()

if __name__ == "__main__":
    start_pqc_proxy(listen_host="0.0.0.0", listen_port=5000)
