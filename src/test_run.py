from pqc_core import PQCKEM, HybridEncryption, PQCDSA

def main():
    print("=== COMPREHENSIVE POST-QUANTUM CRYPTOGRAPHY SIMULATION SYSTEM ===")

    # 1. Initialize KEM session for both endpoints
    server_kem = PQCKEM("Kyber768")
    client_kem = PQCKEM("Kyber768")

    # Initialize DSA session for Server
    server_dsa = PQCDSA("ML-DSA-65")

    print("\n[0] Server is generating Digital Signature Key Pair...")
    dsa_pub_key, dsa_pri_key = server_dsa.generate_sig_keypair()

    # --- PHASE 1: KEY EXCHANGE CHANNEL (KEM) ---
    print("\n[1] Server is generating lattice-based key pair (Kyber768)...")
    public_key, secret_key = server_kem.generate_keypair()

    print("[] Server signs its own KEM public key to prove identity")
    kem_pub_signature = server_dsa.sign_message(public_key)

    print("[2] Client receives KEM Public Key and signature from Server...")
    # Client verifies signature before using Public Key
    is_authentic = server_dsa.verify_signature(public_key, kem_pub_signature, dsa_pub_key)
    assert is_authentic == True, "ERROR: Invalid digital signature! Possible impersonation attack detected."
    print("--> [Verification] Dilithium signature is valid. Server identity is verified!")

    # Client proceeds to generate 256-bit session key
    kem_ciphertext, client_shared_secret = client_kem.encapsulate_secret(public_key)

    print("[3] Server receives Ciphertext and decapsulates using Private Key...")
    server_shared_secret = server_kem.decapsulate_secret(kem_ciphertext)

    # Validate shared secret
    assert client_shared_secret == server_shared_secret, "ERROR: Shared secret mismatch!"
    print("-> [Mathematical confirmation] Shared secret is successfully synchronized!")

    # --- PHASE 2: DATA TRANSMISSION CHANNEL (DEM) ---
    # Prepare raw data stream (Plaintext)
    msg = "Internship report at Viettel Cybersecurity OMLLC: Compliance with company policies and code of conduct."
    plaintext_bytes = msg.encode('utf-8')

    print("\n[4] Client encrypts data using AES-GCM...")
    client_cipher = HybridEncryption(client_shared_secret)
    nonce, encrypted_data = client_cipher.encrypt_data(plaintext_bytes)
    print(f"-> Encrypted data size: {len(encrypted_data)} bytes")

    print("[5] Server decrypts data using the shared session key...")
    server_cipher = HybridEncryption(server_shared_secret)
    decrypted_bytes = server_cipher.decrypt_data(nonce, encrypted_data)

    print(f"-> Decryption result: '{decrypted_bytes.decode('utf-8')}'")

    # Cleanup low-level resources
    server_dsa.free()
    server_kem.free()
    client_kem.free()
    print("\n=== SESSION TERMINATED. MEMORY RESOURCES RELEASED. ===")

if __name__ == "__main__":
    main()
