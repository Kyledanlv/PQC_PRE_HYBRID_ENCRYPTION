import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="oqs")
import oqs
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PQCKEM:
    def __init__(self, kem_alg="Kyber768"):
       	#Khởi tạo đối tượng Cơ chế đóng gói khóa (KEM)
       	#Default sử dụng Kyber768 (ML-KEM-768)
       	self.kem_alg = kem_alg
       	#Khởi tạo phiên làm việc với thư viện lõi C
       	self.kem = oqs.KeyEncapsulation(self.kem_alg)

    def generate_keypair(self):
	#Giai đoạn 1: Tạo cặp khóa Kháng lượng tử.
	#Gọi hàm biên dịch C để sinh khóa
       	public_key = self.kem.generate_keypair()

	#Trích xuất khóa bí mật từ bộ nhớ lưu trữ
       	secret_key = self.kem.export_secret_key()
       	return public_key, secret_key

    def encapsulate_secret(self, public_key):
	#Giai đoạn 2: Sinh khóa phiên và Đóng gói.
	#Client dùng public_key của Server để thực hiện thao tác này.

       	ciphertext, shared_secret = self.kem.encap_secret(public_key)
       	return ciphertext, shared_secret

    def decapsulate_secret(self, ciphertext):
	#Giai đoạn 3: Mở gói để thu hồi Khóa phiên
       	shared_secret = self.kem.decap_secret(ciphertext)
       	return shared_secret

    def free(self):
	#Giải phóng bộ nhớ C khi không còn sử dụng
       	self.kem.free()

class HybridEncryption:
    def __init__(self, shared_secret):
	#Khởi tạo bộ mã hóa đối xứng AES-256-GCM sử dụng Shared Secret từ ML-KEM.5
	#Kyber768 trả về shared_secret chuẩn 32 bytes (256 bít) làm khóa AES
       	self.aesgcm = AESGCM(shared_secret)

    def encrypt_data(self, plaintext_data: bytes):
	#Giai đoạn 2: Khóa chặt dữ liệu thực tế
	#Trả về nonce (vector khởi tạo) và ciphertext_data (dữ liệu đã mã hóa)
	#Sinh ngẫu nhiên một Nonce (Number used Once) - chuẩn 12 bytes
       	nonce = os.urandom(12)

	#Mã hóa dữ liệu và tự động gắn thêm nhãn xác thực (MAC) vào cuối bản mã
       	ciphertext_data = self.aesgcm.encrypt(nonce, plaintext_data, associated_data=None)

       	return nonce, ciphertext_data

    def decrypt_data(self, nonce: bytes, ciphertext_data: bytes):
	#Giai đoạn cuối: Mở khóa dữ liệu gốc
       	plaintext_data = self.aesgcm.decrypt(nonce, ciphertext_data, associated_data=None)
       	return plaintext_data

class PQCDSA:
    def __init__(self, sig_alg="ML-DSA-65"):
        #Khởi tạo chữ ký số hậu lượng tử
        #Sử dụng thuật toán ML-DSA (NIST FIPS 204), bản triển khai tiêu chuẩn là Dithilium
        self.sig_alg = sig_alg
        self.sig = oqs.Signature(sig_alg)

    def generate_sig_keypair(self):
        #Sinh cặp khóa bất đối xứng dùng riêng cho chữ ký số
        #Khóa này độc lập hoàn toàn với khóa KEM
        verify_key = self.sig.generate_keypair()
        sign_key = self.sig.export_secret_key()
        return verify_key, sign_key

    def sign_message(self, message: bytes):
        #Thực hiện ký số lên mảng byte của thông điệp
        return self.sig.sign(message)

    def verify_signature(self, message: bytes, signature: bytes, verify_key: bytes):
        #Xác thực chữ ký số hậu lượng tử
        try:
            #Khởi tạo không gian nhớ C và tự động giải phóng khi thoát khối
            with oqs.Signature(self.sig_alg) as verifier:
                return verifier.verify(message, signature, verify_key)
        except Exception as e:
            #Chặn mọi ngoại lệ từ tầng CFFT (ví dụ: sai độ dài bytes)
            print(f"[!] Lỗi cấu trúc chữ ký/khóa tại tầng CFFI: {e}")
            return False

    def free(self):
        self.sig.free()
