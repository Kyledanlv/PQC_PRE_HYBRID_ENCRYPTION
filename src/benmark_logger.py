import os
import csv
import time
import math
import tracemalloc
from datetime import datetime

class TransactionLogger:
    def __init__(self, log_file="/app/data/traffic_benchmark.csv"):
        self.log_file = log_file
        self.metrics = {}
        self._init_csv()

    def _init_csv(self):
        headers = [
            "timestamp", "action", "file_name", "file_size_bytes", 
            "crypto_suite", "security_level", 
            "pub_key_size_bytes", "sig_size_bytes", "ciphertext_expansion_bytes",
            "key_gen_time_ms", "handshake_time_ms", 
            "encryption_time_ms", "decryption_time_ms", 
            "throughput_mbps", "peak_ram_kb"
        ]
        if not os.path.isfile(self.log_file):
            with open(self.log_file, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers)

    def log_transaction(self, action, filename, file_size, suite, security_level,
                        pub_key_size, sig_size, ciphertext_expansion,
                        key_gen_time, handshake_time, enc_time, dec_time, peak_ram):
        
        process_time_ms = enc_time if action.lower() == 'upload' else dec_time
        throughput = 0.0
        if process_time_ms > 0 and file_size > 0:
            throughput = (file_size / 1048576) / (process_time_ms / 1000)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        data_row = [
            timestamp, action.upper(), filename, file_size,
            suite, security_level,
            pub_key_size, sig_size, ciphertext_expansion,
            round(key_gen_time, 3), round(handshake_time, 3), 
            round(enc_time, 3), round(dec_time, 3), 
            round(throughput, 2), round(peak_ram, 2)
        ]
        
        with open(self.log_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(data_row)
        print(f"[# LOGGER] Transaction recorded (Throughput: {round(throughput, 2)} MB/s)")
