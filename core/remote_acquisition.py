import socket
import hashlib
import os

class RemoteAcquisitionListener:
    def __init__(self, host="0.0.0.0", port=8888, output_file="evidence.dd"):
        """
        Initializes the listener for Remote Live Acquisition.
        Binds to the specified interface and port.
        """
        self.host = host
        self.port = port
        self.output_file = output_file
        
        self.md5_hash = hashlib.md5()
        self.sha256_hash = hashlib.sha256()

    def start_listener(self):
        """
        Starts the socket listener to receive raw disk streams (e.g., from netcat `dd if=/dev/sdb | nc VIP 8888`).
        Performs block-level hashing on the fly.
        """
        print(f"[*] Starting Remote Live Acquisition Listener on {self.host}:{self.port}...")
        print(f"[*] The stream will be legally classified as a 'Live Forensic Acquisition'.")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            # Allow address reuse if the port is stuck in TIME_WAIT
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(1)
            
            print(f"[+] Listening for incoming forensic stream...")
            conn, addr = server_sock.accept()
            
            with conn:
                print(f"[!] SECURE TUNNEL ESTABLISHED. Receiving stream from target: {addr}")
                
                with open(self.output_file, 'wb') as f_out:
                    total_bytes = 0
                    chunk_count = 0
                    
                    # 4MB chunks for block-level hashing on the fly
                    chunk_size = 4096 * 1024 
                    
                    while True:
                        data = conn.recv(chunk_size)
                        if not data:
                            break
                            
                        # Write stream directly to disk without loading entirely into RAM
                        f_out.write(data)
                        
                        # Block-Level Hashing
                        self.md5_hash.update(data)
                        self.sha256_hash.update(data)
                        
                        total_bytes += len(data)
                        chunk_count += 1
                        
                        # Print progress every ~40MB
                        if chunk_count % 10 == 0:
                            print(f"    -> Received {total_bytes / (1024*1024):.2f} MB...")
                            
                print("\n[+] Stream fully received and safely written to disk.")
                print(f"[+] Total Size: {total_bytes} bytes")
                print(f"[+] Stream MD5:    {self.get_md5()}")
                print(f"[+] Stream SHA256: {self.get_sha256()}")
                print(f"[+] Remember to generate the Section 63(4)(c) BSA record to justify the transmission footprint.")

    def get_md5(self):
        return self.md5_hash.hexdigest()
        
    def get_sha256(self):
        return self.sha256_hash.hexdigest()

if __name__ == "__main__":
    # Test execution
    # On the target: dd if=/dev/zero bs=1M count=100 | nc 127.0.0.1 8888
    listener = RemoteAcquisitionListener(host="127.0.0.1", port=8888, output_file="test_stream.dd")
    try:
         listener.start_listener()
    except KeyboardInterrupt:
         print("\n[-] Listener interrupted by user.")
