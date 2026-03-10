import math
import os

class EntropyScanner:
    def __init__(self, target_directories=None):
        """
        Initializes the Entropy-Based Obfuscation Scanner.
        Target directories are usually world-writable staging areas like /tmp, /var/tmp, /dev/shm
        """
        if target_directories is None:
            self.target_directories = ["/tmp", "/var/tmp", "/dev/shm"]
        else:
            self.target_directories = target_directories

    def calculate_shannon_entropy(self, data):
        """
        Calculates the Shannon entropy of a byte array.
        Returns a float between 0.0 and 8.0.
        Scores > 7.0 typically indicate encryption or aggressive compression (packing like UPX).
        """
        if not data:
            return 0.0
            
        entropy = 0.0
        length = len(data)
        
        # Calculate frequency of each byte
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
            
        for count in frequencies:
            if count > 0:
                p_x = count / length
                entropy += - p_x * math.log2(p_x)
                
        return entropy

    def scan_directories(self, root_mount="/"):
        print("[*] Commencing Entropy-Based Obfuscation & Packing Scan...")
        print("[*] Scanning highly volatile staging directories for packed payloads (> 7.0 entropy).")
        
        for d in self.target_directories:
            full_path = os.path.normpath(os.path.join(root_mount, d.lstrip("/")))
            if not os.path.exists(full_path):
                continue
                
            print(f"[*] Scanning {full_path}...")
            for root, _, files in os.walk(full_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Skip purely empty files or massively large safe media 
                        # Focus on typical executable drops (<= 20MB)
                        size = os.path.getsize(file_path)
                        if size == 0 or size > 20 * 1024 * 1024:
                            continue
                            
                        with open(file_path, "rb") as f:
                            data = f.read()
                            
                        ent = self.calculate_shannon_entropy(data)
                        
                        if ent > 7.0:
                            print(f"[!] ENCRYPTED/PACKED ANOMALY DETECTED:")
                            print(f"    -> File: {file_path} (Size: {size} bytes)")
                            print(f"    -> Entropy Score: {ent:.3f} / 8.0")
                    except Exception:
                        pass # Ignore permission errors or unreadable files in live scans

if __name__ == "__main__":
    scanner = EntropyScanner(target_directories=["."]) 
    scanner.scan_directories()
