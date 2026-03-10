import hashlib
import os
import datetime
from jinja2 import Template

class BSACertificateGenerator:
    def __init__(self, investigator_name="LUMO Automated Agent", case_number="LUMO-LIVE-001"):
        self.investigator_name = investigator_name
        self.case_number = case_number
        self.date_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Basic Section 63(4)(c) Template
        self.template_string = """
================================================================================
                    SECTION 63(4)(c) BSA CERTIFICATE
                        OF EVIDENCE ACQUISITION

CASE NUMBER: {{ case_number }}
DATE/TIME:   {{ date_time }}
EXAMINER:    {{ investigator_name }}

1. IDENTIFICATION OF EVIDENCE
--------------------------------------------------------------------------------
Evidence Target: {{ target_path }}
Acquisition Type: {{ acquisition_type }}

{% if 'Live Forensic Acquisition' in acquisition_type %}
[!] LEGAL NOTIFICATION: This acquisition was performed on a LIVE system across a 
secure network tunnel. The execution of the agent and transmission tools left an 
unavoidable trace in the target's Volatile Memory (RAM). This footprint is legally 
justified as a "Live Forensic Acquisition" when a Static Image is technically or 
tactically impossible (e.g., due to encryption or active amnesic environments like Tails).
{% else %}
[!] LEGAL NOTIFICATION: This acquisition was performed via Non-Destructive Static
Acquisition, strictly preserving the original state of the evidentiary media.
{% endif %}

2. CRYPTOGRAPHIC VERIFICATION (CHAIN OF CUSTODY)
--------------------------------------------------------------------------------
MD5 Hash:    {{ md5_hash }}
SHA256 Hash: {{ sha256_hash }}

3. ATTESTATION
--------------------------------------------------------------------------------
I, {{ investigator_name }}, hereby certify that the digital evidence described above 
was acquired using validated forensic processes. The cryptographic hashes generated 
during the acquisition match the hashes presented above, ensuring digital integrity
and non-repudiation.

Signature: ___________________________
Date:      ___________________________

================================================================================
"""

    def hash_file(self, filepath):
        """Calculates MD5 and SHA256 of a local file."""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        if not os.path.exists(filepath):
            return "FILE_NOT_FOUND", "FILE_NOT_FOUND"
            
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096 * 1024), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except Exception as e:
            return f"ERROR: {e}", f"ERROR: {e}"

    def generate_certificate(self, output_dir, target_path, is_live=False, precomputed_md5=None, precomputed_sha256=None):
        """
        Generates and saves the certificate.
        If precomputed hashes are provided (e.g., from the Remote Live Acquisition stream), it uses them.
        Otherwise, it calculates them locally.
        """
        acquisition_type = "Live Forensic Acquisition (Network Stream)" if is_live else "Static Non-Destructive Acquisition"
        
        md5_hash = precomputed_md5
        sha256_hash = precomputed_sha256
        
        if not md5_hash or not sha256_hash:
            print(f"[*] Calculating standard hashes for {target_path}...")
            md5_hash, sha256_hash = self.hash_file(target_path)

        template = Template(self.template_string)
        cert_content = template.render(
            case_number=self.case_number,
            date_time=self.date_time,
            investigator_name=self.investigator_name,
            target_path=target_path,
            acquisition_type=acquisition_type,
            md5_hash=md5_hash,
            sha256_hash=sha256_hash
        )

        cert_path = os.path.join(output_dir, "BSA_Certificate.txt")
        try:
            with open(cert_path, "w") as f:
                f.write(cert_content)
            print(f"[+] Successfully generated Legal Compliance Certificate: {cert_path}")
            return cert_path
        except IOError as e:
            print(f"[-] Failed to write certificate: {e}")
            return None

if __name__ == "__main__":
    generator = BSACertificateGenerator()
    # Mocking a live stream completion
    print("\n--- Testing Live Stream Cert Generation ---")
    generator.generate_certificate(
        output_dir=".", 
        target_path="192.168.1.50 -> Streamed -> evidence.dd", 
        is_live=True, 
        precomputed_md5="d41d8cd98f00b204e9800998ecf8427e", 
        precomputed_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
