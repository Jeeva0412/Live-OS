import os
import re

class OSFingerprinter:
    def __init__(self, root_mount="/"):
        """
        Initializes the fingerprinting module.
        Expects a path to the root of the mounted filesystem (or extracted files).
        """
        self.root_mount = root_mount

    def identify_os(self):
        """
        Attempts to identify the OS by parsing common release files and signatures.
        Target OS: Kali Linux, TailsOS, Parrot Security, BackBox, Windows, MacOS.
        """
        print("[*] Starting OS Fingerprinting...")
        
        # Windows Detection
        if self._is_windows():
            return "Windows"
            
        # MacOS Detection
        if self._is_macos():
            return "MacOS (Darwin)"
            
        # Linux Detection (specifically Kali, Tails, Parrot, BackBox)
        linux_os = self._identify_linux()
        if linux_os:
            return linux_os
            
        return "Unknown Distribution / Generic Linux"

    def _is_windows(self):
        # A simple check for Windows typical structures
        win_dir = os.path.join(self.root_mount, "Windows", "System32")
        program_files = os.path.join(self.root_mount, "Program Files")
        if os.path.exists(win_dir) or os.path.exists(program_files):
            print("[+] Detected Windows directory structures.")
            return True
        return False

    def _is_macos(self):
        # A simple check for MacOS typical structures
        sys_library = os.path.join(self.root_mount, "System", "Library", "CoreServices", "SystemVersion.plist")
        applications = os.path.join(self.root_mount, "Applications")
        if os.path.exists(sys_library) or (os.path.exists(applications) and os.path.exists(os.path.join(self.root_mount, "Users"))):
            print("[+] Detected MacOS directory structures.")
            return True
        return False

    def _identify_linux(self):
        os_release_path = os.path.join(self.root_mount, "etc", "os-release")
        issue_path = os.path.join(self.root_mount, "etc", "issue")
        
        fingerprint = None
        
        if os.path.exists(os_release_path):
            with open(os_release_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()
                
                if "kali" in content:
                    fingerprint = "Kali Linux (Offensive)"
                elif "parrot" in content:
                    fingerprint = "Parrot Security OS (Offensive)"
                elif "tails" in content or "amnesic" in content:
                    fingerprint = "TailsOS (Privacy/Amnesic)"
                elif "backbox" in content:
                    fingerprint = "BackBox Linux (Offensive)"
        
        if not fingerprint and os.path.exists(issue_path):
            with open(issue_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()
                if "kali" in content:
                    fingerprint = "Kali Linux (Offensive)"
                elif "parrot" in content:
                    fingerprint = "Parrot Security OS (Offensive)"
                elif "tails" in content:
                    fingerprint = "TailsOS (Privacy/Amnesic)"
                elif "backbox" in content:
                    fingerprint = "BackBox Linux (Offensive)"
                    
        if fingerprint:
             print(f"[+] Precise Linux Match Found: {fingerprint}")
        return fingerprint

if __name__ == "__main__":
    fingerprinter = OSFingerprinter("/") # Uses the current root for local testing
    identified = fingerprinter.identify_os()
    print(f"\n[>>>] Final OS Identification: {identified}")
