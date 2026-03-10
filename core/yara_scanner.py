import yara
import os
import glob

class YaraScanner:
    def __init__(self, rules_dir="../signatures/"):
        """
        Initializes the YARA scanner by compiling all rules in the signatures directory.
        """
        self.rules_dir = rules_dir
        self.rules = self._compile_rules()

    def _compile_rules(self):
        print(f"[*] Compiling YARA signatures from {self.rules_dir}...")
        rule_files = {}
        target_dir = os.path.abspath(self.rules_dir)
        
        if not os.path.exists(target_dir):
            print(f"[-] Signatures directory not found: {target_dir}")
            return None
            
        for file in glob.glob(os.path.join(target_dir, "*.yar")):
            base_name = os.path.basename(file)
            rule_files[base_name] = file
            
        if not rule_files:
            print("[-] No .yar rule files found.")
            return None
            
        try:
            compiled_rules = yara.compile(filepaths=rule_files)
            print(f"[+] Successfully compiled {len(rule_files)} rule package(s).")
            return compiled_rules
        except yara.SyntaxError as e:
            print(f"[-] YARA Syntax Error: {e}")
            return None

    def scan_file(self, file_path):
        """
        Scans a specific file against the compiled YARA rules.
        """
        if not self.rules:
            return []
            
        if not os.path.exists(file_path):
            print(f"[-] File not found for scanning: {file_path}")
            return []
            
        try:
            matches = self.rules.match(file_path)
            results = []
            for match in matches:
                severity = match.meta.get("severity", "Unknown")
                desc = match.meta.get("description", "No description")
                results.append({"rule": match.rule, "severity": severity, "description": desc, "file": file_path})
                print(f"[!] YARA MATCH: {match.rule} [{severity}] in {file_path}")
            return results
        except Exception as e:
            print(f"[-] Error scanning file {file_path}: {e}")
            return []

    def scan_directory(self, directory_path):
        """
        Recursively scans a directory using the compiled YARA rules.
        """
        if not self.rules:
            return []
            
        print(f"[*] Starting recursive deep-content scan on {directory_path}...")
        all_matches = []
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                # Skip massive files for demo speed, or unreadable files
                try:
                    if os.path.getsize(file_path) > 50 * 1024 * 1024:
                        continue 
                    matches = self.scan_file(file_path)
                    all_matches.extend(matches)
                except Exception:
                    pass
                    
        print(f"[+] Directory scan complete. Total matches: {len(all_matches)}")
        return all_matches

if __name__ == "__main__":
    scanner = YaraScanner(rules_dir=os.path.join(os.path.dirname(__file__), "../signatures/"))
    
    # Simple test run on the signatures dir itself (it won't match, but verifies the logic)
    test_dir = os.path.dirname(__file__)
    scanner.scan_directory(test_dir)
