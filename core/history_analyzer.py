import os
import re

class HistoryAnalyzer:
    def __init__(self, root_mount="/"):
        """
        Initializes the Heuristic Command History Analyzer.
        """
        self.root_mount = root_mount
        # Define high-risk command patterns (heuristics)
        # Weight represents the "Malicious Intent Score" (0-100 threshold)
        self.heuristics = [
            {"pattern": r"nc.*?(-e|--exec)", "weight": 90, "desc": "Reverse shell initiation via Netcat"},
            {"pattern": r"bash\s+-i\s+>\&", "weight": 95, "desc": "Bash interactive reverse shell"},
            {"pattern": r"nmap.*?(-p-|--top-ports)", "weight": 60, "desc": "Aggressive network enumeration"},
            {"pattern": r"sqlmap.*?-u", "weight": 70, "desc": "SQL Injection testing"},
            {"pattern": r"chattr\s+\+i", "weight": 50, "desc": "Making files immutable (potential rootkit persistence)"},
            {"pattern": r"rm\s+-rf\s+/(?!$)", "weight": 80, "desc": "Destructive deletion"},
            {"pattern": r"wget.*?http.*?-O", "weight": 40, "desc": "Downloading external payloads"},
            {"pattern": r"curl.*?http.*?\|", "weight": 60, "desc": "Piping external scripts directly to bash (Fileless exec)"},
            {"pattern": r"chmod.*?777", "weight": 30, "desc": "Insecure permission changes"},
            {"pattern": r"\.py.*?(impacket|psexec)", "weight": 80, "desc": "Lateral movement tools execution"}
        ]

    def locate_histories(self):
        """Finds .bash_history and .zsh_history files across users."""
        histories = []
        home_base = os.path.join(self.root_mount, "home")
        root_dir = os.path.join(self.root_mount, "root")
        
        search_dirs = [root_dir]
        if os.path.exists(home_base):
            try:
                for user in os.listdir(home_base):
                    search_dirs.append(os.path.join(home_base, user))
            except Exception:
                pass
                
        for d in search_dirs:
            bash_hist = os.path.join(d, ".bash_history")
            zsh_hist = os.path.join(d, ".zsh_history")
            if os.path.exists(bash_hist): histories.append(bash_hist)
            if os.path.exists(zsh_hist): histories.append(zsh_hist)
            
        return histories

    def analyze(self):
        print("[*] Commencing Heuristic Command History Analysis...")
        histories = self.locate_histories()
        
        if not histories:
            print("[-] No command history files located.")
            return

        for filepath in histories:
            score = 0
            findings = []
            
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    
                for line in lines:
                    cmd_line = line.strip()
                    if not cmd_line: continue
                    
                    for h in self.heuristics:
                        if re.search(h["pattern"], cmd_line, re.IGNORECASE):
                            score += h["weight"]
                            findings.append(f"[{h['weight']} pts] {h['desc']} -> '{cmd_line}'")
                            
                user = os.path.basename(os.path.dirname(filepath))
                print(f"\n[+] Analysis for User: '{user}' ({os.path.basename(filepath)})")
                
                if score > 0:
                    print(f"    Total Risk Score: {score}")
                    for finding in findings:
                        print(f"    - {finding}")
                        
                    if score >= 100:
                         print("    [!!!] CRITICAL MALICIOUS INTENT THRESHOLD REACHED")
                else:
                    print("    No malicious heuristics triggered.")

            except Exception as e:
                print(f"[-] Error reading {filepath}: {e}")

if __name__ == "__main__":
    analyzer = HistoryAnalyzer()
    analyzer.analyze()
