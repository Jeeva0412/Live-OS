rule Nmap_Binary_Detection
{
    meta:
        description = "Detects Nmap network scanner binary. Commonly found in Kali/Parrot."
        author = "LUMO Live OS Detector"
        severity = "High"
    strings:
        // Common strings found inside the Nmap binary
        $s1 = "Nmap done: %d IP address" ascii
        $s2 = "Starting Nmap %s" ascii
        $s3 = "Host is up" ascii
        $s4 = "nmap.org" ascii
        $s5 = "--traceroute" ascii
        
        // Pcap interaction and common scripts
        $p1 = "pcap_loop" ascii fullword
        $p2 = "ssl-enum-ciphers" ascii
    condition:
        // It's likely an ELF or PE, but we match strictly on strings for byte-level robustness
        3 of ($s*) or ($p1 and 1 of ($s*)) or $p2
}

rule SQLMap_Detection
{
    meta:
        description = "Detects sqlmap python project files or binary packers containing sqlmap."
        author = "LUMO Live OS Detector"
        severity = "High"
    strings:
        // Common SQLMap unique strings and configurations
        $s1 = "sqlmap/1." ascii
        $s2 = "sqlmap needs Python" ascii
        $s3 = "https://sqlmap.org" ascii
        $s4 = "tamper scripts" ascii nocase
        $s5 = "DBMS error" ascii
        
        $payload1 = "boolean-based blind" ascii
        $payload2 = "time-based blind" ascii
        $payload3 = "UNION query" ascii
    condition:
        2 of ($s*) or (1 of ($s*) and 2 of ($payload*))
}

rule Metasploit_Framework_Detection
{
    meta:
        description = "Detects Metasploit Framework Ruby components or compiled payloads."
        author = "LUMO Live OS Detector"
        severity = "Critical"
    strings:
        $s1 = "Metasploit::Framework" ascii
        $s2 = "msfconsole" ascii fullword
        $s3 = "lib/msf/core" ascii
        $s4 = "meterpreter" ascii nocase
        $s5 = "reverse_tcp" ascii fullword
        $s6 = "LocalExploit" ascii
    condition:
        3 of ($s*)
}

rule Mimikatz_Detection
{
    meta:
        description = "Detects Windows Mimikatz binary or memory remnants."
        author = "LUMO Live OS Detector"
        severity = "Critical"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "mimikatz" ascii wide nocase
        $s3 = "kiwi_passwords" ascii wide
        $s4 = "lsass.exe" ascii wide nocase fullword
        $s5 = "wdigest.dll" ascii wide nocase
    condition:
        2 of ($s*)
}
