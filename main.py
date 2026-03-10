import click
import os
import sys
from rich.console import Console
from rich.panel import Panel

# Import Phase 1 Core Modules
sys.path.append(os.path.dirname(__file__))
from core.acquisition import StaticAcquisition
from core.fingerprint import OSFingerprinter
from core.yara_scanner import YaraScanner
from core.memory_analysis import MemoryAnalyzer
from core.remote_acquisition import RemoteAcquisitionListener
from core.compliance import BSACertificateGenerator
from core.history_analyzer import HistoryAnalyzer
from core.entropy_scanner import EntropyScanner

console = Console()

def print_banner():
    banner = """
    ██╗     ██╗   ██╗███╗   ███╗ ██████╗ 
    ██║     ██║   ██║████╗ ████║██╔═══██╗
    ██║     ██║   ██║██╔████╔██║██║   ██║
    ██║     ██║   ██║██║╚██╔╝██║██║   ██║
    ███████╗╚██████╔╝██║ ╚═╝ ██║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ 
    Live OS Detection & Forensics Framework
    """
    console.print(Panel.fit(banner, style="bold cyan", border_style="blue"))

@click.group()
def cli():
    """LUMO Live OS Forensic Toolkit"""
    pass

@cli.command()
@click.option('--target', required=True, help="Path to raw disk image or block device (e.g., /dev/sdb or image.dd)")
@click.option('--output', default=".", help="Output directory for reports and certificates")
def static_scan(target, output):
    """Run a Non-Destructive Static Scan against a disk image or block device."""
    print_banner()
    console.print("[bold green][*] Initiating Non-Destructive Static Scan...[/bold green]")
    
    # 1. Acquisition
    acq = StaticAcquisition(target)
    if not acq.open_image() or not acq.load_filesystem(0):
        console.print("[bold red][-] Aborting scan due to acquisition failure.[/bold red]")
        sys.exit(1)
        
    # NOTE: In a true deployment we'd mount or extract files to a temp dir here for fingerprinting/YARA,
    # but for script demonstration we will just point the modules at the local root '/'
    # or a simulated extracted path.
    scan_root = "/" # Simulated
        
    # 2. OS Fingerprinting
    fingerprinter = OSFingerprinter(scan_root)
    os_name = fingerprinter.identify_os()
    console.print(f"\n[bold yellow][>>>] TARGET OS IDENTIFIED: {os_name}[/bold yellow]\n")
    
    # 3. YARA Signature Matching
    scanner = YaraScanner(rules_dir=os.path.join(os.path.dirname(__file__), "signatures"))
    matches = scanner.scan_directory(scan_root)
    if matches:
        console.print(f"\n[bold red][!] {len(matches)} OFFENSIVE TOOL SIGNATURES VERIFIED[/bold red]")
    else:
        console.print("\n[bold green][+] No offensive signatures detected.[/bold green]")
        
    # 4. Compliance Certificate
    generator = BSACertificateGenerator()
    cert_path = generator.generate_certificate(output, target, is_live=False)
    console.print(f"\n[bold cyan][*] Execution Complete. Artifacts saved to {output}[/bold cyan]")

@cli.command()
@click.option('--port', default=8888, help="Port to listen on for the incoming data stream")
@click.option('--output', default="evidence.dd", help="Filename to stream the blocks into")
def remote_listen(port, output):
    """Start a Remote Live Acquisition listener to receive streams securely."""
    print_banner()
    console.print(f"[bold green][*] Initiating Remote Live Acquisition (Listening on Port {port})[/bold green]")
    
    listener = RemoteAcquisitionListener(port=port, output_file=output)
    try:
        listener.start_listener()
        
        # Once finished, generate the Live BSA Certificate
        console.print("\n[bold yellow][*] Stream complete. Generating Legal Live Acquisition Record...[/bold yellow]")
        generator = BSACertificateGenerator()
        generator.generate_certificate(
            output_dir=os.path.dirname(os.path.abspath(output)),
            target_path=f"Network Stream -> {output}",
            is_live=True,
            precomputed_md5=listener.get_md5(),
            precomputed_sha256=listener.get_sha256()
        )
    except KeyboardInterrupt:
        console.print("\n[bold red][-] Remote listener terminated by user.[/bold red]")

@cli.command()
@click.option('--dump', default=None, help="Path to Volatility3 offline memory dump (Optional)")
def ram_scan(dump):
    """Analyze Live RAM or a provided memory dump for recently executed tools."""
    print_banner()
    console.print("[bold green][*] Initiating Live RAM Analysis...[/bold green]")
    
    analyzer = MemoryAnalyzer(dump_path=dump)
    if dump:
        analyzer.analyze_dump()
    else:
        results = analyzer.analyze_live_system()
        if results:
             console.print(f"\n[bold red][!] DANGER: Found {len(results)} suspicious processes in live memory![/bold red]")

@cli.command()
@click.option('--target', default="/", help="Path to the mounted filesystem root to scan")
def heuristic_history(target):
    """Analyze bash/zsh command histories for malicious intent heuristics."""
    print_banner()
    console.print(f"[bold green][*] Initiating AI/Heuristic Command History Analyzer on {target}...[/bold green]")
    
    analyzer = HistoryAnalyzer(root_mount=target)
    analyzer.analyze()

@cli.command()
@click.option('--target', default="/tmp,/var/tmp,/dev/shm", help="Comma-separated list of directories to scan")
@click.option('--root', default="/", help="Root mount point")
def entropy_scan(target, root):
    """Scan highly volatile staging directories for packed or encrypted payloads."""
    print_banner()
    console.print(f"[bold green][*] Initiating Entropy-Based Obfuscation Scanner on {target}...[/bold green]")
    
    dirs = target.split(",")
    scanner = EntropyScanner(target_directories=dirs)
    scanner.scan_directories(root_mount=root)

if __name__ == '__main__':
    cli()
