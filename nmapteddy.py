import nmap
import socket
from tabulate import tabulate
from pyfiglet import figlet_format
from colorama import init, Fore, Style

# Initialize colorama (for Windows compatibility)
init(autoreset=True)

def ascii_art(text, color=Fore.CYAN):
    art = figlet_format(text, font="slant")
    print(f"{color}{art}{Style.RESET_ALL}")")

def prompt_choice(prompt, options, allow_multiple=False):
    print(f"{Fore.LIGHTYELLOW_EX}{prompt}{Style.RESET_ALL}")
    for key, (desc, explanation) in options.items():
        print(f"[{key}] {desc} - {explanation}")
    if allow_multiple:
        choice = input("Enter choices (comma-separated): ").strip()
        return [c.strip() for c in choice.split(',') if c.strip() in options]
    else:
        choice = input("Enter choice: ").strip()
        return choice if choice in options else None

def prompt_input(prompt, default=""):
    value = input(f"{Fore.LIGHTCYAN_EX}{prompt} [{default}]: {Style.RESET_ALL}").strip()
    return value or default

def port_scan():
    target = prompt_input("Target for port scan", "scanme.nmap.org")
    ports = prompt_input("Number of top ports to scan", "100")
    command = f"nmap -Pn --top-ports {ports} {target}"
    print(f"\n{Fore.LIGHTGREEN_EX}Command: {command}{Style.RESET_ALL}\n")

def service_scan():
    target = prompt_input("Target for service/version detection", "scanme.nmap.org")
    ports = prompt_input("Number of top ports to scan", "100")
    command = f"nmap -sV -Pn --top-ports {ports} {target}"
    print(f"\n{Fore.LIGHTGREEN_EX}Command: {command}{Style.RESET_ALL}\n")

def os_detection():
    target = prompt_input("Target for OS detection", "scanme.nmap.org")
    command = f"nmap -O -Pn {target}"
    print(f"\n{Fore.LIGHTGREEN_EX}Command: {command}{Style.RESET_ALL}\n")

def vuln_scan():
    target = prompt_input("Target for vulnerability scan", "scanme.nmap.org")
    command = f"nmap --script vuln -Pn {target}"
    print(f"\n{Fore.LIGHTGREEN_EX}Command: {command}{Style.RESET_ALL}\n")

def stealth_scan():
    target = prompt_input("Target for stealth scan (SYN)", "scanme.nmap.org")
    command = f"nmap -sS -Pn -T3 {target}"
    print(f"\n{Fore.LIGHTGREEN_EX}Command: {command}{Style.RESET_ALL}\n")

def aggressive_scan():
    target = prompt_input("Target for aggressive scan (-A)", "scanme.nmap.org")
    command = f"nmap -A {target}"
    print(f"\n{Fore.LIGHTGREEN_EX}Command: {command}{Style.RESET_ALL}\n")

def traceroute_scan():
    target = prompt_input("Target for traceroute", "scanme.nmap.org")
    command = f"nmap -sn --traceroute {target}"
    print(f"\n{Fore.LIGHTGREEN_EX}Command: {command}{Style.RESET_ALL}\n")

def custom_scan():
    flags = []
    scan_types = {
        'sS': ("SYN Scan", "Stealthy and fast TCP scan"),
        'sT': ("TCP Connect", "Standard full TCP connection scan"),
        'sU': ("UDP Scan", "Scan UDP ports"),
        'sV': ("Version Detection", "Identify services and versions"),
        'sN': ("Null Scan", "No flags set - stealth scan"),
        'sF': ("FIN Scan", "TCP FIN packets sent"),
        'sX': ("Xmas Scan", "Sets FIN, PSH and URG flags"),
        'sA': ("ACK Scan", "For firewall rule detection"),
        'sW': ("Window Scan", "Advanced ACK scan variant")
    }
    chosen_types = prompt_choice("Select scan types (you can choose multiple):", scan_types, True)
    flags.extend([f"-{t}" for t in chosen_types])

    target = prompt_input("Enter target IP, domain, or file of targets (-iL)", "scanme.nmap.org")
    if target.endswith(".txt") or os.path.exists(target):
        flags.append(f"-iL {target}")
        target = ""

    print("\nPort Options:")
    port_mode = prompt_input("Scan top ports [t] or specific ports [s] or full scan [f]", "t")
    if port_mode == 't':
        num = prompt_input("Enter number of top ports", "100")
        flags.append(f"--top-ports {num}")
    elif port_mode == 's':
        ports = prompt_input("Enter comma-separated port numbers or ranges", "22,80,443")
        flags.append(f"-p {ports}")
    elif port_mode == 'f':
        flags.append("-p-")

    host_discovery = {
        'Pn': ("No Ping", "Skip host discovery"),
        'PE': ("ICMP Echo", "Ping with ICMP Echo"),
        'PS': ("TCP SYN Ping", "Ping with TCP SYN"),
        'PA': ("TCP ACK Ping", "Ping with TCP ACK"),
        'PU': ("UDP Ping", "Ping with UDP packets"),
        'PR': ("ARP Ping", "Ping using ARP requests (LAN only)")
    }
    hd_choice = prompt_choice("Select host discovery method(s):", host_discovery, True)
    flags.extend([f"-{h}" for h in hd_choice])

    timing = {
        'T0': ("Paranoid", "Very slow, useful against IDS"),
        'T1': ("Sneaky", "Slow, IDS evasion"),
        'T2': ("Polite", "Slows down to use less bandwidth/CPU"),
        'T3': ("Normal", "Default"),
        'T4': ("Aggressive", "Faster scan, less stealth"),
        'T5': ("Insane", "Very fast, likely to be detected")
    }
    timing_choice = prompt_choice("Choose timing template:", timing)
    if timing_choice:
        flags.append(f"-{timing_choice}")

    verbosity = prompt_input("Add verbosity? [v/vv] (leave blank to skip)", "")
    if verbosity:
        flags.append(f"-{verbosity}")

    use_scripts = prompt_input("Use NSE scripts? (y/n)", "n")
    if use_scripts.lower() == 'y':
        print("\nCommon categories: auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln")
        script = prompt_input("Enter script name or category (e.g., vuln,http-title,default)", "vuln")
        flags.append(f"--script {script}")

    if prompt_input("Enable OS detection? (y/n)", "n").lower() == 'y':
        flags.append("-O")
    if prompt_input("Enable traceroute? (y/n)", "n").lower() == 'y':
        flags.append("--traceroute")

    if prompt_input("Add firewall evasion techniques? (y/n)", "n").lower() == 'y':
        if prompt_input("Use decoy mode? (y/n)", "n").lower() == 'y':
            decoys = prompt_input("Enter decoy IPs (comma-separated)", "1.2.3.4,5.6.7.8")
            flags.append(f"--decoy {decoys}")
        if prompt_input("Use fragmented packets? (y/n)", "n").lower() == 'y':
            flags.append("-f")
        if prompt_input("Randomize targets? (y/n)", "n").lower() == 'y':
            flags.append("--randomize-hosts")
        if prompt_input("Spoof MAC address? (y/n)", "n").lower() == 'y':
            mac = prompt_input("Enter MAC (0 for random)", "0")
            flags.append(f"--spoof-mac {mac}")

    output_format = prompt_input("Save output to file? Enter format (n: normal, x: xml, g: grepable, a: all) or blank to skip", "")
    if output_format in ['n', 'x', 'g', 'a']:
        file_name = prompt_input("Enter output file name prefix", f"nmap_output")
        if output_format == 'a':
            flags.append(f"-oA {file_name}")
        else:
            flags.append(f"-o{output_format.upper()} {file_name}.{output_format}")

    command = f"nmap {' '.join(flags)} {target}".strip()
    print(f"\n{Fore.LIGHTGREEN_EX}Constructed Nmap Command:{Style.RESET_ALL}\n{command}\n")
    save = prompt_input("Save this command to file? (y/n)", "n")
    if save.lower() == 'y':
        filename = prompt_input("Enter filename", "nmap_command.sh")
        with open(filename, 'w') as f:
            f.write(command + '\n')
        print(f"Saved to {filename}")

def main():
    ascii_art("Nmap Teddy", Fore.LIGHTGREEN_EX)
    print("1. Port Scan\n2. Service Detection\n3. OS Detection\n4. Vulnerability Scan\n5. Stealth Scan\n6. Aggressive Scan\n7. Traceroute Scan\n8. Custom Scan")
    choice = prompt_input("Choose scan type", "1")
    if choice == '1': port_scan()
    elif choice == '2': service_scan()
    elif choice == '3': os_detection()
    elif choice == '4': vuln_scan()
    elif choice == '5': stealth_scan()
    elif choice == '6': aggressive_scan()
    elif choice == '7': traceroute_scan()
    elif choice == '8': custom_scan()
    else: print("Invalid choice")

if __name__ == "__main__":
    main()

