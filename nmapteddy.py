import nmap
import socket
from tabulate import tabulate
from pyfiglet import figlet_format
from colorama import init, Fore, Style

# Initialize colorama (for Windows compatibility)
init(autoreset=True)

def ascii_art(text, color=Fore.CYAN):
    art = figlet_format(text, font="slant")
    print(f"{color}{art}{Style.RESET_ALL}")

# Display tool name
ascii_art("Nmap Teddy", Fore.LIGHTGREEN_EX)

def resolve_host(user_input):
    try:
        ip = socket.gethostbyname(user_input)
        print(f"{Fore.LIGHTCYAN_EX}Resolved {user_input} to {ip}{Style.RESET_ALL}")
        return ip
    except socket.gaierror:
        print(f"{Fore.LIGHTRED_EX}Could not resolve hostname: {user_input}{Style.RESET_ALL}")
        return None

def save_results(filename, content):
    try:
        with open(filename, 'w') as f:
            f.write(content)
        print(f"{Fore.LIGHTGREEN_EX}Results saved to {filename}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.LIGHTRED_EX}Failed to save file: {e}{Style.RESET_ALL}")

def prompt_save(tabulated_result):
    choice = input(f"\n{Fore.LIGHTYELLOW_EX}Save this output? (y/n): {Style.RESET_ALL}").strip().lower()
    if choice == 'y':
        filename = input("Enter filename (e.g., result.txt): ").strip()
        save_results(filename, tabulated_result)

def port_scan(scanner, host):
    try:
        top_ports = int(input(f"{Fore.LIGHTCYAN_EX}Enter number of top ports to scan: {Style.RESET_ALL}").strip())
    except ValueError:
        print(f"{Fore.LIGHTRED_EX}Invalid number of ports.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.LIGHTGREEN_EX}Scanning {host} for top {top_ports} ports...\n{Style.RESET_ALL}")
    scanner.scan(host, arguments=f'-Pn --top-ports {top_ports}')

    if host not in scanner.all_hosts():
        print(f"{Fore.LIGHTRED_EX}No results. Host '{host}' may be unreachable.{Style.RESET_ALL}")
        return

    results = []
    for proto in scanner[host].all_protocols():
        for port in sorted(scanner[host][proto].keys()):
            data = scanner[host][proto][port]
            results.append({
                'Port': port,
                'State': data['state'],
                'Service': data.get('name', 'unknown')
            })

    results = sorted(results, key=lambda x: {'open': 0, 'filtered': 1}.get(x['State'], 2))
    table = tabulate(results, headers="keys", tablefmt="grid")
    print(table)

    print(f"\n{Fore.LIGHTCYAN_EX}Options:{Style.RESET_ALL}")
    print("1. Save output")
    print("2. Scan & show running services (version detection)")
    option = input(f"{Fore.LIGHTYELLOW_EX}Enter your choice (1/2): {Style.RESET_ALL}").strip()

    if option == '1':
        prompt_save(table)
    elif option == '2':
        print(f"\n{Fore.LIGHTGREEN_EX}Scanning with service/version detection...\n{Style.RESET_ALL}")
        scanner.scan(host, arguments=f'-sV -Pn --top-ports {top_ports}')
        if host not in scanner.all_hosts():
            print(f"{Fore.LIGHTRED_EX}Service scan failed. Host '{host}' may be unreachable.{Style.RESET_ALL}")
            return

        results = []
        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                data = scanner[host][proto][port]
                results.append({
                    'Port': port,
                    'State': data['state'],
                    'Service': data.get('name', 'unknown'),
                    'Product': data.get('product', 'unknown'),
                    'Version': data.get('version', 'unknown')
                })
        table = tabulate(results, headers="keys", tablefmt="grid")
        print(table)
        prompt_save(table)
    else:
        print(f"{Fore.LIGHTRED_EX}Invalid choice.{Style.RESET_ALL}")

def system_detection(scanner, host):
    print(f"\n{Fore.LIGHTGREEN_EX}Performing OS detection on {host}...\n{Style.RESET_ALL}")
    scanner.scan(host, arguments='-O -Pn')

    if host not in scanner.all_hosts():
        print(f"{Fore.LIGHTRED_EX}No results. Host '{host}' may be unreachable.{Style.RESET_ALL}")
        return

    results = []
    try:
        for match in scanner[host]['osmatch'][:3]:
            results.append({
                'OS': match['name'],
                'Accuracy': f"{match['accuracy']}%",
                'Type': match.get('osclass', [{}])[0].get('type', 'unknown')
            })
    except KeyError:
        results.append({'OS': 'N/A', 'Accuracy': 'N/A', 'Type': 'N/A'})

    table = tabulate(results, headers="keys", tablefmt="grid")
    print(table)
    prompt_save(table)

def vulnerability_scan(scanner, host):
    print(f"\n{Fore.LIGHTGREEN_EX}Running vulnerability scan... (This might take some time){Style.RESET_ALL}")
    scanner.scan(host, arguments='-Pn --script vuln')

    if host not in scanner.all_hosts():
        print(f"{Fore.LIGHTRED_EX}No results. Host '{host}' may be unreachable.{Style.RESET_ALL}")
        return

    results = []
    for proto in scanner[host].all_protocols():
        for port in scanner[host][proto]:
            scripts = scanner[host][proto][port].get('script', {})
            for name, output in scripts.items():
                results.append({
                    'Script': name,
                    'Port': port,
                    'Output': (output[:100] + '...') if len(output) > 100 else output
                })

    if results:
        table = tabulate(results, headers="keys", tablefmt="grid")
        print(table)
        prompt_save(table)
    else:
        print(f"{Fore.LIGHTYELLOW_EX}No vulnerabilities found or scripts returned no output.{Style.RESET_ALL}")

def network_topology(scanner, host):
    print(f"\n{Fore.LIGHTGREEN_EX}Tracing network path to {host}...\n{Style.RESET_ALL}")
    scanner.scan(host, arguments='-Pn -sn --traceroute')

    if host not in scanner.all_hosts():
        print(f"{Fore.LIGHTRED_EX}No results. Host '{host}' may be unreachable.{Style.RESET_ALL}")
        return

    results = []
    trace_data = scanner[host].get('traceroute', {}).get('hop', [])
    if not trace_data:
        results.append({'Hop': 'N/A', 'IP': 'N/A', 'RTT': 'N/A'})
    else:
        for hop in trace_data:
            results.append({
                'Hop': hop.get('ttl', 'N/A'),
                'IP': hop.get('ipaddr', 'N/A'),
                'RTT': hop.get('rtt', 'N/A')
            })

    table = tabulate(results, headers="keys", tablefmt="grid")
    print(table)
    prompt_save(table)

def main():
    scanner = nmap.PortScanner()
    user_input = input(f"{Fore.LIGHTCYAN_EX}Enter the domain or IP address to scan: {Style.RESET_ALL}").strip()
    host = resolve_host(user_input)
    if not host:
        return

    print(f"\n{Fore.LIGHTYELLOW_EX}Choose a functionality:{Style.RESET_ALL}")
    print("1. Port Scan")
    print("2. System Detection")
    print("3. Vulnerability Identification")
    print("4. Network Topology & Architecture")

    choice = input(f"{Fore.LIGHTYELLOW_EX}Enter choice (1/2/3/4): {Style.RESET_ALL}").strip()

    if choice == '1':
        port_scan(scanner, host)
    elif choice == '2':
        system_detection(scanner, host)
    elif choice == '3':
        vulnerability_scan(scanner, host)
    elif choice == '4':
        network_topology(scanner, host)
    else:
        print(f"{Fore.LIGHTRED_EX}Invalid choice. Exiting.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
