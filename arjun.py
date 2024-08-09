import nmap

def run_nmap_vuln_scan(target):
    # Initialize the Nmap PortScanner
    nm = nmap.PortScanner()

    # Run the Nmap vuln script against the target
    print(f"Running Nmap vulnerability scan on {target}...")
    nm.scan(target, arguments="--script vuln -nvv")

    # Parse the results
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")

            lport = nm[host][proto].keys()
            for port in sorted(lport):
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
                
                # Check if any script output is available
                if 'script' in nm[host][proto][port]:
                    for script_name, script_output in nm[host][proto][port]['script'].items():
                        print(f"Script: {script_name}\nOutput: {script_output}\n")

if __name__ == "__main__":
    target = input("Enter the IP address or website to scan: ")
    run_nmap_vuln_scan(target)