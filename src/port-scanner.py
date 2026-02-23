import socket
import argparse
import sys
import subprocess
import platform
import concurrent.futures
import time
from components.ports import TOP_100, TOP_500, TOP_1000

# Terminal Colors
class Color:
  RED = '\033[91m'
  GREEN = '\033[92m'
  YELLOW = '\033[93m'
  BLUE = '\033[94m'
  RESET = '\033[0m'

class ColoredIcons:
  OPEN = f"{Color.GREEN}[+]{Color.RESET}"
  CLOSED = f"{Color.YELLOW}[-]{Color.RESET}"
  ERROR = f"{Color.RED}[!]{Color.RESET}"
  INFO = f"{Color.BLUE}[*]{Color.RESET}"

def get_args():
  parser = argparse.ArgumentParser(
      description="Simple Python-Based Port Scanner.",
      epilog="Usage: python port-scanner.py scanme.nmap.org",
      formatter_class=argparse.RawTextHelpFormatter
      )

  parser.add_argument("target", help="The target IP address or hostname to scan") # .target
  parser.add_argument("-p", "--ports", help="The target ports (e.g., 80, 21,22,23, 1-100).\n-p- to scan all 65535 ports (1-65535)\ntop100 to scan Nmap's top 100 most common TCP ports\ntop500 to scan Nmap's top 500 most common TCP ports\ntop1000 to scan Nmap's top 1000 most common TCP ports", default="top100") # .ports
  parser.add_argument("-e", "--exclude", help="Ports to exclude from scanning (e.g., 80, 21,22,23, 1-100)", default="") # .exclude
  parser.add_argument("-Pn", help="Disable host discovery, treating all hosts as online", action="store_true") # .Pn
  parser.add_argument("-v", help="More verbose", action="store_true") # .v
  parser.add_argument("-t", "--threads", help="Number of threads for concurrent scanning (default: 4)", type=int, default=4) # .threads
  parser.add_argument("--disable-multithreading", help="Disable multithreading and scan ports sequentially.", action="store_true") # .disable_multithreading
  
  return parser.parse_args()

def parse_ports(port_args: str) -> list:
  if port_args == "top100":
    print(f"{ColoredIcons.INFO} Scanning Nmap's Top 100 TCP ports")
    return TOP_100
  elif port_args == "top500":
    print(f"{ColoredIcons.INFO} Scanning Nmap's Top 500 TCP ports")
    return TOP_500
  elif port_args == "top1000":
    print(f"{ColoredIcons.INFO} Scanning Nmap's Top 1000 TCP ports")
    return TOP_1000
  elif port_args == "-":
    print(f"{ColoredIcons.INFO} Scanning all 65535 ports (1-65535)")
    return list(range(1, 65536))

  ports = []
  try:
    if '-' in port_args:
      start, end = port_args.split('-')
      ports = list(range(int(start), int(end) + 1))
    elif ',' in port_args:
      ports = [int(p) for p in port_args.split(',')]
    else:
      ports = [int(port_args)]
    return ports
  except ValueError:
    print(f"{ColoredIcons.ERROR} Invalid Port Format.")
    sys.exit(1)


def discover_host(target: str):
  current_os = platform.system().lower() # get this computer's OS
  count_opt = '-n' if current_os == 'windows' else '-c'
  command = ['ping', count_opt, '1', target]

  try:
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) # stdout sent to NULL
    # For debugging purpose
    # result = subprocess.run(command)
    return result.returncode == 0
  except Exception as e:
    print(f"{ColoredIcons.ERROR} Ping Failed: {e}")
    return False

def scan_port(
    target: str, 
    port: int,
    verbose: bool
    ):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(1)
  try:
    s.connect((target, port))
    if verbose: print(f"{ColoredIcons.OPEN} Port {port} is OPEN")
    return port
  except ConnectionRefusedError:
    if verbose: print(f"{ColoredIcons.CLOSED} Port {port} is CLOSED (Connection Refused)")
  except socket.timeout:
    if verbose: print(f"{ColoredIcons.CLOSED} Port {port} is FILTERED/CLOSED (Timeout)")
  except socket.error as err:
    print(f"{ColoredIcons.ERROR} Socket Failed To Initialize: {err}")
  finally:
    # Making sure that socket always closes
    s.close()

# Main
if __name__ == "__main__":
  args = get_args()

  # Host Discovery
  try:
    target_ip = socket.gethostbyname(args.target)
    print(f"{ColoredIcons.OPEN} Target IP: {target_ip}")
  except socket.gaierror:
    print(f"{ColoredIcons.ERROR} Could not resolve hostname: {args.target}")
    sys.exit(1)

  if args.Pn:
    print(f"{ColoredIcons.INFO} Skipping host discovery (-Pn), Treating {target_ip} as online")
  else:
    print(f"{ColoredIcons.INFO} Checking if {target_ip} is online...")
    if discover_host(target_ip):
      print(f"{ColoredIcons.OPEN} Host {target_ip} is online.")
    else:
      print(f"{ColoredIcons.CLOSED} Host {target_ip} seems to be DOWN or not replying to ICMP Echo.")
      print(f"{ColoredIcons.CLOSED} Exiting Scanner...")
      sys.exit(0)

  # Port Scanning
  ports = parse_ports(args.ports)

  if args.exclude:
    ports_to_exclude = parse_ports(args.exclude)
    ports = [p for p in ports if p not in ports_to_exclude]
    print(f"{ColoredIcons.INFO} Excluded {len(ports_to_exclude)} from the scanning process")

  open_ports = []
  if args.disable_multithreading:
    print(f"{ColoredIcons.INFO} Scanning ports sequentially...")
    start_time = time.perf_counter()
    for p in ports:
      open_port = scan_port(target_ip, p, args.v)
      if open_port is not None: open_ports.append(open_port)
    end_time = time.perf_counter()
    print(f"{ColoredIcons.INFO} Scanned {len(ports)} ports in {end_time - start_time:.2f} seconds")
  else:
    start_time = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
      futures = {executor.submit(scan_port, target_ip, p, args.v): p for p in ports}
      for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result is not None: open_ports.append(result)
    end_time = time.perf_counter()
    print(f"{ColoredIcons.INFO} Scanned {len(ports)} ports in {end_time - start_time:.2f} seconds")
    open_ports.sort() # Sort open ports in ascending order

  # Reporting

  print(f"{ColoredIcons.INFO} Reporting...")
  if not open_ports:
    print(f"{ColoredIcons.CLOSED}Host {target_ip} does not have any open port.")
  else:
    print(f"Port\t\tStatus")
    print(f"====\t\t======")
    for port in open_ports:
      print(f"{port}\t\tOPEN")

  print(f"{ColoredIcons.INFO} Port Scanning Complete")
