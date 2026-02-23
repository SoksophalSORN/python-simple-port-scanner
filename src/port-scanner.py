import socket
import argparse
import sys
import subprocess
import platform
import concurrent.futures

# Terminal Colors
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 
    135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 
    544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 
    3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5190, 5357, 5432, 5631, 5666, 
    5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
]

def get_args():
  parser = argparse.ArgumentParser(
      description="Simple Python-Based Port Scanner.",
      epilog="Usage: python port-scanner.py 192.168.1.1"
      )

  parser.add_argument("target", help="The target IP address or hostname to scan") # .target
  parser.add_argument("-p", "--ports", help="The target ports (e.g., 80, 21,22,23, 1-100)", default="top100") # .ports
  parser.add_argument("-Pn", help="Disable host discovery, treating all hosts as online", action="store_true")
  parser.add_argument("-v", help="More verbose", action="store_true")
  
  return parser.parse_args()

def parse_ports(port_args: str) -> list:
  if port_args == "top100":
    print(f"{Color.BLUE}[*]{Color.RESET} No port given. Defaulting to Nmap's Top 100 most common TCP ports")
    return TOP_100_PORTS

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
    print(f"{Color.RED}[!]{Color.RESET} Invalid Port Format.")
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
    print(f"{Color.RED}[!]{Color.RESET} Ping Failed: {e}")
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
    if verbose: print(f"{Color.GREEN}[+]{Color.RESET} Port {port} is OPEN")
    return port
  except ConnectionRefusedError:
    if verbose: print(f"{Color.YELLOW}[-]{Color.RESET} Port {port} is CLOSED (Connection Refused)")
  except socket.timeout:
    if verbose: print(f"{Color.YELLOW}[-]{Color.RESET} Port {port} is FILTERED/CLOSED (Timeout)")
  except socket.error as err:
    print(f"{Color.RED}[!]{Color.RESET} Socket Failed To Initialize: {err}")
  finally:
    # Making sure that socket always closes
    s.close()

# Main
if __name__ == "__main__":
  args = get_args()

  # Host Discovery
  try:
    target_ip = socket.gethostbyname(args.target)
    print(target_ip)
  except socket.gaierror:
    print(f"{Color.RED}[!]{Color.RESET} Could not resolve hostname: {args.target}")
    sys.exit(1)

  if args.Pn:
    print(f"{Color.BLUE}[*]{Color.RESET} Skipping host discovery (-Pn), Treating {target_ip} as online")
  else:
    print(f"{Color.BLUE}[*]{Color.RESET} Checking if {target_ip} is online...")
    if discover_host(target_ip):
      print(f"{Color.GREEN}[+]{Color.RESET} Host {target_ip} is online.")
    else:
      print(f"{Color.YELLOW}[-]{Color.RESET} Host {target_ip} seems to be DOWN or not replying to ICMP Echo.")
      print("{Color.YELLOW}[-]{Color.RESET} Exiting Scanner...")
      sys.exit(0)

  # Port Scanning
  ports = parse_ports(args.ports)

  open_ports = []
  for p in ports:
    open_port = scan_port(target_ip, p, args.v)
    if open_port is not None: open_ports.append(open_port)

  # Reporting

  print(f"{Color.BLUE}[*]{Color.RESET} Reporting...")
  if not open_ports:
    print(f"{Color.YELLOW}[-]{Color.RESET}Host {target_ip} does not have any open port.")
  else:
    print(f"Port\t\tStatus")
    print(f"====\t\t======")
    for port in open_ports:
      print(f"{port}\t\tOPEN")

  print(f"{Color.BLUE}[*]{Color.RESET} Port Scanning Complete")
