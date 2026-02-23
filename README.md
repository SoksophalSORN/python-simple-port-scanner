# **Python Simple Port Scanner**

A fast, customizable, multithreaded TCP port scanner written purely in Python. Built to mirror the core functionality of Nmap, this tool includes ICMP host discovery, multithreading, custom port range parsing, and integration with Nmap's official top open-frequency port lists.

## **Features**

* **TCP Connect Scanning**: Accurately determines if ports are OPEN, CLOSED, or FILTERED.  
* **Multithreading**: Scans ports concurrently for incredibly fast execution times using Python's concurrent.futures.  
* **Host Discovery**: Automatically pings targets using OS-level ICMP before scanning to save time on dead hosts.  
* **Nmap Port Lists**: Built-in support for scanning Nmap's top 100, 500, or 1000 most common TCP ports.  
* **Port Exclusion**: Easily exclude specific ports or ranges from your scan.  
* **Colorized Output**: Clean, visually appealing terminal output for quick reading.

## **Prerequisites**

This script uses only built-in Python libraries\! No external pip installations are required for the main engine.

* Python 3.6 or higher.  
* Compatible with Windows, Linux, and macOS.

*(Note: The project relies on a components/ports.py file which houses the Nmap top port lists).*

## **Usage**

### **Basic Syntax**

python port-scanner.py \<target\> \[options\]

### **Options & Flags**

| **Flag** | **Example** | **Description** |
|----------|-------------|-----------------|
| \<target\> | 192.168.1.1 | **(Required)** The IP address or hostname to scan. |
| \-p, \--ports | \-p 80,443 | Ports to scan. Accepts commas, ranges (1-100), \- (all 65535), or top100/top500/top1000. |
| \-e, \--exclude | \-e 21-25 | Ports to exclude from the scan. Uses the same format as \-p. |
| \-Pn | \-Pn | Disables ICMP host discovery. Treats the target as online and forces the scan. |
| \-t, \--threads | \-t 50 | Number of concurrent threads to use. Default is 4\. |
| \--disable-multithreading | \--disable-multithreading | Forces a sequential scan (one port at a time). |
| \-v | \-v | Verbose mode. Prints the status of closed and filtered ports during the scan. |
| \-h, \--help | \-h | Shows the detailed help menu. |

## **Examples**

**1\. Default Scan (Top 100 ports)**
```bash
python port-scanner.py scanme.nmap.org
```
**2\. Fast Scan (Top 1000 ports using 100 threads)**
```bash
python port-scanner.py 192.168.1.5 \-p top1000 \-t 100
```
**3\. Scan specific ports with verbose output**
```bash
python port-scanner.py 10.0.0.1 \-p 21,22,80,443,8080 \-v
```
**4\. Scan all 65,535 ports, but exclude port 80**
```bash
python port-scanner.py 192.168.1.1 \-p \- \-e 80 \-t 200
```
**5\. Scan a host that blocks ICMP Pings (Force Scan)**
```bash
python port-scanner.py 10.0.0.25 \-Pn
```
## **Disclaimer**

This tool is intended for educational purposes, network administration, and authorized security auditing. **Do not use this tool to scan networks or hosts that you do not own or do not have explicit permission to test.**