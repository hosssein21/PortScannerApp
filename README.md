# PortScannerApp
This is application for scaning IP  to find open ports


## Overview

The Network Port Scanner is a Python-based tool designed to scan a specified range of IP addresses and ports to identify open ports and retrieve available banners. This tool leverages the Scapy library for packet manipulation and socket programming for banner retrieval, making it an effective utility for network administrators and security professionals.

## Features

- **Multi-threaded Scanning**: Efficiently scans multiple ports using threading.
- **Banner Grabbing**: Retrieves and displays banners from open ports.
- **Customizable IP and Port Range**: Specify any range of IP addresses and ports to scan.
- **Network Visualization**: Visual representation of the network being scanned.

## Installation

### Prerequisites

- Python 3.x
- Scapy
- Npcap (for Windows users)

### Steps

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/your-username/network-port-scanner.git
   cd network-port-scanner

    Install the Dependencies:

    bash

    pip install -r requirements.txt

    Install Npcap:
        For Windows users, download and install Npcap from Npcap's official website.

## Usage

    Configure the Scanning Parameters:

    Open scanner.py and configure the parameters:

    python

ip_start = "192.168.1.1"  # Start IP address
ip_end = "192.168.1.10"  # End IP address
start_port = 20
end_port = 26
num_threads = 100

Run the Scanner:

Execute the script:

bash

    python scanner.py

## Output

The script outputs the scan results to the console, indicating the status of each port and any banners retrieved from open ports.

Example output:
<pre>
<code>
=======================
Scanning IP: 192.168.1.1
Port Range: 20-26
=======================
Port 21 on 192.168.1.1 is open.
Port 21 on 192.168.1.1: Open - Banner: 220 FTP Server ready.
Port 22 on 192.168.1.1 is closed or filtered.
Port 23 on 192.168.1.1 is open.
Port 23 on 192.168.1.1: Open - No banner retrieved
...
No ports were open.
=======================
Scanning IP: 192.168.1.2
Port Range: 20-26
=======================
...
</code>
</pre>
## Testing

This project includes unit tests to ensure functionality. Tests are written using unittest and unittest.mock.
Running Tests

bash

python -m unittest discover tests

Test Cases
TestPortScanner

    test_scan_port: Tests scanning a single port.
    test_no_open_ports: Tests scanning with no open ports.

TestNetworkScanner

    test_generate_ip_range: Tests IP range generation.
    test_run: Tests the full scan process.

Code Explanation
PortScanner Class

    __init__(self, ip, port_range, num_threads=100): Initializes the scanner.
    get_banner(self, port): Retrieves banner from open port.
    scan_port(self, port): Scans a single port.
    worker(self): Thread worker function.
    run(self): Starts the scan process.

NetworkScanner Class

    __init__(self, ip_range, port_range, num_threads=100): Initializes the network scanner.
    generate_ip_range(self, ip_range): Generates IP range.
    run(self): Runs the scanner over the IP range.

Network Diagram

Figure 1: Network diagram illustrating the IP range and devices being scanned.
Contributing

Contributions are welcome! Submit a pull request or open an issue on GitHub.
 ## License

This project is licensed under the MIT License. See the LICENSE file for details.
Disclaimer

This tool is intended for educational and authorized testing purposes only. Unauthorized use is illegal and unethical.
