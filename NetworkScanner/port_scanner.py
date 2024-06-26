import socket
import threading
from queue import Queue
from scapy.all import IP, TCP, sr1, conf
import ipaddress

# Set Scapy to use Npcap if available
conf.use_pcap = True

class PortScanner:
    def __init__(self, ip, port_range, num_threads=100):
        self.ip = ip
        self.port_range = port_range
        self.num_threads = num_threads
        self.queue = Queue()
        self.output = Queue()
        self.open_ports = []

    def get_banner(self, port):
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((self.ip, port))
            s.send(b'HELLO\r\n')
            banner = s.recv(1024).decode().strip()
            s.close()
            return banner
        except Exception as e:
            print(f"Error retrieving banner from {self.ip}:{port} - {e}")
            return None

    def scan_port(self, port):
        ip_pkt = IP(dst=self.ip)
        tcp_pkt = TCP(dport=port, flags="S")
        pkt = ip_pkt / tcp_pkt
        try:
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:  # SYN-ACK check
                print(f"Port {port} on {self.ip} is open.")
                self.open_ports.append(port)
                banner = self.get_banner(port)
                self.output.put((port, banner))
            else:
                print(f"Port {port} on {self.ip} is closed or filtered.")
        except Exception as e:
            print(f"Error scanning port {port} on {self.ip} - {e}")

    def worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            self.scan_port(port)
            self.queue.task_done()

    def run(self):
        for port in range(self.port_range[0], self.port_range[1] + 1):
            self.queue.put(port)

        threads = []
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self.worker)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        while not self.output.empty():
            port, banner = self.output.get()
            if banner:
                print(f"Port {port} on {self.ip}: Open - Banner: {banner}")
            else:
                print(f"Port {port} on {self.ip}: Open - No banner retrieved")
        
        if not self.open_ports:
            print("No ports were open.")

class NetworkScanner:
    def __init__(self, ip_range, port_range, num_threads=100):
        self.ip_range = self.generate_ip_range(ip_range)
        self.port_range = port_range
        self.num_threads = num_threads

    def generate_ip_range(self, ip_range):
        ip_start, ip_end = ip_range
        start = int(ipaddress.IPv4Address(ip_start))
        end = int(ipaddress.IPv4Address(ip_end))
        return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]

    def run(self):
        for ip in self.ip_range:
            print(f"=======================\nScanning IP: {ip}\nPort Range: {self.port_range[0]}-{self.port_range[1]}\n=======================")
            scanner = PortScanner(ip, self.port_range, self.num_threads)
            scanner.run()

if __name__ == "__main__":
    ip_start = "192.168.1.1"  # Start IP address
    ip_end = "192.168.1.10"  # End IP address
    start_port = 20
    end_port = 26
    num_threads = 100

    ip_range = (ip_start, ip_end)
    port_range = (start_port, end_port)

    network_scanner = NetworkScanner(ip_range, port_range, num_threads)
    network_scanner.run()
