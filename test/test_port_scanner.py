import unittest
from unittest.mock import patch, MagicMock
import ipaddress
import socket
from scapy.all import IP, TCP, conf

# Import the classes from the original script
from port_scanner import PortScanner, NetworkScanner

class TestPortScanner(unittest.TestCase):
    def setUp(self):
        self.ip = "192.168.1.1"
        self.port_range = (20, 1024)
        self.num_threads = 100

    @patch('socket.socket')
    @patch('scapy.all.sr1')
    def test_scan_port(self, mock_sr1, mock_socket):
        # Mock the sr1 function to simulate an open port
        mock_resp = MagicMock()
        mock_resp.haslayer.return_value = True
        mock_resp.getlayer.return_value.flags = 0x12  # SYN-ACK response
        mock_sr1.return_value = mock_resp

        # Mock the socket connection to simulate a banner retrieval
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.recv.return_value = b"Mock Banner"

        scanner = PortScanner(self.ip, self.port_range, self.num_threads)
        scanner.scan_port(80)

        self.assertIn(80, scanner.open_ports)
        self.assertEqual(scanner.output.get(), (80, "Mock Banner"))

    @patch('socket.socket')
    @patch('scapy.all.sr1')
    def test_no_open_ports(self, mock_sr1, mock_socket):
        # Mock the sr1 function to simulate a closed port
        mock_sr1.return_value = None

        scanner = PortScanner(self.ip, self.port_range, self.num_threads)
        scanner.run()

        self.assertEqual(scanner.open_ports, [])
        self.assertTrue(scanner.output.empty())

class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        self.ip_range = ("192.168.1.1", "192.168.1.10")
        self.port_range = (20, 1024)
        self.num_threads = 100

    def test_generate_ip_range(self):
        scanner = NetworkScanner(self.ip_range, self.port_range, self.num_threads)
        expected_ips = [str(ip) for ip in ipaddress.IPv4Network('192.168.1.0/24')][1:11]
        self.assertEqual(scanner.ip_range, expected_ips)

    @patch('socket.socket')
    @patch('scapy.all.sr1')
    def test_run(self, mock_sr1, mock_socket):
        # Mock the sr1 function to simulate an open port
        mock_resp = MagicMock()
        mock_resp.haslayer.return_value = True
        mock_resp.getlayer.return_value.flags = 0x12  # SYN-ACK response
        mock_sr1.return_value = mock_resp

        # Mock the socket connection to simulate a banner retrieval
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.recv.return_value = b"Mock Banner"

        scanner = NetworkScanner(self.ip_range, self.port_range, self.num_threads)
        scanner.run()

        for ip in scanner.ip_range:
            port_scanner = PortScanner(ip, self.port_range, self.num_threads)
            self.assertIn(80, port_scanner.open_ports)
            self.assertEqual(port_scanner.output.get(), (80, "Mock Banner"))

if __name__ == '__main__':
    unittest.main()
