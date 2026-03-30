"""
Unit Tests for Assignment 2 — Port Scanner
"""

import unittest

from assignment2_101604337 import PortScanner, common_ports


class TestPortScanner(unittest.TestCase):

    def test_scanner_initialization(self):
        """check if scanner starts properly"""
        scanner = PortScanner("127.0.0.1")

        self.assertEqual(scanner.target, "127.0.0.1")
        self.assertEqual(scanner.scan_results, [])

    def test_get_open_ports_filters_correctly(self):
        """make sure only open ports are returned"""
        scanner = PortScanner("127.0.0.1")

        scanner.scan_results = [
            (22, "Open", "SSH"),
            (23, "Closed", "Telnet"),
            (80, "Open", "HTTP")
        ]

        result = scanner.get_open_ports()

        self.assertEqual(len(result), 2)
        self.assertTrue((22, "Open", "SSH") in result)
        self.assertTrue((80, "Open", "HTTP") in result)

    def test_common_ports_dict(self):
        """check if dictionary has correct values"""
        self.assertEqual(common_ports[80], "HTTP")
        self.assertEqual(common_ports[22], "SSH")

    def test_invalid_target(self):
        """try setting empty target"""
        scanner = PortScanner("127.0.0.1")

        try:
            scanner.target = ""
        except:
            pass 

       
        self.assertEqual(scanner.target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()