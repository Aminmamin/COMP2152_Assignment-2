"""
Author: Muhammad-Amin Farhan Ali
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime
import sys

print("Python version:", sys.version)
print("OS name:", platform.system())

# This stores some common ports and what they are usually used for
common_ports = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value.strip() == "":
            raise ValueError("Target cannot be empty.")
        self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q3: What is the benefit of using @property and @target.setter?
# One benefit is that it helps protect the data in the class.
# It lets us check the value before changing it.
# In this case, it stops the target from being set to an empty string.


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner reuses code by inheriting from NetworkTool.
# That means it can use the target part from the parent class instead of making it again.
# This helps keep the code shorter and easier to follow.


class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, the whole program could stop if a socket error happens.
        # For example, if one port gives a problem, the scan may crash.
        # With try-except, it can keep going and scan the other ports.

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error on port {port}: {e}")

        finally:
            if sock:
                sock.close()

    def get_open_ports(self):
        # Q2: Why do we use threading instead of scanning one port at a time?
        # We use threading because it makes scanning faster.
        # It checks many ports at the same time instead of going one by one.
        # This is better when there are a lot of ports to scan.

        return [result for result in self.scan_results if result[1] == "Open"]

    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)

        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print("Database error:", e)


def load_past_scans():
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        if rows:
            print("\nPast Scan History:")
            for row in rows:
                print(f"ID: {row[0]}, Target: {row[1]}, Port: {row[2]}, Status: {row[3]}, Service: {row[4]}, Date: {row[5]}")
        else:
            print("No past scans found.")

    except sqlite3.Error:
        print("No past scans found.")

    finally:
        if conn:
            conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    try:
        target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
        if target == "":
            target = "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target)
            print(f"\nScanning {target} from port {start_port} to {end_port}...")

            scanner.scan_range(start_port, end_port)

            open_ports = scanner.get_open_ports()

            print("\nOpen Ports:")
            if open_ports:
                for port, status, service in open_ports:
                    print(f"Port {port}: {status} ({service})")
            else:
                print("No open ports found.")

            print(f"\nTotal open ports found: {len(open_ports)}")

            save_results(target, scanner.scan_results)

            choice = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
            if choice == "yes":
                load_past_scans()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")


# Q5: New Feature Proposal
# A good new feature would be adding hostname scanning instead of only IP addresses.
# This would make the program easier to use because the user could type a website name too.
# Diagram: See diagram_studentID.png in the repository root
