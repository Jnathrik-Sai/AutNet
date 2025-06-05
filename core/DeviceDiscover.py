import ipaddress
import subprocess
import socket
import concurrent.futures

class DeviceDiscoverer:
    def __init__(self, max_workers=50):
        self.max_workers = max_workers

    def discover(self, ip_range):
        ip_list = self.parse_ip_range(ip_range.strip())
        discovered = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.ping_and_scan, ip): ip for ip in ip_list}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)

        return discovered

    def parse_ip_range(self, ip_range):
        if "/" in ip_range:
            return [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False)]
        elif "-" in ip_range:
            base = ".".join(ip_range.split(".")[:-1])
            start, end = map(int, ip_range.split(".")[-1].split("-"))
            return [f"{base}.{i}" for i in range(start, end + 1)]
        else:
            return [ip_range]

    def ping_and_scan(self, ip):
        try:
            result = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            if result.returncode != 0:
                return None

            hostname = self.get_ssh_banner(ip)
            return {"ip": ip, "hostname": hostname}
        except:
            return None

    def get_ssh_banner(self, ip, port=22, timeout=1):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner = sock.recv(1024).decode(errors="ignore").strip()
                return banner if banner else ip
        except:
            return ip