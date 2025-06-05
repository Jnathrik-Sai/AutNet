# ==============================
# SSHClient Class (core/ssh_client.py)
# ==============================
import logging
import time
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
import paramiko

logging.basicConfig(filename="logs/app.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

class SSHClient:
    def __init__(self, device, password):
        self.device = device
        self.password = password
        self.connection = None  # For Netmiko
        self.client = None      # For Paramiko
        self.is_netmiko = False
        self.device_type = device.get("device_type", "generic_ssh").strip().lower()

    def connect(self):
        ip = self.device["ip"]
        port = self.device.get("port", 22)
        username = self.device["username"]

        # Cisco devices use Netmiko for better handling
        if self.device_type.startswith("cisco"):
            try:
                self.connection = ConnectHandler(
                    device_type=self.device_type,
                    ip=ip,
                    port=port,
                    username=username,
                    password=self.password,
                    secret=self.password,  # Enable secret
                    timeout=10
                )
                # Enter enable mode automatically
                self.connection.enable()
                self.is_netmiko = True
                logging.info(f"[+] Netmiko connected to {ip} ({self.device_type})")
                return True
            except NetMikoAuthenticationException as e:
                logging.error(f"[Netmiko Auth Error] {ip}: {e}")
                return False
            except NetMikoTimeoutException as e:
                logging.error(f"[Netmiko Timeout] {ip}: {e}")
                return False
            except Exception as e:
                logging.error(f"[Netmiko SSH Error] {ip}: {e}")
                return False
        else:
            try:
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.client.connect(
                    hostname=ip,
                    port=port,
                    username=username,
                    password=self.password,
                    timeout=10
                )
                logging.info(f"[+] Paramiko connected to {ip} ({self.device_type})")
                return True
            except Exception as e:
                logging.error(f"[Paramiko SSH Error] {ip}: {e}")
                return False

    def run_command(self, command):
        ip = self.device["ip"]

        if self.is_netmiko:
            if not self.connection:
                raise Exception("Netmiko SSH not connected")
            try:
                # No need to manually check enable mode - handled automatically
                output = self.connection.send_command(command)
                logging.info(f"[Command - Netmiko] {ip}: {command}")
                return output
            except Exception as e:
                logging.error(f"[Command Error - Netmiko] {ip}: {e}")
                return str(e)
        else:
            if not self.client:
                raise Exception("Paramiko SSH not connected")
            try:
                stdin, stdout, stderr = self.client.exec_command(command, timeout=30)
                output = stdout.read().decode()
                error = stderr.read().decode()
                if error:
                    logging.warning(f"[Command STDERR - Paramiko] {ip}: {error.strip()}")
                logging.info(f"[Command - Paramiko] {ip}: {command}")
                return output + error
            except Exception as e:
                logging.error(f"[Command Error - Paramiko] {ip}: {e}")
                return str(e)

    def send_config(self, commands):
        ip = self.device["ip"]
        if isinstance(commands, str):
            commands = commands.strip().splitlines()

        # Check if we need to save the configuration (for Cisco devices)
        save_needed = any(
            cmd.strip().startswith(("hostname", "interface", "ip route")) 
            for cmd in commands
        )

        if self.is_netmiko:
            if not self.connection:
                raise Exception("Netmiko SSH not connected")
            try:
                # Netmiko handles config mode automatically
                output = self.connection.send_config_set(commands)
                
                # For Cisco devices, save if needed
                if save_needed and self.device_type.startswith("cisco"):
                    save_output = self.connection.send_command("write memory")
                    output += "\n" + save_output
                    
                logging.info(f"[Config Sent - Netmiko] {ip}")
                return output
            except Exception as e:
                logging.error(f"[Send Config Error - Netmiko] {ip}: {e}")
                return str(e)
        else:
            # For Paramiko, we have to handle config mode manually for Cisco
            if self.device_type.startswith("cisco"):
                commands = ["configure terminal"] + commands + ["end"]
                if save_needed:
                    commands.append("write memory")

            if not self.client:
                raise Exception("Paramiko SSH not connected")
            output = ""
            try:
                for cmd in commands:
                    if not cmd.strip():
                        continue
                    stdin, stdout, stderr = self.client.exec_command(cmd)
                    cmd_output = stdout.read().decode()
                    error_output = stderr.read().decode()
                    output += f"$ {cmd}\n{cmd_output}\n{error_output}"
                    # Increased delay for stability
                    time.sleep(0.5)
                logging.info(f"[Config Sent - Paramiko] {ip}")
                return output.strip()
            except Exception as e:
                logging.error(f"[Send Config Error - Paramiko] {ip}: {e}")
                return str(e)

    def disconnect(self):
        ip = self.device["ip"]
        if self.is_netmiko:
            if self.connection:
                try:
                    self.connection.disconnect()
                    logging.info(f"[-] Netmiko disconnected from {ip}")
                except Exception as e:
                    logging.error(f"[Netmiko Disconnect Error] {ip}: {e}")
                finally:
                    self.connection = None
        else:
            if self.client:
                try:
                    self.client.close()
                    logging.info(f"[-] Paramiko disconnected from {ip}")
                except Exception as e:
                    logging.error(f"[Paramiko Disconnect Error] {ip}: {e}")
                finally:
                    self.client = None

    def is_connected(self):
        return self.connection is not None or self.client is not None