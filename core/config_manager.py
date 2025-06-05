from netmiko import ConnectHandler
import os
import datetime

def connect(device):
    return ConnectHandler(**device)

def backup_config(device):
    ssh = connect(device)
    config = ssh.send_command("show running-config")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{device['host']}_backup_{timestamp}.cfg"
    path = os.path.join("backups", filename)
    os.makedirs("backups", exist_ok=True)
    with open(path, "w") as f:
        f.write(config)
    ssh.disconnect()
    return path

def rollback_config(device, backup_path):
    ssh = connect(device)
    with open(backup_path, "r") as f:
        lines = f.read().splitlines()
    output = ssh.send_config_set(lines)
    ssh.disconnect()
    return output

def get_latest_backup(device_host):
    backups = sorted(
        [f for f in os.listdir("backups") if f.startswith(device_host)],
        reverse=True
    )
    if not backups:
        return None
    return os.path.join("backups", backups[0])