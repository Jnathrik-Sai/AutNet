import os
import json
import shutil
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, QTimer
import subprocess
import platform
import csv
import threading
import time
from core.ssh_client import SSHClient

DEVICE_FILE = "data/devices.json"
BACKUP_DIR = "backups"

class MonitorTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.devices = []
        self.monitoring_active = False
        self.monitoring_thread = None
        self.setLayout(QVBoxLayout())
        self.init_ui()
        self.load_devices()
        self.create_backup_dir()

    def create_backup_dir(self):
        os.makedirs(BACKUP_DIR, exist_ok=True)

    def init_ui(self):
        # Device selection
        selection_layout = QHBoxLayout()
        self.device_combo = QComboBox()
        selection_layout.addWidget(QLabel("Select Device:"))
        selection_layout.addWidget(self.device_combo)
        self.layout().addLayout(selection_layout)

        # Real-time monitoring controls
        monitor_layout = QHBoxLayout()
        self.start_monitor_btn = QPushButton("Start Monitoring")
        self.stop_monitor_btn = QPushButton("Stop Monitoring")
        self.stop_monitor_btn.setEnabled(False)
        monitor_layout.addWidget(self.start_monitor_btn)
        monitor_layout.addWidget(self.stop_monitor_btn)
        self.layout().addLayout(monitor_layout)
        
        # Status/Monitoring section
        status_layout = QVBoxLayout()
        self.status_label = QLabel("Status: Not Monitored")
        self.status_label.setStyleSheet("font-weight: bold;")
        
        self.config_status_label = QLabel("Config Status: Unknown")
        self.config_status_label.setStyleSheet("font-weight: bold;")
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.config_status_label)
        self.layout().addLayout(status_layout)

        # Rollback button
        rollback_layout = QHBoxLayout()
        self.rollback_btn = QPushButton("Rollback Configuration")
        self.view_backups_btn = QPushButton("View Backups")
        rollback_layout.addWidget(self.rollback_btn)
        rollback_layout.addWidget(self.view_backups_btn)
        self.layout().addLayout(rollback_layout)

        # Logs or output view
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.layout().addWidget(QLabel("Logs/Output:"))
        self.layout().addWidget(self.log_output)

        # Event bindings
        self.start_monitor_btn.clicked.connect(self.start_monitoring)
        self.stop_monitor_btn.clicked.connect(self.stop_monitoring)
        self.rollback_btn.clicked.connect(self.rollback_config)
        self.view_backups_btn.clicked.connect(self.view_backups)
        self.device_combo.currentIndexChanged.connect(self.device_changed)

    def device_changed(self):
        if not self.monitoring_active:
            self.status_label.setText("Status: Not Monitored")
            self.config_status_label.setText("Config Status: Unknown")

    def load_devices(self):
        if not os.path.exists(DEVICE_FILE):
            QMessageBox.warning(self, "Missing File", f"{DEVICE_FILE} not found.")
            return

        try:
            with open(DEVICE_FILE, "r") as f:
                self.devices = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load devices: {e}")
            return

        self.device_combo.clear()
        for d in self.devices:
            self.device_combo.addItem(f"{d['hostname']} ({d['ip']})", d)

    def get_selected_device(self):
        index = self.device_combo.currentIndex()
        if index < 0:
            QMessageBox.warning(self, "Missing", "Please select a device.")
            return None
        return self.device_combo.itemData(index)

    def start_monitoring(self):
        device = self.get_selected_device()
        if not device:
            return

        self.monitoring_active = True
        self.start_monitor_btn.setEnabled(False)
        self.stop_monitor_btn.setEnabled(True)
        
        # Start monitoring in a separate thread
        self.monitoring_thread = threading.Thread(target=self.monitor_device, args=(device,))
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        self.log_output.appendPlainText(f"Started monitoring {device['hostname']} ({device['ip']})...")

    def stop_monitoring(self):
        self.monitoring_active = False
        self.start_monitor_btn.setEnabled(True)
        self.stop_monitor_btn.setEnabled(False)
        self.log_output.appendPlainText("Monitoring stopped.")

    def monitor_device(self, device):
        ip = device["ip"]
        last_status = None
        last_config_status = None
        
        while self.monitoring_active:
            try:
                # Check connectivity
                online = self.check_connectivity(ip)
                status_text = f"Status: {ip} is {'Online' if online else 'Offline'}"
                
                # Check config status if online
                config_status = "Unknown"
                if online:
                    config_status = self.check_config_status(device)
                    config_text = f"Config Status: {config_status}"
                else:
                    config_text = "Config Status: Device offline"
                
                # Update UI if status changed
                if status_text != last_status or config_text != last_config_status:
                    self.status_label.setText(status_text)
                    self.config_status_label.setText(config_text)
                    self.status_label.setStyleSheet(
                        f"color: {'green' if online else 'red'}; font-weight: bold;"
                    )
                    self.config_status_label.setStyleSheet(
                        f"color: {'green' if config_status == 'OK' else 'orange' if config_status == 'Unknown' else 'red'}; "
                        "font-weight: bold;"
                    )
                    last_status = status_text
                    last_config_status = config_text
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.log_output.appendPlainText(f"Monitoring error: {str(e)}")
                time.sleep(10)

    def check_connectivity(self, ip):
        """Check if device is reachable via ping"""
        count_flag = "-n" if platform.system().lower() == "windows" else "-c"
        
        try:
            response = subprocess.run(
                ["ping", count_flag, "1", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3
            )
            return response.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False

    def check_config_status(self, device):
        """
        Check if device configuration matches the expected state
        Supports Linux and optionally other device types like Cisco
        """
        try:
            password = self.get_password_from_vault(device)
            if not password:
                return "Password not available"

            ssh = SSHClient(device, password)
            if not ssh.connect():
                return "Connection Failed"

            device_type = device.get("type", "linux").lower()

            # Choose command based on device type
            if device_type == "linux":
                command = "ip a"  # Can customize this further
            elif device_type == "cisco":
                command = "show running-config"
            elif device_type == "juniper":
                command = "show configuration"
            else:
                command = "ip a"  # Safe default

            output = ssh.run_command(command)
            ssh.disconnect()

            # Validation logic based on device type
            if device_type == "linux":
                if "inet" in output:
                    return "OK"
                else:
                    return "Config Error"
            elif device_type in ["cisco", "juniper"]:
                if "Current configuration" in output or "version" in output:
                    return "OK"
                else:
                    return "Config Error"
            else:
                return "Unknown device type"

        except Exception as e:
            return f"Error: {str(e)}"

    def rollback_config(self):
        device = self.get_selected_device()
        if not device:
            return

        backups = self.get_device_backups(device)
        if not backups:
            QMessageBox.warning(self, "No Backups", f"No backups found for {device['ip']}")
            return

        # Show backup selection dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Backup to Restore")
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("Available Backups:"))

        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Timestamp", "Size", "Path"])
        table.setRowCount(len(backups))
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)

        for i, (timestamp, size, path) in enumerate(backups):
            table.setItem(i, 0, QTableWidgetItem(timestamp))
            table.setItem(i, 1, QTableWidgetItem(f"{size} bytes"))
            table.setItem(i, 2, QTableWidgetItem(path))

        table.resizeColumnsToContents()
        layout.addWidget(table)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec_() != QDialog.Accepted or not table.selectedItems():
            return

        selected_row = table.currentRow()
        backup_path = backups[selected_row][2]

        password = self.get_password_dialog(device)
        if password is None:
            return

        with open(backup_path, "r") as f:
            config = f.read()

        ssh = SSHClient(device, password)
        if ssh.connect():
            device_type = device.get("type", "linux").lower()
            try:
                if device_type == "linux":
                    # Write config to a temp file and execute it
                    remote_path = "/tmp/rollback_config.sh"
                    escaped_config = config.replace("'", "'\"'\"'")
                    ssh.run_command(f"echo '{escaped_config}' > {remote_path}")
                    output = ssh.run_command(f"bash {remote_path}")
                elif device_type in ["cisco", "juniper"]:
                    output = ssh.send_config(config.splitlines())
                else:
                    output = "Unsupported device type for rollback."
            except Exception as e:
                output = f"Rollback failed: {str(e)}"
            ssh.disconnect()

            self.log_output.appendPlainText(f"Rollback completed for {device['ip']}:\n{output}")
            QMessageBox.information(self, "Rollback", "Configuration rolled back successfully.")
        else:
            QMessageBox.critical(self, "SSH Failed", "Could not connect to device.")

    def view_backups(self):
        device = self.get_selected_device()
        if not device:
            return

        backups = self.get_device_backups(device)
        if not backups:
            QMessageBox.warning(self, "No Backups", f"No backups found for {device['ip']}")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Backups for {device['hostname']} ({device['ip']})")
        dialog.resize(600, 400)
        layout = QVBoxLayout(dialog)
        
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Timestamp", "Size", "Path"])
        table.setRowCount(len(backups))
        
        for i, (timestamp, size, path) in enumerate(backups):
            table.setItem(i, 0, QTableWidgetItem(timestamp))
            table.setItem(i, 1, QTableWidgetItem(f"{size} bytes"))
            table.setItem(i, 2, QTableWidgetItem(path))
        
        table.resizeColumnsToContents()
        layout.addWidget(table)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.exec_()

    def get_device_backups(self, device):
        """Get sorted list of backups for a device (newest first)"""
        device_backup_dir = os.path.join(BACKUP_DIR, device['ip'])
        if not os.path.exists(device_backup_dir):
            return []
            
        backups = []
        for filename in os.listdir(device_backup_dir):
            if filename.endswith(".txt"):
                path = os.path.join(device_backup_dir, filename)
                timestamp = filename.replace(".txt", "").replace("_", " ")
                size = os.path.getsize(path)
                backups.append((timestamp, size, path))
                
        # Sort by filename (which contains timestamp) descending
        backups.sort(key=lambda x: x[0], reverse=True)
        return backups

    def get_password_dialog(self, device):
        password, ok = QInputDialog.getText(
            self, "SSH Password",
            f"Enter password for {device['hostname']} ({device['ip']}):",
            echo=QLineEdit.Password
        )
        return password if ok and password else None
        
    def get_password_from_vault(self, device):
        """Retrieve password from secure storage (simplified for demo)"""
        # In a real implementation, use a proper credential manager
        return device.get("password", None)