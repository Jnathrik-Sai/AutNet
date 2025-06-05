import os
import json
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QMessageBox, QDialog,
    QLabel, QLineEdit, QFormLayout, QDialogButtonBox,
    QInputDialog, QComboBox, QFileDialog
)
from PyQt5.QtCore import Qt

from core.DeviceDiscover import DeviceDiscoverer  # 🔹 Discovery logic

DEVICE_FILE = "data/devices.json"

class AddDeviceDialog(QDialog):
    def __init__(self, device=None):
        super().__init__()
        self.setWindowTitle("Device Details")
        self.setModal(True)

        layout = QFormLayout()
        self.ip_input = QLineEdit()
        self.hostname_input = QLineEdit()
        self.username_input = QLineEdit()
        self.port_input = QLineEdit()
        self.group_input = QLineEdit()
        self.tag_input = QLineEdit()
        self.type_combo = QComboBox()
        self.port_input.setText("22")

        self.type_combo.addItems([
            "cisco_ios", "cisco_nxos", "cisco_asa",
            "juniper_junos", "arista_eos", "generic_ssh"
        ])

        layout.addRow("IP Address:", self.ip_input)
        layout.addRow("Hostname:", self.hostname_input)
        layout.addRow("Username:", self.username_input)
        layout.addRow("SSH Port:", self.port_input)
        layout.addRow("Device Type:", self.type_combo)
        layout.addRow("Group / Role:", self.group_input)
        layout.addRow("Tags (comma sep):", self.tag_input)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.validate)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

        if device:
            self.ip_input.setText(device.get("ip", ""))
            self.hostname_input.setText(device.get("hostname", ""))
            self.username_input.setText(device.get("username", ""))
            self.port_input.setText(str(device.get("port", "22")))
            self.group_input.setText(device.get("group", ""))
            self.tag_input.setText(",".join(device.get("tags", [])))
            if "device_type" in device:
                index = self.type_combo.findText(device["device_type"])
                if index >= 0:
                    self.type_combo.setCurrentIndex(index)

    def validate(self):
        if not all([
            self.ip_input.text().strip(),
            self.hostname_input.text().strip(),
            self.username_input.text().strip(),
            self.port_input.text().strip().isdigit()
        ]):
            QMessageBox.warning(self, "Invalid Input", "Please fill all fields correctly.")
            return
        self.accept()

    def get_data(self):
        tags = [t.strip() for t in self.tag_input.text().split(",") if t.strip()]
        return {
            "ip": self.ip_input.text().strip(),
            "hostname": self.hostname_input.text().strip(),
            "username": self.username_input.text().strip(),
            "port": int(self.port_input.text().strip()),
            "group": self.group_input.text().strip(),
            "device_type": self.type_combo.currentText().strip(),
            "tags": tags
        }

class DeviceTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout())
        self.devices = []

        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add Device")
        self.edit_btn = QPushButton("Edit Selected")
        self.remove_btn = QPushButton("Remove Selected")
        self.test_btn = QPushButton("Test Connection")
        self.import_btn = QPushButton("Import Devices")
        self.export_btn = QPushButton("Export Devices")
        
        # Removed discover_btn - replaced with scan input below

        for btn in [self.add_btn, self.edit_btn, self.remove_btn, self.test_btn,
                    self.import_btn, self.export_btn]:
            btn_layout.addWidget(btn)
        self.layout().addLayout(btn_layout)

        # Add discovery input field and scan button
        discovery_layout = QHBoxLayout()
        self.discover_input = QLineEdit()
        self.discover_input.setPlaceholderText("Enter IP range (CIDR or dash)...")
        discovery_layout.addWidget(self.discover_input)
        
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setFixedWidth(80)
        discovery_layout.addWidget(self.scan_btn)
        self.layout().addLayout(discovery_layout)

        filter_layout = QHBoxLayout()
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Devices")
        self.filter_combo.currentIndexChanged.connect(self.populate_table)
        filter_layout.addWidget(QLabel("Filter by Group/Tag:"))
        filter_layout.addWidget(self.filter_combo)
        self.layout().addLayout(filter_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["IP", "Hostname", "Username", "Port", "Type", "Group", "Tags"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.layout().addWidget(self.table)

        self.add_btn.clicked.connect(self.open_add_dialog)
        self.edit_btn.clicked.connect(self.edit_selected_device)
        self.remove_btn.clicked.connect(self.remove_selected_device)
        self.test_btn.clicked.connect(self.test_connection)
        self.import_btn.clicked.connect(self.import_devices)
        self.export_btn.clicked.connect(self.export_devices)
        self.scan_btn.clicked.connect(self.run_device_discovery)  # 🔹 Connect to scan button

        self.load_devices()


    def open_add_dialog(self):
        dialog = AddDeviceDialog()
        if dialog.exec_() == QDialog.Accepted:
            self.devices.append(dialog.get_data())
            self.save_devices()
            self.populate_table()
            self.update_filter_options()

    def edit_selected_device(self):
        row = self.table.currentRow()
        if row >= 0:
            dialog = AddDeviceDialog(self.devices[row])
            if dialog.exec_() == QDialog.Accepted:
                self.devices[row] = dialog.get_data()
                self.save_devices()
                self.populate_table()
                self.update_filter_options()

    def remove_selected_device(self):
        row = self.table.currentRow()
        if row >= 0:
            if QMessageBox.question(self, "Confirm Delete", "Remove selected device?",
                                    QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
                del self.devices[row]
                self.save_devices()
                self.populate_table()
                self.update_filter_options()

    def test_connection(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a device to test.")
            return
        device = self.devices[row]
        password, ok = QInputDialog.getText(self, "SSH Password", f"Enter password for {device['username']}@{device['ip']}:",
                                            QLineEdit.Password)
        if not ok or not password:
            return
        from core.ssh_client import SSHClient
        ssh = SSHClient(device, password)
        if ssh.test_connection():
            QMessageBox.information(self, "Success", f"✅ SSH connection to {device['ip']} successful.")
        else:
            QMessageBox.critical(self, "Failed", f"❌ SSH connection to {device['ip']} failed.")

    def populate_table(self):
        self.table.setRowCount(0)
        selected_filter = self.filter_combo.currentText()
        filtered = self.devices if selected_filter == "All Devices" else [
            d for d in self.devices if d.get("group", "") == selected_filter or selected_filter in d.get("tags", [])
        ]
        for device in filtered:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(device["ip"]))
            self.table.setItem(row, 1, QTableWidgetItem(device["hostname"]))
            self.table.setItem(row, 2, QTableWidgetItem(device["username"]))
            self.table.setItem(row, 3, QTableWidgetItem(str(device["port"])))
            self.table.setItem(row, 4, QTableWidgetItem(device.get("device_type", "generic_ssh")))
            self.table.setItem(row, 5, QTableWidgetItem(device.get("group", "")))
            self.table.setItem(row, 6, QTableWidgetItem(", ".join(device.get("tags", []))))

    def update_filter_options(self):
        current = self.filter_combo.currentText()
        self.filter_combo.blockSignals(True)
        self.filter_combo.clear()
        self.filter_combo.addItem("All Devices")
        options = set()
        for d in self.devices:
            if d.get("group"): options.add(d["group"])
            for tag in d.get("tags", []): options.add(tag)
        self.filter_combo.addItems(sorted(options))
        i = self.filter_combo.findText(current)
        if i >= 0: self.filter_combo.setCurrentIndex(i)
        self.filter_combo.blockSignals(False)

    def load_devices(self):
        if os.path.exists(DEVICE_FILE):
            try:
                with open(DEVICE_FILE, "r") as f:
                    self.devices = json.load(f)
                for d in self.devices:
                    d.setdefault("device_type", "generic_ssh")
                    d.setdefault("tags", [])
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error loading devices: {str(e)}")
                self.devices = []
        self.update_filter_options()
        self.populate_table()

    def save_devices(self):
        os.makedirs(os.path.dirname(DEVICE_FILE), exist_ok=True)
        with open(DEVICE_FILE, "w") as f:
            json.dump(self.devices, f, indent=2)

    def import_devices(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Devices", "", "JSON Files (*.json)")
        if path:
            try:
                with open(path, "r") as f:
                    imported = json.load(f)
                    for d in imported:
                        d.setdefault("device_type", "generic_ssh")
                        d.setdefault("tags", [])
                    self.devices.extend(imported)
                    self.save_devices()
                    self.populate_table()
                    self.update_filter_options()
                    QMessageBox.information(self, "Import Success", "Devices imported successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Import Failed", f"Error: {str(e)}")

    def export_devices(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Devices", "devices.json", "JSON Files (*.json)")
        if path:
            try:
                with open(path, "w") as f:
                    json.dump(self.devices, f, indent=2)
                    QMessageBox.information(self, "Export Success", "Devices exported successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Error: {str(e)}")

    def run_device_discovery(self):
        ip_range = self.discover_input.text().strip()
        if not ip_range:
            QMessageBox.warning(self, "Input Error", "Please enter an IP range to scan")
            return
            
        try:
            discoverer = DeviceDiscoverer()
            discovered = discoverer.discover(ip_range)

            if not discovered:
                QMessageBox.information(self, "Discovery Complete", "No devices found.")
                return

            default_username, ok = QInputDialog.getText(self, "Username", "Enter default SSH username:")
            if not ok:
                return
                
            default_type, ok = QInputDialog.getItem(
                self, "Device Type", "Select default device type:",
                ["cisco_ios", "cisco_nxos", "cisco_asa", "juniper_junos", "arista_eos", "generic_ssh"],
                editable=False
            )
            if not ok:
                return

            count = 0
            for d in discovered:
                ip = d["ip"]
                if any(dev["ip"] == ip for dev in self.devices):
                    continue
                self.devices.append({
                    "ip": ip,
                    "hostname": d.get("hostname", ip),
                    "username": default_username,
                    "port": 22,
                    "device_type": default_type,
                    "group": "",
                    "tags": []
                })
                count += 1

            self.save_devices()
            self.populate_table()
            self.update_filter_options()
            QMessageBox.information(self, "Discovery Done", f"{count} new device(s) added.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Discovery failed: {str(e)}")