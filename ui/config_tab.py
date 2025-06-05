# ==============================
# ConfigTab Class (GUI) - Complete Fixed Version
# ==============================
import os
import json
import logging
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QComboBox,
    QPushButton, QLabel, QFormLayout, QLineEdit,
    QPlainTextEdit, QMessageBox, QInputDialog,
    QTextEdit, QDialog, QDialogButtonBox, QGroupBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from jinja2 import Environment, FileSystemLoader, meta
from core.ssh_client import SSHClient
from utils.TemplateVarsDialog import TemplateVarsDialog
import getpass

DEVICE_FILE = "data/devices.json"
TEMPLATE_DIR = "templates"

class BulkConfigPushWorker(QThread):
    """Worker for bulk configuration push with backup support"""
    progress = pyqtSignal(int, str, str)  # index, device_ip, status
    finished = pyqtSignal()
    
    def __init__(self, devices, template, variables, get_password_func, backup_dir):
        super().__init__()
        self.devices = devices
        self.template = template
        self.variables = variables
        self.get_password_func = get_password_func
        self.backup_dir = backup_dir

    def run(self):
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template(self.template)
        
        for idx, device in enumerate(self.devices):
            try:
                self.progress.emit(idx, device['ip'], "Starting...")
                
                # Generate config
                config = template.render(device=device, **self.variables)
                config_lines = config.splitlines()
                
                # Get password
                password = self.get_password_func(device)
                if not password:
                    self.progress.emit(idx, device['ip'], "Skipped (no password)")
                    continue
                
                # Connect to device
                ssh = SSHClient(device, password)
                if not ssh.connect():
                    self.progress.emit(idx, device['ip'], "Connection failed")
                    continue
                
                # Backup current config
                backup_success = self.backup_config(device, ssh)
                if not backup_success:
                    self.progress.emit(idx, device['ip'], "Backup failed - skipped")
                    ssh.disconnect()
                    continue
                
                # Push new config
                output = ssh.send_config(config_lines)
                ssh.disconnect()
                
                # Log the change
                self.log_change(device, config_lines)
                
                self.progress.emit(idx, device['ip'], "Success")
                
            except Exception as e:
                error_msg = str(e).replace('\n', ' ')  # Sanitize error message
                self.progress.emit(idx, device['ip'], f"Error: {error_msg}")
        
        self.finished.emit()

    def backup_config(self, device, ssh_client):
        """Backup current configuration"""
        try:
            config_output = ssh_client.run_command("show running-config")
            if not config_output:
                return False
                
            device_dir = os.path.join(self.backup_dir, device['ip'])
            os.makedirs(device_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"config_{timestamp}.txt"
            backup_path = os.path.join(device_dir, filename)
            
            with open(backup_path, 'w') as f:
                f.write(config_output)
                
            return True
        except Exception as e:
            logging.error(f"Backup failed for {device['ip']}: {str(e)}")
            return False

    def log_change(self, device, config_lines):
        """Log configuration changes"""
        log_dir = os.path.join(self.backup_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, device['ip'] + "_changes.log")

        config_text = '\n'.join(config_lines)

        log_content = (
            "=== " + timestamp + " ===\n"
            "Device: " + device['hostname'] + " (" + device['ip'] + ")\n"
            "Configuration:\n" + config_text + "\n\n"
        )

        with open(log_file, 'a') as f:
            f.write(log_content)

class BulkCommandWorker(QThread):
    """Worker for bulk command execution"""
    progress = pyqtSignal(int, str, str)  # index, device_ip, status
    finished = pyqtSignal()
    
    def __init__(self, devices, command, get_password_func):
        super().__init__()
        self.devices = devices
        self.command = command
        self.get_password_func = get_password_func
        
    def run(self):
        for idx, device in enumerate(self.devices):
            try:
                self.progress.emit(idx, device['ip'], "Starting...")
                
                password = self.get_password_func(device)
                if not password:
                    self.progress.emit(idx, device['ip'], "Skipped (no password)")
                    continue
                
                ssh = SSHClient(device, password)
                if ssh.connect():
                    output = ssh.run_command(self.command)
                    ssh.disconnect()
                    display_output = output[:100] + "..." if len(output) > 100 else output
                    self.progress.emit(idx, device['ip'], f"Output: {display_output}")
                else:
                    self.progress.emit(idx, device['ip'], "Connection failed")
                    
            except Exception as e:
                error_msg = str(e).replace('\n', ' ')
                self.progress.emit(idx, device['ip'], f"Error: {error_msg}")
        
        self.finished.emit()

class ConfigTab(QWidget):
    def __init__(self):
        super().__init__()
        self.devices = []
        self.setLayout(QVBoxLayout())
        self.current_template_vars = []
        self.progress_bar = None
        self.backup_dir = "backups"
        self.init_ui()
        self.load_devices()
        self.load_templates()
        self.create_backup_dir()

    def create_backup_dir(self):
        """Ensure backup directory exists"""
        os.makedirs(self.backup_dir, exist_ok=True)

    def init_ui(self):
        # Device/template selection
        selection_layout = QHBoxLayout()
        self.device_combo = QComboBox()
        self.template_combo = QComboBox()
        selection_layout.addWidget(QLabel("Select Device:"))
        selection_layout.addWidget(self.device_combo)
        selection_layout.addWidget(QLabel("Select Template:"))
        selection_layout.addWidget(self.template_combo)
        self.layout().addLayout(selection_layout)

        # Action buttons
        btn_layout = QHBoxLayout()
        self.generate_btn = QPushButton("Generate Config")
        self.push_btn = QPushButton("Push to Device")
        self.run_cmd_btn = QPushButton("Run Command")
        btn_layout.addWidget(self.generate_btn)
        btn_layout.addWidget(self.push_btn)
        btn_layout.addWidget(self.run_cmd_btn)
        self.layout().addLayout(btn_layout)

        # Config preview
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.layout().addWidget(QLabel("Configuration Preview:"))
        self.layout().addWidget(self.preview)

        # Bulk operations
        bulk_group = QGroupBox("Bulk Operations:")
        bulk_layout = QVBoxLayout()
        
        # Filter selection
        filter_layout = QHBoxLayout()
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Devices")
        filter_layout.addWidget(QLabel("Device Group/Tag:"))
        filter_layout.addWidget(self.filter_combo)
        bulk_layout.addLayout(filter_layout)
        
        # Template selection
        template_layout = QHBoxLayout()
        self.bulk_template_combo = QComboBox()
        template_layout.addWidget(QLabel("Template:"))
        template_layout.addWidget(self.bulk_template_combo)
        bulk_layout.addLayout(template_layout)
        
        # Command input
        self.bulk_command = QLineEdit()
        self.bulk_command.setPlaceholderText("Enter command for bulk execution")
        bulk_layout.addWidget(self.bulk_command)
        
        # Bulk action buttons
        bulk_btn_layout = QHBoxLayout()
        self.bulk_generate_btn = QPushButton("Generate for Group")
        self.bulk_push_btn = QPushButton("Push to Group")
        self.bulk_run_btn = QPushButton("Run Command on Group")
        bulk_btn_layout.addWidget(self.bulk_generate_btn)
        bulk_btn_layout.addWidget(self.bulk_push_btn)
        bulk_btn_layout.addWidget(self.bulk_run_btn)
        bulk_layout.addLayout(bulk_btn_layout)
        
        bulk_group.setLayout(bulk_layout)
        self.layout().addWidget(bulk_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.layout().addWidget(self.progress_bar)
        
        # Progress table
        self.layout().addWidget(QLabel("Operation Progress:"))
        self.progress_table = QTableWidget()
        self.progress_table.setColumnCount(3)
        self.progress_table.setHorizontalHeaderLabels(["Device IP", "Status", "Details"])
        self.progress_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.layout().addWidget(self.progress_table)

        # Connect signals
        self.generate_btn.clicked.connect(self.generate_config)
        self.push_btn.clicked.connect(self.push_config)
        self.run_cmd_btn.clicked.connect(self.run_command_on_device)
        self.template_combo.currentIndexChanged.connect(self.on_template_change)
        self.bulk_generate_btn.clicked.connect(self.bulk_generate)
        self.bulk_push_btn.clicked.connect(self.bulk_push)
        self.bulk_run_btn.clicked.connect(self.bulk_run_command)
        self.filter_combo.currentIndexChanged.connect(self.update_filter_options)

    def load_devices(self):
        self.device_combo.clear()
        if not os.path.exists(DEVICE_FILE):
            QMessageBox.warning(self, "Missing File", f"{DEVICE_FILE} not found.")
            return

        try:
            with open(DEVICE_FILE, "r") as f:
                self.devices = json.load(f)
                for device in self.devices:
                    device.setdefault("device_type", "generic_ssh")
                    device.setdefault("tags", [])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading devices: {str(e)}")
            return

        if not self.devices:
            QMessageBox.warning(self, "No Devices", "No devices found in devices.json")
            return

        for device in self.devices:
            self.device_combo.addItem(f"{device['hostname']} ({device['ip']})", device)
            
        self.update_filter_options()

    def update_filter_options(self):
        current = self.filter_combo.currentText()
        self.filter_combo.blockSignals(True)
        self.filter_combo.clear()
        self.filter_combo.addItem("All Devices")
        
        # Collect unique groups and tags
        filter_options = set()
        for device in self.devices:
            if device.get("group"):
                filter_options.add(device["group"])
            for tag in device.get("tags", []):
                filter_options.add(tag)
                
        self.filter_combo.addItems(sorted(filter_options))
        
        # Restore previous selection if possible
        index = self.filter_combo.findText(current)
        if index >= 0:
            self.filter_combo.setCurrentIndex(index)
        self.filter_combo.blockSignals(False)
        
    def get_filtered_devices(self):
        selected_filter = self.filter_combo.currentText()
        if selected_filter == "All Devices":
            return self.devices
            
        return [
            d for d in self.devices 
            if d.get("group", "") == selected_filter or 
            selected_filter in d.get("tags", [])
        ]

    def load_templates(self):
        self.template_combo.clear()
        self.bulk_template_combo.clear()

        if not os.path.exists(TEMPLATE_DIR):
            os.makedirs(TEMPLATE_DIR)
            QMessageBox.information(self, "No Templates",
                                   f"Created '{TEMPLATE_DIR}' directory. Add .j2 templates.")
            return

        templates = sorted(f for f in os.listdir(TEMPLATE_DIR) if f.endswith(".j2"))
        if not templates:
            QMessageBox.information(self, "No Templates",
                                   "No .j2 templates found in templates directory.")
            return

        self.template_combo.addItems(templates)
        self.bulk_template_combo.addItems(templates)

    def on_template_change(self):
        self.preview.clear()
        self.current_template_vars = []
        selected_template = self.template_combo.currentText()
        if not selected_template:
            return

        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        try:
            source = env.loader.get_source(env, selected_template)[0]
            parsed = env.parse(source)
            self.current_template_vars = sorted(meta.find_undeclared_variables(parsed))
        except Exception as e:
            QMessageBox.critical(self, "Template Error", f"Failed to load template:\n{str(e)}")

    def generate_config(self):
        template_name = self.template_combo.currentText()
        if not template_name:
            QMessageBox.warning(self, "Missing", "Please select a template.")
            return

        device_data = self.get_selected_device()
        if not device_data:
            return

        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        try:
            template = env.get_template(template_name)
        except Exception as e:
            QMessageBox.critical(self, "Template Error", f"Error loading template:\n{str(e)}")
            return

        if not self.current_template_vars:
            try:
                config = template.render(device=device_data)
                self.preview.setPlainText(config)
            except Exception as e:
                QMessageBox.critical(self, "Render Error", f"Error rendering:\n{str(e)}")
            return

        dialog = TemplateVarsDialog(self.current_template_vars, self)
        context = dialog.get_values()
        if context is None:
            return

        try:
            config = template.render(device=device_data, **context)
            self.preview.setPlainText(config)
        except Exception as e:
            QMessageBox.critical(self, "Render Error", f"Error rendering with variables:\n{str(e)}")

    def push_config(self):
        device = self.get_selected_device()
        if not device:
            return

        config_lines = self.preview.toPlainText().splitlines()
        if not any(line.strip() for line in config_lines):
            QMessageBox.warning(self, "Empty", "No config to push.")
            return

        password = self.get_password_dialog(device)
        if password is None:
            return

        ssh = SSHClient(device, password)
        if not ssh.connect():
            QMessageBox.critical(self, "SSH Failed", "Failed to connect to device.")
            return

        try:
            # Backup current config
            backup_success = self.backup_device_config(device, ssh)
            if not backup_success:
                reply = QMessageBox.question(
                    self, "Backup Failed",
                    "Backup failed. Continue anyway?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    ssh.disconnect()
                    return

            # Push new config
            output = ssh.send_config(config_lines)
            ssh.disconnect()
            
            # Log the change
            self.log_config_push(device, config_lines)
            
            self.show_output_dialog(output)
            QMessageBox.information(self, "Success", "Configuration pushed successfully!")
            
        except Exception as e:
            ssh.disconnect()
            QMessageBox.critical(self, "Error", f"Failed to push configuration: {str(e)}")

    def backup_device_config(self, device, ssh_client):
        """Backup device configuration"""
        try:
            config_output = ssh_client.run_command("show running-config")
            if not config_output:
                return False
                
            device_dir = os.path.join(self.backup_dir, device['ip'])
            os.makedirs(device_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"config_{timestamp}.txt"
            backup_path = os.path.join(device_dir, filename)
            
            with open(backup_path, 'w') as f:
                f.write(config_output)
                
            return True
        except Exception as e:
            logging.error(f"Backup failed for {device['ip']}: {str(e)}")
            return False
        
    def log_config_push(self, device, config_lines):
        """Log configuration push with user info"""
        log_dir = os.path.join(self.backup_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, device['ip'] + "_changes.log")

        config_text = '\n'.join(config_lines)

        try:
            username = os.getlogin()
        except OSError:
            username = getpass.getuser()

        log_content = (
            "=== " + timestamp + " ===\n"
            "Device: " + device['hostname'] + " (" + device['ip'] + ")\n"
            "User: " + username + "\n"
            "Configuration:\n" + config_text + "\n\n"
        )

        with open(log_file, 'a') as f:
            f.write(log_content)

    def run_command_on_device(self):
        device = self.get_selected_device()
        if not device:
            return

        command, ok = QInputDialog.getText(
            self, "Run Command",
            f"Command for {device['hostname']} ({device['ip']}):"
        )
        if not ok or not command.strip():
            return

        password = self.get_password_dialog(device)
        if password is None:
            return

        ssh = SSHClient(device, password)
        if ssh.connect():
            try:
                output = ssh.run_command(command.strip())
            except Exception as e:
                output = f"Error: {str(e)}"
            ssh.disconnect()
            self.show_output_dialog(output)
        else:
            QMessageBox.critical(self, "SSH Failed", "Could not connect to device.")

    def bulk_generate(self):
        template_name = self.bulk_template_combo.currentText()
        if not template_name:
            QMessageBox.warning(self, "Missing", "Please select a template.")
            return
            
        devices = self.get_filtered_devices()
        if not devices:
            QMessageBox.warning(self, "No Devices", "No devices match the selected filter.")
            return
            
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        try:
            source = env.loader.get_source(env, template_name)[0]
            parsed = env.parse(source)
            variables = sorted(meta.find_undeclared_variables(parsed))
        except Exception as e:
            QMessageBox.critical(self, "Template Error", f"Failed to load template:\n{str(e)}")
            return
            
        if variables:
            dialog = TemplateVarsDialog(variables, self)
            context = dialog.get_values()
            if context is None:
                return
        else:
            context = {}
            
        try:
            template = env.get_template(template_name)
            configs = []
            for device in devices:
                config = template.render(device=device, **context)
                configs.append(f"=== {device['hostname']} ({device['ip']}) ===\n{config}\n\n")
                
            self.preview.setPlainText("\n".join(configs))
            QMessageBox.information(self, "Success", f"Generated configs for {len(devices)} devices.")
        except Exception as e:
            QMessageBox.critical(self, "Render Error", f"Error rendering:\n{str(e)}")

    def bulk_push(self):
        template_name = self.bulk_template_combo.currentText()
        if not template_name:
            QMessageBox.warning(self, "Missing", "Please select a template.")
            return
            
        devices = self.get_filtered_devices()
        if not devices:
            QMessageBox.warning(self, "No Devices", "No devices match the selected filter.")
            return
            
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        try:
            source = env.loader.get_source(env, template_name)[0]
            parsed = env.parse(source)
            variables = sorted(meta.find_undeclared_variables(parsed))
        except Exception as e:
            QMessageBox.critical(self, "Template Error", f"Failed to load template:\n{str(e)}")
            return
            
        if variables:
            dialog = TemplateVarsDialog(variables, self)
            context = dialog.get_values()
            if context is None:
                return
        else:
            context = {}
            
        # Setup progress UI
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(devices))
        self.progress_bar.setValue(0)
        
        # Setup progress table
        self.progress_table.setRowCount(len(devices))
        for i, device in enumerate(devices):
            self.progress_table.setItem(i, 0, QTableWidgetItem(device['ip']))
            self.progress_table.setItem(i, 1, QTableWidgetItem("Pending"))
            self.progress_table.setItem(i, 2, QTableWidgetItem(""))
            
        # Create worker
        self.worker = BulkConfigPushWorker(
            devices=devices,
            template=template_name,
            variables=context,
            get_password_func=self.get_password_from_vault,
            backup_dir=self.backup_dir
        )
        
        # Connect signals
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.on_bulk_complete)
        self.worker.start()
    
    def bulk_run_command(self):
        command = self.bulk_command.text().strip()
        if not command:
            QMessageBox.warning(self, "Missing Command", "Enter a command to execute")
            return
            
        devices = self.get_filtered_devices()
        if not devices:
            QMessageBox.warning(self, "No Devices", "No devices match the selected filter.")
            return
            
        # Setup progress UI
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(devices))
        self.progress_bar.setValue(0)
        
        # Setup progress table
        self.progress_table.setRowCount(len(devices))
        for i, device in enumerate(devices):
            self.progress_table.setItem(i, 0, QTableWidgetItem(device['ip']))
            self.progress_table.setItem(i, 1, QTableWidgetItem("Pending"))
            self.progress_table.setItem(i, 2, QTableWidgetItem(""))
            
        # Create worker
        self.worker = BulkCommandWorker(
            devices=devices,
            command=command,
            get_password_func=self.get_password_from_vault
        )
        
        # Connect signals
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.on_bulk_complete)
        self.worker.start()
    
    def update_progress(self, idx, device_ip, status):
        self.progress_table.setItem(idx, 1, QTableWidgetItem("Running" if "..." in status else "Completed"))
        self.progress_table.setItem(idx, 2, QTableWidgetItem(status))
        self.progress_table.scrollToItem(self.progress_table.item(idx, 0))
        self.progress_bar.setValue(idx + 1)
        
    def on_bulk_complete(self):
        self.progress_bar.setVisible(False)
        QMessageBox.information(self, "Complete", "Bulk operation finished")
    
    def get_selected_device(self):
        index = self.device_combo.currentIndex()
        if index < 0:
            QMessageBox.warning(self, "Missing", "Please select a device.")
            return None
        return self.device_combo.itemData(index)

    def get_password_dialog(self, device):
        password, ok = QInputDialog.getText(
            self, "SSH Password",
            f"Enter password for {device['hostname']} ({device['ip']}):",
            echo=QLineEdit.Password
        )
        return password if ok and password else None
        
    def get_password_from_vault(self, device):
        """Retrieve password from secure storage"""
        # In a real implementation, this would use proper credential management
        return device.get("password", "default_password")

    def show_output_dialog(self, output):
        dialog = QDialog(self)
        dialog.setWindowTitle("Device Output")
        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setPlainText(output)
        layout.addWidget(text_edit)
        dialog.resize(600, 400)
        dialog.exec_()