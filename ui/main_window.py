from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QListWidget,
    QStackedWidget, QListWidgetItem, QLabel, QFrame
)
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import QSize
import json

from .device_tab import DeviceTab
from .config_tab import ConfigTab
from .monitorTab import MonitorTab
from utils.backup_manager import BackupManager

def load_devices(file_path="data/devices.json"):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print("⚠️ devices.json not found.")
        return []
    except json.JSONDecodeError:
        print("⚠️ Invalid JSON format in devices.json.")
        return []


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AutoNet Pro")
        self.setMinimumSize(1000, 600)

        # Load devices from JSON file
        self.devices = load_devices("devices.json")

        # Central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Main horizontal layout
        self.layout = QHBoxLayout(self.central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Sidebar (Apple-style dark)
        self.sidebar = QListWidget()
        self.sidebar.setIconSize(QSize(24, 24))
        self.sidebar.setFont(QFont("Helvetica Neue", 10))
        self.sidebar.setStyleSheet("""
            QListWidget {
                background-color: #323232;
                font-size: 15px;
                padding: 10px;
                color: #FFFFFF;
            }
            QListWidget::item {
                padding: 12px 10px;
                margin: 4px;
                border-radius: 8px;
            }
            QListWidget::item:selected {
                background-color: #007AFF;
                color: #FFFFFF;
            }
            QListWidget::item:hover {
                background-color: #3C3C3C;
            }
        """)

        # Sidebar width (1/5 of window)
        self.sidebar.setFixedWidth(self.width() // 5)

        # Vertical line to simulate border with gaps
        self.border_line = QFrame()
        self.border_line.setFrameShape(QFrame.VLine)
        self.border_line.setFrameShadow(QFrame.Plain)
        self.border_line.setStyleSheet("color: #C7C7CC;")
        self.border_line.setLineWidth(1)
        self.border_line.setContentsMargins(0, 10, 0, 10)  # top & bottom gaps

        # Pages (stacked widget)
        self.pages = QStackedWidget()

        # Tabs content
        self.device_tab = DeviceTab()
        self.config_tab = ConfigTab()
        self.monitor_tab = MonitorTab()
        self.logs_tab = QLabel("Logs coming soon...")

        for widget in [self.device_tab, self.config_tab, self.monitor_tab, self.logs_tab]:
            widget.setContentsMargins(20, 20, 20, 20)

        self.pages.addWidget(self.device_tab)
        self.pages.addWidget(self.config_tab)
        self.pages.addWidget(self.monitor_tab)
        self.pages.addWidget(self.logs_tab)

        # Sidebar items with icons
        tabs = [
            ("Devices", "assets/icons/wifi.router.fill.svg"),
            ("Configuration", "assets/icons/wrench.and.screwdriver.fill.svg"),
            ("Monitoring", "assets/icons/display.svg"),
            ("Logs", "assets/icons/scroll.fill.svg")
        ]

        for name, icon_path in tabs:
            item = QListWidgetItem(QIcon(icon_path), name)
            item.setSizeHint(QSize(130, 40))
            self.sidebar.addItem(item)

        self.sidebar.setCurrentRow(0)
        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)

        # Add sidebar, separator line, and pages to layout
        self.layout.addWidget(self.sidebar, 1)        # 1/5 width
        self.layout.addWidget(self.border_line)       # Simulated right border
        self.layout.addWidget(self.pages, 4)          # 4/5 width