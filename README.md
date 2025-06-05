# AuthNet Pro – Automated Network Configuration Tool

**AuthNet Pro** is a Python + Qt-based automation tool designed to simplify network device management. Built with a focus on real-world scenarios, it enables network engineers to onboard devices, push configurations, monitor devices, and handle failures efficiently.
Configurations Template management is also possible.It hepls you automate the config tasks for devices.

> 🔧 This is a functional and actively developed tool (approx. 80% complete). Core features are in place, with additional enhancements underway.This is the 1st Version, log Printing & auth feature are underway in the next Version

---

## 🌐 Key Features

### 🔌 Device Management
- Add, edit, and remove network devices
- it has a multithreaded device discovery feature that scans IP ranges, pings hosts, and retrieves SSH banners to identify active network devices.it
- Import/export device inventory via CSV or JSON

### ⚙️ Configuration Management
- **Single Push**: Send configs to individual devices
- **Bulk Push**: Push to multiple devices at once
- **Command Output**: View real-time response from devices
- **State Tracking**: Stores the device state post-push

### 🖥️ Monitoring & Rollback
- Continuous live monitoring of connected devices
- Manual rollback available on error detection
- Alerts on misconfigurations or connectivity loss

---

## 🖼️ GUI Interface

- Developed with **Python + Qt (PyQt5 or PySide2)**
- Intuitive tab-based layout: Devices, Configurations, Monitoring
- Clean user experience designed for engineers and admins
- Style Sheets are included, style as u like, I love the qpple ui so my styles are inspired from Apple Finder
  
- <img width="1002" alt="Screenshot 2025-06-05 at 3 26 19 PM" src="https://github.com/user-attachments/assets/db0f6d73-e802-45f7-b066-a02324140a00" />
- Get To intro Folder for more GUI images


---

## 🚀 Tech Stack

- **Python 3**
- **PyQt5 / PySide2** (GUI)
- **Netmiko / Paramiko** (SSH connectivity)
- **JSON / CSV** (Data storage and import/export)

---

## 🔧 Target Use Case

AuthNet Pro is ideal for:
- Network engineers automating configuration tasks
- Lab environments simulating large-scale deployments
- Anyone managing Cisco or similar devices at scale

---

## 🛣️ Roadmap

- [ ] Auto rollback on config failure
- [ ] Role-based access control for users
- [ ] Enhanced logging and device history
- [ ] CLI template support (especially for Cisco)

---

## 📦 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/authnet-pro.git
cd authnet-pro
```
### 2. (Recommended) Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate     # On Windows: venv\Scripts\activate
```

### 3. Install Required Packages
```bash
pip install -r requirements.txt
```

### 4. Run The Application
```bash
python main.py
```

### 🤝 Let’s Connect

For collaboration, demo requests, or feedback, feel free to reach out. I’d love to discuss how this tool can be used, improved, or integrated into real-world network automation workflows.
