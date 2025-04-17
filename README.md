# ⚠️ This tool requires root/admin privileges and only works on systems with network interfaces that support monitor mode (usually Linux).

# 📡 Wi-Fi Network Sniffer (Python + Scapy)

A Python-based tool that passively scans nearby Wi-Fi networks and displays information like SSID, BSSID, signal strength, and channel.

Perfect for understanding how wireless devices communicate, and learning about wireless reconnaissance.

---

## ⚙️ Features

- Uses `scapy` to sniff 802.11 beacon frames
- Displays:
  - SSID (Network Name)
  - BSSID (MAC Address of Access Point)
  - Channel
  - Signal Strength (dBm)
- Real-time terminal output
- Lightweight and CLI-friendly

---

## ⚠️ Requirements

- **Linux or macOS**
- Python 3
- `scapy`
- Root privileges
- Wireless adapter in **monitor mode**

---

## 🚀 Setup

### 1. Clone the repo

git clone https://github.com/yourusername/wifi-network-sniffer.git
cd wifi-network-sniffer

 
### 2. Install dependencies

pip install -r requirements.txt

### 3. Set interface to monitor mode

sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up


Replace wlan0 with your interface name (iwconfig to check).


## 🧪 Run the Sniffer

sudo python3 wifi_sniffer.py wlan0

Sample output:

[📶] SSID: Starbucks_WiFi | BSSID: 34:2C:C4:10:1A:AB | Channel: 6 | Signal: -41 dBm
[📶] SSID: Hidden | BSSID: 22:1B:78:8C:FF:13 | Channel: 11 | Signal: -58 dBm

---
## 👨‍💻 Educational Value
Learn about 802.11 wireless frames

Understand how passive sniffing works

Experience terminal-based packet analysis
---
## 🧠 Notes
Hidden SSIDs appear as "" — they can be captured with more advanced probing.

Does not de-authenticate or interfere — it's purely passive.

Only beacon frames are analyzed for safety and legality.
---
## ⭐ Like the Project?
Leave a ⭐ on GitHub and share your thoughts!

---
## 🔮 Future Ideas
Export results to CSV/JSON

Add filtering for channels or vendor MAC

Integrate geolocation from public MAC databases (e.g., Wigle)

Build a simple GUI with Tkinter or PyQT
