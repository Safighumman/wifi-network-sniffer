
---

## 🐍 `wifi_sniffer.py`

```python
import sys
import os
from scapy.all import sniff, Dot11
from collections import defaultdict

networks = defaultdict(dict)

def callback(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:  # Beacon frame
            ssid = packet.info.decode(errors="ignore")
            bssid = packet.addr2
            stats = packet[Dot11].network_stats()
            channel = stats.get("channel", "N/A")
            dbm_signal = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else "N/A"

            if bssid not in networks:
                networks[bssid] = {"ssid": ssid, "channel": channel, "signal": dbm_signal}
                print(f"[📶] SSID: {ssid or 'Hidden'} | BSSID: {bssid} | Channel: {channel} | Signal: {dbm_signal} dBm")

def main():
    if os.geteuid() != 0:
        print("[!] Please run as root.")
        return

    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface>")
        return

    iface = sys.argv[1]
    print("=== Wi-Fi Network Sniffer ===\n")
    sniff(prn=callback, iface=iface, monitor=True)

if __name__ == "__main__":
    main()
