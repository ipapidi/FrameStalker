# beacon_sniffer.py

from scapy.all import *
from datetime import datetime

# Dictionary to keep track of seen APs
discovered_aps = {}

def sniff_beacons(interface: str, log_callback=None, stop_filter=None) -> None:
    """
    Sniffs for 802.11 Beacon frames on the specified interface using Scapy.

    Parameters:
        interface (str): The monitor-mode interface to sniff on (e.g., wlan0mon)
        log_callback (function): Optional function to handle logs externally (e.g., GUI)
        stop_filter (function): Optional function to stop sniffing (used by GUI)
    """

    def process_packet(packet):
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            ssid = packet[Dot11Elt].info.decode(errors='ignore').strip()

            # Attempt to extract channel info
            channel = None
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3:  # DS Parameter Set
                    try:
                        channel = int.from_bytes(elt.info, byteorder='little')
                    except:
                        channel = "?"
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            # Avoid duplicates
            if bssid not in discovered_aps:
                discovered_aps[bssid] = ssid
                timestamp = datetime.now().strftime("%H:%M:%S")
                message = f"[{timestamp}] Beacon ➜ SSID: '{ssid}' | BSSID: {bssid} | Channel: {channel}"
                print(message)
                if log_callback:
                    log_callback(message)

    sniff(
        iface=interface,
        prn=process_packet,
        store=0,
        stop_filter=stop_filter
    )

# CLI Test Mode
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: sudo python3 beacon_sniffer.py <interface>")
        sys.exit(1)

    sniff_beacons(sys.argv[1])
