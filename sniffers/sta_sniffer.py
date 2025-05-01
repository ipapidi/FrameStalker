from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
from datetime import datetime
from .vendor_lookup import get_vendor

# Track seen STAs to reduce log spam
discovered_stas = {}

def sniff_stas(interface: str, log_callback=None, stop_filter=None) -> None:
    """
    Sniffs for 802.11 frames to identify client (STA) MAC addresses.

    Args:
        interface (str): Monitor-mode interface (e.g., wlan1)
        log_callback (function): For GUI log updates
        stop_filter (function): For stopping sniffing (used in GUI)
    """

    def process_packet(pkt):
        if pkt.haslayer(Dot11):
            src = pkt.addr2
            dst = pkt.addr1
            bssid = pkt.addr3

            # Ignore broadcast or null MACs
            for mac in [src, dst]:
                if not mac or mac.lower().startswith("ff:ff:ff") or mac == "00:00:00:00:00:00":
                    continue

                # Filter out AP frames — skip beacons and probe responses
                if pkt.type == 0 and pkt.subtype in [8, 5]:
                    continue

                # Only log unique STAs
                if mac not in discovered_stas:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    discovered_stas[mac] = timestamp

                    vendor = get_vendor(mac)
                    msg = f"[{timestamp}] STA Detected: {mac} ({vendor}) ➜ Associated with: {bssid}"
                    print(msg)
                    if log_callback:
                        log_callback(msg)

    sniff(
        iface=interface,
        prn=process_packet,
        store=0,
        stop_filter=stop_filter
    )


# CLI test mode
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: sudo python3 sta_sniffer.py <interface>")
        sys.exit(1)

    sniff_stas(sys.argv[1])

