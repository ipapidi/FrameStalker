# beacon_sniffer.py

from scapy.all import *
from ui.logger import log
from datetime import datetime
import sys

# Dictionary to keep track of seen APs
discovered_aps = {}

def sniff_beacons(interface: str, log_callback=None, stop_event=None) -> None:
    """
    Sniffs for 802.11 Beacon frames on the specified interface using Scapy.

    Parameters:
        interface (str): The monitor-mode interface to sniff on (e.g., wlan0mon)
        log_callback (function): Optional function to handle logs externally (e.g., GUI)
    """

    def should_stop(pkt): #function to help threading stop gracefully
    	return stop_event and stop_event.is_set()
    
    def process_packet(packet):
        if packet.haslayer(Dot11Beacon): #beacon frames only
            bssid = packet[Dot11].addr2
            ssid = packet[Dot11Elt].info.decode(errors='ignore').strip()

            # Attempt to extract channel info
            channel = None
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3:  # DS parameter set usually contains the channel number
                    try:
                        channel = int.from_bytes(elt.info, byteorder='little')
                    except:
                        channel = "?" #if cant find channel number
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            # Print either to gui or terminal but avoid duplicates
            if bssid not in discovered_aps:
                discovered_aps[bssid] = ssid
                timestamp = datetime.now().strftime("%H:%M:%S")
                message = f"[{timestamp}] Beacon ➜ SSID: '{ssid}' | BSSID: {bssid} | Channel: {channel}"
                if log_callback:
                    log_callback(message)
                else:
                    print(message)

    
    try:
    	sniff( iface=interface, prn=process_packet, store=0,  stop_filter=should_stop)
    except Exception as e:
    	log(f"[+] Exception {e}. Stopped sniffing", log_callback)
    finally:
        log(f"[+] Sniffing complete!")
    
    

# CLI Test Mode
def main():
    if len(sys.argv) != 2:
        print("Usage: sudo python3 beacon_sniffer.py <interface>")
        sys.exit(1)

    sniff_beacons(sys.argv[1])

if __name__ == "__main__":
    main()
