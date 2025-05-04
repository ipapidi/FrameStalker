from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
from datetime import datetime
from .vendor_lookup import get_vendor
import sys
from ui.logger import log

# Track unique STAs only in dictionary
discovered_stas = {}

def sniff_stas(interface: str, log_callback=None, stop_event=None) -> None:
    """
    Sniffs for 802.11 frames to identify client (STA) MAC addresses.

    Args:
        interface (str): Monitor-mode interface (e.g., wlan1)
        log_callback (function): For GUI log updates
    """
	
    def should_stop(pkt): #function to help threading stop gracefully
    	return stop_event and stop_event.is_set()
    
    def process_packet(pkt):
        if not pkt.haslayer(Dot11): # check if packet has the base 802.11 wifi layer - if not skip
            return
        
        src = pkt.addr2
        dst = pkt.addr1
        bssid = pkt.addr3
        sta_mac=None

        # Filter out broadcast/null MACs
        for mac in [src, dst]:
            if not mac or mac.lower().startswith("ff:ff:ff") or mac == "00:00:00:00:00:00":
                return
        #check management frames for sta mac address
        if pkt.type == 0:
            if pkt.subtype == 8: # Filter out beacons 
                return
            elif pkt.subtype in [0,2,4,10,11]  : #association req, reassoc request, probe req, disassociation, authentication packets from sta to ap
                sta_mac=src
            elif pkt.subtype in [1,3,5]: #association,reassoc and probe responses from ap to sta 
                sta_mac=dst
            elif pkt.subtype == 12: # Deauth frame
                if src == bssid: sta_mac = dst  # AP to STA
                else: sta_mac = src  # STA to AP

        # Data frames
        elif pkt.type == 2:
            to_ds = pkt.FCfield & 0x1 != 0 #grab the To DS bits
            from_ds = pkt.FCfield & 0x2 != 0

            if to_ds and not from_ds: sta_mac = src #To DS =1 and From DS=0 - sta to ap
            elif from_ds and not to_ds:  sta_mac = dst #To DS =0 and From DS=1 - ap to sta
            #Ignore if both to and from ds are 1 since its a wds frame (ap to ap) - if both are 0 its sta to sta / for adhoc network, also ignore to be safe its not bssid

        # Control frames
        elif pkt.type == 1 and pkt.subtype in [10, 11]:  # PS-Poll, RTS
            sta_mac = src

        # Only log unique STAs
        if sta_mac and sta_mac not in discovered_stas:
            timestamp = datetime.now().strftime("%H:%M:%S")
            discovered_stas[sta_mac] = timestamp

            vendor = get_vendor(sta_mac)
            msg = f"[{timestamp}] STA Detected: {sta_mac} ({vendor}) ➜ Associated with: {bssid}" 
            if log_callback:
                log_callback(msg)
            else: print(msg)

    try:
    	sniff(iface=interface, prn=process_packet, store=0, stop_filter=should_stop)
    except Exception as e:
    	log(f"[+] Exception {e}. Stopped sniffing", log_callback)
    finally:
        log(f"[+] Sniffing complete!")


# CLI test mode
def main():
    if len(sys.argv) != 2:
        print("Usage: sudo python3 sta_sniffer.py <interface>")
        sys.exit(1)

    sniff_stas(sys.argv[1])

if __name__ == "__main__":
    main()
