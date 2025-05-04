#!/bin/bash

# Launch GUI if requested
if [[ "$1" == "--gui" ]]; then
    echo "[*] Launching FrameStalker GUI..."
    sudo python3 frame_stalker_gui.py
    exit 0
fi

echo "=== FrameStalker CLI ==="
read -p "Enter monitor-mode interface (e.g. wlan0mon): " iface

# Check if interface exists
if [[ ! -d "/sys/class/net/$iface" ]]; then
    echo "[!] Interface '$iface' does not exist."
    exit 1
fi

# Check if interface is in monitor mode
mode=$(cat "/sys/class/net/$iface/type")
if [[ "$mode" != "803" ]]; then
    echo "[!] '$iface' is not in monitor mode."
    echo "    ➤ You can enable it by using: https://github.com/ipapidi/WiSniff"
    exit 1
fi

echo
echo "1. Beacon Sniffer"
echo "2. STA Sniffer"
echo "3. Deauth Sniffer (Passive)"
echo "4. Deauth Attack (Active)"
echo "5. Exit"
echo
read -p "Choose an option [1-5]: " choice

case $choice in
    1)
        sudo python3 -m sniffers.beacon_sniffer "$iface"
        ;;
    2)
        sudo python3 -m sniffers.sta_sniffer "$iface"
        ;;
    3)
        echo "Choose folder to save pcap (GUI dialog will open)..."
        python3 -c "from tkinter import Tk, filedialog; Tk().withdraw(); print(filedialog.askdirectory())" > temp_dir.txt
        save_dir=$(<temp_dir.txt)
        rm temp_dir.txt
        if [ -z "$save_dir" ]; then
            echo "[!] Cancelled. No folder selected."
            exit 1
        fi
        sudo python3 -m sniffers.deauth_sniffer passive "$iface" "$save_dir"
        ;;
    4)
        read -p "Enter AP MAC address: " ap_mac
        read -p "Enter target MAC (or ff:ff:ff:ff:ff:ff): " target_mac
        read -p "Enter channel (e.g. 1, 6, 36): " channel
        read -p "Enter number of deauth frames to send (0 = continuous): " count
        echo "Choose folder to save pcap (GUI dialog will open)..."
        python3 -c "from tkinter import Tk, filedialog; Tk().withdraw(); print(filedialog.askdirectory())" > temp_dir.txt
        save_dir=$(<temp_dir.txt)
        rm temp_dir.txt
        if [ -z "$save_dir" ]; then
            echo "[!] Cancelled. No folder selected."
            exit 1
        fi
        sudo python3 -m sniffers.deauth_sniffer active "$iface" "$ap_mac" "$target_mac" "$channel" "$count" "$save_dir"
        ;;
    5)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "[!] Invalid choice."
        ;;
esac

