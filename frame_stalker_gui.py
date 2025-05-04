import sys
import random
import time
import re
import os
import threading
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextBrowser,
    QComboBox, QLabel, QHBoxLayout, QGroupBox, QMessageBox, QInputDialog, QFileDialog
)
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot, Qt
from PyQt5.QtGui import QColor, QPalette

from scapy.all import get_if_list, RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp

from sniffers.beacon_sniffer import sniff_beacons
from sniffers.deauth_sniffer import sniff_deauth, send_deauth
from sniffers.sta_sniffer import sniff_stas
from ui.logger import log_bridge, log

def is_valid_mac(mac: str) -> bool:
    return re.fullmatch(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac) is not None or mac.lower() == 'ff:ff:ff:ff:ff:ff'

def is_monitor_mode(interface: str) -> bool:
    try:
        with open(f"/sys/class/net/{interface}/type") as f:
            return f.read().strip() == '803'
    except Exception:
        return False

class SnifferThread(QThread):
    def __init__(self, sniffer_function, interface, pcap_path=None):
        super().__init__()
        self.sniffer_function = sniffer_function
        self.interface = interface
        self.pcap_path = pcap_path
        self.stop_event = threading.Event()  # used to stop sniffing cleanly

    def run(self):
        try:
            if self.sniffer_function.__name__ == "sniff_deauth":
                self.sniffer_function(self.interface, self.pcap_path, log_callback=log, stop_event=self.stop_event)
            else:
                self.sniffer_function(self.interface, log_callback=log, stop_event=self.stop_event)
        except Exception as e:
            log(f"[!] Error running sniffer: {e}")

    def stop(self):
        self.stop_event.set()

class DeauthThread(QThread):
    def __init__(self, interface, bssid, target, channel, count, pcap_path=None):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.target = target
        self.channel = channel
        self.count = count
        self.pcap_path = pcap_path
        self.stop_event = threading.Event()  

    def run(self):
        try:
            send_deauth(self.interface, self.bssid, self.target, self.channel, self.count, self.pcap_path, log_callback=log, stop_event=self.stop_event )
        except Exception as e:
            log(f"[!] Error during deauth: {e}")
            
    def stop(self):
    	self.stop_event.set()

class FrameStalkerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FrameStalker")
        self.setMinimumSize(800, 600)

        self.active_thread = None
        self.packet_count = 0
        self.beacon_count = 0
        self.deauth_count = 0
        self.sta_count = 0
        self.current_sniffer = None

        self.init_ui()
        self.apply_dark_mode()
        log_bridge.signal.connect(self.append_log)

    def init_ui(self):
        layout = QVBoxLayout()

        interface_layout = QHBoxLayout()
        interface_label = QLabel("Select Interface:")
        self.interface_dropdown = QComboBox()
        interfaces = get_if_list()
        if not interfaces:
            QMessageBox.critical(self, "No Interfaces", "No interfaces found on system.")
            sys.exit(1)
        self.interface_dropdown.addItems(interfaces)
        self.interface_dropdown.currentIndexChanged.connect(self.on_interface_change)
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_dropdown)
        layout.addLayout(interface_layout)

        button_group = QGroupBox("Choose a Tool:")
        button_layout = QHBoxLayout()

        self.beacon_btn = QPushButton("Beacon Sniffer")
        self.beacon_btn.clicked.connect(self.start_beacon)

        self.sta_btn = QPushButton("STA Sniffer")
        self.sta_btn.clicked.connect(self.start_sta)
        
        self.deauth_btn = QPushButton("Deauth Attack")
        self.deauth_btn.clicked.connect(self.choose_deauth_mode)

        button_layout.addWidget(self.beacon_btn)
        button_layout.addWidget(self.sta_btn)
        button_layout.addWidget(self.deauth_btn)
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

    def on_interface_change(self):
        iface = self.interface_dropdown.currentText()
        if not iface:
            self.status_label.setText("[!] No interface selected.")
            self.beacon_btn.setEnabled(False)
            self.deauth_btn.setEnabled(False)
            self.sta_btn.setEnabled(False)
            return
        if is_monitor_mode(iface):
            self.beacon_btn.setEnabled(True)
            self.deauth_btn.setEnabled(True)
            self.sta_btn.setEnabled(True)
            self.status_label.setText(f"[i] {iface} is in monitor mode.")
        else:
            self.beacon_btn.setEnabled(False)
            self.deauth_btn.setEnabled(False)
            self.sta_btn.setEnabled(False)
            self.status_label.setText(f"[!] {iface} is not in monitor mode. Please select an interface in monitor mode.")
            msg = QMessageBox(self)
            msg.setWindowTitle("Monitor Mode Required")
            msg.setTextFormat(Qt.RichText)
            msg.setText(
                f"The selected interface '<b>{iface}</b>' is not in monitor mode.<br><br>"
                f"To set monitor mode, you can use this tool: <span>https://github.com/ipapidi/WiSniff</span>"
            )
            msg.setStandardButtons(QMessageBox.Ok)
            msg.setTextInteractionFlags(Qt.TextBrowserInteraction)
            msg.exec_()

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
        if "Beacon" in message:
            self.packet_count += 1
            self.beacon_count += 1
        elif "STA Detected" in message:
            self.packet_count += 1
            self.sta_count += 1
        elif "Deauth" in message:
            self.packet_count += 1
            self.deauth_count += 1
        self.update_status()

    def update_status(self):
        self.status_label.setText(
            f"[i] Total Packets: {self.packet_count} | Beacons: {self.beacon_count} | Deauths Sniffed: {self.deauth_count} | STAs: {self.sta_count}"
        )

    def save_log(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Log", "frame_stalker_log.txt", "Text Files (*.txt)")
        if filename:
            try:
                with open(filename, "w") as f:
                    f.write(self.log_box.toPlainText())
                log(f"[+] Log saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Save Failed", f"Could not save log: {e}")

    def stop_sniffer(self):
        if self.active_thread and self.active_thread.isRunning():
        	self.active_thread.stop()     # signals the sniff loop to stop
        	self.active_thread.wait()     # waits for the thread to finish
        	log("[!] Stopped by user.")
        self.active_thread = None
        self.current_sniffer = None

    def start_sniffer(self, sniffer_func, pcap_path=None):
        iface = self.interface_dropdown.currentText()
        if not iface:
            QMessageBox.critical(self, "No Interface", "Please select a valid network interface.")
            return

        if self.active_thread and self.active_thread.isRunning():
            QMessageBox.warning(self, "Already Running", "A thread is already running. Use Stop to end it.")
            return

        self.active_thread = SnifferThread(sniffer_func, iface, pcap_path)
        self.active_thread.start()
        log("[i] Sniffer started...")

    def start_beacon(self):
        self.start_sniffer(sniff_beacons)

    def start_deauth_passive(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder to save capture", options=QFileDialog.ShowDirsOnly)
        if not folder:
            QMessageBox.information(self, "Cancelled", "No folder selected.")
            return
        self.current_sniffer = "deauth"
        self.start_sniffer(sniff_deauth, pcap_path=folder)

    def start_deauth_active(self):
        iface = self.interface_dropdown.currentText()
        if not iface:
            QMessageBox.critical(self, "No Interface", "No network interface selected.")
            return

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

        count, ok4 = QInputDialog.getInt(self, "Count", "Enter number of deauth frames (0 = continuous attack):", value=0, min=0)
        if not ok4:
            return
        
        folder = QFileDialog.getExistingDirectory(self, "Select folder to save capture", options=QFileDialog.ShowDirsOnly)
        if not folder:
            QMessageBox.information(self, "Cancelled", "No folder selected.")
            return
        self.active_thread = DeauthThread(iface, bssid, target, channel, count, pcap_path=folder)
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


def main():
    app = QApplication(sys.argv)
    window = FrameStalkerGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

