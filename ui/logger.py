from PyQt5.QtCore import QObject, pyqtSignal

class LogBridge(QObject):
    signal = pyqtSignal(str)

log_bridge = LogBridge()

def log(message):
    print(message)  # Optional: add file logging here
    log_bridge.signal.emit(message)
