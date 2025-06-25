from PyQt6.QtWidgets import QVBoxLayout, QLabel, QPlainTextEdit, QPushButton
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from gui.matrix_page import MatrixPage
import subprocess
import time
import os

class LogReaderThread(QThread):
    log_signal = pyqtSignal(str)
    done_signal = pyqtSignal()

    def run(self):
        log_path = "logs/launcher.log"
        while not os.path.exists(log_path):
            time.sleep(0.5)

        with open(log_path, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    self.log_signal.emit(line.strip())
                    if "ALL MODULES COMPLETED SUCCESSFULLY" in line:
                        self.done_signal.emit()
                        break
                else:
                    time.sleep(0.5)

class ExecutionPage(MatrixPage):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        layout = QVBoxLayout()

        self.label = QLabel("Module Execution in Progress...")
        self.label.setStyleSheet("color: white; font-size: 16px;")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("background-color: rgba(0,0,0,150); color: lime;")

        self.finish_button = QPushButton("Finish & View Report")
        self.finish_button.setEnabled(False)
        self.finish_button.setStyleSheet("font-size: 14px; padding: 8px;")
        self.finish_button.clicked.connect(self.goto_report)

        layout.addWidget(self.label)
        layout.addWidget(self.log_area)
        layout.addWidget(self.finish_button)
        self.setLayout(layout)

        self.process = None
        self.log_thread = None

    def showEvent(self, event):
        self.start_launcher()
        super().showEvent(event)

    def start_launcher(self):
        try:
            self.process = subprocess.Popen(
                ["python3", "core/launcher.py"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception as e:
            self.log_area.appendPlainText(f"[!] Error starting launcher: {e}")
            return

        self.log_thread = LogReaderThread()
        self.log_thread.log_signal.connect(self.append_log)
        self.log_thread.done_signal.connect(self.enable_finish)
        self.log_thread.start()

    def append_log(self, text):
        self.log_area.appendPlainText(text)

    def enable_finish(self):
        self.label.setText("✅ Test Completed.")
        self.finish_button.setEnabled(True)

    def goto_report(self):
        self.stacked_widget.setCurrentIndex(3)
