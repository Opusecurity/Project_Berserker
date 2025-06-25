from PyQt6.QtWidgets import QVBoxLayout, QLabel, QPushButton, QFileDialog, QMessageBox
from PyQt6.QtCore import Qt
from gui.matrix_page import MatrixPage
import os

class ReportPage(MatrixPage):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        label = QLabel("✅ Pentest Completed.\nYou can now export the final report.")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("font-size: 16px; color: white;")

        self.export_button = QPushButton("Export Report")
        self.export_button.setFixedHeight(48)
        self.export_button.setEnabled(False)  # Başlangıçta pasif
        self.export_button.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                padding: 12px 24px;
                background-color: qlineargradient(
                    x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 #2b5876, stop: 1 #4e4376
                );
                color: white;
                border: 1px solid #ccc;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: qlineargradient(
                    x1: 0, y1: 0, x2: 1, y2: 0,
                    stop: 0 #3e78a0, stop: 1 #5e5d8f
                );
            }
            QPushButton:disabled {
                background-color: #444;
                color: #999;
                border: 1px solid #666;
            }
        """)
        self.export_button.clicked.connect(self.export_report)

        layout.addStretch()
        layout.addWidget(label)
        layout.addSpacing(20)
        layout.addWidget(self.export_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()
        self.setLayout(layout)

    def showEvent(self, event):
        super().showEvent(event)
        source = "reports/final_report.pdf"
        self.export_button.setEnabled(os.path.exists(source))

    def export_report(self):
        source = "reports/final_report.pdf"
        if not os.path.exists(source):
            QMessageBox.critical(self, "Error", "Report file not found!")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Save Report As", "final_report.pdf", "PDF Files (*.pdf)")
        if path:
            try:
                with open(source, "rb") as f_in, open(path, "wb") as f_out:
                    f_out.write(f_in.read())
                QMessageBox.information(self, "Success", "Report exported successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export report:\n{e}")
