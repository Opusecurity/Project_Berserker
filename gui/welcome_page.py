from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap, QPalette, QBrush
from gui.matrix_page import MatrixPage

class WelcomePage(MatrixPage):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        self.setAutoFillBackground(True)
        palette = QPalette()
        pixmap = QPixmap("gui/assets/background.jpg")
        palette.setBrush(QPalette.ColorRole.Window, QBrush(pixmap))
        self.setPalette(palette)

        layout = QVBoxLayout()
        title = QLabel("PROJECT BERSERKER")
        title.setStyleSheet("font-size: 36px; font-weight: bold; color: white;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("AI-Powered Automated Pentest Engine")
        subtitle.setStyleSheet("font-size: 14px; color: lightgray;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        start_button = QPushButton("Start the Berserker")
        start_button.setFixedHeight(40)
        start_button.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                padding: 10px 20px;
                background-color: rgba(0, 0, 0, 180);
                color: white;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: rgba(30, 30, 30, 200);
            }
        """)
        start_button.clicked.connect(self.goto_confirmation)

        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(30)
        layout.addWidget(start_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()

        self.setLayout(layout)

    def goto_confirmation(self):
        self.stacked_widget.setCurrentIndex(1)
