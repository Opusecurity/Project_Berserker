from PyQt6.QtWidgets import QVBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import Qt
from gui.matrix_page import MatrixPage

class ConfirmationPage(MatrixPage):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        label = QLabel("Are you sure you want to launch the BERSERKER?")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("font-size: 18px; color: white;")

        yes_button = QPushButton("Yes, Launch")
        yes_button.setFixedHeight(40)
        yes_button.setStyleSheet("background-color: #228B22; color: white; font-size: 14px;")
        yes_button.clicked.connect(self.goto_execution)

        no_button = QPushButton("No, Go Back")
        no_button.setFixedHeight(40)
        no_button.setStyleSheet("background-color: #8B0000; color: white; font-size: 14px;")
        no_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))

        layout.addStretch()
        layout.addWidget(label)
        layout.addSpacing(20)
        layout.addWidget(yes_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(no_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()

        self.setLayout(layout)

    def goto_execution(self):
        self.stacked_widget.setCurrentIndex(2)
