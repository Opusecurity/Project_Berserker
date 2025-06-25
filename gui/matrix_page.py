from PyQt6.QtWidgets import QWidget
from gui.binary_rain import BinaryRainWidget

class MatrixPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rain = BinaryRainWidget(self)
        self.rain.setGeometry(self.rect())
        self.rain.lower()

    def resizeEvent(self, event):
        self.rain.setGeometry(self.rect())
        super().resizeEvent(event)
