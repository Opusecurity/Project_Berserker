from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QPainter, QColor, QFont
import random

class BinaryRainWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.columns = 80
        self.rows = 40
        self.speed = 2
        self.data = [[random.choice("01") for _ in range(self.rows)] for _ in range(self.columns)]
        self.offsets = [random.randint(0, self.rows) for _ in range(self.columns)]

        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setStyleSheet("background-color: black;")

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_rain)
        self.timer.start(50)

    def update_rain(self):
        for i in range(self.columns):
            self.offsets[i] = (self.offsets[i] + 1) % self.rows
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setFont(QFont("Courier", 10))
        cell_width = self.width() // self.columns
        cell_height = self.height() // self.rows
        for x in range(self.columns):
            for y in range(self.rows):
                i = (y + self.offsets[x]) % self.rows
                text = self.data[x][i]
                alpha = int(255 * (1 - (y / self.rows)))
                painter.setPen(QColor(0, 255, 0, alpha))
                painter.drawText(x * cell_width, y * cell_height, cell_width, cell_height, Qt.AlignmentFlag.AlignCenter, text)
