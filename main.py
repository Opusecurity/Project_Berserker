import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QStackedWidget
from gui.welcome_page import WelcomePage
from gui.confirm_page import ConfirmationPage
from gui.execution_page import ExecutionPage
from gui.report_page import ReportPage

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Project Berserker - Pentest GUI")
        self.setGeometry(100, 100, 800, 600)

        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        self.stacked_widget.addWidget(WelcomePage(self.stacked_widget))
        self.stacked_widget.addWidget(ConfirmationPage(self.stacked_widget))
        self.stacked_widget.addWidget(ExecutionPage(self.stacked_widget))
        self.stacked_widget.addWidget(ReportPage())

def run_app():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    run_app()
