import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon
from ui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)

    app.setApplicationName("AuthNet Pro")
    app.setOrganizationName("ajsai")
    app.setWindowIcon(QIcon("assets/logo.png"))

    window = MainWindow()
    window.setWindowTitle("AuthNet Pro")
    window.setWindowIcon(QIcon("assets/logo.png"))
    window.show()

    sys.exit(app.exec_())

if __name__ == "__main__":
    main()