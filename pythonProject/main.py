import sys
import platform
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout,
    QWidget, QFileDialog, QListWidget, QLabel
)
import psutil


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PDF i Pendrive Detector")

        # Utworzenie layoutu
        self.layout = QVBoxLayout()

        # Przycisk do wyboru pliku PDF
        self.btn_select_pdf = QPushButton("Wybierz PDF")
        self.btn_select_pdf.clicked.connect(self.select_pdf)
        self.layout.addWidget(self.btn_select_pdf)

        # Etykieta pokazująca wybrany plik PDF
        self.label_pdf = QLabel("Wybrany plik PDF: brak")
        self.layout.addWidget(self.label_pdf)

        # Przycisk do wykrywania pendrive'ów
        self.btn_detect_pendrive = QPushButton("Wykryj Pendrive'y")
        self.btn_detect_pendrive.clicked.connect(self.detect_pendrives)
        self.layout.addWidget(self.btn_detect_pendrive)

        # Lista wyświetlająca znalezione pendrive'y
        self.list_pendrives = QListWidget()
        self.layout.addWidget(self.list_pendrives)

        # Ustawienie głównego widgetu i layoutu
        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

    def select_pdf(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self,
            "Wybierz plik PDF",
            "",
            "Pliki PDF (*.pdf)",
            options=options
        )
        if fileName:
            self.label_pdf.setText("Wybrany plik PDF: " + fileName)
        else:
            self.label_pdf.setText("Wybrany plik PDF: brak")

    def detect_pendrives(self):
        self.list_pendrives.clear()  # Czyszczenie listy przed wykrywaniem
        partitions = psutil.disk_partitions(all=False)

        for partition in partitions:
            if platform.system() == 'Windows':
                # W systemie Windows flagą 'removable' określa się urządzenia przenośne
                if 'removable' in partition.opts.lower():
                    self.list_pendrives.addItem(f"{partition.device} - montowany w {partition.mountpoint}")
            else:
                # Na systemach Linux/Mac - pendrive'y są zamontowane w /media lub /run/media
                if partition.mountpoint.startswith("/media") or partition.mountpoint.startswith("/run/media"):
                    self.list_pendrives.addItem(f"{partition.device} - montowany w {partition.mountpoint}")

        if self.list_pendrives.count() == 0:
            self.list_pendrives.addItem("Brak wykrytych pendrive'ów.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
