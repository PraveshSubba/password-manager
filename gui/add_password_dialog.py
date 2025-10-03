from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QPushButton, QLabel, QMessageBox
from PyQt6.QtGui import QFont

class AddPasswordDialog(QDialog):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.setWindowTitle("Add Password")
        self.setGeometry(600, 350, 300, 200)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        self.site_input = QLineEdit()
        self.site_input.setPlaceholderText("Site name")
        layout.addWidget(self.site_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password (leave empty to auto-generate)")
        layout.addWidget(self.password_input)

        self.add_btn = QPushButton("Add")
        self.add_btn.clicked.connect(self.add_password)
        layout.addWidget(self.add_btn)

        self.setLayout(layout)

    def add_password(self):
        site = self.site_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        status, score = self.manager.add_password(site, username, password)
        if status:
            QMessageBox.information(self, "Success", f"Password for {site} added successfully!\nStrength Score: {score}")
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Failed to add password.")
