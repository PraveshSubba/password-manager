from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QListWidget, QInputDialog, QMessageBox
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
from .add_password_dialog import AddPasswordDialog

class VaultScreen(QWidget):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.setWindowTitle("Password Vault")
        self.setGeometry(500, 250, 400, 400)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🔐 Your Vault")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.site_list = QListWidget()
        self.refresh_sites()
        layout.addWidget(self.site_list)

        self.add_btn = QPushButton("Add Password")
        self.add_btn.clicked.connect(self.add_password)
        layout.addWidget(self.add_btn)

        self.get_btn = QPushButton("Get Password")
        self.get_btn.clicked.connect(self.get_password)
        layout.addWidget(self.get_btn)

        self.delete_btn = QPushButton("Delete Password")
        self.delete_btn.clicked.connect(self.delete_password)
        layout.addWidget(self.delete_btn)

        self.setLayout(layout)

    def refresh_sites(self):
        self.site_list.clear()
        empty, passwords = self.manager.check_vault_empty()
        if not empty:
            self.site_list.addItems(passwords.keys())

    def add_password(self):
        dialog = AddPasswordDialog(self.manager)
        dialog.exec()
        self.refresh_sites()

    def get_password(self):
        site = self.site_list.currentItem()
        if not site:
            QMessageBox.warning(self, "Error", "Select a site first!")
            return
        username = self.manager.get_password(site.text(), self.manager.passwords)
        if username:
            QMessageBox.information(self, "Password Copied", f"Username: {username}\nPassword copied to clipboard!")
        else:
            QMessageBox.warning(self, "Error", "Password not found!")

    def delete_password(self):
        site = self.site_list.currentItem()
        if not site:
            QMessageBox.warning(self, "Error", "Select a site first!")
            return
        status = self.manager.delete_password(site.text(), self.manager.passwords)
        if status:
            QMessageBox.information(self, "Deleted", f"Password for {site.text()} deleted.")
        self.refresh_sites()
