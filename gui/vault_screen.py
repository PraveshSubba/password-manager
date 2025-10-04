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
        self.setFixedSize(400, 350)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("🔐 Your Vault")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Site list (hidden initially)
        self.site_list = QListWidget()
        self.site_list.hide()
        layout.addWidget(self.site_list)

        # Common button style
        button_style = """
            QPushButton {
                background-color: #4CAF50; 
                color: white;
                border-radius: 8px;
                padding: 10px 15px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
        """

        # Add Password Button
        self.add_btn = QPushButton("Add Password")
        self.add_btn.setStyleSheet(button_style)
        self.add_btn.clicked.connect(self.add_password)
        layout.addWidget(self.add_btn)

        # Get Password Button
        self.get_btn = QPushButton("Get Password")
        self.get_btn.setStyleSheet(button_style)
        #self.get_btn.clicked.connect(self.show_site_list)
        layout.addWidget(self.get_btn)

        # Delete Password Button
        self.delete_btn = QPushButton("Delete Password")
        self.delete_btn.setStyleSheet(button_style)
        self.delete_btn.clicked.connect(self.delete_password)
        layout.addWidget(self.delete_btn)

        # Change Master Password Button
        self.change_master_btn = QPushButton("Change Master Password")
        self.change_master_btn.setStyleSheet(button_style)
        self.change_master_btn.clicked.connect(self.change_delete_password)
        layout.addWidget(self.change_master_btn)

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

    def change_delete_password(self):
        new_password, ok = QInputDialog.getText(self, "Change Master Password", "Enter New Master Password:")
        if ok and new_password:
            hint, ok = QInputDialog.getText(self, "Password Hint (optional)", "Enter a hint for your new password (optional):")
            if ok:
                self.manager.change_master_password(new_password, hint)
                QMessageBox.information(self, "Success", "Master password changed successfully!")
