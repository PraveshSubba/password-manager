from PyQt6.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
from .vault_screen import VaultScreen

class SetupScreen(QWidget):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.setWindowTitle("Setup Master Password")
        self.setGeometry(650, 350, 350, 250)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🔑 First-Time Setup")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password.setPlaceholderText("Enter new master password")
        layout.addWidget(self.new_password)

        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password.setPlaceholderText("Re-enter new password")
        layout.addWidget(self.confirm_password)

        self.hint_input = QLineEdit()
        self.hint_input.setPlaceholderText("Password hint")
        layout.addWidget(self.hint_input)

        self.setup_btn = QPushButton("Set Master Password")
        self.setup_btn.clicked.connect(self.set_master_password)
        layout.addWidget(self.setup_btn)

        self.setLayout(layout)

    def set_master_password(self):
        if self.new_password.text() == self.confirm_password.text():
            self.manager.change_master_password(
                self.new_password.text(), self.hint_input.text()
            )
            self.hide()
            self.vault_window = VaultScreen(self.manager)
            self.vault_window.show()
