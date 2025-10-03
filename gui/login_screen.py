from PyQt6.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt
from .setup_screen import SetupScreen
from .vault_screen import VaultScreen
from password_manager import PasswordManager

class LoginScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(600, 300, 350, 250)
        self.setWindowIcon(QIcon("assets/vault_icon.ico"))

        self.manager = PasswordManager()
        self.first_time = self.manager.load_master_password()
        self.attempts_left = 3

        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(40, 20, 40, 20)
        main_layout.setSpacing(10)

        self.title_label = QLabel("🔐 Vault Access")
        self.title_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.title_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Master Password")
        main_layout.addWidget(self.password_input)

        self.hint_label = QLabel("")
        self.hint_label.setStyleSheet("color: gray; font-style: italic;")
        self.hint_label.hide()
        main_layout.addWidget(self.hint_label)

        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.check_login)
        main_layout.addWidget(self.login_btn)

        self.setLayout(main_layout)

    def check_login(self):
        if self.first_time:
            self.hide()
            self.setup_window = SetupScreen(self.manager)
            self.setup_window.show()
            return

        password = self.password_input.text()
        if self.manager.verify_master_password(password):
            self.hide()
            self.vault_window = VaultScreen(self.manager)
            self.vault_window.show()
        else:
            self.attempts_left -= 1
            self.hint_label.setText(f"Incorrect password! {self.attempts_left} attempts left")
            self.hint_label.show()
            self.password_input.clear()

            if self.attempts_left <= 0:
                self.login_btn.setEnabled(False)
                self.hint_label.setText("Too many failed attempts.")
