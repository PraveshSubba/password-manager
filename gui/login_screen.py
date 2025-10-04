from PyQt6.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QSpacerItem, QSizePolicy
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt
from password_manager import PasswordManager
from .vault_screen import VaultScreen

class LoginScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.manager = PasswordManager()
        self.first_time = self.manager.load_master_password()
        self.attempts_left = 3

        self.setWindowTitle("My Vault")
        self.setFixedSize(430, 280)  # Fixed size
        self.setWindowIcon(QIcon("assets/vault.png"))

        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(40, 30, 40, 30)
        self.main_layout.setSpacing(15)
        self.main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setLayout(self.main_layout)

        self.init_ui()

    def init_ui(self):
        # Title
        self.title_label = QLabel()
        self.title_label.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.main_layout.addWidget(self.title_label)

        # Password input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(30)
        self.password_input.setStyleSheet(
            "padding: 5px; border-radius: 5px; border: 1px solid #ccc;"
        )
        self.main_layout.addWidget(self.password_input)

        # Re-enter password (only for setup)
        self.re_password_input = QLineEdit()
        self.re_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.re_password_input.setMinimumHeight(30)
        self.re_password_input.setStyleSheet(
            "padding: 5px; border-radius: 5px; border: 1px solid #ccc;"
        )
        self.main_layout.addWidget(self.re_password_input)

        # Hint label
        self.hint_label = QLabel("")
        self.hint_label.setStyleSheet("color: gray; font-style: italic;")
        self.hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hint_label.hide()
        self.main_layout.addWidget(self.hint_label)

        # Action button
        self.action_btn = QPushButton()
        self.action_btn.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.action_btn.setMinimumHeight(35)
        self.action_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.main_layout.addWidget(self.action_btn)

        # Spacer to push everything to top
        self.main_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        if self.first_time:
            self.show_setup_ui()
        else:
            self.show_login_ui()

    # ---------------- First-time setup ----------------
    def show_setup_ui(self):
        self.title_label.setText("🔐 Setup Master Password")

        self.password_input.setPlaceholderText("Enter New Master Password")
        self.password_input.clear()
        self.password_input.show()

        self.re_password_input.setPlaceholderText("Re-enter New Master Password")
        self.re_password_input.clear()
        self.re_password_input.show()

        if not hasattr(self, "hint_input"):
            self.hint_input = QLineEdit()
            self.hint_input.setPlaceholderText("Password Hint (optional)")
            self.hint_input.setMinimumHeight(30)
            self.hint_input.setStyleSheet(
                "padding: 5px; border-radius: 5px; border: 1px solid #ccc;"
            )
            self.main_layout.insertWidget(3, self.hint_input)

        self.action_btn.setText("Set Password")
        self.action_btn.clicked.connect(self.set_new_master_password)
        self.password_input.returnPressed.connect(self.set_new_master_password)
        self.re_password_input.returnPressed.connect(self.set_new_master_password)
        self.hint_input.returnPressed.connect(self.set_new_master_password)

    # ---------------- Login UI ----------------
    def show_login_ui(self):
        self.main_layout.setContentsMargins(30, 50, 30, 30) 
        self.title_label.setText("🔐 Vault Access")

        if not hasattr(self, 'login_spacer'):
            self.login_spacer = QSpacerItem(20, 80, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)

        self.main_layout.insertSpacerItem(1, self.login_spacer)  # insert after title_label
        self.password_input.setPlaceholderText("Enter Master Password")
        self.password_input.clear()
        self.re_password_input.hide()


        self.action_btn.setText("Login")
        self.action_btn.clicked.disconnect() if self.action_btn.receivers(self.action_btn.clicked) else None
        self.action_btn.clicked.connect(self.check_login)
        self.password_input.returnPressed.connect(self.check_login)

    def set_new_master_password(self):
        new_password = self.password_input.text()
        re_password = self.re_password_input.text()
        hint = self.hint_input.text()

        if not new_password:
            self.hint_label.setText("Password cannot be empty.")
            self.hint_label.show()
            return

        if new_password != re_password:
            self.hint_label.setText("Passwords do not match! Try again.")
            self.hint_label.show()
            self.password_input.clear()
            self.re_password_input.clear()
            return

        self.manager.create_master_password(new_password, hint)
        self.hint_label.setText("Master password set successfully!")
        self.hint_label.show()

        self.main_layout.removeWidget(self.hint_input)
        self.hint_input.deleteLater()
        self.password_input.clear()
        self.action_btn.clicked.disconnect()
        self.first_time = False

        self.show_login_ui()

    def check_login(self):
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
                self.action_btn.setEnabled(False)
                self.hint_label.setText("Too many failed attempts.")
