from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout
)
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt
import sys
from password_manager import PasswordManager 

class LoginScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(600, 300, 350, 250)

        # Set window icon
        self.setWindowIcon(QIcon("assets/vault_icon.ico"))

        self.manager = PasswordManager()
        self.manager.load_master_password()
        self.attempts_left = 3
        self.setup_master_login_ui()

    def setup_master_login_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(40, 20, 40, 20)
        main_layout.setSpacing(10)

        # Title
        self.title_label = QLabel("🔐 Vault Access")
        self.title_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("color: #2E86C1;")
        main_layout.addWidget(self.title_label)

        # Input + hint layout
        input_layout = QVBoxLayout()
        input_layout.setSpacing(2)  # very tight spacing

        # Label
        self.label = QLabel(" Enter Master Password")
        self.label.setFont(QFont("Arial", 10, QFont.Weight.DemiBold))
        self.label.setContentsMargins(0, 0, 0, 0)
        self.label.setStyleSheet("margin:0px; padding:0px;")  
        input_layout.addWidget(self.label, alignment=Qt.AlignmentFlag.AlignLeft)

        # Password input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Master Password")
        self.password_input.setMinimumHeight(30)
        self.password_input.setFont(QFont("Arial", 10))
        self.password_input.setStyleSheet("margin:0px; padding:0px;")  
        input_layout.addWidget(self.password_input)

        # Hint label (hidden initially)
        self.hint_label = QLabel("")
        self.hint_label.setStyleSheet("color: gray; font-style: italic;")
        self.hint_label.hide()
        input_layout.addWidget(self.hint_label)

        main_layout.addLayout(input_layout)

        # Small gap before login button
        main_layout.addSpacing(12)

        # Login button
        self.login_btn = QPushButton("Login")
        self.login_btn.setMinimumHeight(30)
        self.login_btn.setMinimumWidth(200)  # wider button
        self.login_btn.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.login_btn.setStyleSheet("""
            QPushButton {
                background-color: #28B463;
                color: white;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #239B56;
            }
        """)
        main_layout.addWidget(self.login_btn, alignment=Qt.AlignmentFlag.AlignHCenter)
        self.setLayout(main_layout)
        self.login_btn.clicked.connect(self.check_login)



    def check_login(self):
        password = self.password_input.text()
        
        if self.manager.verify_master_password(password):
            self.hint_label.hide()
            self.password_input.clear()
            print("Login successful!")
            
            # Here you can open your Vault screen:
            # self.hide()
            # self.vault_window = VaultScreen(self.pm)
            # self.vault_window.show()
            
        else:
            self.attempts_left -= 1
            self.hint_label.setText(f"Incorrect password! {self.attempts_left} attempts left")
            self.hint_label.show()
            self.password_input.clear()

            if self.attempts_left <= 0:
                self.login_btn.setEnabled(False)
                self.hint_label.setText("Too many failed attempts. Try again later.")




if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginScreen()
    window.show()
    sys.exit(app.exec())
