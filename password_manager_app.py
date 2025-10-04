import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QHBoxLayout, QStackedWidget, QListWidget, QMessageBox, QDialog,
    QFormLayout, QTextEdit, QInputDialog
)
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt
from password_manager import PasswordManager


class LoginScreen(QWidget):
    def __init__(self, stack: QStackedWidget, manager: PasswordManager):
        super().__init__()
        self.stack = stack
        self.manager = manager
        self.attempts_left = 3
        self.setup_master_login_ui()

    def setup_master_login_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(40, 20, 40, 20)
        main_layout.setSpacing(10)

        # Title
        title_label = QLabel("🔐 Vault Access")
        title_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("color: #2E86C1;")
        main_layout.addWidget(title_label)

        # Label
        label = QLabel(" Enter Master Password")
        label.setFont(QFont("Arial", 10, QFont.Weight.DemiBold))
        label.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(label, alignment=Qt.AlignmentFlag.AlignLeft)

        # Password input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Master Password")
        self.password_input.setMinimumHeight(30)
        self.password_input.setFont(QFont("Arial", 10))
        main_layout.addWidget(self.password_input)

        # Hint label
        self.hint_label = QLabel("")
        self.hint_label.setStyleSheet("color: gray; font-style: italic;")
        self.hint_label.hide()
        main_layout.addWidget(self.hint_label)

        # Buttons
        btn_layout = QHBoxLayout()
        self.login_btn = QPushButton("Login")
        self.login_btn.setMinimumHeight(30)
        self.login_btn.clicked.connect(self.check_login)
        btn_layout.addWidget(self.login_btn)

        # If no master password exists, show Setup button
        self.setup_btn = QPushButton("First-time Setup")
        self.setup_btn.setMinimumHeight(30)
        self.setup_btn.clicked.connect(self.goto_setup)
        btn_layout.addWidget(self.setup_btn)

        main_layout.addLayout(btn_layout)

        self.setLayout(main_layout)

    def check_login(self):
        password = self.password_input.text()
        if self.manager.verify_master_password(password):
            self.hint_label.hide()
            self.password_input.clear()
            # Move to vault screen
            self.stack.setCurrentIndex(self.stack.indexOf(self.stack.widget(1)))
            self.stack.widget(1).refresh_vault()
        else:
            self.attempts_left -= 1
            self.hint_label.setText(f"Incorrect password! {self.attempts_left} attempts left")
            self.hint_label.show()
            self.password_input.clear()

            if self.attempts_left <= 0:
                self.login_btn.setEnabled(False)
                self.hint_label.setText("Too many failed attempts. Try again later.")

    def goto_setup(self):
        self.stack.setCurrentIndex(self.stack.indexOf(self.stack.widget(2)))


class SetupScreen(QWidget):
    """Used for first-time master password setup or changing the master password."""

    def __init__(self, stack: QStackedWidget, manager: PasswordManager, first_time=True):
        super().__init__()
        self.stack = stack
        self.manager = manager
        self.first_time = first_time
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 20, 30, 20)
        layout.setSpacing(10)

        title = QLabel("Set Master Password" if self.first_time else "Change Master Password")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        form = QFormLayout()

        if not self.first_time:
            self.current_input = QLineEdit()
            self.current_input.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow("Current Password:", self.current_input)

        self.new_input = QLineEdit()
        self.new_input.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("New Password:", self.new_input)

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Confirm Password:", self.confirm_input)

        self.hint_input = QLineEdit()
        form.addRow("Password Hint:", self.hint_input)

        layout.addLayout(form)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_master_password)
        btn_layout.addWidget(save_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.cancel)
        btn_layout.addWidget(cancel_btn)

        layout.addLayout(btn_layout)

        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def save_master_password(self):
        if not self.first_time:
            if not self.manager.verify_master_password(self.current_input.text()):
                QMessageBox.warning(self, "Wrong password", "Current master password is incorrect.")
                return

        new_pw = self.new_input.text()
        confirm_pw = self.confirm_input.text()
        hint = self.hint_input.text()

        if new_pw != confirm_pw:
            QMessageBox.warning(self, "Mismatch", "Passwords do not match. Try again.")
            return

        score = self.manager.change_master_password(new_pw, hint)
        QMessageBox.information(self, "Success",
                                "Master password set successfully." if self.first_time else "Master password changed successfully.")
        strength = self._score_to_text(score)
        QMessageBox.information(self, "Password Strength", f"{strength}")

        # Return to login or vault depending on first_time
        if self.first_time:
            # After setup, go to login screen
            self.stack.setCurrentIndex(self.stack.indexOf(self.stack.widget(0)))
        else:
            self.stack.setCurrentIndex(self.stack.indexOf(self.stack.widget(1)))
            self.stack.widget(1).refresh_vault()

    def cancel(self):
        # go back to previous screen
        if self.first_time:
            self.stack.setCurrentIndex(self.stack.indexOf(self.stack.widget(0)))
        else:
            self.stack.setCurrentIndex(self.stack.indexOf(self.stack.widget(1)))

    def _score_to_text(self, score: int) -> str:
        if score == 0:
            return "Password Strength: Weak"
        if score <= 2:
            return "Password Strength: Weak"
        elif score <= 4:
            return "Password Strength: Medium"
        else:
            return "Password Strength: Strong"


class AddPasswordDialog(QDialog):
    def __init__(self, manager: PasswordManager, parent=None):
        super().__init__(parent)
        self.manager = manager
        self.setWindowTitle("Add Vault Password")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        form = QFormLayout()

        self.site_input = QLineEdit()
        form.addRow("Site:", self.site_input)

        self.username_input = QLineEdit()
        form.addRow("Username:", self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Leave empty to auto-generate")
        form.addRow("Password:", self.password_input)

        layout.addLayout(form)

        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self.add_password)
        btn_layout.addWidget(add_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def add_password(self):
        site = self.site_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not site:
            QMessageBox.warning(self, "Missing field", "Please enter the site name.")
            return

        status, score = self.manager.add_password(site, username, password)
        if status:
            QMessageBox.information(self, "Added", f"Password for {site} added successfully.\nStrength: {self._score_to_text(score)}")
            self.accept()
        else:
            QMessageBox.warning(self, "Failed", "Failed to add password. It may already exist.")

    def _score_to_text(self, score: int) -> str:
        if score == 0:
            return "Weak"
        if score <= 2:
            return "Weak"
        elif score <= 4:
            return "Medium"
        else:
            return "Strong"


class VaultScreen(QWidget):
    def __init__(self, stack: QStackedWidget, manager: PasswordManager):
        super().__init__()
        self.stack = stack
        self.manager = manager
        self.passwords = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        title = QLabel("🔒 Your Vault")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        btn_layout = QHBoxLayout()

        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self.open_add_dialog)
        btn_layout.addWidget(add_btn)

        get_btn = QPushButton("Get/Copy")
        get_btn.clicked.connect(self.get_password)
        btn_layout.addWidget(get_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self.delete_password)
        btn_layout.addWidget(delete_btn)

        change_master_btn = QPushButton("Change Master")
        change_master_btn.clicked.connect(self.goto_change_master)
        btn_layout.addWidget(change_master_btn)

        logout_btn = QPushButton("Logout")
        logout_btn.clicked.connect(self.logout)
        btn_layout.addWidget(logout_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def refresh_vault(self):
        empty, passwords = self.manager.check_vault_empty()
        self.list_widget.clear()
        self.passwords = passwords or []

        if empty:
            self.list_widget.addItem("<Vault is empty>")
            self.list_widget.setEnabled(False)
        else:
            self.list_widget.setEnabled(True)
            for site in self.passwords:
                self.list_widget.addItem(site)

    def open_add_dialog(self):
        dlg = AddPasswordDialog(self.manager, self)
        if dlg.exec():
            self.refresh_vault()

    def get_password(self):
        selected = self.list_widget.currentItem()
        if not selected:
            QMessageBox.information(self, "Select", "Please select a site first.")
            return
        site = selected.text()
        if site == "<Vault is empty>":
            QMessageBox.information(self, "Empty", "Vault is empty.")
            return

        # manager.get_password(site, passwords) is assumed to return the password (or username)
        pw = self.manager.get_password(site, self.passwords)
        if pw:
            # copy to clipboard
            clipboard = QApplication.clipboard()
            clipboard.setText(pw)
            QMessageBox.information(self, "Copied", f"Password for '{site}' copied to clipboard!")
        else:
            QMessageBox.warning(self, "Not found", "No password found for this site.")

    def delete_password(self):
        selected = self.list_widget.currentItem()
        if not selected:
            QMessageBox.information(self, "Select", "Please select a site first.")
            return
        site = selected.text()
        if site == "<Vault is empty>":
            QMessageBox.information(self, "Empty", "Vault is empty.")
            return

        reply = QMessageBox.question(self, 'Confirm Delete', f"Delete password for {site}?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            status = self.manager.delete_password(site, self.passwords)
            if status:
                QMessageBox.information(self, "Deleted", f"Deleted password for {site}.")
                self.refresh_vault()
            else:
                QMessageBox.warning(self, "Not found", "No password found for this site.")

    def goto_change_master(self):
        # Go to change master screen (index 2)
        self.stack.setCurrentIndex(self.stack.indexOf(self.stack.widget(2)))

    def logout(self):
        # Return to login screen and reset attempts
        self.stack.setCurrentIndex(self.stack.indexOf(self.stack.widget(0)))
        self.stack.widget(0).attempts_left = 3
        self.stack.widget(0).login_btn.setEnabled(True)


def main():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("assets/vault_icon.ico"))

    manager = PasswordManager()
    first_time_setup = manager.load_master_password()

    stack = QStackedWidget()

    login = LoginScreen(stack, manager)
    vault = VaultScreen(stack, manager)
    setup = SetupScreen(stack, manager, first_time=first_time_setup)

    stack.addWidget(login)  # index 0
    stack.addWidget(vault)  # index 1
    stack.addWidget(setup)  # index 2

    # If first time, show setup screen directly
    if first_time_setup:
        stack.setCurrentIndex(2)
    else:
        stack.setCurrentIndex(0)

    stack.setWindowTitle("Password Manager")
    stack.resize(480, 420)
    stack.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
