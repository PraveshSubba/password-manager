from password_manager import PasswordManager
from cli_handler import CLIHandler

def main():
    manager = PasswordManager()
    cli = CLIHandler(manager)
    cli.run()

if __name__ == "__main__":
    main()