from password_manager import PasswordManager
from getpass import getpass 

class CLIHandler:
    def __init__(self, manager: PasswordManager):
        self.manager = manager

    def set_master_password(self,is_new_password):
        verified = True

        if is_new_password:
            print("\n======$ First Time Password Setup $=======\n")
        else:
            current_password = getpass("Enter current master password: ")
            verified = self.manager.verify_master_password(current_password)

        while True:
            if verified:
                new_password = getpass("Enter New Master Password: ")
                check_password = getpass("Re-enter New Password : ")

                if new_password == check_password:
                    password_hint = input("Enter the Password Hint : ")
                    self.manager.change_master_password(new_password,password_hint, is_new_password)
                    del check_password, new_password,password_hint #delete from memory
                    break
                else:
                    print("Passwords do not match. Try again.\n")
            else:
                print("Wrong master password.")
                break



    def run(self):
        menu = {
            "1": ("Add password", self.manager.add_password),
            "2": ("Get password", self.manager.get_password),
            "3": ("Delete password", self.manager.delete_password),
            "4": ("Change Master Password", lambda: self.set_master_password(False)),
            "5": ("Quit", lambda: None),
        }

        try:
            first_time_setup = self.manager.load_master_password()  
        except KeyboardInterrupt:
            print("\nForceful shutdown")
            return

        chances = 3
        master_verified = False 
        running = True
        print("\n=========$ PASSWORD MANAGER $==========")

        while chances > 0 and running:
            try:
                # ask for master password if not verified yet
                if not master_verified:
                    if not first_time_setup:
                        master_password = getpass("Enter Master Password: ")
                        if not self.manager.verify_master_password(master_password):
                            chances -= 1
                            print(f"Wrong password! Chances left: {chances}")
                            if chances == 1:
                                print("Hint:", self.manager.hint)
                            del master_password
                            continue  # Ask for master password again
                        del master_password
                    else:
                        self.set_master_password(True)
                        first_time_setup = False

                    master_verified = True  # mark as verified

                # Show menu and handle choice
                print("\n         Choose the options - Admin")
                for key, (desc, _) in menu.items():
                    print(f"         {key}. {desc}")

                choice = input("Enter choice: ").strip()
                if choice in menu:
                    _, action = menu[choice]
                    action()
                    if choice == "5":  # Quit
                        print("Exiting Password Manager...")
                        running = False
                else:
                    print("Invalid choice! Please try again.")
                    # master_verified stays True, so user doesn't need to re-enter master password

            except KeyboardInterrupt:
                print("\nForceful shutdown")
                break