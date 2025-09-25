from password_manager import PasswordManager
from getpass import getpass 

class CLIHandler:
    def __init__(self, manager: PasswordManager):
        self.manager = manager

    def score_calc(self,score):
        if score != 0:
            if score <= 2:
                print("Password Strength: Weak")
            elif score <= 4:
                print("Password Strength: Medium") 
            else:
                print("Password Strength: Strong")
            

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
                    score = self.manager.change_master_password(new_password,password_hint)

                    if not is_new_password:
                        print("Master password changed successfully.")
                    else:
                        print("Master password added successfully.")
                    self.score_calc(score)

                    del check_password, new_password,password_hint #delete from memory
                    break
                else:
                    print("Passwords do not match. Try again.\n")
            else:
                print("Wrong master password.")
                break

    def add_vault_passwords(self):
        site = input("Enter site name: ")
        username = input("Enter username: ")
        password = getpass("Enter password(no password - auto generate): ")

        status,score = self.manager.add_password(site,username,password)
        
        if status:
            self.score_calc(score)
            print(f"Password for {site} added successfully.")
        del site,username,password
    
    def get_vault_passwords(self):
        empty,passwords = self.manager.check_vault_empty()

        if empty:
            print("Vault is empty.")
            return
        print("\n---- Stored sites -----\n")

        for count,site in enumerate(passwords,start=1):
            print(f"{count}. {site}")

        site = input("\nEnter site name: ")
        username = self.manager.get_password(site,passwords)

        if username:
            print(f"Password for '{site}' copied to clipboard!")
        else:
            print("No password found for this site.")

        del passwords

    def delete_vault_passwords(self):
        empty,passwords = self.manager.check_vault_empty()

        if empty:
            print("Vault is empty.")
            return
        print("\n---- Stored sites -----\n")

        for count,site in enumerate(passwords,start=1):
            print(f"{count}. {site}")

        site = input("\nEnter site name: ")
        status = self.manager.delete_password(site, passwords)

        if status:
            print(f"Deleted password for {site}.")
        else:
            print("No password found for this site.")

        del passwords


    def run(self):
        menu = {
            "1": ("Add password", self.add_vault_passwords),
            "2": ("Get password", self.get_vault_passwords),
            "3": ("Delete password", self.delete_vault_passwords),
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