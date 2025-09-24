from password_manager import PasswordManager
from getpass import getpass 

class CLIHandler:
    def __init__(self, manager: PasswordManager):
        self.manager = manager

    def run(self):
        try:
            is_new_password = self.manager.load_master_password()
        except KeyboardInterrupt:
            print("\nForceful shutdown")
            return

        chances = 3
        running = True
        print("\n=========$ PASSWORD MANAGER $==========")

        while chances > 0 and running:
            try:
                if chances != 3:
                    print("\nHint:",self.manager.hint)

                if not is_new_password:#if password is not loaded new password is created
                    master_password = getpass("Enter Master Password: ")
                    master = self.manager.verify_master_password(master_password)
                    del master_password # delete from memory
                else:
                    master = True # new password is created thats y true

                while master:
                    print('\n         Choose the options - Admin')
                    print('         1. Add password')
                    print('         2. Get the password')
                    print("         3. Delete password")
                    print('         4. Change Master Password')
                    print('         5. Quit\n')

                    choice = input("Enter choice: ")

                    if choice == "1":
                        self.manager.add_password()
                    elif choice == "2":
                        self.manager.get_password()
                    elif choice == "3":
                        self.manager.delete_password()
                    elif choice == "4":
                        self.manager.change_master_password()
                    elif choice == "5":
                        print("Exiting Password Manager...")
                        running = False # stops outer loop
                        break
                    else:
                        print("Invalid choice!")
                if not master:
                    chances -= 1
                    print(f"Wrong password! Chances left: {chances}")
            except KeyboardInterrupt:
                print("\nforceful shutdown")
                return

        if chances == 0:
            print("Access denied. Exiting...")
