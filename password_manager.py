from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import json, os, secrets, string,pyperclip
from getpass import getpass


class PasswordManager:
    def __init__(self,password_file = 'passwords.json',master_file = 'master.json'):
        # Get the folder of the current script
        base_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(base_dir, "data")
        os.makedirs(data_dir, exist_ok=True)#creates folder

        self.password_file = os.path.join(data_dir, password_file)
        self.master_file = os.path.join(data_dir, master_file)

        self.master_password_hash = None #for master
        self.salt = None

        self.encrypted_dek = None #for vault - passwords
        self.enc_salt = None
        self.dek_nonce = None
        self.dek = None  # Data Encryption Key
        self.hint = None 

    # master password
    def load_master_password(self):
        if os.path.exists(self.master_file):
            try:
                with open(self.master_file,'r') as f:
                    data = json.load(f)
                    self.master_password_hash = base64.b64decode(data['hash'])
                    self.salt = base64.b64decode(data['salt'])

                    self.enc_salt = base64.b64decode(data['enc_salt'])
                    self.encrypted_dek = base64.b64decode(data["enc_dek"])
                    self.dek_nonce = base64.b64decode(data["dek_nonce"])
                    self.hint = data["hint"]

            except (json.JSONDecodeError, KeyError, ValueError):
                # File is empty or malformed, treat as first-time setup
                print("Master file is empty or corrupted. Setting up a new master password.")
                self.new_master_password()
                return True
        else:
            self.new_master_password()
            return True
        
        return False

    def save_master_file(self):#save to master file
        with open(self.master_file, "w") as f:
            json.dump({
                "hash": base64.b64encode(self.master_password_hash).decode(),
                "salt": base64.b64encode(self.salt).decode(),
                "enc_salt": base64.b64encode(self.enc_salt).decode(),
                "enc_dek": base64.b64encode(self.encrypted_dek).decode(),
                "dek_nonce": base64.b64encode(self.dek_nonce).decode(),
                "hint": self.hint
            }, f, indent=2)  

    def create_master_password(self,new_password,password_hint):
        #generate salt
        self.salt = secrets.token_bytes(16)
        self.enc_salt = secrets.token_bytes(16)

        #generate hash password in base64 #idea can be merged into one
        self.master_password_hash = PBKDF2(
            new_password, self.salt, dkLen=32,
            count=100_000, hmac_hash_module=SHA256
        )
        
        self.dek = secrets.token_bytes(32)
        
        #encrypt dek with kek
        kek = PBKDF2(new_password, self.enc_salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)#key encrytion key
        cipher = AES.new(kek, AES.MODE_EAX)
        self.encrypted_dek, tag = cipher.encrypt_and_digest(self.dek)
        self.dek_nonce = cipher.nonce
        self.hint = password_hint

        del new_password #delete from memory
        #save to master file
        self.save_master_file()
                
                

    def new_master_password(self):
        print("======$ First Time Password Setup $\n")
        while True:
            new_password = getpass("Enter the Master Password: ")
            check_password = getpass("Re-enter the Password : ")
            password_hint = input("Enter the Password Hint : ")
            
            if new_password == check_password:
                self.create_master_password(new_password,password_hint)
                print("Master password added successfully.")
                break
            else:
                print("Passwords do not match. Try again.\n")


    def verify_master_password(self, password):# for verification whether the password is correct or not and load DEK
        hashed = PBKDF2(password, self.salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)
        if hashed != self.master_password_hash:
                print("Invalid master password.")
                return False

        # Derive KEK and decrypt DEK
        kek = PBKDF2(password, self.enc_salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)
        cipher = AES.new(kek, AES.MODE_EAX, nonce=self.dek_nonce)
        self.dek = cipher.decrypt(self.encrypted_dek)  # DEK now loaded
        return True
    

    def change_master_password(self): #change master password
        current_password = getpass("Enter current master password: ")

        if self.verify_master_password(current_password):
            new_password = getpass("Enter new master password: ")
            check = getpass("Re-enter New Password: ")
            password_hint = input("Enter the Password Hint : ") #storing password hint
           
            if new_password == check:
                self.create_master_password(new_password,password_hint)
                print("Master password changed successfully.")

        else:
            print("Wrong master password.")
    
    #----------password Vault for sites ---------

    def generate_password(self,length = 16):#generates password
        alphabets = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabets) for i in range(length))

    def load_passwords(self):#load password in the file
        if os.path.exists(self.password_file):
            try:
                with open(self.password_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, ValueError):
                return {}
        else:
            return {}
    
    def save_passwords(self, passwords):#save in the file
        with open(self.password_file, "w") as f:
            json.dump(passwords, f,indent=2)

    def encrypt_with_dek(self,password):

        cipher = AES.new(self.dek, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(password.encode())

        return {
            "ciphertext": base64.b64encode(cipher_text).decode(),
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "tag": base64.b64encode(tag).decode()
        }
    
    def decrypt_with_dek(self, data):
        cipher = AES.new(self.dek, AES.MODE_EAX, nonce=base64.b64decode(data["nonce"]))
        plaintext = cipher.decrypt_and_verify(base64.b64decode(data["ciphertext"]), base64.b64decode(data["tag"]))
        return plaintext.decode()

    def add_password(self):# add new password
        site = input("Enter site name: ")
        username = input("Enter username: ")
        password = getpass("Enter password(no password - auto generate): ")

        if password == "":
            password = self.generate_password()

        encrypted_password = self.encrypt_with_dek(password)
        passwords = self.load_passwords()
        passwords[site] = {"username": username, "password": encrypted_password}
        self.save_passwords(passwords)
        print(f"Password for {site} added successfully.")


    def check_vault_empty(self):#check if vault is empty
        passwords = self.load_passwords()
        if not passwords:
            print("Vault is empty.")
            return True, passwords
        return False, passwords
    
    def get_password(self):#get the password
        empty,passwords = self.check_vault_empty()

        if empty:
            return

        site = input("Enter site name: ")
        if site in passwords:
        
            password = passwords[site]['password']
            decrypted_password = self.decrypt_with_dek(password)
        
            # Copy password to clipboard
            pyperclip.copy(decrypted_password)
            print(f"\nUsername: {passwords[site]['username']}")
            print(f"Password for '{site}' copied to clipboard!")
            del password
        else:
            print("No password found for this site.")

    def delete_password(self):#deleting the stored password
        empty,passwords = self.check_vault_empty()

        if empty:
            return
        
        site = input("Enter site name to delete: ")

        if site in passwords:
            del passwords[site]
            self.save_passwords(passwords)
            print(f"Deleted password for {site}.")
        else:
            print("No password found for this site.")

