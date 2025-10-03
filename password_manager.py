from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import json, os, secrets, string, pyperclip, sys
from getpass import getpass
import hmac
import threading
import time


class PasswordManager:
    def __init__(self,password_file = 'passwords.json',master_file = 'master.json'):

        # Detect if running as PyInstaller executable
        if getattr(sys, 'frozen', False):
            # When running as exe, base_dir is folder containing the exe
            base_dir = os.path.dirname(sys.executable)
        else:
            # When running as Python script
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
                    self.dek_tag = base64.b64decode(data["dek_tag"])
                    self.hint = data["hint"]

            except (json.JSONDecodeError, KeyError, ValueError):
                # File is empty or malformed, treat as first-time setup
                #print("Master file is empty or corrupted. Setting up a new master password.")
                return True
        else:   
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
                "dek_tag": base64.b64encode(self.dek_tag).decode(),
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
        self.encrypted_dek, self.dek_tag = cipher.encrypt_and_digest(self.dek)
        self.dek_nonce = cipher.nonce
        self.hint = password_hint

        del new_password #delete from memory
        #save to master file
        self.save_master_file()
                     

    def verify_master_password(self, password):# for verification whether the password is correct or not and load DEK
        hashed = PBKDF2(password, self.salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)
        if not hmac.compare_digest(hashed, self.master_password_hash):
            return False

        # Derive KEK and decrypt DEK
        kek = PBKDF2(password, self.enc_salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)
        cipher = AES.new(kek, AES.MODE_EAX, nonce=self.dek_nonce)

        try:
            self.dek = cipher.decrypt_and_verify(self.encrypted_dek, self.dek_tag)
        except ValueError:
            #print("Decryption failed. Possible tampering detected!")
            del kek
            return False      
        
        del kek      
        return True
    

    def change_master_password(self,new_password, password_hint ): #change master password     
        self.create_master_password(new_password,password_hint)

        score = self.password_strength(new_password)
        del new_password, password_hint #delete from memory
        return score


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

    def add_password(self,site,username,password):# add new password

        score = self.password_strength(password)

        if password == "":
            password = self.generate_password()

        encrypted_password = self.encrypt_with_dek(password)
        del password  # Remove plaintext password from memory
        passwords = self.load_passwords()
        passwords[site] = {"username": username, "password": encrypted_password}
        self.save_passwords(passwords)

        return True,score



    def check_vault_empty(self):#check if vault is empty
        passwords = self.load_passwords()
        if not passwords:
            return True, passwords
        return False, passwords
    
    def get_password(self,site,passwords,timeout=15):# get the password

        if site in passwords:
        
            password = passwords[site]['password']
            decrypted_password = self.decrypt_with_dek(password)
        
            # Copy password to clipboard
            pyperclip.copy(decrypted_password)

            # clear clipboard after timeout
            def clear_clipboard():
                time.sleep(timeout)
                if pyperclip.paste() == decrypted_password:
                    pyperclip.copy("")  # clear clipboard
                    
            threading.Thread(target=clear_clipboard, daemon=True).start()

            username = passwords[site]['username']
            del password
            return username
        
        else:
            return None

    def delete_password(self, site, passwords ):#deleting the stored password

        if site in passwords:
            del passwords[site]
            self.save_passwords(passwords)
            return True
        else:
            return False



    def password_strength(self,password):#check the password strength
        score = 0
    
        # Rule 1: Length
        if len(password) >= 12:
            score += 2

        elif len(password) >= 8:
            score += 1
        
        # Rule 2: Uppercase
        if any(c.isupper() for c in password):
            score += 1
        
        # Rule 3: Lowercase
        if any(c.islower() for c in password):
            score += 1
        
        # Rule 4: Digit
        if any(c.isdigit() for c in password):
            score += 1
        
        # Rule 5: Special character
        if any(c in string.punctuation for c in password):
            score += 1
            
        return score

