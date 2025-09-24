


# Password Manager 🔐

This is a simple command-line password manager I built in Python for my own use. It helps me securely store, retrieve, and manage my passwords, all protected by a master password. I wanted a tool that keeps everything local and doesn't depend on any external services.

## Features ✨
- Store and retrieve passwords from the command line
- Master password authentication
- No cloud or third-party dependencies—everything stays on your computer
- Passwords and master credentials are stored in local JSON files

## Project Structure 🗂️
```
cli_handler.py         # Command-line interface and user input
main.py               # Application entry point
password_manager.py   # Core logic for password management
data/master.json      # Stores the (hashed) master password
data/passwords.json   # Stores saved passwords
```

## Getting Started 🚀

### Prerequisites 📋
- Python 3.10 or higher

### Installation & Usage 💻
1. Download or clone this project.
2. Open a terminal and go to the project directory:
   ```cmd
   cd c:\Users\Pravesh Subba\python\PasswordManager
   ```
3. (Optional) Create and activate a virtual environment:
   ```cmd
   python -m venv venv
   .\venv\Scripts\activate
   ```
4. Run the program:
   ```cmd
   python main.py
   ```
5. Follow the prompts to set up your master password and start storing your credentials.



## Privacy & Data Security 🛡️
- All data (including your master password and stored credentials) stays on your local machine. Nothing is sent anywhere else.
- I chose not to use any external/cloud services so I can keep full control of my information and avoid unnecessary risks.
- Never share your master password with anyone.

## Contributions 🤗
If you have suggestions or ideas for improvement, feel free to let me know or submit a pull request. I'm always open to making this tool better! 😊



