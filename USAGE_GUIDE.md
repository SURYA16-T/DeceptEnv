# DeceptEnv: Complete Usage & Architecture Guide

## 🌟 What is DeceptEnv? (How it works & Why it's helpful)
DeceptEnv is a **zero-privilege active defense engine** designed to hunt and neutralize **Infostealers** (like RedLine, Raccoon, or Vidar). 

Infostealers are a specific type of malware that try to steal your browser cookies, cryptocurrency wallets, and cloud credentials (like AWS keys). Because they do this using completely normal file-read operations, traditional Anti-Viruses and EDRs often miss them or require heavy kernel-level access to stop them.

**How it works:**
1. **Deception:** It creates "honey-tokens" (fake, highly-enticing files like synthetic AWS credentials and Chrome cookies) in the exact folders where malware expects to find them.
2. **Monitoring:** It watches these fake files silently using the OS's native file-system hooks with near-zero CPU overhead.
3. **Mitigation:** The moment an unauthorized script or malware tries to read the fake file, DeceptEnv instantly freezes the process at the OS-scheduler level (in under 2 milliseconds!) before it can steal your data.
4. **Forensics:** It safely dumps the frozen malware's memory, command line, and active network connections, and ships it off to Slack for your incident response team.

**Where to use it:**
- On developer workstations (Mac/Linux/Windows) to protect sensitive source code and cloud credentials.
- On corporate laptops as a lightweight, user-space addition to existing EDR solutions.
- In CI/CD build environments to catch rogue supply-chain dependencies trying to steal environment variables.

---

## 💻 CLI & Terminal Usage

DeceptEnv is packaged as a standard Python command-line interface (CLI). To use it, simply activate your virtual environment and run the `deceptenv` command!

### General Commands
- **Help Menu:** `deceptenv --help`
- **Deploy Canaries:** `deceptenv init`
  *(This creates the fake files across your system)*
- **Check Status:** `deceptenv list-canaries`
  *(Shows you exactly where the fake files were deployed)*
- **Cleanup:** `deceptenv clean`
  *(Removes all fake files safely)*
- **Start Defense Engine:** `deceptenv run`
  *(Starts the live monitoring dashboard and active mitigation loop)*

---

## 🖥️ Operating System Specifics

DeceptEnv is fully cross-platform and adapts to the OS it is running on automatically.

### 🍎 macOS
- **Canary Locations:**
  - AWS: `~/.aws/credentials.honey`
  - System: `~/Library/Preferences/com.apple.deceptenv.sys.plist.honey`
- **Under the hood:** Uses `FSEvents` for monitoring and `SIGSTOP` signals to instantly freeze malware threads.
- **How to test:** 
  ```bash
  # Open two terminals
  # Terminal 1:
  deceptenv init
  deceptenv run
  
  # Terminal 2:
  cat ~/.aws/credentials.honey
  # The 'cat' process will be instantly frozen by Terminal 1!
  ```

### 🐧 Linux
- **Canary Locations:**
  - AWS: `~/.aws/credentials.honey`
  - System: `~/.config/deceptenv/system.conf.honey`
- **Under the hood:** Uses `inotify` for file monitoring and `SIGSTOP` for mitigation. Safely extracts memory from `/proc/[pid]/mem`.
- **How to test:** 
  ```bash
  # Open two terminals
  # Terminal 1:
  deceptenv init
  deceptenv run
  
  # Terminal 2:
  cat ~/.aws/credentials.honey
  ```

### 🪟 Windows
- **Canary Locations:**
  - AWS: `%USERPROFILE%\.aws\credentials.honey`
  - System: `%APPDATA%\Microsoft\Windows\deceptenv_config.ini.honey`
- **Under the hood:** Uses `ReadDirectoryChangesW` for zero-overhead monitoring. Uses the powerful `NtSuspendProcess` undocumented API call to freeze the malware's threads without needing Administrator privileges.
- **How to test (PowerShell):** 
  ```powershell
  # Open two PowerShell windows
  # Window 1:
  deceptenv init
  deceptenv run
  
  # Window 2:
  Get-Content $env:USERPROFILE\.aws\credentials.honey
  # The command will hang as the process is frozen!
  ```

---

## 🚨 Slack Webhook Integration
To receive live alerts when an attack is stopped:
```bash
# Set your webhook URL in your terminal
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Then run the engine
deceptenv run
```
