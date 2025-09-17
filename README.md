# WindowsLogChecker

Windows Security monitoring for failed logons (Event ID 4625) with Telegram notifications.
The script tracks failed logon attempts (incl. RDP — LogonType 10) within a configurable time window and sends a summary to Telegram. Useful for catching brute-force attacks and responding quickly (e.g., blocking IPs at the firewall).

Russian documentation: `README.ru.md`.

## Features
- Parse 4625 events from `Security.evtx`
- Aggregate by IP address and count attempts
- Filter by time window (e.g., last 60 minutes)
- Telegram notifications (bot + chat)
- Process a copied log file (no lock on the original)
- Bilingual support (EN/RU)

## Requirements
- Windows 10/11/Server with access to the Security log
- Python 3.9+
- Read permissions for `C:\\Windows\\System32\\winevt\\Logs\\Security.evtx`

## Installation
```powershell
# Clone the repository
git clone https://github.com/<your-username>/WindowsLogChecker.git

# Enter the project directory
cd WindowsLogChecker

# Install dependencies
pip install -r requirements.txt
```

## Configuration
1. Create a Telegram bot via @BotFather and get the token.
2. Find the chat/channel ID where notifications will be sent.
3. Copy the config template and fill it in:
```powershell
copy config.ini.template config.ini
```
Open `config.ini` and set values:
```ini
[TELEGRAM]
TOKEN = <TELEGRAM_BOT_TOKEN>
CHAT_ID = <TELEGRAM_CHAT_OR_CHANNEL_ID>

[GENERAL]
LANG = en  ; en or ru

[PATHS]
SRC_PATH = C:\\Windows\\System32\\winevt\\Logs\\Security.evtx
DST_PATH = Security.evtx

[SCAN]
PERIOD_MINUTES = 60
SLEEP_MINUTES = 60
```

You can also set secrets and language via environment variables (they take precedence):
```powershell
setx APP_LANG "en"      # or ru
setx TELEGRAM_TOKEN "YOUR_TOKEN"
setx TELEGRAM_CHAT_ID "YOUR_CHAT_ID"
```

Important: `config.ini` and temporary files are excluded from Git via `.gitignore`.

## Run
```powershell
python main.py
```
The script runs in an infinite loop: copies the log, parses 4625 events for the last `PERIOD_MINUTES` minutes, and sends a summary. Delay between cycles — `SLEEP_MINUTES`.

## Operational recommendations
- For continuous running, use Task Scheduler or NSSM/WinSW as a service.
- Restrict the account permissions used to run the script to the minimum required.
- Set up log rotation and bot availability monitoring.

## Dependencies
See `requirements.txt`.

## License
MIT.
