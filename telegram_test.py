import os
import requests
from dotenv import load_dotenv

load_dotenv(".env", override=True)  

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

if not TOKEN or not CHAT_ID:
    raise ValueError(
        "Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in .env"
    )

url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"

payload = {
    "chat_id": CHAT_ID,
    "text": "Network Anomaly Detector: Telegram test successful!"
}

try:
    response = requests.post(url, json=payload, timeout=10)
    response.raise_for_status()
    result = response.json()

    if result.get("ok"):
        print("Telegram test message sent successfully.")
    else:
        print("Telegram API rejected the message.")

except requests.RequestException as error:
    print("Could not send Telegram message.")
    print("Check your network connection and bot configuration.")
