import os
import requests
from dotenv import load_dotenv

load_dotenv(".env")

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_telegram_alert(source_ip, destination_ip, attack_type, severity):
    if not TOKEN or not CHAT_ID:
        print("Telegram notification skipped: credentials are missing.")
        return False

    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"

    message = (
        "Network Anomaly Detector Alert\n"
        f"Attack: {attack_type}\n"
        f"Source IP: {source_ip}\n"
        f"Destination IP: {destination_ip}\n"
        f"Severity: {severity}"
    )

    try:
        response = requests.post(
            url,
            json={"chat_id": CHAT_ID, "text": message},
            timeout=10,
        )
        response.raise_for_status()

        if response.json().get("ok"):
            print("Telegram alert sent successfully.")
            return True

        print("Telegram API rejected the alert.")
        return False

    except requests.RequestException:
        print("Telegram notification failed; detector will continue.")
        return False
