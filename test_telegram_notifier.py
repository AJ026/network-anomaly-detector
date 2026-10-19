from telegram_notifier import send_telegram_alert

success = send_telegram_alert(
    "192.0.2.10",
    "192.0.2.20",
    "Telegram Integration Test",
    "High",
)

if success:
    print("Telegram notifier integration test passed.")
else:
    raise SystemExit("Telegram notifier integration test failed.")
