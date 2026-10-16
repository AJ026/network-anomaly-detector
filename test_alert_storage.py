
from database import initialize_database, save_alert, get_alerts

initialize_database()

# Insert a clearly identifiable test alert.
save_alert(
    "192.0.2.10",
    "192.0.2.20",
    "Database Integration Test",
    "High"
)

alerts = get_alerts()

if alerts:
    print("Latest saved alert:")
    print(alerts[0])

    assert alerts[0][2] == "192.0.2.10"
    assert alerts[0][3] == "192.0.2.20"
    assert alerts[0][4] == "Database Integration Test"

    print("Database alert storage test passed!")
else:
    print("No alerts found.")
