from database import(
	initialize_database,
	save_alert,
	get_alerts,
)

# MAKE sure the database table exists.
initialize_database()

# Insert one test alert.

save_alert(
	"192.0.2.10",
	"192.0.2.20",
	"Possible SYN flood",
	"High",
)

# retrive saved alerts.

alerts = get_alerts()

print("Total alerts retrived:", len(alerts))
print("Latest alert:",alerts[0])
