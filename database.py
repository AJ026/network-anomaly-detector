import sqlite3
from datetime import datetime, timezone

DATABASE_NAME = "alerts.db"

def initialize_database():
    connection = sqlite3.connect(DATABASE_NAME)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT not NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()

def save_alert(source_ip,destination_ip,attack_type,severity):
    timestamp =datetime.now(timezone.utc).isoformat()

    connection= sqlite3.connect(DATABASE_NAME)

    connection.execute("""
        INSERT INTO alerts (
            timestamp, source_ip, destination_ip,
            attack_type, severity
        )
        VALUES(?,?,?,?,?)
    """, (
        timestamp,
        source_ip,
        destination_ip,
        attack_type,
        severity
    ))

    connection.commit()
    connection.close()

def get_alerts():
    connection = sqlite3.connect(DATABASE_NAME)

    rows = connection.execute("""
        SELECT id, timestamp, source_ip, destination_ip, attack_type,
            severity
        FROM alerts
        ORDER BY id DESC
    """).fetchall()

    connection.close()
    return rows

if __name__ == "__main__":
    initialize_database()
    print("Database and alerts table are ready.")
