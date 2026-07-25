import sqlite3

connection = sqlite3.connect(
    "flowtrace.db",
    check_same_thread=False
)

cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    packet_count INTEGER,
    total_bytes INTEGER,
    duration REAL,
    state TEXT,
    capture_time TEXT
)
""")

connection.commit()


def save_flow(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    packet_count,
    total_bytes,
    duration,
    state,
    capture_time
):
    cursor.execute("""
    INSERT INTO flows (
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        packet_count,
        total_bytes,
        duration,
        state,
        capture_time
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        packet_count,
        total_bytes,
        duration,
        state,
        capture_time
    ))

    connection.commit()


def get_all_flows():
    cursor.execute("SELECT * FROM flows")
    return cursor.fetchall()