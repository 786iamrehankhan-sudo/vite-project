import sqlite3

# Connect to database
conn = sqlite3.connect('threat_protection.db')
cursor = conn.cursor()

# View all users
print("="*50)
print("USERS IN DATABASE:")
print("="*50)
cursor.execute("SELECT id, email, is_email_valid, threat_score, threat_details, created_at FROM users")
users = cursor.fetchall()
for user in users:
    print(f"ID: {user[0]}")
    print(f"Email: {user[1]}")
    print(f"Valid: {'✅' if user[2] else '❌'}")
    print(f"Threat Score: {user[3]}")
    print(f"Details: {user[4]}")
    print(f"Created: {user[5]}")
    print("-"*30)

# View threat logs
print("\n" + "="*50)
print("THREAT LOGS:")
print("="*50)
cursor.execute("SELECT email, threat_type, threat_score, details, timestamp FROM threat_logs")
logs = cursor.fetchall()
for log in logs:
    print(f"Email: {log[0]}")
    print(f"Type: {log[1]}")
    print(f"Score: {log[2]}")
    print(f"Details: {log[3]}")
    print(f"Time: {log[4]}")
    print("-"*30)

conn.close()