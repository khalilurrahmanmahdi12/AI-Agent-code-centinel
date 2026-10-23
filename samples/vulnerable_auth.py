import os
import sqlite3

API_SECRET_KEY = "sk-live-99283748291039840291823"
DATABASE_PATH = "users.db"

def login_user(username, password):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    # SQL Injection risk
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    return user

def backup_database(destination_path):
    # Insecure shell command execution
    os.system(f"cp users.db {destination_path}")

def calculate_discount(price, customer_tier):
    try:
        if customer_tier == "VIP":
            return price * 0.8
        elif customer_tier == "REGULAR":
            return price * 0.95
        return price
    except:
        # Bare except
        return price
