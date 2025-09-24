# database.py
import sqlite3
import json
import os
import uuid
import time
from werkzeug.security import generate_password_hash

DB_FILE = "server_data.sqlite"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(script_dir):
    conn = get_db_connection()
    cursor = conn.cursor()

    # --- Check for users table and update schema if necessary (migration) ---
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    if cursor.fetchone():
        try:
            cursor.execute("SELECT email FROM users LIMIT 1")
        except sqlite3.OperationalError:
            print("INFO: Older database schema detected. Adding new profile columns to 'users' table...")
            cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
            cursor.execute("ALTER TABLE users ADD COLUMN phone_number TEXT")
            cursor.execute("ALTER TABLE users ADD COLUMN dob TEXT")
            cursor.execute("ALTER TABLE users ADD COLUMN profile_picture_path TEXT")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email)")
            print("✅ 'users' table schema updated.")
    else:
        # --- Create all tables from scratch if database is new ---
        print("INFO: Database not found. Initializing new database...")
        cursor.execute('CREATE TABLE companies (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE)')
        
        cursor.execute('''
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            company_id TEXT NOT NULL,
            role TEXT NOT NULL,
            phone_number TEXT,
            dob TEXT,
            profile_picture_path TEXT,
            FOREIGN KEY (company_id) REFERENCES companies (id),
            UNIQUE (username, company_id)
        )''')

        cursor.execute('''
        CREATE TABLE printers (
            id TEXT PRIMARY KEY, company_id TEXT NOT NULL, brand TEXT, model TEXT, setup_cost REAL,
            maintenance_cost REAL, lifetime_years INTEGER, power_w REAL, price_kwh REAL,
            buffer_factor REAL, uptime_percent REAL, FOREIGN KEY (company_id) REFERENCES companies (id)
        )''')
        cursor.execute('''
        CREATE TABLE filaments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL, material TEXT NOT NULL,
            brand TEXT NOT NULL, price REAL, stock_g REAL, efficiency_factor REAL,
            FOREIGN KEY (company_id) REFERENCES companies (id), UNIQUE (company_id, material, brand)
        )''')
        print("✅ Core database tables created successfully.")

        # --- Create default data for a new installation ---
        print("INFO: Creating default company and data.")
        default_company_id = "fabraforma_default"
        default_password_hash = generate_password_hash("password")

        cursor.execute("INSERT INTO companies (id, name) VALUES (?, ?)", (default_company_id, "FabraForma"))
        
        default_email = f"admin@{default_company_id}.com"
        cursor.execute("INSERT INTO users (id, username, email, password_hash, company_id, role) VALUES (?, ?, ?, ?, ?, ?)",
                       (str(uuid.uuid4()), "admin", default_email, default_password_hash, default_company_id, "admin"))
        print(f"  -> Created default admin user (login with email: {default_email} and password: password).")

        cursor.execute("""
            INSERT INTO printers (id, company_id, brand, model, setup_cost, maintenance_cost, lifetime_years, power_w, price_kwh, buffer_factor, uptime_percent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (str(time.time()), default_company_id, "Bambu Lab", "P1S", 70000, 5000, 5, 300, 8.0, 1.0, 50))
        print("  -> Created default printer.")

        default_filaments = [
            (default_company_id, "PLA", "Generic", 1200, 1000, 1.0),
            (default_company_id, "PETG", "Generic", 1400, 1000, 1.0)
        ]
        cursor.executemany("""
            INSERT INTO filaments (company_id, material, brand, price, stock_g, efficiency_factor)
            VALUES (?, ?, ?, ?, ?, ?)""", default_filaments)
        print("  -> Created default filaments.")

    # --- NEW: Create the auth_tokens table if it doesn't exist ---
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_tokens';")
    if not cursor.fetchone():
        print("INFO: Creating 'auth_tokens' table for 'Remember Me' functionality...")
        cursor.execute('''
        CREATE TABLE auth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        print("✅ 'auth_tokens' table created.")

    conn.commit()
    conn.close()
    print("✅ Database initialization/check complete.")
