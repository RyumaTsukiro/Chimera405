# modules/database.py
import sqlite3, logging
from datetime import datetime

DB_FILE = "chimera405.db"
logger = logging.getLogger(__name__)

def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS analysis_history (id INTEGER PRIMARY KEY, target_type TEXT, target_identifier TEXT, risk_level TEXT, score INTEGER, report_text TEXT, timestamp DATETIME)')
    cursor.execute('CREATE TABLE IF NOT EXISTS user_reports (id INTEGER PRIMARY KEY, contract_address TEXT UNIQUE, reason TEXT, reported_by TEXT, timestamp DATETIME)')
    conn.commit()
    conn.close()
    logger.info("Database berhasil disiapkan.")

def add_analysis_to_history(target_type, target_identifier, risk_level, score, report_text):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("INSERT INTO analysis_history (target_type, target_identifier, risk_level, score, report_text, timestamp) VALUES (?, ?, ?, ?, ?, ?)", (target_type, target_identifier, risk_level, score, report_text, datetime.now()))
    conn.commit()
    conn.close()

def get_history(limit=10):
    conn = sqlite3.connect(DB_FILE)
    history = conn.execute("SELECT timestamp, risk_level, target_type, target_identifier FROM analysis_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return history

def add_report(contract_address, reason, user):
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute("INSERT INTO user_reports (contract_address, reason, reported_by, timestamp) VALUES (?, ?, ?, ?)", (contract_address, reason, user, datetime.now()))
        conn.commit()
        return True
    except sqlite3.IntegrityError: return False
    finally: conn.close()

def check_reported_status(contract_address):
    conn = sqlite3.connect(DB_FILE)
    report = conn.execute("SELECT reason, reported_by FROM user_reports WHERE contract_address = ?", (contract_address,)).fetchone()
    conn.close()
    return report
