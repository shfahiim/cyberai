import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "benchmark.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            description TEXT NOT NULL
        );

        DELETE FROM users;
        DELETE FROM invoices;

        INSERT INTO users (id, email, role) VALUES
            (1, 'alice@example.test', 'user'),
            (2, 'bob@example.test', 'admin');

        INSERT INTO invoices (id, user_id, amount, description) VALUES
            (100, 1, 1500, 'Alice private invoice'),
            (200, 2, 9900, 'Bob admin invoice');
        """
    )
    conn.commit()
    conn.close()
