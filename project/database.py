import sqlite3
from datetime import datetime, timedelta


def init_db(db_file):
    con = sqlite3.connect("user.db")
    print("Database opened successfully")

    con.execute("""
                DROP TABLE IF EXISTS users
            """)

    con.execute("""
                DROP TABLE IF EXISTS mfatoken
            """)


    con.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    mfa_enabled INTEGER NOT NULL
                )
            """)

    con.execute("""
                CREATE TABLE mfatoken (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mfacode TEXT NOT NULL,
                    user TEXT NOT NULL,
                    mfatime TEXT NOT NULL
                )
            """)

    print("successfully create table")
    con.close()