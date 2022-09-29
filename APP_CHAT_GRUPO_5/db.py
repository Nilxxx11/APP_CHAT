import sqlite3
DATABASE_NAME = "database.sqlite"


def get_db():
    conn = sqlite3.connect(DATABASE_NAME)
    return conn


def create_tables():
    tables = [
        """CREATE TABLE USUARIOS (
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
username VARCHAR NOT NULL,
email VARCHAR NOT NULL,
password VARCHAR NOT NULL);
            """]
    db = get_db()
    cursor = db.cursor()
    for table in tables:
        cursor.execute(table)
