"""Работа с SQLite: создание таблиц, проверка и загрузка логов."""
import ipaddress
import sqlite3
from datetime import datetime

DB_NAME = "auth.db"
LOG_FILE = "auth.log"


def get_connection(db_name=DB_NAME):
    """Открывает соединение с базой (файл создастся сам, если его нет)."""
    return sqlite3.connect(db_name)


def create_database(conn):
    """Создаёт таблицы events и users, если их ещё нет."""
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_events (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       TEXT NOT NULL,
                username TEXT NOT NULL,
                ip       TEXT NOT NULL,
                result   TEXT NOT NULL CHECK (result IN ('success', 'failure'))
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_result_ip
            ON auth_events (result, ip)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                role     TEXT NOT NULL
            )
        """)
        known = [("alice", "analyst"), ("bob", "developer"),
                 ("carol", "manager"), ("dave", "developer"),
                 ("eve", "analyst"), ("admin", "administrator")]
        for username, role in known:
            conn.execute(
                "INSERT OR IGNORE INTO users (username, role) VALUES (?, ?)",
                (username, role),
            )


def parse_line(line):
    """Проверяет одну строку лога. При ошибке бросает ValueError."""
    parts = [p.strip() for p in line.strip().split(",")]
    if len(parts) != 4:
        raise ValueError(f"ожидалось 4 поля, найдено {len(parts)}")
    ts, username, ip, result = parts
    datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    ipaddress.ip_address(ip)
    if not username:
        raise ValueError("пустое имя пользователя")
    if result not in ("success", "failure"):
        raise ValueError(f"неизвестный результат: {result!r}")
    return ts, username, ip, result


def load_logs(conn, path=LOG_FILE):
    """Загружает корректные строки; при новом запуске заменяет прежний набор событий."""
    loaded = skipped = 0
    try:
        with open(path, encoding="utf-8") as f, conn:
            conn.execute("DELETE FROM auth_events")
            for number, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    row = parse_line(line)
                except ValueError as error:
                    print(f"Строка {number} пропущена: {error}")
                    skipped += 1
                    continue
                conn.execute(
                    "INSERT INTO auth_events (ts, username, ip, result) "
                    "VALUES (?, ?, ?, ?)",
                    row,
                )
                loaded += 1
    except FileNotFoundError:
        print(f"Файл {path} не найден")
    except sqlite3.Error as error:
        # Контекстный менеджер откатил всю загрузку, поэтому строк фактически не загружено.
        print(f"Ошибка базы данных: {error}")
        loaded = 0
    return loaded, skipped
