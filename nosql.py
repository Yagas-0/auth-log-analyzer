"""Тот же анализ через Redis; если Redis недоступен, через JSON-файл."""
import json
from collections import Counter
from datetime import datetime

from database import LOG_FILE, parse_line

# Отдельное пространство имён не затрагивает ключи других приложений в Redis.
KEY_PREFIX = "auth-log-analyzer:failed:"
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def read_failures(path=LOG_FILE, start=None, end=None):
    """Возвращает IP неудачных попыток, при необходимости ограничивая период."""
    ips = []
    start_dt = datetime.strptime(start, DATETIME_FORMAT) if start else None
    end_dt = datetime.strptime(end, DATETIME_FORMAT) if end else None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                ts, username, ip, result = parse_line(line)
            except ValueError:
                continue
            event_dt = datetime.strptime(ts, DATETIME_FORMAT)
            if start_dt and not start_dt <= event_dt <= end_dt:
                continue
            if result == "failure":
                ips.append(ip)
    return ips


def analyze_with_redis(ips, client=None):
    """Считает неудачи через INCR в отдельном пространстве ключей Redis."""
    if client is None:
        import redis

        client = redis.Redis(host="localhost", port=6379, decode_responses=True)
    client.ping()

    old_keys = list(client.scan_iter(f"{KEY_PREFIX}*"))
    if old_keys:
        client.delete(*old_keys)

    pipe = client.pipeline()
    for ip in ips:
        pipe.incr(f"{KEY_PREFIX}{ip}")
    pipe.execute()

    keys = list(client.scan_iter(f"{KEY_PREFIX}*"))
    values = client.mget(keys) if keys else []
    return {key[len(KEY_PREFIX):]: int(value) for key, value in zip(keys, values)}


def analyze_with_json(ips, out_file="failed_counts.json"):
    counts = Counter(ips)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(counts, f, indent=2)
    return dict(counts)


def _redis_errors():
    """Какие ошибки считаем «Redis недоступен»: нет библиотеки или соединения."""
    try:
        import redis
    except ImportError:
        return (ImportError,)
    return (ImportError, redis.exceptions.ConnectionError)


def run_nosql_analysis(path=LOG_FILE, threshold=3, start=None, end=None):
    try:
        ips = read_failures(path, start, end)
    except FileNotFoundError:
        print(f"Файл {path} не найден")
        return
    try:
        counts = analyze_with_redis(ips)
        source = "Redis"
    except _redis_errors() as error:
        print(f"Redis недоступен ({type(error).__name__}), используем JSON-файл")
        counts = analyze_with_json(ips)
        source = "JSON"
    period = f" за период {start} — {end}" if start and end else ""
    print(f"\n=== Анализ через {source}: IP с > {threshold} неудач{period} ===")
    for ip, count in sorted(counts.items(), key=lambda x: -x[1]):
        if count > threshold:
            print(f"{ip}: {count}")
