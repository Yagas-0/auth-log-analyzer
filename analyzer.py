"""SQL-анализ загруженных логов."""


def analyze_failed_ips(conn):
    """Количество неудачных входов для каждого IP."""
    return conn.execute("""
        SELECT ip, COUNT(*) AS failures
        FROM auth_events
        WHERE result = 'failure'
        GROUP BY ip
        ORDER BY failures DESC
    """).fetchall()


def find_suspicious_ips(conn, threshold=3):
    """IP, у которых неудач больше порога."""
    return conn.execute("""
        SELECT ip, COUNT(*) AS failures
        FROM auth_events
        WHERE result = 'failure'
        GROUP BY ip
        HAVING COUNT(*) > ?
        ORDER BY failures DESC
    """, (threshold,)).fetchall()


def find_spraying_ips(conn, min_users=3):
    """IP, с которых пробовали много разных логинов."""
    return conn.execute("""
        SELECT ip, COUNT(DISTINCT username) AS users, COUNT(*) AS failures
        FROM auth_events
        WHERE result = 'failure'
        GROUP BY ip
        HAVING COUNT(DISTINCT username) >= ?
        ORDER BY users DESC, failures DESC
    """, (min_users,)).fetchall()


def top_failed_users(conn, limit=5):
    """Пользователи с наибольшим числом неудач."""
    return conn.execute("""
        SELECT username, COUNT(*) AS failures
        FROM auth_events
        WHERE result = 'failure'
        GROUP BY username
        ORDER BY failures DESC, username
        LIMIT ?
    """, (limit,)).fetchall()


def events_between(conn, start, end):
    """Записи за промежуток времени в формате ISO."""
    return conn.execute("""
        SELECT ts, username, ip, result
        FROM auth_events
        WHERE ts BETWEEN ? AND ?
        ORDER BY ts
    """, (start, end)).fetchall()


def users_with_both_results(conn):
    """Пользователи, у которых были и успехи, и неудачи."""
    return conn.execute("""
        SELECT username
        FROM auth_events
        GROUP BY username
        HAVING COUNT(DISTINCT result) = 2
        ORDER BY username
    """).fetchall()


def failures_with_roles_inner(conn):
    """Неудачи только известных пользователей, для которых задана роль."""
    return conn.execute("""
        SELECT e.username, u.role, COUNT(*) AS failures
        FROM auth_events e
        INNER JOIN users u ON u.username = e.username
        WHERE e.result = 'failure'
        GROUP BY e.username, u.role
        ORDER BY failures DESC, e.username
    """).fetchall()


def failures_with_roles_left(conn):
    """Неудачи всех пользователей; неизвестные роли помечаются как unknown."""
    return conn.execute("""
        SELECT e.username, COALESCE(u.role, 'unknown') AS role, COUNT(*) AS failures
        FROM auth_events e
        LEFT JOIN users u ON u.username = e.username
        WHERE e.result = 'failure'
        GROUP BY e.username, u.role
        ORDER BY failures DESC, e.username
    """).fetchall()


def print_table(title, rows, headers):
    print(f"\n=== {title} ===")
    if not rows:
        print("(нет данных)")
        return
    print(" | ".join(headers))
    print("-" * 40)
    for row in rows:
        print(" | ".join(str(value) for value in row))


def print_report(conn, threshold=3, start=None, end=None):
    """Печатает полный отчёт; интервал времени необязателен."""
    total = conn.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]
    failed = conn.execute(
        "SELECT COUNT(*) FROM auth_events WHERE result = 'failure'").fetchone()[0]
    print("ОТЧЁТ ПО ЛОГАМ АВТОРИЗАЦИИ")
    print(f"Всего записей: {total}, неудачных: {failed}")

    print_table("Неудачи по IP", analyze_failed_ips(conn), ["IP", "неудач"])
    print_table(f"Подозрительные IP (> {threshold} неудач)",
                find_suspicious_ips(conn, threshold), ["IP", "неудач"])
    print_table("Перебор логинов (3+ разных имени с одного IP)",
                find_spraying_ips(conn), ["IP", "логинов", "неудач"])
    print_table("Топ-5 пользователей по неудачам",
                top_failed_users(conn), ["пользователь", "неудач"])
    if start and end:
        print_table(f"Записи с {start} до {end}",
                    events_between(conn, start, end),
                    ["время", "пользователь", "IP", "результат"])
    print_table("Пользователи и с успехами, и с неудачами",
                users_with_both_results(conn), ["пользователь"])
    print_table("INNER JOIN: неудачи известных пользователей",
                failures_with_roles_inner(conn), ["пользователь", "роль", "неудач"])
    print_table("LEFT JOIN: неудачи всех (неизвестные помечены)",
                failures_with_roles_left(conn), ["пользователь", "роль", "неудач"])
