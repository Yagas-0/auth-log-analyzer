"""Точка входа.

python main.py                     - SQLite: загрузка логов и отчёт
python main.py --backend redis     - тот же анализ через Redis (или JSON)
python main.py --log other.log --threshold 5
python main.py --from "2026-11-03 14:00:00" --to "2026-11-03 14:05:00"
"""
import argparse
from contextlib import closing
from datetime import datetime

import analyzer
import database
import nosql

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def parse_args():
    parser = argparse.ArgumentParser(description="Анализ лога авторизации")
    parser.add_argument("--log", default=database.LOG_FILE,
                        help="путь к файлу лога (по умолчанию auth.log)")
    parser.add_argument("--threshold", type=int, default=3,
                        help="IP с числом неудач больше этого значения подозрительные")
    parser.add_argument("--backend", choices=["sqlite", "redis"], default="sqlite")
    parser.add_argument("--from", dest="start",
                        help="начало интервала, формат 'ГГГГ-ММ-ДД ЧЧ:ММ:СС'")
    parser.add_argument("--to", dest="end", help="конец интервала, тот же формат")
    args = parser.parse_args()
    if bool(args.start) != bool(args.end):
        parser.error("--from и --to нужно указывать вместе")
    if args.start and args.end:
        try:
            start = datetime.strptime(args.start, DATETIME_FORMAT)
            end = datetime.strptime(args.end, DATETIME_FORMAT)
        except ValueError:
            parser.error("--from и --to должны иметь формат 'ГГГГ-ММ-ДД ЧЧ:ММ:СС'")
        if start > end:
            parser.error("--from не может быть позже --to")
    if args.threshold < 0:
        parser.error("--threshold не может быть отрицательным")
    return args


def main():
    args = parse_args()

    if args.backend == "redis":
        nosql.run_nosql_analysis(args.log, args.threshold, args.start, args.end)
        return

    with closing(database.get_connection()) as conn:
        database.create_database(conn)
        loaded, skipped = database.load_logs(conn, args.log)
        print(f"Загружено записей: {loaded}, пропущено: {skipped}")
        if loaded == 0:
            print("Анализировать нечего: проверьте путь к файлу и формат строк")
            return
        analyzer.print_report(conn, args.threshold, args.start, args.end)


if __name__ == "__main__":
    main()
