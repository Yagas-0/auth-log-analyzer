from datetime import datetime

import pytest

import analyzer
import database
import nosql


def test_parse_line_accepts_valid_ipv4_and_ipv6():
    assert database.parse_line("2026-11-03 14:00:00, alice, 192.0.2.1, failure\n") == (
        "2026-11-03 14:00:00", "alice", "192.0.2.1", "failure"
    )
    assert database.parse_line("2026-11-03 14:00:00,bob,2001:db8::1,success") == (
        "2026-11-03 14:00:00", "bob", "2001:db8::1", "success"
    )


@pytest.mark.parametrize("line", [
    "not-a-date,alice,192.0.2.1,failure",
    "2026-11-03 14:00:00,alice,not-an-ip,failure",
    "2026-11-03 14:00:00,,192.0.2.1,failure",
    "2026-11-03 14:00:00,alice,192.0.2.1,unknown",
    "too,few,fields",
])
def test_parse_line_rejects_invalid_rows(line):
    with pytest.raises(ValueError):
        database.parse_line(line)


def test_load_logs_skips_invalid_rows_and_replaces_existing_events(tmp_path):
    log = tmp_path / "input.log"
    log.write_text(
        "2026-11-03 14:00:00,alice,192.0.2.1,failure\n"
        "invalid,row\n"
        "2026-11-03 14:00:01,bob,192.0.2.2,success\n",
        encoding="utf-8",
    )
    conn = database.get_connection(":memory:")
    database.create_database(conn)
    loaded, skipped = database.load_logs(conn, log)
    assert (loaded, skipped) == (2, 1)
    assert conn.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0] == 2
    conn.close()


def test_analyzer_failed_ip_counts():
    conn = database.get_connection(":memory:")
    database.create_database(conn)
    conn.executemany(
        "INSERT INTO auth_events (ts, username, ip, result) VALUES (?, ?, ?, ?)",
        [
            ("2026-11-03 14:00:00", "alice", "192.0.2.1", "failure"),
            ("2026-11-03 14:00:01", "alice", "192.0.2.1", "failure"),
            ("2026-11-03 14:00:02", "bob", "192.0.2.2", "success"),
        ],
    )
    assert analyzer.analyze_failed_ips(conn) == [("192.0.2.1", 2)]
    assert analyzer.find_suspicious_ips(conn, threshold=1) == [("192.0.2.1", 2)]
    conn.close()


def test_read_failures_filters_inclusive_period(tmp_path):
    log = tmp_path / "input.log"
    log.write_text(
        "2026-11-03 14:00:00,alice,192.0.2.1,failure\n"
        "2026-11-03 14:00:01,bob,192.0.2.2,success\n"
        "2026-11-03 14:00:02,carol,192.0.2.3,failure\n",
        encoding="utf-8",
    )
    assert nosql.read_failures(
        log, "2026-11-03 14:00:00", "2026-11-03 14:00:02"
    ) == ["192.0.2.1", "192.0.2.3"]


@pytest.mark.parametrize(("start", "end"), [
    ("2026-11-03 14:00:00", None),
    (None, "2026-11-03 14:00:00"),
    ("2026-11-03 14:01:00", "2026-11-03 14:00:00"),
])
def test_read_failures_rejects_invalid_period(tmp_path, start, end):
    log = tmp_path / "input.log"
    log.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        nosql.read_failures(log, start, end)


def test_analyze_with_redis_counts_using_fake_client():
    fakeredis = pytest.importorskip("fakeredis")
    client = fakeredis.FakeRedis(decode_responses=True)
    assert nosql.analyze_with_redis(
        ["192.0.2.1", "192.0.2.1", "192.0.2.2"], client
    ) == {"192.0.2.1": 2, "192.0.2.2": 1}
