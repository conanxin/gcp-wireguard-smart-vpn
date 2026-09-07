#!/usr/bin/env python3
import datetime as dt
import os
import sqlite3
import subprocess

WG = "/usr/bin/wg"
IFACE = "wg0"
DB = "/var/lib/wg-traffic/usage.db"

CLIENTS = {
    "10.66.66.2/32": "windows",
    "10.66.66.3/32": "phone",
}

def read_peers():
    out = subprocess.check_output([WG, "show", IFACE, "dump"], text=True)
    lines = out.splitlines()
    peers = []
    for line in lines[1:]:
        f = line.split("\t")
        if len(f) < 8:
            continue
        pub, _psk, endpoint, allowed, latest, rx, tx, keepalive = f[:8]
        primary_allowed = allowed.split(",")[0]
        name = CLIENTS.get(primary_allowed, primary_allowed or pub[:8])
        peers.append({
            "pub": pub,
            "name": name,
            "allowed": primary_allowed,
            "latest": int(latest or 0),
            "rx": int(rx),
            "tx": int(tx),
        })
    return peers

def delta(current, previous):
    if previous is None:
        return current
    if current >= previous:
        return current - previous
    return current

def main():
    os.makedirs(os.path.dirname(DB), mode=0o755, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    day = now.date().isoformat()
    peers = read_peers()

    con = sqlite3.connect(DB)
    try:
        con.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS peer_state (
            pub TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            allowed_ip TEXT NOT NULL,
            last_rx INTEGER NOT NULL,
            last_tx INTEGER NOT NULL,
            latest_handshake INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS daily_usage (
            day TEXT NOT NULL,
            name TEXT NOT NULL,
            rx INTEGER NOT NULL DEFAULT 0,
            tx INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (day, name)
        );
        CREATE TABLE IF NOT EXISTS total_usage (
            name TEXT PRIMARY KEY,
            rx INTEGER NOT NULL DEFAULT 0,
            tx INTEGER NOT NULL DEFAULT 0
        );
        """)
        total_rx_delta = 0
        total_tx_delta = 0

        with con:
            for p in peers:
                row = con.execute(
                    "SELECT last_rx, last_tx FROM peer_state WHERE pub = ?",
                    (p["pub"],),
                ).fetchone()
                prev_rx = row[0] if row else None
                prev_tx = row[1] if row else None
                drx = delta(p["rx"], prev_rx)
                dtx = delta(p["tx"], prev_tx)
                total_rx_delta += drx
                total_tx_delta += dtx

                con.execute(
                    """INSERT INTO daily_usage(day, name, rx, tx)
                       VALUES(?, ?, ?, ?)
                       ON CONFLICT(day, name) DO UPDATE SET
                         rx = rx + excluded.rx,
                         tx = tx + excluded.tx""",
                    (day, p["name"], drx, dtx),
                )
                con.execute(
                    """INSERT INTO total_usage(name, rx, tx)
                       VALUES(?, ?, ?)
                       ON CONFLICT(name) DO UPDATE SET
                         rx = rx + excluded.rx,
                         tx = tx + excluded.tx""",
                    (p["name"], drx, dtx),
                )
                con.execute(
                    """INSERT INTO peer_state(
                         pub, name, allowed_ip, last_rx, last_tx,
                         latest_handshake, updated_at
                       ) VALUES(?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(pub) DO UPDATE SET
                         name = excluded.name,
                         allowed_ip = excluded.allowed_ip,
                         last_rx = excluded.last_rx,
                         last_tx = excluded.last_tx,
                         latest_handshake = excluded.latest_handshake,
                         updated_at = excluded.updated_at""",
                    (
                        p["pub"], p["name"], p["allowed"], p["rx"], p["tx"],
                        p["latest"], now.isoformat(),
                    ),
                )
        print(
            f"COLLECTED peers={len(peers)} "
            f"upload_delta={total_rx_delta} download_delta={total_tx_delta}"
        )
    finally:
        con.close()

if __name__ == "__main__":
    main()
