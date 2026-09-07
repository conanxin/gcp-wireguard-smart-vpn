#!/usr/bin/env python3
import datetime as dt
import sqlite3
import subprocess

DB = "/var/lib/wg-traffic/usage.db"
WG = "/usr/bin/wg"
IFACE = "wg0"
MONTHLY_EGRESS_REFERENCE_GIB = 200

CLIENTS = {
    "10.66.66.2/32": "windows",
    "10.66.66.3/32": "phone",
}

def human_bytes(value):
    value = int(value or 0)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.2f} {unit}"
        n /= 1024

def human_age(seconds):
    if seconds is None:
        return "never"
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"

def read_peer_status():
    out = subprocess.check_output([WG, "show", IFACE, "dump"], text=True)
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    peers = {}
    for line in out.splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        _, _, endpoint, allowed, latest, rx, tx, _ = fields[:8]
        allowed_ip = allowed.split(",")[0]
        name = CLIENTS.get(allowed_ip, allowed_ip)
        latest = int(latest or 0)
        age = None if latest == 0 else now - latest
        if latest == 0:
            state = "NEVER"
        elif age <= 180:
            state = "ONLINE"
        else:
            state = "IDLE"
        peers[name] = {
            "state": state,
            "age": age,
            "endpoint": endpoint or "-",
            "session_rx": int(rx),
            "session_tx": int(tx),
        }
    return peers

def query_usage():
    now = dt.datetime.now(dt.timezone.utc)
    today = now.date().isoformat()
    month = today[:7]
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        names = set()
        total = {}
        daily = {}
        monthly = {}

        for name, rx, tx in con.execute(
            "SELECT name,rx,tx FROM total_usage ORDER BY name"
        ):
            names.add(name)
            total[name] = (int(rx), int(tx))

        for name, rx, tx in con.execute(
            "SELECT name,rx,tx FROM daily_usage WHERE day=? ORDER BY name",
            (today,),
        ):
            names.add(name)
            daily[name] = (int(rx), int(tx))

        for name, rx, tx in con.execute(
            """
            SELECT name,COALESCE(SUM(rx),0),COALESCE(SUM(tx),0)
            FROM daily_usage
            WHERE substr(day,1,7)=?
            GROUP BY name
            ORDER BY name
            """,
            (month,),
        ):
            names.add(name)
            monthly[name] = (int(rx), int(tx))

        return sorted(names), daily, monthly, total, today, month
    finally:
        con.close()

def pair_total(pair):
    return int(pair[0]) + int(pair[1])

def sum_pairs(mapping):
    rx = sum(v[0] for v in mapping.values())
    tx = sum(v[1] for v in mapping.values())
    return rx, tx

def main():
    names, daily, monthly, total, today, month = query_usage()
    peers = read_peer_status()
    names = sorted(set(names) | set(peers))

    print("WireGuard VPN Traffic")
    print("=" * 78)
    print(f"UTC day: {today}    UTC month: {month}")
    print()
    print(f"{'CLIENT':<12} {'TODAY':>14} {'THIS MONTH':>14} {'ALL TIME':>14} {'STATUS':>10} {'HANDSHAKE':>12}")
    for name in names:
        d = daily.get(name, (0, 0))
        m = monthly.get(name, (0, 0))
        t = total.get(name, (0, 0))
        peer = peers.get(name, {"state": "UNKNOWN", "age": None})
        print(
            f"{name:<12} "
            f"{human_bytes(pair_total(d)):>14} "
            f"{human_bytes(pair_total(m)):>14} "
            f"{human_bytes(pair_total(t)):>14} "
            f"{peer['state']:>10} "
            f"{human_age(peer['age']):>12}"
        )

    d_rx, d_tx = sum_pairs(daily)
    m_rx, m_tx = sum_pairs(monthly)
    t_rx, t_tx = sum_pairs(total)

    print()
    print("Direction totals")
    print("-" * 78)
    print(f"{'':<12} {'TODAY':>14} {'THIS MONTH':>14} {'ALL TIME':>14}")
    print(f"{'UPLOAD':<12} {human_bytes(d_rx):>14} {human_bytes(m_rx):>14} {human_bytes(t_rx):>14}")
    print(f"{'DOWNLOAD':<12} {human_bytes(d_tx):>14} {human_bytes(m_tx):>14} {human_bytes(t_tx):>14}")
    print(f"{'TOTAL':<12} {human_bytes(d_rx+d_tx):>14} {human_bytes(m_rx+m_tx):>14} {human_bytes(t_rx+t_tx):>14}")

    quota_bytes = MONTHLY_EGRESS_REFERENCE_GIB * 1024**3
    pct = 0.0 if quota_bytes == 0 else (m_tx / quota_bytes) * 100
    filled = min(20, max(0, int(round(pct / 5))))
    bar = "#" * filled + "-" * (20 - filled)

    print()
    print("GCP monthly egress reference")
    print("-" * 78)
    print(
        f"WireGuard DOWNLOAD this month: {human_bytes(m_tx)} / "
        f"{MONTHLY_EGRESS_REFERENCE_GIB} GiB  [{bar}] {pct:.2f}%"
    )
    print()
    print("UPLOAD   = client -> VPN server")
    print("DOWNLOAD = VPN server -> client")
    print("Persistent totals come from /var/lib/wg-traffic/usage.db.")
    print("GCP egress figure is an approximation: it excludes other VM traffic and protocol overhead.")

if __name__ == "__main__":
    main()
