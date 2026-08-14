#!/usr/bin/env python3
"""Generate realistic sample logs containing known attack patterns.

The point of this script is that the repo demos out of the box without anyone
shipping real (and therefore sensitive) log data. Every attack it plants is
labelled below, so the sample doubles as the fixture the README's expected
output is measured against.

Planted scenarios
-----------------
1. SSH brute force from 45.83.12.9, ending in a successful login  -> LS-001
2. Password spray from 185.220.101.45 across 12 accounts          -> LS-002
3. Impossible travel for 'j.okoro' (Doha -> Sao Paulo in 40 min)  -> LS-003
4. Off-hours root login at 03:47                                  -> LS-004
5. Post-compromise sudo: shadow read, auditd stop, history clear   -> LS-005
6. sqlmap + directory brute force from 196.52.43.87                -> LS-006
7. .env and .git probing that returns HTTP 200                     -> LS-007

Everything else is benign background traffic.

Usage::

    python scripts/generate_sample_logs.py --out data/
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 1337
HOST = "web-01"

BENIGN_USERS = ["deploy", "a.hassan", "j.okoro", "m.rahman", "backup", "svc_ci"]
SPRAY_USERS = [
    "admin", "administrator", "root", "test", "guest", "oracle",
    "postgres", "jenkins", "git", "ubuntu", "ftp", "webadmin",
]
INTERNAL_IPS = ["10.0.4.7", "10.0.4.19", "10.0.8.3", "192.168.10.22"]

BENIGN_PATHS = ["/", "/index.html", "/api/v1/health", "/static/app.css",
                "/static/app.js", "/favicon.ico", "/api/v1/orders", "/about"]
SCAN_PATHS = ["/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/administrator/",
              "/.git/config", "/.env", "/config.php.bak", "/backup.sql",
              "/actuator/env", "/cgi-bin/test.cgi", "/vendor/phpunit/phpunit.php",
              "/solr/admin/info/system", "/api/../../etc/passwd", "/xmlrpc.php",
              "/wp-content/plugins/revslider/temp/update_extract/rev.php",
              "/typo3/index.php", "/adminer.php", "/.aws/credentials"]

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
)


def syslog(ts: datetime, message: str, proc: str = "sshd", pid: int = 0) -> str:
    pid = pid or random.randint(1000, 30000)
    return f"{ts:%b %e %H:%M:%S} {HOST} {proc}[{pid}]: {message}"


def build_auth_log(base: datetime) -> list[str]:
    rng = random.Random(SEED)
    entries: list[tuple[datetime, str]] = []

    def add(ts: datetime, message: str, proc: str = "sshd", pid: int = 0) -> None:
        entries.append((ts, syslog(ts, message, proc, pid)))

    # --- Benign background: normal working-hours logins -------------------
    for day in range(3):
        for user in BENIGN_USERS[:4]:
            ts = base + timedelta(
                days=day, hours=rng.randint(8, 17), minutes=rng.randint(0, 59)
            )
            ip = rng.choice(INTERNAL_IPS)
            add(ts, f"Accepted publickey for {user} from {ip} port "
                    f"{rng.randint(40000, 60000)} ssh2")
            add(ts + timedelta(seconds=1),
                f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
            # Everyone fat-fingers a password now and then; keeps the data honest.
            if rng.random() < 0.3:
                add(ts - timedelta(seconds=rng.randint(5, 30)),
                    f"Failed password for {user} from {ip} port "
                    f"{rng.randint(40000, 60000)} ssh2")

    # --- 1. Brute force from 45.83.12.9, succeeding on 'root' -------------
    attack_ip = "45.83.12.9"
    attack_start = base + timedelta(days=1, hours=3, minutes=14)
    for i in range(64):
        ts = attack_start + timedelta(seconds=i * 4 + rng.randint(0, 2))
        user = rng.choice(["root", "admin", "root", "root"])
        if user == "admin":
            add(ts, f"Invalid user {user} from {attack_ip} port {50000 + i}")
            add(ts + timedelta(seconds=1),
                f"Failed password for invalid user {user} from {attack_ip} "
                f"port {50000 + i} ssh2")
        else:
            add(ts, f"Failed password for {user} from {attack_ip} "
                    f"port {50000 + i} ssh2")

    # 4 + 5: the break-in lands at 03:47, then covers its tracks.
    breach = attack_start + timedelta(minutes=33)
    add(breach, f"Accepted password for root from {attack_ip} port 51999 ssh2")
    add(breach + timedelta(seconds=1),
        "pam_unix(sshd:session): session opened for user root by (uid=0)")
    for offset, command in [
        (40, "/bin/cat /etc/shadow"),
        (95, "/usr/sbin/useradd -m -s /bin/bash svc_update"),
        (140, "/usr/bin/systemctl stop auditd"),
        (185, "/bin/bash -c history -c"),
        (220, "/usr/bin/tee -a /root/.ssh/authorized_keys"),
    ]:
        add(
            breach + timedelta(seconds=offset),
            f"root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND={command}",
            proc="sudo",
        )

    # --- 2. Password spray from 185.220.101.45 ----------------------------
    spray_ip = "185.220.101.45"
    spray_start = base + timedelta(days=2, hours=11, minutes=5)
    for i, user in enumerate(SPRAY_USERS):
        for attempt in range(2):
            ts = spray_start + timedelta(minutes=i * 2, seconds=attempt * 37)
            add(ts, f"Invalid user {user} from {spray_ip} port {40000 + i * 10 + attempt}")
            add(ts + timedelta(seconds=1),
                f"Failed password for invalid user {user} from {spray_ip} "
                f"port {40000 + i * 10 + attempt} ssh2")

    # --- 3. Impossible travel for j.okoro (Doha -> Sao Paulo, 40 min) -----
    travel_base = base + timedelta(days=2, hours=14)
    add(travel_base, "Accepted password for j.okoro from 212.83.44.18 port 43122 ssh2")
    add(travel_base + timedelta(minutes=40),
        "Accepted password for j.okoro from 191.96.77.204 port 51880 ssh2")

    # Benign long-haul move: London -> Singapore over 14h is flight-plausible.
    add(base + timedelta(days=1, hours=9),
        "Accepted publickey for m.rahman from 82.102.19.4 port 44001 ssh2")
    add(base + timedelta(days=1, hours=23),
        "Accepted publickey for m.rahman from 156.146.55.12 port 44210 ssh2")

    entries.sort(key=lambda item: item[0])
    return [line for _, line in entries]


def build_access_log(base: datetime) -> list[str]:
    rng = random.Random(SEED + 1)
    entries: list[tuple[datetime, str]] = []

    def add(ts: datetime, ip: str, method: str, path: str, status: int,
            size: int, agent: str) -> None:
        line = (
            f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
            f'{status} {size} "-" "{agent}"'
        )
        entries.append((ts, line))

    # Benign traffic across three days
    for day in range(3):
        for _ in range(120):
            ts = base + timedelta(
                days=day, hours=rng.randint(6, 22),
                minutes=rng.randint(0, 59), seconds=rng.randint(0, 59),
            )
            add(ts, f"129.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}",
                "GET", rng.choice(BENIGN_PATHS), rng.choice([200, 200, 200, 304]),
                rng.randint(200, 9000), BROWSER_UA)

    # --- 6. sqlmap + directory brute force from 196.52.43.87 --------------
    scanner_ip = "196.52.43.87"
    scan_start = base + timedelta(days=1, hours=2, minutes=41)
    for i, path in enumerate(SCAN_PATHS * 2):
        ts = scan_start + timedelta(seconds=i * 3)
        agent = "sqlmap/1.7.11#stable (https://sqlmap.org)" if i % 4 == 0 else "python-requests/2.31.0"
        add(ts, scanner_ip, "GET", path, 404, 162, agent)
    add(scan_start + timedelta(minutes=3), scanner_ip, "GET",
        "/api/v1/orders?id=1%27+UNION+SELECT+null%2Cversion%28%29--",
        500, 0, "sqlmap/1.7.11#stable (https://sqlmap.org)")

    # --- 7. .env / .git probing that actually succeeds ---------------------
    leak_ip = "89.248.165.72"
    leak_start = base + timedelta(days=2, hours=5, minutes=12)
    for i, (path, status, size) in enumerate([
        ("/.env", 200, 1834),
        ("/.git/config", 200, 412),
        ("/.git/HEAD", 200, 23),
        ("/config.php.bak", 404, 162),
        ("/.aws/credentials", 403, 162),
        ("/api/../../etc/passwd", 400, 162),
    ]):
        add(leak_start + timedelta(seconds=i * 11), leak_ip, "GET", path, status,
            size, "Go-http-client/2.0")

    entries.sort(key=lambda item: item[0])
    return [line for _, line in entries]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="data", help="Output directory")
    parser.add_argument("--start", default="2025-03-10", help="First day, YYYY-MM-DD")
    args = parser.parse_args()

    base = datetime.strptime(args.start, "%Y-%m-%d")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    auth_path = out_dir / "auth.log"
    access_path = out_dir / "access.log"
    auth_path.write_text("\n".join(build_auth_log(base)) + "\n", encoding="utf-8")
    access_path.write_text("\n".join(build_access_log(base)) + "\n", encoding="utf-8")

    print(f"Wrote {auth_path} ({len(auth_path.read_text().splitlines()):,} lines)")
    print(f"Wrote {access_path} ({len(access_path.read_text().splitlines()):,} lines)")


if __name__ == "__main__":
    main()
