# net_analyzer.py — VaultX Ultra (military-grade darknet scanner)

import os, json, asyncio, time, aiohttp, aiosqlite
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# ───── Configuration ─────
VAULT          = Path("/data/vaultx/net_analyzer")
DB_FILE        = VAULT / "leaks.db"
KEYFILE        = VAULT / ".enc.key"
SCAN_FULL      = 600       # seconds if UI is active
SCAN_IDLE      = 7200      # seconds in background
NOTIFY_EVERY   = timedelta(days=2)

HIBP_URL       = "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=true"
LEAKCHECK_URL  = "https://leakcheck.net/api/public?email={}"
DEHASHED_URL   = "https://api.dehashed.com/search?query=email=\"{}\"&size=5"
AHMIA_URL      = "http://ahmia.fi/search/?q={}"
TOR_SOCKS      = "socks5://127.0.0.1:9050"

# ───── Init Vault and Encryption ─────
def load_key():
    VAULT.mkdir(parents=True, exist_ok=True)
    if KEYFILE.exists():
        return KEYFILE.read_bytes()
    key = Fernet.generate_key()
    KEYFILE.write_bytes(key)
    return key

FERNET = Fernet(load_key())

async def init_db():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS leaks (
                id INTEGER PRIMARY KEY,
                email TEXT,
                service TEXT,
                url TEXT,
                breach_date TEXT,
                enc_blob BLOB,
                first_seen TEXT
            )
        """)
        await db.commit()

asyncio.run(init_db())

# ───── Core Daemon Class ─────
class NetAnalyzer:
    def __init__(self):
        self.email = None
        self.last_notification = datetime.utcnow() - NOTIFY_EVERY

    async def set_email(self, email: str):
        self.email = email.strip().lower()
        await self.full_scan()

    def ui_active(self) -> bool:
        flag = VAULT / ".ui_active"
        return flag.exists() and time.time() - flag.stat().st_mtime < 300

    async def loop(self):
        while True:
            interval = SCAN_FULL if self.ui_active() else SCAN_IDLE
            await asyncio.sleep(interval)
            if self.email:
                await self.full_scan()

    async def full_scan(self):
        results = []
        async with aiohttp.ClientSession() as session:
            results += await self.scan_hibp(session)
            results += await self.scan_leakcheck(session)
            results += await self.scan_dehashed(session)
            results += await self.scan_ahmia(session)

        new_leaks = await self.store_if_new(results)
        if new_leaks:
            await self.notify_flutter(new_leaks)

    # ───── Breach Sources ─────
    async def scan_hibp(self, session):
        try:
            async with session.get(HIBP_URL.format(self.email), headers={"User-Agent": "VaultX"}) as r:
                if r.status == 200:
                    breaches = await r.json()
                    return [dict(service=b["Name"], url="https://haveibeenpwned.com/" + b["Name"], breach_date=b["BreachDate"]) for b in breaches]
        except: pass
        return []

    async def scan_leakcheck(self, session):
        try:
            async with session.get(LEAKCHECK_URL.format(self.email)) as r:
                data = await r.json()
                return [dict(service=i["source"], url=i["line"], breach_date="") for i in data.get("result", [])]
        except: return []

    async def scan_dehashed(self, session):
        try:
            auth = aiohttp.BasicAuth("guest", "guest")
            async with session.get(DEHASHED_URL.format(self.email), auth=auth) as r:
                data = await r.json()
                return [dict(service="Dehashed", url=i.get("password") or "", breach_date="") for i in data.get("entries", [])]
        except: return []

    async def scan_ahmia(self, session):
        try:
            async with session.get(AHMIA_URL.format(self.email), proxy=TOR_SOCKS, timeout=30) as r:
                html = await r.text()
                hits = [ln for ln in html.split("\n") if ".onion" in ln]
                return [dict(service="DarkWeb", url=ln.strip(), breach_date="") for ln in hits[:10]]
        except: return []

    # ───── Store Only New Results ─────
    async def store_if_new(self, leaks: list):
        if not leaks: return []
        new_leaks = []
        async with aiosqlite.connect(DB_FILE) as db:
            for leak in leaks:
                row = await db.execute_fetchone(
                    "SELECT id FROM leaks WHERE email=? AND service=? AND url=?",
                    (self.email, leak["service"], leak["url"])
                )
                if row: continue
                enc_blob = FERNET.encrypt(json.dumps(leak).encode())
                await db.execute("""
                    INSERT INTO leaks(email,service,url,breach_date,enc_blob,first_seen)
                    VALUES(?,?,?,?,?,?)
                """, (self.email, leak["service"], leak["url"], leak["breach_date"], enc_blob, datetime.utcnow().isoformat()))
                new_leaks.append(leak)
            await db.commit()
        return new_leaks

    async def notify_flutter(self, leaks: list):
        if not self.ui_active() and datetime.utcnow() - self.last_notification < NOTIFY_EVERY:
            return
        self.last_notification = datetime.utcnow()
        print(f"[VaultX-Net] New leaks found for {self.email}:")
        for l in leaks:
            print("  → {service}: {url}".format(**l))
        # TODO: Actual Flutter push notification here

# Launch is handled by main.py
