import asyncio, hashlib, hmac, ipaddress, json, os, re, secrets, smtplib, socket, sqlite3, ssl, threading, time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
import dns.resolver, httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

E = os.getenv
DB = E("DB_PATH", "csw.db"); SECURE = E("COOKIE_SECURE", "1") == "1"
INTERVAL = int(E("SCAN_INTERVAL_DAYS", "7")); CT = E("ENABLE_CT", "1") == "1"
PLANS = {"starter": 3, "agency": 10}
VN = "_csw-verify"
HDRS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
DOM = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
RES = dns.resolver.Resolver(); RES.lifetime = 5
SCHEMA = """
create table if not exists users(id integer primary key, email text unique not null, pw text not null, plan text not null default 'starter', is_admin int not null default 0, disabled int not null default 0, created text not null);
create table if not exists sessions(token text primary key, user_id integer not null references users(id) on delete cascade, expires real not null);
create table if not exists domains(id integer primary key, user_id integer not null references users(id) on delete cascade, name text not null, token text not null, verified int not null default 0, last_scan real, unique(user_id,name));
create table if not exists scans(id integer primary key, domain_id integer not null references domains(id) on delete cascade, ts real not null, result text not null, changes text not null);"""

@contextmanager
def tx():
    c = sqlite3.connect(DB, timeout=10); c.row_factory = sqlite3.Row; c.execute("pragma foreign_keys=on")
    try:
        yield c; c.commit()
    finally:
        c.close()

def iso(): return datetime.now(timezone.utc).isoformat()
def hash_pw(p):
    s = os.urandom(16); return s.hex() + "$" + hashlib.scrypt(p.encode(), salt=s, n=2**14, r=8, p=1, dklen=32).hex()
def check_pw(p, h):
    s, k = h.split("$"); return hmac.compare_digest(hashlib.scrypt(p.encode(), salt=bytes.fromhex(s), n=2**14, r=8, p=1, dklen=32).hex(), k)
DUMMY = hash_pw("dummy-password")

HITS = {}
def limit(key, n, per):
    t = time.time(); h = [x for x in HITS.get(key, []) if t - x < per]
    if len(h) >= n: raise HTTPException(429, "Too many attempts. Try again later.")
    h.append(t); HITS[key] = h
def ip(r): return r.client.host if r.client else "?"

# ---------- checks (all targets are verified domains; connections go to validated public IPs only) ----------
def addrs(host):
    out = []
    for t in ("A", "AAAA"):
        try: out += [a.address for a in RES.resolve(host, t)]
        except Exception: pass
    return out
def txt(n):
    try: return ["".join(x.decode() for x in a.strings) for a in RES.resolve(n, "TXT")]
    except Exception: return []
def http(ip_, host, port, tls):
    s = socket.create_connection((ip_, port), timeout=6)
    if tls: s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
    s.settimeout(6); s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ClientSiteWatch\r\nConnection: close\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        d = s.recv(4096)
        if not d: break
        buf += d
    cert = s.getpeercert() if tls else None; s.close()
    head = buf.split(b"\r\n\r\n")[0].decode("latin1").split("\r\n")
    return head[0], {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in head[1:] if ":" in l)}, cert
def rdap_days(d):
    try:
        j = httpx.get("https://rdap.org/domain/" + d, timeout=10, follow_redirects=True).json()
        e = [x["eventDate"] for x in j["events"] if x["eventAction"] == "expiration"][0]
        return (datetime.fromisoformat(e.replace("Z", "+00:00")) - datetime.now(timezone.utc)).days
    except Exception: return None
def ct_subs(d):
    try:
        j = httpx.get("https://crt.sh/", params={"q": "%." + d, "output": "json"}, timeout=25).json()
        return {n.strip().lower() for r in j for n in r["name_value"].split("\n") if n.lower().endswith("." + d) and "*" not in n}
    except Exception: return set()
def dangling(s):
    try: cn = [str(a.target).rstrip(".") for a in RES.resolve(s, "CNAME")]
    except Exception: return False
    for c in cn:
        try: RES.resolve(c, "A")
        except dns.resolver.NXDOMAIN: return True
        except Exception: pass
    return False
def scan(d):
    r = {}; ips = addrs(d); r["resolves"] = bool(ips)
    if ips and all(ipaddress.ip_address(i).is_global for i in ips):
        a = ips[0]
        try:
            _, h, cert = http(a, d, 443, True)
            r["tls_days_left"] = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
            r["headers"] = {k: k in h for k in HDRS}
        except Exception as e: r["tls_error"] = type(e).__name__
        try:
            line, h, _ = http(a, d, 80, False)
            r["http_redirects_to_https"] = line.split()[1] in ("301", "302", "307", "308") and h.get("location", "").startswith("https://")
        except Exception: r["http_redirects_to_https"] = None
    elif ips: r["blocked"] = "non-public address"
    r["spf"] = any(t.startswith("v=spf1") for t in txt(d))
    r["dmarc"] = any(t.lower().startswith("v=dmarc1") for t in txt("_dmarc." + d))
    r["domain_expiry_days"] = rdap_days(d)
    r["subdomains"] = sorted(ct_subs(d))[:200] if CT else []
    r["dangling"] = [s for s in r["subdomains"][:50] if dangling(s)]
    return r
def diff(o, n):
    if not o: return []
    ch = [f"New subdomain: {s}" for s in sorted(set(n["subdomains"]) - set(o.get("subdomains", [])))]
    ch += [f"Dangling CNAME: {s}" for s in n["dangling"] if s not in o.get("dangling", [])]
    ch += [f"{k.upper()} record is no longer present" for k in ("spf", "dmarc") if o.get(k) and not n.get(k)]
    if n.get("tls_error") and not o.get("tls_error"): ch.append("HTTPS check now fails: " + n["tls_error"])
    if n.get("tls_days_left") is not None and n["tls_days_left"] <= 14: ch.append(f"TLS certificate expires in {n['tls_days_left']} days")
    if n.get("domain_expiry_days") is not None and n["domain_expiry_days"] <= 30: ch.append(f"Domain registration expires in {n['domain_expiry_days']} days")
    return ch
def mail(to, subj, body):
    h = E("SMTP_HOST")
    if not h: print("[mail]", to, subj, body); return
    m = EmailMessage(); m["To"] = to; m["From"] = E("SMTP_FROM"); m["Subject"] = subj; m.set_content(body)
    try:
        with smtplib.SMTP(h, int(E("SMTP_PORT", "587")), timeout=15) as s:
            s.starttls(); s.login(E("SMTP_USER"), E("SMTP_PASS")); s.send_message(m)
    except Exception as e: print("mail failed:", e)
def run_scan(did):
    with tx() as c:
        d = c.execute("select d.name,u.email from domains d join users u on u.id=d.user_id where d.id=? and d.verified=1 and u.disabled=0", (did,)).fetchone()
        p = c.execute("select result from scans where domain_id=? order by ts desc limit 1", (did,)).fetchone()
    if not d: return
    new = scan(d["name"]); ch = diff(json.loads(p["result"]) if p else None, new)
    with tx() as c:
        c.execute("insert into scans(domain_id,ts,result,changes) values(?,?,?,?)", (did, time.time(), json.dumps(new), json.dumps(ch)))
        c.execute("update domains set last_scan=? where id=?", (time.time(), did))
    if ch: mail(d["email"], "ClientSiteWatch: changes on " + d["name"], "\n".join(ch))
def kick(did): threading.Thread(target=run_scan, args=(did,), daemon=True).start()
async def loop():
    while True:
        with tx() as c:
            due = [r["id"] for r in c.execute("select d.id from domains d join users u on u.id=d.user_id where d.verified=1 and u.disabled=0 and (d.last_scan is null or d.last_scan<?)", (time.time() - INTERVAL * 86400,))]
        for i in due: await asyncio.to_thread(run_scan, i)
        await asyncio.sleep(3600)

# ---------- app ----------
@asynccontextmanager
async def life(app):
    with tx() as c:
        c.executescript(SCHEMA)
        em, pw = E("ADMIN_EMAIL"), E("ADMIN_PASSWORD")
        if em and pw and not c.execute("select 1 from users where email=?", (em.lower(),)).fetchone():
            c.execute("insert into users(email,pw,plan,is_admin,created) values(?,?,?,?,?)", (em.lower(), hash_pw(pw), "agency", 1, iso()))
    t = asyncio.create_task(loop()); yield; t.cancel()
app = FastAPI(lifespan=life, docs_url=None, redoc_url=None, openapi_url=None)

@app.middleware("http")
async def secure(req, call):
    if req.method in ("POST", "PUT", "PATCH", "DELETE") and req.headers.get("x-csw") != "1":
        return JSONResponse({"detail": "Missing X-CSW header"}, 403)
    r = await call(req)
    r.headers.update({"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin"})
    if req.url.path.startswith("/api"): r.headers["Cache-Control"] = "no-store"
    if SECURE: r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r

def user_of(req: Request):
    t = req.cookies.get("sid")
    if not t: raise HTTPException(401, "Not signed in")
    with tx() as c:
        u = c.execute("select u.* from sessions s join users u on u.id=s.user_id where s.token=? and s.expires>? and u.disabled=0", (hashlib.sha256(t.encode()).hexdigest(), time.time())).fetchone()
    if not u: raise HTTPException(401, "Not signed in")
    return u
def admin_of(u=Depends(user_of)):
    if not u["is_admin"]: raise HTTPException(403, "Admins only")
    return u
def mine(c, u, did):
    d = c.execute("select * from domains where id=? and user_id=?", (did, u["id"])).fetchone()
    if not d: raise HTTPException(404, "Domain not found")
    return d
def start(res, uid):
    t = secrets.token_urlsafe(32)
    with tx() as c:
        c.execute("delete from sessions where expires<?", (time.time(),))
        c.execute("insert into sessions values(?,?,?)", (hashlib.sha256(t.encode()).hexdigest(), uid, time.time() + 7 * 86400))
    res.set_cookie("sid", t, max_age=7 * 86400, httponly=True, secure=SECURE, samesite="strict")

class Cred(BaseModel): email: str; password: str
class DomainIn(BaseModel): name: str
class UserPatch(BaseModel): plan: str | None = None; disabled: bool | None = None

@app.post("/api/register")
def register(b: Cred, req: Request, res: Response):
    limit("reg" + ip(req), 5, 3600); e = b.email.strip().lower()
    if not EMAIL.match(e) or not 10 <= len(b.password) <= 128: raise HTTPException(400, "Enter a valid email and a password of 10 to 128 characters.")
    try:
        with tx() as c: uid = c.execute("insert into users(email,pw,created) values(?,?,?)", (e, hash_pw(b.password), iso())).lastrowid
    except sqlite3.IntegrityError: raise HTTPException(409, "That email is already registered.")
    start(res, uid); return {"ok": True}
@app.post("/api/login")
def login(b: Cred, req: Request, res: Response):
    e = b.email.strip().lower(); limit("ip" + ip(req), 20, 300); limit("em" + e, 5, 300)
    with tx() as c: u = c.execute("select * from users where email=?", (e,)).fetchone()
    ok = check_pw(b.password, u["pw"] if u else DUMMY)
    if not (u and ok) or u["disabled"]: raise HTTPException(401, "Wrong email or password.")
    start(res, u["id"]); return {"ok": True}
@app.post("/api/logout")
def logout(req: Request, res: Response):
    t = req.cookies.get("sid")
    if t:
        with tx() as c: c.execute("delete from sessions where token=?", (hashlib.sha256(t.encode()).hexdigest(),))
    res.delete_cookie("sid"); return {"ok": True}
@app.get("/api/me")
def me(u=Depends(user_of)): return {"email": u["email"], "plan": u["plan"], "limit": PLANS[u["plan"]], "is_admin": bool(u["is_admin"])}

@app.get("/api/domains")
def domains(u=Depends(user_of)):
    out = []
    with tx() as c:
        for d in c.execute("select * from domains where user_id=? order by name", (u["id"],)).fetchall():
            s = c.execute("select ts,result,changes from scans where domain_id=? order by ts desc limit 1", (d["id"],)).fetchone()
            out.append({"id": d["id"], "name": d["name"], "verified": bool(d["verified"]), "txt_name": VN + "." + d["name"], "txt_value": "csw=" + d["token"],
                        "scan": s and {"ts": s["ts"], "result": json.loads(s["result"]), "changes": json.loads(s["changes"])}})
    return out
@app.post("/api/domains")
def add(b: DomainIn, u=Depends(user_of)):
    n = b.name.strip().lower().rstrip(".")
    if not DOM.match(n): raise HTTPException(400, "Enter a domain such as example.com.")
    with tx() as c:
        if c.execute("select count(*) from domains where user_id=?", (u["id"],)).fetchone()[0] >= PLANS[u["plan"]]: raise HTTPException(403, "Your plan’s domain limit is reached.")
        try: c.execute("insert into domains(user_id,name,token) values(?,?,?)", (u["id"], n, secrets.token_hex(16)))
        except sqlite3.IntegrityError: raise HTTPException(409, "You already added that domain.")
    return {"ok": True}
@app.post("/api/domains/{did}/verify")
def verify(did: int, u=Depends(user_of)):
    limit("v%d" % u["id"], 20, 3600)
    with tx() as c:
        d = mine(c, u, did)
        if "csw=" + d["token"] not in txt(VN + "." + d["name"]): raise HTTPException(400, "TXT record not found yet. DNS changes can take a few minutes.")
        c.execute("update domains set verified=1 where id=?", (did,))
    kick(did); return {"ok": True}
@app.post("/api/domains/{did}/scan")
def rescan(did: int, u=Depends(user_of)):
    limit("s%d" % u["id"], 10, 3600)
    with tx() as c:
        if not mine(c, u, did)["verified"]: raise HTTPException(400, "Verify the domain first.")
    kick(did); return {"ok": True}
@app.delete("/api/domains/{did}")
def remove(did: int, u=Depends(user_of)):
    with tx() as c: mine(c, u, did); c.execute("delete from domains where id=?", (did,))
    return {"ok": True}

@app.get("/api/admin/users")
def a_users(a=Depends(admin_of)):
    with tx() as c: return [dict(r) | {"pw": None} for r in c.execute("select id,email,plan,is_admin,disabled,created,(select count(*) from domains where user_id=users.id) as domains from users order by id")]
@app.get("/api/admin/domains")
def a_domains(a=Depends(admin_of)):
    with tx() as c: return [dict(r) for r in c.execute("select d.id,d.name,d.verified,d.last_scan,u.email from domains d join users u on u.id=d.user_id order by d.id desc limit 500")]
@app.patch("/api/admin/users/{uid}")
def a_patch(uid: int, b: UserPatch, a=Depends(admin_of)):
    with tx() as c:
        if b.plan is not None:
            if b.plan not in PLANS: raise HTTPException(400, "Unknown plan")
            c.execute("update users set plan=? where id=?", (b.plan, uid))
        if b.disabled is not None:
            if uid == a["id"]: raise HTTPException(400, "You can’t disable yourself.")
            c.execute("update users set disabled=? where id=?", (int(b.disabled), uid))
            if b.disabled: c.execute("delete from sessions where user_id=?", (uid,))
    return {"ok": True}

app.mount("/", StaticFiles(directory=Path(__file__).resolve().parent.parent / "web", html=True))
