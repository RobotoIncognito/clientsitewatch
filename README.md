# ClientSiteWatch

FastAPI + SQLite backend, admin page, and static UI (landing, app, admin) served from one process.

## Run
    pip install -r requirements.txt
    export ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='long-random-passphrase' COOKIE_SECURE=0   # COOKIE_SECURE=0 only for local http
    uvicorn app.main:app --port 8000
Open http://localhost:8000 (landing), /app.html (customers), /admin.html (admin).

## Deploy
Build the Dockerfile, mount a volume at /data, copy .env.example to an env file, and put it behind an HTTPS reverse proxy (Caddy or Nginx).
Publish port 8000 only to the proxy: `--forwarded-allow-ips=*` trusts X-Forwarded-For, so direct exposure lets clients spoof IPs and dodge rate limits.
Run one worker only: rate limits and the weekly scheduler are in-process.

## Security built in
scrypt password hashing; random server-side sessions stored hashed (HttpOnly, SameSite=Strict, Secure); CSRF defence via SameSite plus a required X-CSW header on every state-changing call;
login and register rate limits; constant-time-style login path; domain ownership proof (DNS TXT) before any check; SSRF guard (only public IPs are contacted, connections go to the validated IP);
CSP, frame, nosniff and HSTS headers; parameterised SQL; UI built with textContent (no innerHTML); API docs disabled.

## Not included yet
Billing webhook (admin sets plans by hand on /admin.html), PDF reports, email verification, password reset, multi-worker rate limiting.
Before charging: write terms and a privacy policy, confirm crt.sh and rdap.org terms allow commercial use, and check ODPC registration.
Replace the [placeholders] in web/index.html and point its buttons at your checkout.
