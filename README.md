# FST Club Hub – US-01 (Register club) + US-08 (Review clubs)
Flask + SQLite. Layers match the SDS: `app.py` (presentation) -> `services.py` (application rules) -> `db.py` (data).

    pip install -r requirements.txt
    python seed.py        # demo users, password: password123
    python app.py         # http://127.0.0.1:5000
    python -m unittest discover -s tests

Rate limiting: 5 wrong passwords per email+IP, 20 per IP and 15 per account in 15 minutes lock sign-in (HTTP 429). Behind a reverse proxy set TRUSTED_PROXY_COUNT=1 so real client IPs are used.
Accounts: anyone can sign up as a student or club representative (admins come from seed.py). Set ALLOWED_EMAIL_DOMAINS="mymona.uwi.edu" to restrict sign-up to university emails.
2FA: leaders and admins can turn on authenticator-app 2FA under Security (set TOTP_ENC_KEY and SECRET_KEY in production).
Announcements: leaders post from My clubs > Announcements; accepted members read them from the club page.
Profile: leaders edit description, contact details and meeting info from My clubs > Edit profile.
Membership: students use Join on a club page; leaders handle requests from My clubs > Membership requests.
Events: leaders manage them from My clubs > Manage events; students see them under Upcoming events.

Logins: leader@uwi.test (register a club) / admin@uwi.test (review) / student@uwi.test
