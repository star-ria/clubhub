"""Password rules + strength feedback. One function is the single source of truth: the sign-up and change-password
pages enforce its `errors`, and the live strength meter (via /password-check) shows its `suggestions`."""
import re

MIN_LEN, MAX_LEN = 8, 128
LABELS = ["Too weak", "Weak", "Fair", "Good", "Strong"]
COMMON = set("""password passw0rd p@ssw0rd p@ssword password1 qwerty qwertyuiop qwerty123 asdfgh asdfghjkl zxcvbnm abc123 abcd1234
letmein welcome welcome1 admin admin123 administrator login iloveyou monkey dragon football baseball master sunshine princess
superman batman trustno1 whatever freedom shadow michael jennifer jamaica jamaica1 reggae bobmarley uwi uwi12345 uwimona mona
chessclub computing computer 11111111 12345678 123456789 1234567890 00000000 87654321 changeme secret hello123 test1234
""".split())


def _has_run(p):
    """True for 3 repeated characters or 3 in a row like abc / 321."""
    low = p.lower()
    for i in range(len(low) - 2):
        a, b, c = ord(low[i]), ord(low[i + 1]), ord(low[i + 2])
        if b - a == c - b and abs(b - a) <= 1:
            return True
    return False


def check_password(password, email="", name=""):
    p = password or ""
    n = len(p)
    low = p.lower()
    errors = []
    if n < MIN_LEN:
        errors.append(f"Use at least {MIN_LEN} characters.")
    elif n > MAX_LEN:
        errors.append(f"Use {MAX_LEN} characters or fewer.")
    if n and (low in COMMON or low.rstrip("0123456789!") in COMMON):
        errors.append("That password is too common and easy to guess.")
    local = (email or "").split("@")[0].lower()
    if (len(local) >= 4 and local in low) or any(t in low for t in re.findall(r"[a-z]{4,}", (name or "").lower())):
        errors.append("Don't include your name or email in your password.")
    if n and len(set(p)) <= 2:
        errors.append("Use a wider variety of characters.")

    classes = sum(bool(re.search(rx, p)) for rx in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    run = _has_run(p)
    if errors:
        score = 0
    else:
        score = 1 if n < 10 else 2 if n < 12 else 3 if n < 16 else 4
        if classes >= 3:
            score = min(4, score + 1)
        if run:
            score = max(1, score - 1)

    tips = []
    if n < 12:
        tips.append("Aim for 12+ characters. A phrase of unrelated words is long and easy to remember.")
    if classes < 3 and n < 16:
        tips.append("Mix upper and lower case letters, numbers and symbols.")
    if run:
        tips.append("Avoid sequences like 123 or abc and repeated characters.")
    return {"ok": not errors, "score": score, "label": LABELS[score], "errors": errors, "suggestions": tips[:3]}
