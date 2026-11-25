"""Presentation Layer: Flask routes. Delegates all rules to services.py."""
import os
from datetime import datetime
import secrets
import time
from functools import wraps

from flask import Flask, abort, jsonify, make_response, flash, g, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import db
import passwords
import services

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
db.init_db()
DUMMY_HASH = generate_password_hash("unused-placeholder")  # checked when the email is unknown, so timing doesn't reveal which emails exist


def apply_proxy_fix(flask_app, hops):
    """Trust X-Forwarded-For only for a known number of reverse proxies. Never by default: clients can fake it."""
    if hops > 0:
        flask_app.wsgi_app = ProxyFix(flask_app.wsgi_app, x_for=hops)
    return flask_app


apply_proxy_fix(app, int(os.environ.get("TRUSTED_PROXY_COUNT", "0") or 0))


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["STATUSES"] = services.STATUSES
app.jinja_env.globals["CATEGORIES"] = services.CATEGORIES
app.jinja_env.filters["pretty_date"] = lambda v: datetime.strptime(v, "%Y-%m-%d").strftime("%a %d %b %Y")
app.jinja_env.filters["pretty_time"] = lambda v: datetime.strptime(v, "%H:%M").strftime("%I:%M %p").lstrip("0")
app.jinja_env.filters["pretty_datetime"] = lambda v: datetime.strptime(v, "%Y-%m-%d %H:%M:%S").strftime("%d %b %Y, %I:%M %p")


@app.before_request
def protect_and_load_user():
    g.user = services.get_user(session["uid"]) if session.get("uid") else None
    if request.method == "POST":
        sent, expected = request.form.get("csrf_token", ""), session.get("csrf")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, "Invalid or missing CSRF token.")


ERRORS = {400: ("That didn't work", "Your session may have expired or the form was incomplete. Go back, refresh the page and try again."),
          403: ("You don't have access to this page", "This page is for a different kind of account, or for a club you don't manage."),
          404: ("Page not found", "The page you're looking for doesn't exist, or it isn't available any more.")}


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def http_error(e):
    title, text = ERRORS[e.code]
    return render_template("error.html", code=e.code, title=title, text=text), e.code


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not g.user:
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return deco


@app.get("/")
def home():
    if not g.user:
        return redirect(url_for("login"))
    return redirect({"leader": url_for("my_clubs"), "admin": url_for("admin_clubs"),
                      "student": url_for("browse_clubs")}.get(g.user["role"], url_for("notifications")))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, ip = request.form.get("email", ""), request.remote_addr or "unknown"
        wait = services.throttle_wait("login", email, ip)
        if wait:  # refuse BEFORE looking at the password, so a lock can't be used to keep guessing
            flash(services.throttle_message(wait), "error")
            resp = make_response(render_template("login.html"), 429)
            resp.headers["Retry-After"] = str(wait)
            return resp
        user = services.get_user_by_email(email)
        password_ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, request.form.get("password", ""))
        if user and password_ok:
            services.clear_failures("login", email, ip)
            session.clear()
            if user["totp_enabled"]:  # password OK, but not signed in until the second factor passes
                session["pending_uid"], session["pending_at"] = user["id"], time.time()
                return redirect(url_for("login_2fa"))
            session["uid"] = user["id"]
            return redirect(url_for("home"))
        services.record_failure("login", email, ip)
        flash("Incorrect email or password.", "error")
    return render_template("login.html")


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    pid = session.get("pending_uid")
    if not pid or time.time() - session.get("pending_at", 0) > 600:  # step 2 must follow step 1 within 10 minutes
        session.clear()
        return redirect(url_for("login"))
    if request.method == "POST":
        ok, msg = services.verify_second_factor(pid, request.form.get("code"))
        if ok:
            session.clear()
            session["uid"] = pid
            return redirect(url_for("home"))
        flash(msg, "error")
    return render_template("login_2fa.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if g.user:
        return redirect(url_for("home"))
    form, errors = request.form if request.method == "POST" else {}, {}
    if request.method == "POST":
        ok, result = services.create_user(request.form)
        if ok:
            session.clear()
            session["uid"] = result
            flash("Welcome to FST Club Hub! Your account is ready.", "success")
            return redirect(url_for("home"))
        errors = result
    return render_template("signup.html", form=form, errors=errors)


@app.route("/account/password", methods=["GET", "POST"])
@role_required("student", "leader", "admin")
def change_password():
    errors = {}
    if request.method == "POST":
        ok, result = services.change_password(g.user["id"], request.form.get("current"), request.form.get("new"), request.form.get("confirm"),
                                          ip=request.remote_addr or "unknown")
        if ok:
            session.pop("csrf", None)  # fresh CSRF token after a credential change
            flash("Password changed. We've added a note to your notifications.", "success")
            return redirect(url_for("home"))
        errors = result
    return render_template("change_password.html", errors=errors)


@app.post("/password-check")
def password_check():
    """Live strength feedback for the meter; same rules the server enforces. Nothing is stored or logged."""
    f = request.form
    return jsonify(passwords.check_password(f.get("password", "")[:200], f.get("email", "")[:120], f.get("name", "")[:60]))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---- US-01 ----
@app.route("/clubs/register", methods=["GET", "POST"])
@role_required("leader")
def register_club():
    form, errors = request.form if request.method == "POST" else {}, {}
    if request.method == "POST":
        ok, result = services.register_club(g.user["id"], request.form)
        if ok:
            flash("Club submitted! It is now Pending until an administrator reviews it.", "success")
            return redirect(url_for("my_clubs"))
        errors = result
    return render_template("register_club.html", form=form, errors=errors)


@app.get("/my-clubs")
@role_required("leader")
def my_clubs():
    return render_template("my_clubs.html", clubs=services.clubs_for_leader(g.user["id"]))


@app.get("/notifications")
@role_required("student", "leader", "admin")
def notifications():
    return render_template("notifications.html", items=services.list_notifications(g.user["id"]))


# ---- US-02 ----
@app.get("/clubs")
@role_required("student")
def browse_clubs():
    q = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "")
    return render_template("clubs.html", clubs=services.search_clubs(q, category), q=q, category=category)


@app.get("/clubs/<int:club_id>")
@role_required("student")
def club_detail(club_id):
    club = services.get_approved_club(club_id)
    if not club:
        abort(404)
    return render_template("club_detail.html", club=club, membership=services.membership_state(g.user["id"], club_id))


# ---- two-factor authentication settings ----
def _security_view(backup_codes=None):
    setup = services.pending_2fa_setup(g.user["id"])
    secret = setup[0] if setup else None
    return render_template("security.html", u=services.get_user(g.user["id"]), backup_codes=backup_codes,
                           secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)) if secret else None,
                           uri=setup[1] if setup else None)


@app.get("/security")
@role_required("leader", "admin")
def security_page():
    return _security_view()


@app.post("/security/2fa/start")
@role_required("leader", "admin")
def start_2fa():
    ok, msg = services.start_2fa_setup(g.user["id"])
    flash(msg, "success" if ok else "error")
    return redirect(url_for("security_page"))


@app.post("/security/2fa/confirm")
@role_required("leader", "admin")
def confirm_2fa():
    ok, result = services.confirm_2fa_setup(g.user["id"], request.form.get("code"))
    if ok:
        return _security_view(backup_codes=result)  # shown once, not stored in clear
    flash(result, "error")
    return redirect(url_for("security_page"))


@app.post("/security/2fa/disable")
@role_required("leader", "admin")
def disable_2fa():
    ok, msg = services.disable_2fa(g.user["id"], request.form.get("password"), request.form.get("code"), ip=request.remote_addr or "unknown")
    flash(msg, "success" if ok else "error")
    return redirect(url_for("security_page"))


# ---- US-05: announcements ----
@app.route("/clubs/<int:club_id>/announcements/new", methods=["GET", "POST"])
@role_required("leader")
def leader_announcements(club_id):
    club = own_club_or_abort(club_id)
    if club["status"] != "Approved":
        flash("Your club must be approved before you can post announcements.", "error")
        return redirect(url_for("my_clubs"))
    form, errors = {}, {}
    if request.method == "POST":
        ok, result = services.post_announcement(g.user["id"], club_id, request.form)
        if ok:
            flash("Announcement posted. Your members have been notified.", "success")
            return redirect(url_for("leader_announcements", club_id=club_id))
        form, errors = request.form, result
    return render_template("leader_announcements.html", club=club, form=form, errors=errors, items=services.list_announcements(club_id))


@app.get("/clubs/<int:club_id>/announcements")
@role_required("student")
def club_announcements(club_id):
    club = services.get_approved_club(club_id)
    if not club:
        abort(404)
    if not services.is_active_member(g.user["id"], club_id):
        abort(403)  # announcements are for active members only
    return render_template("announcements.html", club=club, items=services.list_announcements(club_id))


# ---- US-07: leaders edit their club profile ----
@app.route("/clubs/<int:club_id>/edit", methods=["GET", "POST"])
@role_required("leader")
def edit_profile(club_id):
    club = own_club_or_abort(club_id)
    if club["status"] != "Approved":
        flash("Your club must be approved before you can edit its profile.", "error")
        return redirect(url_for("my_clubs"))
    form, errors = dict(club), {}
    if request.method == "POST":
        ok, result = services.update_club_profile(g.user["id"], club_id, request.form)
        if ok:
            flash("Club profile updated. The new details are now on your public club page.", "success")
            return redirect(url_for("my_clubs"))
        form, errors = request.form, result
    return render_template("edit_profile.html", club=club, form=form, errors=errors)


# ---- US-03: join a club / UC-05: accept or decline ----
@app.post("/clubs/<int:club_id>/join")
@role_required("student")
def join_club(club_id):
    ok, msg = services.request_to_join(g.user["id"], club_id)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("club_detail", club_id=club_id) if services.get_approved_club(club_id) else url_for("browse_clubs"))


@app.get("/my-memberships")
@role_required("student")
def my_memberships():
    return render_template("my_memberships.html", items=services.student_memberships(g.user["id"]))


@app.get("/clubs/<int:club_id>/requests")
@role_required("leader")
def membership_requests(club_id):
    club = own_club_or_abort(club_id)
    return render_template("requests.html", club=club, requests=services.list_requests(club_id))


@app.post("/clubs/<int:club_id>/requests/<int:membership_id>/<decision>")
@role_required("leader")
def decide_membership(club_id, membership_id, decision):
    own_club_or_abort(club_id)
    ok, msg = services.decide_request(g.user["id"], club_id, membership_id, decision, request.form.get("expected_status"))
    flash(msg, "success" if ok else "error")
    return redirect(url_for("membership_requests", club_id=club_id))


@app.post("/clubs/<int:club_id>/accepting")
@role_required("leader")
def toggle_accepting(club_id):
    own_club_or_abort(club_id)
    services.set_accepting_members(g.user["id"], club_id, request.form.get("accepting") == "1")
    flash("Club is now open to new members." if request.form.get("accepting") == "1" else "Club is now closed to new members.", "success")
    return redirect(url_for("my_clubs"))


# ---- US-04: leaders create / publish events ----
def own_club_or_abort(club_id):
    club = services.get_club(club_id)
    if not club:
        abort(404)
    if club["leader_id"] != g.user["id"]:
        abort(403)
    return club


@app.get("/clubs/<int:club_id>/events")
@role_required("leader")
def leader_events(club_id):
    club = own_club_or_abort(club_id)
    return render_template("leader_events.html", club=club, events=services.list_club_events(club_id))


@app.route("/clubs/<int:club_id>/events/new", methods=["GET", "POST"])
@role_required("leader")
def new_event(club_id):
    club = own_club_or_abort(club_id)
    if club["status"] != "Approved":
        flash("Your club must be approved before you can create events.", "error")
        return redirect(url_for("my_clubs"))
    form, errors = request.form if request.method == "POST" else {}, {}
    if request.method == "POST":
        action = request.form.get("action")
        if action not in ("save_draft", "publish"):
            abort(400)
        ok, result = services.create_event(g.user["id"], club_id, request.form, publish=(action == "publish"))
        if ok:
            flash("Event published." if action == "publish" else "Event saved as a draft (not visible to students).", "success")
            return redirect(url_for("leader_events", club_id=club_id))
        errors = result
    return render_template("event_form.html", club=club, form=form, errors=errors)


@app.post("/clubs/<int:club_id>/events/<int:event_id>/publish")
@role_required("leader")
def publish_draft(club_id, event_id):
    own_club_or_abort(club_id)
    ok, msg = services.publish_draft(g.user["id"], club_id, event_id)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("leader_events", club_id=club_id))


# ---- US-06: students view upcoming events ----
@app.get("/events")
@role_required("student")
def student_events():
    errors, args = [], request.args

    def date_arg(name):
        raw = args.get(name, "").strip()
        if not raw:
            return None
        try:
            return datetime.strptime(raw, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            errors.append("Please enter valid dates."); return None

    date_from, date_to = date_arg("from"), date_arg("to")
    if date_from and date_to and date_from > date_to:
        errors.append("The 'to' date must be on or after the 'from' date."); date_from = date_to = None
    clubs = services.approved_clubs()
    club_id = int(args["club"]) if args.get("club", "").isdigit() and int(args["club"]) in {c["id"] for c in clubs} else None
    events = services.upcoming_events(club_id, date_from, date_to)
    filtered = bool(club_id or date_from or date_to)
    any_upcoming = bool(events) or (filtered and bool(services.upcoming_events()))
    return render_template("events.html", events=events, clubs=clubs, club_id=club_id, date_from=date_from or "",
                           date_to=date_to or "", filtered=filtered, any_upcoming=any_upcoming, errors=errors)


@app.get("/events/<int:event_id>")
@role_required("student")
def event_detail(event_id):
    event = services.get_published_event(event_id)
    if not event:
        abort(404)
    return render_template("event_detail.html", event=event)


# ---- US-08 ----
@app.get("/admin/clubs")
@role_required("admin")
def admin_clubs():
    status = request.args.get("status", "")
    return render_template("admin_clubs.html", clubs=services.list_clubs(status), selected=status)


@app.post("/admin/clubs/<int:club_id>/<action>")
@role_required("admin")
def admin_action(club_id, action):
    ok, msg = services.change_club_status(club_id, action, request.form.get("expected_status"), request.form.get("reason"))
    flash(msg, "success" if ok else "error")
    return redirect(url_for("admin_clubs", status=request.form.get("filter", "")))


if __name__ == "__main__":
    app.run(debug=True)
