"""mailcow User-Alias Self-Service Portal.

Standalone companion app: users log in with their mailbox credentials
(verified via IMAP against dovecot-mailcow) and manage permanent aliases
of the form {prefix}-{localpart|synonym}@{their-domain}. All alias
mutations go through the official mailcow REST API — mailcow core is
never modified.

Security model
  - The admin API key exists only server-side (env var), never in HTML/JS.
  - The portal server composes every alias address itself from validated
    parts; clients cannot submit arbitrary addresses.
  - Every mutation re-checks ownership against live mailcow data
    (goto == logged-in user AND address matches the user's scheme).
  - CSRF double-check on all POSTs, hardened session cookies, rate
    limiting on login and alias creation, security response headers,
    no JavaScript at all (server-rendered forms only).
"""

import hmac
import logging
import os
import secrets

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)

import validation as v
from auth import imap_login
from mailcow import MailcowAPI, MailcowError
from ratelimit import RateLimiter
from store import Store

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("portal")

DATA_DIR = os.environ.get("DATA_DIR", "/data")


def _env_bool(name, default):
    return os.environ.get(name, default) in ("1", "true", "yes", "y")


def _load_secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(DATA_DIR, "secret_key")
    try:
        with open(path, encoding="ascii") as f:
            return f.read().strip()
    except FileNotFoundError:
        key = secrets.token_hex(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(key)
        return key


app = Flask(__name__)
app.secret_key = _load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_env_bool("COOKIE_SECURE", "1"),
    SESSION_COOKIE_NAME="ua_portal",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=16 * 1024,
)

if _env_bool("TRUST_PROXY", "0"):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

api = MailcowAPI(
    base_url=os.environ.get("MAILCOW_API_URL", "https://nginx-mailcow"),
    api_key=os.environ["MAILCOW_API_KEY"],
    verify=_env_bool("MAILCOW_API_VERIFY_TLS", "1"),
)
store = Store(os.path.join(DATA_DIR, "portal.sqlite3"))
limiter = RateLimiter()

IMAP_HOST = os.environ.get("IMAP_HOST", "dovecot-mailcow")
IMAP_PORT = int(os.environ.get("IMAP_PORT", "993"))
IMAP_VERIFY_TLS = _env_bool("IMAP_VERIFY_TLS", "1")
MAX_ALIASES = int(os.environ.get("MAX_ALIASES_PER_USER", "50"))
SYNONYM_ENABLED = _env_bool("SYNONYM_ENABLED", "1")


# ── security plumbing ─────────────────────────────────────────────────────
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def check_csrf():
    token = request.form.get("_csrf", "")
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(token, expected):
        abort(400)


def current_user():
    return session.get("user")


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# ── domain logic helpers ──────────────────────────────────────────────────
def user_parts(email):
    local, domain = email.rsplit("@", 1)
    return local, domain


def allowed_bases(email):
    local, _ = user_parts(email)
    synonym = store.get_synonym(email)
    bases = [local]
    if synonym:
        bases.append(synonym)
    return bases, synonym


def list_user_aliases(email):
    """Aliases in mailcow that belong to this user's scheme."""
    _, domain = user_parts(email)
    bases, _ = allowed_bases(email)
    result = []
    for a in api.get_aliases():
        if a.get("goto") != email:
            continue
        address = a.get("address") or ""
        if "@" not in address:
            continue
        a_local, a_domain = address.rsplit("@", 1)
        if a_domain != domain:
            continue
        if v.is_valid_user_alias(a_local, bases):
            result.append(a)
    result.sort(key=lambda x: x.get("address", ""))
    return result


def flash_api_errors(errors):
    flash("Fehler: " + ("; ".join(errors) if errors else "unbekannter Fehler"),
          "error")


# ── routes ────────────────────────────────────────────────────────────────
@app.get("/")
def index():
    if current_user():
        return redirect(url_for("portal"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("portal"))
    if request.method == "POST":
        check_csrf()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        ip = request.remote_addr or "?"
        if not limiter.allow("login-ip:" + ip, 10, 900) or \
           not limiter.allow("login-user:" + email, 5, 900):
            flash("Zu viele Anmeldeversuche. Bitte später erneut versuchen.",
                  "error")
            return render_template("login.html"), 429

        # Same generic error for bad format and bad credentials:
        # do not leak which accounts exist.
        if not v.is_valid_email(email) or not password:
            flash("Anmeldung fehlgeschlagen.", "error")
            return render_template("login.html"), 401

        ok = imap_login(IMAP_HOST, IMAP_PORT, email, password,
                        verify_tls=IMAP_VERIFY_TLS)
        if ok is None:
            flash("Anmeldedienst derzeit nicht erreichbar.", "error")
            return render_template("login.html"), 503
        if not ok:
            log.warning("failed login for %s from %s", email, ip)
            flash("Anmeldung fehlgeschlagen.", "error")
            return render_template("login.html"), 401

        # prevent session fixation
        session.clear()
        session.permanent = True
        session["user"] = email
        csrf_token()
        log.info("login ok: %s from %s", email, ip)
        return redirect(url_for("portal"))
    return render_template("login.html")


@app.post("/logout")
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.get("/portal")
@login_required
def portal():
    email = current_user()
    local, domain = user_parts(email)
    bases, synonym = allowed_bases(email)
    try:
        aliases = list_user_aliases(email)
        api_ok = True
    except MailcowError:
        aliases = []
        api_ok = False
        flash("mailcow API derzeit nicht erreichbar – Aliase können nicht "
              "geladen werden.", "error")
    return render_template(
        "portal.html",
        email=email, local=local, domain=domain,
        bases=bases, synonym=synonym,
        synonym_enabled=SYNONYM_ENABLED,
        aliases=aliases, api_ok=api_ok,
        max_aliases=MAX_ALIASES,
    )


@app.post("/alias/add")
@login_required
def alias_add():
    check_csrf()
    email = current_user()
    _, domain = user_parts(email)
    bases, _ = allowed_bases(email)

    if not limiter.allow("add:" + email, 5, 60):
        flash("Zu viele Anfragen – bitte kurz warten.", "error")
        return redirect(url_for("portal"))

    prefix = (request.form.get("prefix") or "").strip().lower()
    base = (request.form.get("base") or "").strip().lower()

    # base must be one of the server-known values; the client cannot
    # inject arbitrary local parts or foreign domains.
    if base not in bases:
        abort(400)
    if not v.is_valid_prefix(prefix):
        flash("Ungültiger Präfix: nur Kleinbuchstaben, Ziffern und "
              "Bindestriche (nicht am Anfang/Ende), max. 40 Zeichen.",
              "error")
        return redirect(url_for("portal"))

    address = v.build_alias_address(prefix, base, domain)
    if address is None:
        flash("Die Alias-Adresse ist zu lang.", "error")
        return redirect(url_for("portal"))

    try:
        if len(list_user_aliases(email)) >= MAX_ALIASES:
            flash("Maximale Anzahl von %d Aliassen erreicht." % MAX_ALIASES,
                  "error")
            return redirect(url_for("portal"))
        ok, errors = api.add_alias(address, email)
    except MailcowError as e:
        flash(str(e), "error")
        return redirect(url_for("portal"))

    if ok:
        log.info("alias added: %s -> %s", address, email)
        flash("Alias %s wurde angelegt." % address, "success")
    else:
        flash_api_errors(errors)
    return redirect(url_for("portal"))


@app.post("/alias/delete")
@login_required
def alias_delete():
    check_csrf()
    email = current_user()
    _, domain = user_parts(email)
    bases, _ = allowed_bases(email)

    try:
        alias_id = int(request.form.get("alias_id", ""))
    except ValueError:
        abort(400)

    try:
        alias = api.get_alias(alias_id)
    except MailcowError as e:
        flash(str(e), "error")
        return redirect(url_for("portal"))

    # Authorisation: the alias must exist, point exactly to this user
    # and match the user's naming scheme in the user's own domain.
    address = (alias or {}).get("address") or ""
    if (not alias or alias.get("goto") != email or "@" not in address):
        abort(403)
    a_local, a_domain = address.rsplit("@", 1)
    if a_domain != domain or not v.is_valid_user_alias(a_local, bases):
        abort(403)

    try:
        ok, errors = api.delete_alias(alias_id)
    except MailcowError as e:
        flash(str(e), "error")
        return redirect(url_for("portal"))

    if ok:
        log.info("alias deleted: %s (id %d) by %s", address, alias_id, email)
        flash("Alias %s wurde gelöscht." % address, "success")
    else:
        flash_api_errors(errors)
    return redirect(url_for("portal"))


@app.post("/synonym")
@login_required
def synonym_set():
    check_csrf()
    if not SYNONYM_ENABLED:
        abort(404)
    email = current_user()
    _, domain = user_parts(email)

    if not limiter.allow("syn:" + email, 3, 60):
        flash("Zu viele Anfragen – bitte kurz warten.", "error")
        return redirect(url_for("portal"))

    synonym = (request.form.get("synonym") or "").strip().lower()
    if not v.is_valid_synonym(synonym):
        flash("Ungültiges Synonym: 2-20 Zeichen, nur Kleinbuchstaben und "
              "Ziffern.", "error")
        return redirect(url_for("portal"))

    cfg = store.get_config(email)
    if cfg and cfg["synonym_set"]:
        flash("Das Synonym wurde bereits festgelegt und kann nicht mehr "
              "geändert werden.", "error")
        return redirect(url_for("portal"))

    target = "%s@%s" % (synonym, domain)
    try:
        if api.mailbox_exists(target):
            flash("Dieses Synonym ist bereits vergeben.", "error")
            return redirect(url_for("portal"))
        if any((a.get("address") or "").lower() == target
               for a in api.get_aliases()):
            flash("Dieses Synonym ist bereits vergeben.", "error")
            return redirect(url_for("portal"))
    except MailcowError as e:
        flash(str(e), "error")
        return redirect(url_for("portal"))

    # Claim first (unique index makes this race-safe), then create the
    # forwarding alias in mailcow; roll back the claim if that fails.
    if not store.claim_synonym(email, synonym, domain):
        flash("Dieses Synonym ist bereits vergeben.", "error")
        return redirect(url_for("portal"))
    try:
        ok, errors = api.add_alias(target, email)
    except MailcowError as e:
        store.release_synonym(email)
        flash(str(e), "error")
        return redirect(url_for("portal"))
    if not ok:
        store.release_synonym(email)
        flash_api_errors(errors)
        return redirect(url_for("portal"))

    log.info("synonym set: %s for %s", synonym, email)
    flash("Synonym %s wurde dauerhaft gespeichert." % synonym, "success")
    return redirect(url_for("portal"))


@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", code=400,
                           text="Ungültige Anfrage."), 400


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403,
                           text="Zugriff verweigert."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404,
                           text="Nicht gefunden."), 404
