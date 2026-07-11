"""Thin client for the official mailcow REST API.

All alias operations go through the documented endpoints
(https://mailcow.docs -> /api). The admin API key never leaves this
backend; the browser only ever talks to the portal itself.
"""

import ipaddress
import logging
from urllib.parse import quote, urlsplit

import requests

log = logging.getLogger(__name__)


class MailcowError(Exception):
    """Raised when the mailcow API is unreachable or reports an error."""


class MailcowAPI:
    def __init__(self, base_url, api_key, verify=True, timeout=10):
        parsed = urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("MAILCOW_API_URL must be an http(s) URL")
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": api_key,
            "Accept": "application/json",
        })

    # ── low level ────────────────────────────────────────────────────────
    def _get(self, path):
        try:
            r = self.session.get(self.base_url + path,
                                 verify=self.verify, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            log.error("mailcow API GET %s failed: %s", path, e)
            raise MailcowError("mailcow API nicht erreichbar") from e

    def _post(self, path, payload):
        try:
            r = self.session.post(self.base_url + path, json=payload,
                                  verify=self.verify, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            log.error("mailcow API POST %s failed: %s", path, e)
            raise MailcowError("mailcow API nicht erreichbar") from e

    @staticmethod
    def _result(messages):
        """mailcow returns a list of {type, msg}; collect outcome."""
        if isinstance(messages, dict):
            messages = [messages]
        if not isinstance(messages, list):
            raise MailcowError("Unerwartete API-Antwort")
        errors = []
        ok = False
        for m in messages:
            mtype = m.get("type")
            msg = m.get("msg")
            if isinstance(msg, list):
                msg = " ".join(str(x) for x in msg)
            if mtype == "success":
                ok = True
            elif mtype in ("danger", "error"):
                errors.append(str(msg))
        return ok and not errors, errors

    # ── aliases ──────────────────────────────────────────────────────────
    def get_aliases(self):
        data = self._get("/api/v1/get/alias/all")
        return data if isinstance(data, list) else []

    def get_alias(self, alias_id):
        data = self._get("/api/v1/get/alias/%d" % int(alias_id))
        return data if isinstance(data, dict) and data.get("id") is not None else None

    def add_alias(self, address, goto):
        messages = self._post("/api/v1/add/alias", {
            "address": address,
            "goto": goto,
            "active": "1",
            "sogo_visible": "0",
        })
        return self._result(messages)

    def delete_alias(self, alias_id):
        messages = self._post("/api/v1/delete/alias", [str(int(alias_id))])
        return self._result(messages)

    # ── mailboxes ────────────────────────────────────────────────────────
    def mailbox_exists(self, email):
        data = self._get("/api/v1/get/mailbox/" + quote(email, safe=""))
        return isinstance(data, dict) and bool(data.get("username"))
