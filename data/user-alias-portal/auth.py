"""User authentication against mailcow's Dovecot via IMAP.

The portal never stores passwords; each login is verified live against
dovecot-mailcow. This automatically honours mailbox state (deactivated
mailboxes cannot log in).
"""

import imaplib
import logging
import socket
import ssl

log = logging.getLogger(__name__)


def imap_login(host, port, username, password, verify_tls=True):
    """Returns True (ok), False (bad credentials) or None (server error)."""
    ctx = ssl.create_default_context()
    if not verify_tls:
        # Inside the mailcow docker network the certificate is issued for
        # the public MAILCOW_HOSTNAME, not for "dovecot-mailcow".
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    conn = None
    try:
        conn = imaplib.IMAP4_SSL(host=host, port=port, ssl_context=ctx, timeout=10)
        conn.login(username, password)
        return True
    except imaplib.IMAP4.error:
        return False
    except (OSError, socket.timeout, ssl.SSLError) as e:
        log.error("IMAP auth backend unreachable: %s", e)
        return None
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:
                pass
