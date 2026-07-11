"""Server-side validation rules for user-managed aliases.

Alias scheme:   {prefix}-{localpart|synonym}@{domain}
  - prefix: [a-z0-9], hyphens inside allowed, no leading/trailing hyphen
  - base:   the user's own local part or their registered synonym
Synonym: 2-20 chars, only [a-z0-9]. Hyphens are deliberately NOT allowed
in synonyms: a synonym like "x-peter" would make aliases such as
"amazon-x-peter@domain" indistinguishable from aliases belonging to the
mailbox "peter@domain" (suffix-collision spoofing).
"""

import re

EMAIL_RE = re.compile(
    r"^[a-z0-9][a-z0-9._+-]{0,63}"
    r"@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
)
PREFIX_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
SYNONYM_RE = re.compile(r"^[a-z0-9]{2,20}$")

MAX_LOCAL_PART = 64   # RFC 5321
MAX_ADDRESS = 254


def is_valid_email(value):
    return bool(EMAIL_RE.fullmatch(value)) and len(value) <= MAX_ADDRESS


def is_valid_prefix(prefix):
    return bool(PREFIX_RE.fullmatch(prefix))


def is_valid_synonym(synonym):
    return bool(SYNONYM_RE.fullmatch(synonym))


def is_valid_user_alias(alias_local, bases):
    """True if alias_local == {valid prefix}-{one of bases}."""
    for base in bases:
        suffix = "-" + base
        if alias_local.endswith(suffix):
            prefix = alias_local[: -len(suffix)]
            if is_valid_prefix(prefix):
                return True
    return False


def build_alias_address(prefix, base, domain):
    """Compose and length-check the full alias address, or return None."""
    local = "%s-%s" % (prefix, base)
    if len(local) > MAX_LOCAL_PART:
        return None
    address = "%s@%s" % (local, domain)
    if len(address) > MAX_ADDRESS:
        return None
    return address
