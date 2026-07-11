# User-Alias Self-Service Portal für mailcow

Eigenständiges Companion-Portal, mit dem sich reguläre Mailbox-User
permanente E-Mail-Aliase nach einem festen Schema selbst anlegen können:

```
{prefix}-{lokalteil}@{domain}        z. B. amazon-peter@domain.de
{prefix}-{synonym}@{domain}          z. B. amazon-ptr@domain.de
```

**Architektur:** Das Portal läuft als eigener Container neben mailcow und
verwendet **ausschließlich die offizielle mailcow REST-API**
(`/api/v1/add/alias`, `/api/v1/get/alias/...`, `/api/v1/delete/alias`).
Es werden **keine mailcow-Core-Dateien verändert** und es wird nicht
direkt in die mailcow-Datenbank geschrieben – `update.sh` von mailcow
bleibt dadurch vollständig kompatibel.

## Funktionsweise

| Schritt | Mechanismus |
|---|---|
| Benutzer-Login | E-Mail + Postfach-Passwort, live geprüft per IMAP gegen `dovecot-mailcow` (deaktivierte Postfächer können sich nicht anmelden) |
| Alias anlegen/löschen | Serverseitig über die mailcow-API mit einem Admin-API-Key, der den Browser nie erreicht |
| Synonym (Kurzname) | Einmalig wählbar, wird in einer kleinen SQLite-DB des Portals gespeichert; `synonym@domain` wird als Weiterleitungs-Alias in mailcow angelegt |

## Einrichtung

1. **API-Key in mailcow erzeugen**
   Admin-UI → *Zugang* → *API* → Lese-/Schreibzugriff aktivieren.
   Bei *„API-Zugriff erlauben von“* das interne Docker-Subnetz eintragen
   (Standard `172.22.1.0/24`, siehe `IPV4_NETWORK` in `mailcow.conf`).

2. **Compose-Override aktivieren**
   mailcow ignoriert `docker-compose.override.yml` bewusst in git – die
   Datei gehört dem Betreiber und übersteht `update.sh` unverändert:

   ```bash
   cp data/user-alias-portal/docker-compose.override.yml.sample docker-compose.override.yml
   ```

   Falls bereits ein eigenes `docker-compose.override.yml` existiert, den
   Service-Block aus der Sample-Datei dort einfügen.

3. **Konfiguration in `mailcow.conf` ergänzen**

   ```ini
   # Pflicht
   ALIAS_PORTAL_API_KEY=DEIN-API-KEY

   # Optional (Defaults in Klammern)
   #ALIAS_PORTAL_BIND=127.0.0.1        # Bind-Adresse des Host-Ports (127.0.0.1)
   #ALIAS_PORTAL_PORT=9091             # Host-Port (9091)
   #ALIAS_PORTAL_MAX_ALIASES=50        # Max. Aliase pro User (50)
   #ALIAS_PORTAL_SYNONYM_ENABLED=1     # Synonym-Feature (1)
   #ALIAS_PORTAL_COOKIE_SECURE=1       # Secure-Flag für Session-Cookie (1)
   #ALIAS_PORTAL_TRUST_PROXY=0         # X-Forwarded-* eines Reverse-Proxy nutzen (0)
   #ALIAS_PORTAL_API_VERIFY_TLS=0      # TLS-Verifikation zur mailcow-API (0, s. u.)
   #ALIAS_PORTAL_IMAP_VERIFY_TLS=0     # TLS-Verifikation zu Dovecot (0, s. u.)
   ```

4. **Starten**

   ```bash
   docker compose up -d --build user-alias-portal-mailcow
   ```

5. **Erreichbarkeit**
   Das Portal lauscht standardmäßig nur auf `127.0.0.1:9091`. Für den
   Produktivbetrieb einen Reverse-Proxy mit TLS davorschalten, z. B.
   (nginx auf dem Host):

   ```nginx
   server {
     listen 443 ssl;
     server_name alias.domain.de;
     # ssl_certificate ...; ssl_certificate_key ...;
     location / {
       proxy_pass http://127.0.0.1:9091;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
     }
   }
   ```

   Dann `ALIAS_PORTAL_TRUST_PROXY=1` setzen, damit Rate-Limits die echte
   Client-IP verwenden.

## Validierungsregeln

* **Präfix:** `[a-z0-9]`, Bindestriche innen erlaubt, kein Bindestrich am
  Anfang/Ende, max. 40 Zeichen. Die vollständige Adresse wird
  **serverseitig** aus Präfix + Basis + Domain zusammengesetzt – Clients
  können keine beliebigen Adressen übermitteln.
* **Synonym:** 2–20 Zeichen, nur `[a-z0-9]` – **bewusst ohne
  Bindestriche**: Ein Synonym wie `x-peter` würde Aliase erzeugen
  (`shop-x-peter@…`), die nicht von Aliassen des Users `peter@…`
  unterscheidbar wären (Spoofing-Risiko). Einmalig, domainweit eindeutig
  (Unique-Index, race-sicher), Kollisionprüfung gegen bestehende
  Mailboxen und Aliase über die mailcow-API.
* **Löschen:** nur möglich, wenn der Alias laut mailcow-API exakt auf das
  eigene Postfach zeigt **und** dem eigenen Namensschema in der eigenen
  Domain entspricht.

## Sicherheitsmaßnahmen

* Admin-API-Key nur serverseitig (Umgebungsvariable), nie im HTML/JS.
* CSRF-Token (konstantzeitverglichen) auf allen POST-Requests.
* Session-Cookies: `HttpOnly`, `SameSite=Lax`, `Secure` (Default an),
  Session-Neuaufbau beim Login (Schutz vor Session-Fixation),
  Lebensdauer 1 h.
* Rate-Limiting: Login 10/15 min pro IP und 5/15 min pro Konto;
  Alias-Anlage 5/min; Synonym 3/min.
* Kein User-Enumeration-Leak: identische Fehlermeldung bei unbekanntem
  Konto und falschem Passwort.
* Security-Header inkl. strikter CSP (`default-src 'none'`), kein
  JavaScript – ausschließlich serverseitig gerenderte Formulare.
* SQLite nur mit Prepared Statements; Jinja2-Autoescaping aktiv.
* Container läuft als unprivilegierter Benutzer (`uid 20001`).
* Host-Port standardmäßig nur an `127.0.0.1` gebunden.

### Hinweis zu TLS im Docker-Netz

`ALIAS_PORTAL_API_VERIFY_TLS` und `ALIAS_PORTAL_IMAP_VERIFY_TLS` stehen
standardmäßig auf `0`, weil die mailcow-Zertifikate auf den öffentlichen
`MAILCOW_HOSTNAME` ausgestellt sind, die interne Kommunikation aber über
die Container-Namen (`nginx-mailcow`, `dovecot-mailcow`) läuft. Der
Verkehr verlässt dabei das interne Docker-Bridge-Netz nicht. Wer
vollständige Verifikation möchte, setzt beide Variablen auf `1` und
konfiguriert `ALIAS_PORTAL_MAILCOW_API_URL`/`ALIAS_PORTAL_IMAP_HOST` auf
den echten `MAILCOW_HOSTNAME` (mailcow setzt dafür einen Netzwerk-Alias).

### Hinweis zum API-Key

Die mailcow-API kennt keine feingranularen Berechtigungen – der Key hat
Admin-Rechte. Deshalb: `Allow from` in den API-Einstellungen auf das
interne Docker-Subnetz beschränken, Portal nur über den Reverse-Proxy
exponieren und den Key ausschließlich in `mailcow.conf` ablegen.

## Grenzen / bewusste Entscheidungen

* Das Synonym wird in der Portal-eigenen SQLite-DB gespeichert
  (Docker-Volume `user-alias-portal-db`) – mailcow selbst kennt nur den
  daraus resultierenden Weiterleitungs-Alias. Backup des Volumes nicht
  vergessen.
* Ein Admin kann ein Synonym zurücksetzen, indem er die Zeile aus der
  SQLite-DB löscht (`docker compose exec user-alias-portal-mailcow
  python3 -c "..."`) und den Weiterleitungs-Alias in mailcow entfernt.
* Aliase, die Admins direkt in mailcow anlegen, tauchen im Portal nur
  auf, wenn sie dem Schema entsprechen und auf das Postfach zeigen.
