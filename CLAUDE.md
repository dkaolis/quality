# CLAUDE.md — eQuality

Οδηγός για Claude Code. Διαβάζεται αυτόματα σε κάθε session. Κράτα τον ενημερωμένο.

## Τι είναι

**eQuality** — Flask πλατφόρμα Διασφάλισης Ποιότητας του **ΟΚΥπΥ**. Οι Μονάδες
Διασφάλισης Ποιότητας των νοσηλευτηρίων καταχωρούν: δείκτες ποιότητας (με στόχους
& όρια), αξιολογήσεις συμμόρφωσης με πρότυπες διαδικασίες, επιθεωρήσεις, και
έγγραφα Word/Excel από τα οποία εξάγονται αυτόματα αριθμητικά δεδομένα & γραφήματα.
Παράγει περιοδικές εκθέσεις Word προς τη διοίκηση. UI στα **Ελληνικά**.

**Κανόνας πρόσβασης:** κάθε νοσηλευτήριο τροποποιεί ΜΟΝΟ τα δικά του δεδομένα,
αλλά βλέπει όλα τα υπόλοιπα (σύγκριση/τάσεις).

## Πού ζει τι

```
GitHub: dkaolis/quality (private) ──► server 10.227.56.22 (Ubuntu 22.04)
                                       ├─ /home/administrator/quality  ← dev / εδώ δουλεύει το Claude
                                       └─ /opt/quality                 ← live app (deploy target)
Domain: quality.shso.online → cloudflared (σε ΑΛΛΟΝ server) → nginx εδώ (:80, vhost) → gunicorn :5002
```

## Stack (ίδιο pattern με eMAP)

- **Backend:** Python 3.10 / Flask 3.1 — μονολιθικό [`app.py`](app.py) (~1.9k γραμμές)
- **Frontend:** Jinja2 ([`templates/`](templates/)), Bootstrap 5, Select2, **Chart.js 4** (γραφήματα)
- **DB:** dual-mode — **SQLite** (`quality.db`, dev) ή **MySQL** (prod). Κενό `db_host` στο `settings.json` → SQLite.
- **Prod:** gunicorn (4 workers, `0.0.0.0:5002`) + nginx (`quality.shso.online`) + systemd (`quality.service`)
- **Έγγραφα:** openpyxl (.xlsx), python-docx (.docx) — parsing & παραγωγή εκθέσεων.

## Τρέξιμο (dev)

```bash
cd /home/administrator/quality
/opt/quality/venv/bin/python3 app.py    # → http://0.0.0.0:5002 (debug)
# (το system python3 ΔΕΝ έχει flask — χρησιμοποίησε το venv)
# Login: admin / admin123
```

## Δομή του app.py (landmarks)

| Περιοχή | Τι |
|---------|-----|
| Config, secret key, settings.json, filters (`fmtdate/fmtdt/fmtnum`) | αρχή |
| DB dual-mode: `USE_MYSQL`, `get_db()`, `db_execute()` (SQLite: `%s`→`?`) | ~120 |
| `SCHEMA_STATEMENTS` + `ALTER_STATEMENTS` (idempotent, τρέχουν στο boot) | ~230 |
| `ROLES`, λεξικά (MONTHS, DIRECTIONS, STATUS_META, COMPLIANCE_STATUS) | ~400 |
| `init_db()` — seed νοσηλευτήρια (κωδικοί ίδιοι με eMAP), δείκτες ΔΠ01–10, διαδικασίες ΠΔ01–08 | ~450 |
| Helpers: `role_required`, `can_edit_hospital`, `value_status` (ok/warn/alert), `latest_period_alerts` | ~550 |
| Parsers: `parse_xlsx`/`parse_docx`/`parse_document` → πίνακας `document_metrics` | ~680 |
| `generate_report_docx()` — έκθεση Word | ~800 |
| Routes: auth → dashboard/alerts → indicators → values → compare → compliance → inspections → documents → reports → admin | ~950+ |

## Ρόλοι

| Ρόλος | Δικαιώματα |
|-------|-----------|
| `admin` | Όλα + χρήστες/ρυθμίσεις |
| `central` | Κεντρική Μονάδα Ποιότητας: επεξεργασία ΟΛΩΝ των νοσηλευτηρίων, ορισμοί δεικτών/διαδικασιών |
| `quality_officer` | Καταχώρηση ΜΟΝΟ για το `hospital_code` του· προβολή όλων |
| `viewer` | Διοίκηση: μόνο προβολή |

Έλεγχος με `can_edit_hospital(code)` — ΠΑΝΤΑ κάλεσέ το σε routes που γράφουν δεδομένα νοσηλευτηρίου.

## Λογική δεικτών

`indicators.direction`: `lower_better` (alarm αν > `limit_high`), `higher_better`
(alarm αν < `limit_low`), `range` (εκτός [low, high]). `value_status()` → `ok`
(εντός στόχου) / `warn` (εκτός στόχου `target_value`) / `alert` (εκτός ορίων).
Συχνότητα: monthly πάντα, quarterly μόνο μήνες 3/6/9/12, yearly μόνο μήνα 12.

## Ρυθμίσεις & μυστικά

- **`settings.json`** (gitignored): DB credentials, org_name, session_timeout. Λείπει → SQLite + defaults.
- **`.secret_key`** (gitignored): αυτο-δημιουργείται.
- Ποτέ secrets σε αρχεία που μπαίνουν στο git. `uploads/`, `reports/`, `quality.db` εκτός git (GDPR).

## Deploy (μετά από ΚΑΘΕ αλλαγή κώδικα)

```bash
sudo cp -r /home/administrator/quality/app.py /home/administrator/quality/templates /opt/quality/
sudo systemctl restart quality
```
(`deploy.sh` = πλήρες first-time setup.) Έλεγχος: `curl --noproxy '*' -s http://127.0.0.1:5002/login`
(το Squid proxy δίνει ψεύτικα 503 χωρίς `--noproxy`).

## Συμβάσεις εργασίας (ίδιες με eMAP)

1. **Changelog υποχρεωτικό:** `CHANGELOG_<YYYY-MM-DD>_<slug>.md` στη ρίζα για κάθε αλλαγή.
2. **Auto-deploy + restart** μετά από κάθε αλλαγή (βλ. πάνω).
3. **UI στα Ελληνικά.**
4. **Git:** commit μετά από λογικές αλλαγές, push στο `dkaolis/quality` (private, PAT auth).
5. **Tests:** `test_quality.py` — `/opt/quality/venv/bin/python3 test_quality.py`.

## Παγίδες

- Γράφε SQL με `%s` placeholders — το `db_execute` τα μεταφράζει για SQLite.
- Νέοι πίνακες/στήλες: ΜΟΝΟ μέσω `SCHEMA_STATEMENTS`/`ALTER_STATEMENTS` (idempotent).
- Το port **5002** (5001=eMAP, 5003=DIAS στον ίδιο server).
- Parsing εγγράφων: μόνο .xlsx/.docx· τα .xls/.doc/.pdf αποθηκεύονται χωρίς εξαγωγή.
- Ο πίνακας `indicator_values` έχει UNIQUE (indicator, hospital, year, month) — upsert με SELECT→UPDATE/INSERT (όχι ON DUPLICATE, για συμβατότητα SQLite).
