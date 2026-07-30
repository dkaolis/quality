"""
eQuality - Πλατφόρμα Διασφάλισης Ποιότητας ΟΚΥπΥ
Καταχώρηση & απεικόνιση δεικτών ποιότητας, αξιολογήσεων συμμόρφωσης και
επιθεωρήσεων από τις Μονάδες Διασφάλισης Ποιότητας των νοσηλευτηρίων.
"""

import os
import re
import json
import secrets
import logging
from datetime import datetime, timedelta, date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_from_directory, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
# Persistent secret key — αποθηκεύεται σε αρχείο ώστε να επιβιώνει restarts & workers
_secret_key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")
if os.environ.get("SECRET_KEY"):
    app.secret_key = os.environ["SECRET_KEY"]
elif os.path.exists(_secret_key_file):
    with open(_secret_key_file, "r") as _f:
        app.secret_key = _f.read().strip()
else:
    _generated = secrets.token_hex(32)
    with open(_secret_key_file, "w") as _f:
        _f.write(_generated)
    app.secret_key = _generated

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"doc", "docx", "xls", "xlsx", "pdf"}
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

# Στο dev (QUALITY_ENV=dev) επαναφόρτωση templates ανά request, ώστε αλλαγές σε .html να φαίνονται άμεσα
if os.environ.get("QUALITY_ENV") == "dev":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

logging.basicConfig(level=logging.INFO)
logger = app.logger


# ---------------------------------------------------------------------------
# Jinja2 filters
# ---------------------------------------------------------------------------
@app.template_filter("fmtdate")
def fmtdate_filter(value, fmt="%Y-%m-%d"):
    if not value:
        return ""
    if isinstance(value, str):
        return value[:10]
    try:
        return value.strftime(fmt)
    except Exception:
        return str(value)


@app.template_filter("fmtdt")
def fmtdt_filter(value):
    """Format ημερομηνία+ώρα → YYYY-MM-DD HH:MM"""
    if not value:
        return ""
    if isinstance(value, str):
        return value[:16]
    try:
        return value.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(value)


@app.template_filter("fmtnum")
def fmtnum_filter(value, decimals=2):
    """Αριθμός χωρίς περιττά μηδενικά (2.50 → 2.5, 3.00 → 3)."""
    if value is None or value == "":
        return ""
    try:
        s = f"{float(value):.{decimals}f}".rstrip("0").rstrip(".")
        return s if s else "0"
    except (TypeError, ValueError):
        return str(value)


def load_settings():
    defaults = {
        "db_host": "", "db_port": "3306", "db_user": "", "db_pass": "", "db_name": "quality",
        "session_timeout": "480",
        "org_name": "Οργανισμός Κρατικών Υπηρεσιών Υγείας",
        "org_short": "ΟΚΥπΥ",
        "app_title": "eQuality — Διασφάλιση Ποιότητας",
    }
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                defaults.update(json.load(f))
        except Exception:
            pass
    return defaults


def save_settings(data):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


@app.before_request
def before_request():
    session.permanent = True
    settings = load_settings()
    app.permanent_session_lifetime = timedelta(minutes=int(settings.get("session_timeout", 480)))


# ---------------------------------------------------------------------------
# Database (MySQL / SQLite dual mode — ίδιο pattern με eMAP)
# ---------------------------------------------------------------------------
SETTINGS = load_settings()
USE_MYSQL = bool(SETTINGS.get("db_host"))

if USE_MYSQL:
    import mysql.connector

    db_config = {
        "host": SETTINGS["db_host"],
        "port": int(SETTINGS.get("db_port", 3306)),
        "user": SETTINGS["db_user"],
        "password": SETTINGS["db_pass"],
        "database": SETTINGS["db_name"],
        "connection_timeout": 10,
    }

    def get_db():
        """Νέα σύνδεση ανά request — αποφεύγει pool issues με gunicorn workers."""
        return mysql.connector.connect(**db_config)

    def db_execute(sql, params=None, fetch=False, lastrowid=False):
        conn = get_db()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(sql, params or ())
            if fetch:
                rows = cur.fetchall()
                cur.close()
                return rows
            if lastrowid:
                rid = cur.lastrowid
                conn.commit()
                cur.close()
                return rid
            conn.commit()
            cur.close()
        finally:
            conn.close()
else:
    import sqlite3

    DB_PATH = os.path.join(BASE_DIR, "quality.db")

    # Parity με MySQL: DATETIME/DATE στήλες επιστρέφουν datetime/date αντικείμενα
    def _sqlite_to_datetime(b):
        s = b.decode() if isinstance(b, (bytes, bytearray)) else b
        if not s:
            return None
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(s, fmt)
                except ValueError:
                    pass
            return s

    def _sqlite_to_date(b):
        v = _sqlite_to_datetime(b)
        return v.date() if isinstance(v, datetime) else v

    sqlite3.register_converter("DATETIME", _sqlite_to_datetime)
    sqlite3.register_converter("TIMESTAMP", _sqlite_to_datetime)
    sqlite3.register_converter("DATE", _sqlite_to_date)

    def dict_factory(cursor, row):
        return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}

    def get_db():
        conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = dict_factory
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def db_execute(sql, params=None, fetch=False, lastrowid=False):
        sql = sql.replace("%s", "?")
        conn = get_db()
        cur = conn.execute(sql, params or ())
        if fetch:
            rows = cur.fetchall()
            conn.close()
            return rows
        if lastrowid:
            rid = cur.lastrowid
            conn.commit()
            conn.close()
            return rid
        conn.commit()
        conn.close()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
AUTO_INCREMENT = "AUTO_INCREMENT" if USE_MYSQL else "AUTOINCREMENT"
ENGINE = " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" if USE_MYSQL else ""
NOW = "NOW()" if USE_MYSQL else "CURRENT_TIMESTAMP"
INSERT_IGNORE = "INSERT IGNORE INTO" if USE_MYSQL else "INSERT OR IGNORE INTO"


def _uniq(name, cols):
    """Cross-DB UNIQUE constraint μέσα σε CREATE TABLE."""
    return f"UNIQUE KEY {name} ({cols})" if USE_MYSQL else f"UNIQUE ({cols})"


SCHEMA_STATEMENTS = [
    # Χρήστες
    f"""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(256) NOT NULL,
        full_name VARCHAR(200) NOT NULL,
        email VARCHAR(200),
        role VARCHAR(50) DEFAULT 'quality_officer',
        hospital_code VARCHAR(10),
        phone VARCHAR(50),
        active TINYINT DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Νοσηλευτήρια / Διευθύνσεις
    f"""CREATE TABLE IF NOT EXISTS hospitals (
        code VARCHAR(10) PRIMARY KEY,
        name_el VARCHAR(300) NOT NULL,
        name_en VARCHAR(300),
        active TINYINT DEFAULT 1,
        sort_order INTEGER DEFAULT 0
    ){ENGINE}""",

    # Ορισμοί δεικτών ποιότητας
    f"""CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        code VARCHAR(20) UNIQUE NOT NULL,
        name VARCHAR(300) NOT NULL,
        category VARCHAR(100) DEFAULT 'Γενικοί',
        description TEXT,
        unit VARCHAR(50),
        direction VARCHAR(20) DEFAULT 'lower_better',
        target_value DOUBLE,
        limit_low DOUBLE,
        limit_high DOUBLE,
        frequency VARCHAR(20) DEFAULT 'monthly',
        active TINYINT DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Τιμές δεικτών ανά νοσηλευτήριο/περίοδο
    f"""CREATE TABLE IF NOT EXISTS indicator_values (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        indicator_id INTEGER NOT NULL,
        hospital_code VARCHAR(10) NOT NULL,
        year INTEGER NOT NULL,
        month INTEGER NOT NULL,
        value DOUBLE NOT NULL,
        comment VARCHAR(500),
        created_by VARCHAR(100),
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        {_uniq('uq_ind_val', 'indicator_id, hospital_code, year, month')}
    ){ENGINE}""",

    # Πρότυπες διαδικασίες
    f"""CREATE TABLE IF NOT EXISTS procedures (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        code VARCHAR(20) UNIQUE NOT NULL,
        name VARCHAR(300) NOT NULL,
        category VARCHAR(100) DEFAULT 'Γενικές',
        description TEXT,
        active TINYINT DEFAULT 1,
        sort_order INTEGER DEFAULT 0
    ){ENGINE}""",

    # Αξιολογήσεις συμμόρφωσης
    f"""CREATE TABLE IF NOT EXISTS compliance_assessments (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        procedure_id INTEGER NOT NULL,
        hospital_code VARCHAR(10) NOT NULL,
        assess_date DATE NOT NULL,
        status VARCHAR(20) NOT NULL,
        score INTEGER,
        findings TEXT,
        actions TEXT,
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Επιθεωρήσεις
    f"""CREATE TABLE IF NOT EXISTS inspections (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        hospital_code VARCHAR(10) NOT NULL,
        inspection_date DATE NOT NULL,
        itype VARCHAR(100) DEFAULT 'Εσωτερική',
        body VARCHAR(200),
        scope VARCHAR(300),
        score DOUBLE,
        findings_major INTEGER DEFAULT 0,
        findings_minor INTEGER DEFAULT 0,
        observations INTEGER DEFAULT 0,
        status VARCHAR(20) DEFAULT 'open',
        summary TEXT,
        actions TEXT,
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Έγγραφα (Word/Excel) με εξαγωγή δεδομένων
    f"""CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        hospital_code VARCHAR(10) NOT NULL,
        title VARCHAR(300) NOT NULL,
        category VARCHAR(100) DEFAULT 'Γενικά',
        year INTEGER,
        month INTEGER,
        filename VARCHAR(300) NOT NULL,
        orig_name VARCHAR(300),
        parse_status VARCHAR(20) DEFAULT 'pending',
        parse_error TEXT,
        uploaded_by VARCHAR(100),
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Εξαγόμενα αριθμητικά δεδομένα από έγγραφα
    f"""CREATE TABLE IF NOT EXISTS document_metrics (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        document_id INTEGER NOT NULL,
        grp VARCHAR(200),
        label VARCHAR(300) NOT NULL,
        value DOUBLE NOT NULL,
        row_no INTEGER DEFAULT 0
    ){ENGINE}""",

    # Ιστορικό ενεργειών
    f"""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        user_id INTEGER,
        username VARCHAR(100),
        action VARCHAR(100),
        entity VARCHAR(50),
        entity_id VARCHAR(50),
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",
]

# Idempotent ALTERs για μελλοντικές migrations — τρέχουν στο boot, αγνοούνται αν υπάρχουν ήδη
ALTER_STATEMENTS = [
    # Ομαδοποίηση δεικτών (π.χ. ΤΑΕΠ Ενηλίκων / ΤΑΕΠ Παίδων) & σύστημα βαθμολογίας
    "ALTER TABLE indicators ADD COLUMN grp VARCHAR(100)",
    "ALTER TABLE indicators ADD COLUMN max_score DOUBLE",
    "ALTER TABLE indicator_values ADD COLUMN score DOUBLE",
    "ALTER TABLE indicator_values ADD COLUMN result_text VARCHAR(100)",
    # Χρονικό διάστημα καταχώρησης (Από/Μέχρι μήνα)· το month κρατά το τέλος (month_to) για γραφήματα/μοναδικότητα
    "ALTER TABLE indicator_values ADD COLUMN month_from INTEGER",
    "ALTER TABLE indicator_values ADD COLUMN month_to INTEGER",
    # Αριθμός αναφοράς εγγράφου (π.χ. F1054) — ανά ομάδα/περίοδο
    "ALTER TABLE indicator_values ADD COLUMN ref_no VARCHAR(50)",
    # Σήμανση «χωρίς δεδομένα» (π.χ. καταχώρηση «NO DATA» αντί αριθμού)
    "ALTER TABLE indicator_values ADD COLUMN no_data INTEGER DEFAULT 0",
]


# ---------------------------------------------------------------------------
# Ρόλοι & λεξικά αναφοράς
# ---------------------------------------------------------------------------
ROLES = {
    "admin": "Διαχειριστής",
    "central": "Κεντρική Μονάδα Ποιότητας",
    "quality_officer": "Λειτουργός Διασφάλισης Ποιότητας",
    "quality_add": "Καταχώρηση (χωρίς τροποποίηση)",
    "viewer": "Διοίκηση (Προβολή)",
}
EDIT_ALL_ROLES = ("admin", "central")  # επεξεργάζονται δεδομένα όλων των νοσηλευτηρίων
ADD_ROLES = ("admin", "central", "quality_officer", "quality_add")  # μπορούν να προσθέτουν δεδομένα

MONTHS = {
    1: "Ιανουάριος", 2: "Φεβρουάριος", 3: "Μάρτιος", 4: "Απρίλιος",
    5: "Μάιος", 6: "Ιούνιος", 7: "Ιούλιος", 8: "Αύγουστος",
    9: "Σεπτέμβριος", 10: "Οκτώβριος", 11: "Νοέμβριος", 12: "Δεκέμβριος",
}
MONTHS_SHORT = {1: "Ιαν", 2: "Φεβ", 3: "Μαρ", 4: "Απρ", 5: "Μαϊ", 6: "Ιουν",
                7: "Ιουλ", 8: "Αυγ", 9: "Σεπ", 10: "Οκτ", 11: "Νοε", 12: "Δεκ"}

DIRECTIONS = {
    "lower_better": "Χαμηλότερο = καλύτερο",
    "higher_better": "Υψηλότερο = καλύτερο",
    "range": "Εντός εύρους ορίων",
}
FREQUENCIES = {"monthly": "Μηνιαίος", "quarterly": "Τριμηνιαίος", "yearly": "Ετήσιος"}

# Κατάσταση τιμής δείκτη → (bootstrap χρώμα, ετικέτα)
STATUS_META = {
    "ok": ("success", "Εντός στόχου"),
    "warn": ("warning", "Εκτός στόχου"),
    "alert": ("danger", "Εκτός ορίων"),
}

COMPLIANCE_STATUS = {
    "compliant": ("Πλήρης Συμμόρφωση", "success"),
    "partial": ("Μερική Συμμόρφωση", "warning"),
    "non_compliant": ("Μη Συμμόρφωση", "danger"),
}

INSPECTION_TYPES = ["Εσωτερική", "Εξωτερική", "Πιστοποίησης", "Υγειονομική", "Άλλη"]
INSPECTION_STATUS = {"open": ("Ανοικτή", "warning"), "closed": ("Κλεισμένη", "success")}

DOCUMENT_CATEGORIES = ["Δείκτες Ποιότητας", "Έκθεση Επιθεώρησης", "Αξιολόγηση Συμμόρφωσης",
                       "Έρευνα Ικανοποίησης", "Στατιστικά Στοιχεία", "Γενικά"]


# ---------------------------------------------------------------------------
# Schema init & seed
# ---------------------------------------------------------------------------
def init_db():
    for stmt in SCHEMA_STATEMENTS:
        try:
            db_execute(stmt)
        except Exception as e:
            logger.error(f"Schema: {e}")
    for stmt in ALTER_STATEMENTS:
        try:
            db_execute(stmt)
        except Exception:
            pass  # στήλη υπάρχει ήδη

    # Seed νοσηλευτήρια (ίδιοι κωδικοί με eMAP)
    hospitals = [
        ("NGH", "Γενικό Νοσοκομείο Λευκωσίας", "Nicosia General Hospital", 1),
        ("LGH", "Γενικό Νοσοκομείο Λεμεσού", "Limassol General Hospital", 2),
        ("LAR", "Γενικό Νοσοκομείο Λάρνακας", "Larnaca General Hospital", 3),
        ("PAP", "Γενικό Νοσοκομείο Πάφου", "Paphos General Hospital", 4),
        ("FAM", "Γενικό Νοσοκομείο Αμμοχώστου", "Famagusta General Hospital", 5),
        ("ARC", "Νοσοκομείο Αρχιεπίσκοπος Μακάριος ΙΙΙ", "Archbishop Makarios III Hospital", 6),
        ("CHR", "Νοσοκομείο Πόλεως Χρυσοχούς", "Chrysochous Hospital", 7),
        ("TRD", "Νοσοκομείο Τροόδους", "Troodos Hospital", 8),
        ("MH", "Υπηρεσίες Ψυχικής Υγείας", "Mental Health Services", 9),
        ("AMB", "Διεύθυνση Ασθενοφόρων", "Ambulance Service", 10),
        ("HC", "Κέντρα Υγείας", "Health Centres", 11),
        ("CNS", "Κοινοτική Νοσηλευτική Υπηρεσία", "Community Home Nursing Service", 12),
        ("HQ", "Κεντρική Διοίκηση", "Headquarters", 13),
    ]
    for code, name_el, name_en, so in hospitals:
        db_execute(f"{INSERT_IGNORE} hospitals (code, name_el, name_en, sort_order) VALUES (%s,%s,%s,%s)",
                   (code, name_el, name_en, so))

    # Seed admin
    existing = db_execute("SELECT id FROM users WHERE username='admin'", fetch=True)
    if not existing:
        # INSERT IGNORE: race-safe όταν πολλοί gunicorn workers κάνουν boot ταυτόχρονα
        db_execute(
            f"{INSERT_IGNORE} users (username, password_hash, full_name, role, hospital_code) VALUES (%s,%s,%s,%s,%s)",
            ("admin", generate_password_hash("admin123"), "Διαχειριστής Συστήματος", "admin", "HQ"))
        logger.info("Δημιουργήθηκε default admin (admin/admin123)")

    # Seed βασικοί δείκτες ποιότητας (μόνο αν ο πίνακας είναι κενός)
    if not db_execute("SELECT id FROM indicators LIMIT 1", fetch=True):
        seed_indicators = [
            # code, name, category, unit, direction, target, low, high, freq
            ("ΔΠ01", "Ενδονοσοκομειακές λοιμώξεις", "Κλινική Ασφάλεια", "%", "lower_better", 3, None, 5, "monthly"),
            ("ΔΠ02", "Πτώσεις ασθενών ανά 1000 ημέρες νοσηλείας", "Κλινική Ασφάλεια", "‰", "lower_better", 2, None, 4, "monthly"),
            ("ΔΠ03", "Έλκη πίεσης (επίπτωση)", "Κλινική Ασφάλεια", "%", "lower_better", 1.5, None, 3, "monthly"),
            ("ΔΠ04", "Επανεισαγωγές εντός 30 ημερών", "Κλινική Αποτελεσματικότητα", "%", "lower_better", 8, None, 12, "monthly"),
            ("ΔΠ05", "Μέσος χρόνος αναμονής ΤΑΕΠ", "Πρόσβαση & Ροή Ασθενών", "λεπτά", "lower_better", 60, None, 120, "monthly"),
            ("ΔΠ06", "Ικανοποίηση ασθενών", "Εμπειρία Ασθενή", "%", "higher_better", 85, 75, None, "quarterly"),
            ("ΔΠ07", "Συμμόρφωση υγιεινής χεριών", "Έλεγχος Λοιμώξεων", "%", "higher_better", 80, 70, None, "monthly"),
            ("ΔΠ08", "Ακυρώσεις προγραμματισμένων χειρουργείων", "Χειρουργική Δραστηριότητα", "%", "lower_better", 5, None, 10, "monthly"),
            ("ΔΠ09", "Παράπονα ανά 1000 επισκέψεις", "Εμπειρία Ασθενή", "‰", "lower_better", 1, None, 3, "monthly"),
            ("ΔΠ10", "Πληρότητα ιατρικών φακέλων", "Τεκμηρίωση", "%", "higher_better", 95, 85, None, "quarterly"),
        ]
        for i, (code, name, cat, unit, direction, target, low, high, freq) in enumerate(seed_indicators):
            db_execute(
                f"""{INSERT_IGNORE} indicators (code, name, category, unit, direction,
                   target_value, limit_low, limit_high, frequency, sort_order)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (code, name, cat, unit, direction, target, low, high, freq, i))
        logger.info("Έγινε seed 10 βασικών δεικτών ποιότητας")

    # Seed πρότυπες διαδικασίες (μόνο αν ο πίνακας είναι κενός)
    if not db_execute("SELECT id FROM procedures LIMIT 1", fetch=True):
        seed_procs = [
            ("ΠΔ01", "Διαχείριση Παραπόνων & Εισηγήσεων", "Εμπειρία Ασθενή"),
            ("ΠΔ02", "Υγιεινή Χεριών & Έλεγχος Λοιμώξεων", "Έλεγχος Λοιμώξεων"),
            ("ΠΔ03", "Ασφαλής Χορήγηση Φαρμάκων", "Κλινική Ασφάλεια"),
            ("ΠΔ04", "Ταυτοποίηση Ασθενών", "Κλινική Ασφάλεια"),
            ("ΠΔ05", "Χειρουργική Λίστα Ελέγχου (Safe Surgery)", "Χειρουργική Δραστηριότητα"),
            ("ΠΔ06", "Διαχείριση Ιατρικών Αποβλήτων", "Περιβάλλον & Υποδομές"),
            ("ΠΔ07", "Πρόληψη & Διαχείριση Πτώσεων", "Κλινική Ασφάλεια"),
            ("ΠΔ08", "Διαχείριση Κλινικών Εγγράφων", "Τεκμηρίωση"),
        ]
        for i, (code, name, cat) in enumerate(seed_procs):
            db_execute(f"{INSERT_IGNORE} procedures (code, name, category, sort_order) VALUES (%s,%s,%s,%s)",
                       (code, name, cat, i))
        logger.info("Έγινε seed 8 πρότυπων διαδικασιών")

    # Seed δεικτών ΤΑΕΠ (ΓΝ Λευκωσίας) — δύο ομάδες: Ενηλίκων & Παίδων.
    # Ίδιοι ορισμοί, ξεχωριστοί δείκτες ανά ομάδα. Τρέχει μία φορά (idempotent με INSERT IGNORE).
    if not db_execute("SELECT id FROM indicators WHERE grp='ΤΑΕΠ Ενηλίκων' LIMIT 1", fetch=True):
        # (num, name, category, unit, direction, target, low, high, max_score, description)
        taep_specs = [
            ("01", "Ανατροφοδότηση Ασθενών", "Εμπειρία Ασθενή", "/9", "higher_better",
             None, None, None, 15, "Μέση βαθμολογία όλων των ερωτηματολογίων που έχουν συλλεγεί για το ΤΑΕΠ."),
            ("02", "Χρόνος μέχρι τη Διαλογή", "Πρόσβαση & Ροή Ασθενών", "%", "higher_better",
             90, 90, None, 10, "Ποσοστό επισκέψεων με διαλογή εντός 10 λεπτών."),
            ("03", "Χρόνος από τη Διαλογή μέχρι τη Διαχείριση", "Πρόσβαση & Ροή Ασθενών", "", "higher_better",
             None, None, None, 20, "Σύνολο βαθμολογίας των επιμέρους κριτηρίων για τις κατηγορίες ESI (άθροισμα 3.1–3.4)."),
            ("03.1", "Χρόνος από τη Διαλογή μέχρι τη Διαχείριση – ESI 1", "Πρόσβαση & Ροή Ασθενών", "%", "higher_better",
             90, 90, None, 5, "Ποσοστό επισκέψεων με χρόνο μέχρι τη διαχείριση εντός 5 λεπτών."),
            ("03.2", "Χρόνος από τη Διαλογή μέχρι τη Διαχείριση – ESI 2", "Πρόσβαση & Ροή Ασθενών", "%", "higher_better",
             90, 90, None, 5, "Ποσοστό επισκέψεων με χρόνο μέχρι τη διαχείριση εντός 10 λεπτών."),
            ("03.3", "Χρόνος από τη Διαλογή μέχρι τη Διαχείριση – ESI 3", "Πρόσβαση & Ροή Ασθενών", "%", "higher_better",
             90, 90, None, 5, "Ποσοστό επισκέψεων με χρόνο μέχρι τη διαχείριση εντός 90 λεπτών."),
            ("03.4", "Χρόνος από τη Διαλογή μέχρι τη Διαχείριση – ESI 4", "Πρόσβαση & Ροή Ασθενών", "%", "higher_better",
             90, 90, None, 5, "Ποσοστό επισκέψεων με χρόνο μέχρι τη διαχείριση εντός 240 λεπτών."),
            ("04", "Συνολικός Χρόνος Διεκπεραίωσης Περιστατικού", "Πρόσβαση & Ροή Ασθενών", "%", "higher_better",
             90, 90, None, 10, "Ποσοστό επισκέψεων με χρόνο μέχρι τη διεκπεραίωση εντός 4 ωρών."),
            ("05", "Χρόνος Αποδέσμευσης Ασθενοφόρου", "Πρόσβαση & Ροή Ασθενών", "%", "higher_better",
             70, 50, None, 10, "Ποσοστό ασθενοφόρων που αποδεσμεύονται εντός 15 λεπτών. Βαθμολογία: ≥70%→10, 50–70%→5, <50%→0."),
            ("06", "Ποσοστό ασθενών που αποχωρούν χωρίς να τύχουν διαχείρισης", "Κλινική Ασφάλεια", "%", "lower_better",
             5, None, 5, 5, "Ποσοστό ασθενών που εγκαταλείπουν το ΤΑΕΠ πριν ολοκληρωθεί η κλινική τους διαχείριση."),
            ("07", "Ποσοστό ασθενών με επανεπισκέψεις σε ΤΑΕΠ εντός 72 ωρών", "Κλινική Αποτελεσματικότητα", "%", "lower_better",
             5, None, 5, 15, "Ένδειξη ποιότητας φροντίδας και πληρότητας αρχικής αντιμετώπισης."),
            ("08", "Τεκμηρίωση εκπαίδευσης ομάδας διαλογής", "Τεκμηρίωση", "", "higher_better",
             None, None, None, 15, "Επαλήθευση εκπαίδευσης και πιστοποίησης του προσωπικού που εκτελεί τη διαλογή (ΕΠΙΤΥΧΙΑ/ΑΠΟΤΥΧΙΑ)."),
        ]
        taep_groups = [("ΤΑΕΠ Ενηλίκων", "TAD"), ("ΤΑΕΠ Παίδων", "TPD")]
        for gi, (gname, prefix) in enumerate(taep_groups):
            for si, (num, name, cat, unit, direction, target, low, high, maxsc, desc) in enumerate(taep_specs):
                db_execute(
                    f"""{INSERT_IGNORE} indicators (code, name, category, description, unit, direction,
                       target_value, limit_low, limit_high, frequency, sort_order, active, grp, max_score)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (f"{prefix}-{num}", name, cat, desc, unit, direction,
                     target, low, high, "monthly", si, 1, gname, maxsc))
        logger.info("Έγινε seed δεικτών ΤΑΕΠ (Ενηλίκων & Παίδων)")

    # Migrations δεδομένων (idempotent): παλιοί κωδικοί TEN-→TAD-, συχνότητα ΤΑΕΠ → Μηνιαία
    db_execute("UPDATE indicators SET code=REPLACE(code, 'TEN-', 'TAD-') WHERE code LIKE 'TEN-%'")
    db_execute("UPDATE indicators SET frequency='monthly' "
               "WHERE grp IN ('ΤΑΕΠ Ενηλίκων','ΤΑΕΠ Παίδων') AND frequency='four_monthly'")


try:
    init_db()
except Exception as _e:  # άλλος worker πρόλαβε το seed — μη ρίξεις τον worker
    logger.warning(f"init_db: {_e}")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Παρακαλώ συνδεθείτε.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Decorator: απαιτεί ο χρήστης να έχει έναν από τους ρόλους."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                flash("Παρακαλώ συνδεθείτε.", "warning")
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                flash("Δεν έχετε δικαίωμα πρόσβασης.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator


def can_edit_hospital(hospital_code):
    """Ο χρήστης μπορεί να τροποποιήσει δεδομένα του συγκεκριμένου νοσηλευτηρίου;
    admin/central: όλα · quality_officer: μόνο το δικό του · viewer: κανένα."""
    role = session.get("role")
    if role in EDIT_ALL_ROLES:
        return True
    if role == "quality_officer":
        return session.get("hospital_code") == hospital_code
    return False


def can_add_hospital(hospital_code):
    """Ο χρήστης μπορεί να ΠΡΟΣΘΕΣΕΙ νέα δεδομένα (ο ρόλος quality_add προσθέτει αλλά ΔΕΝ τροποποιεί υπάρχοντα)."""
    role = session.get("role")
    if role in EDIT_ALL_ROLES:
        return True
    if role == "quality_officer":
        return session.get("hospital_code") == hospital_code
    if role == "quality_add":
        return True
    return False


def log_action(action, entity="", entity_id="", details=""):
    try:
        db_execute(
            "INSERT INTO audit_log (user_id, username, action, entity, entity_id, details) VALUES (%s,%s,%s,%s,%s,%s)",
            (session.get("user_id"), session.get("username", ""), action, entity, str(entity_id), details))
    except Exception as e:
        logger.error(f"audit: {e}")


def get_hospitals(active_only=True):
    sql = "SELECT * FROM hospitals"
    if active_only:
        sql += " WHERE active=1"
    sql += " ORDER BY sort_order, code"
    return db_execute(sql, fetch=True) or []


def hospital_names():
    return {h["code"]: h["name_el"] for h in get_hospitals(active_only=False)}


# ---------------------------------------------------------------------------
# Λογική κατάστασης δεικτών (εντός/εκτός στόχου & ορίων)
# ---------------------------------------------------------------------------
def value_status(ind, value):
    """Επιστρέφει 'ok' / 'warn' / 'alert' / None για τιμή δείκτη.
    alert = εκτός ορίου (limit) · warn = εκτός στόχου (target) · ok = εντός στόχου."""
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    d = ind.get("direction") or "lower_better"
    target = ind.get("target_value")
    low, high = ind.get("limit_low"), ind.get("limit_high")
    if d == "lower_better":
        if high is not None and v > float(high):
            return "alert"
        if target is not None and v > float(target):
            return "warn"
    elif d == "higher_better":
        if low is not None and v < float(low):
            return "alert"
        if target is not None and v < float(target):
            return "warn"
    else:  # range
        if (low is not None and v < float(low)) or (high is not None and v > float(high)):
            return "alert"
    return "ok"


def limits_text(ind):
    """Σύντομη περιγραφή στόχου/ορίων για tooltips & πίνακες."""
    parts = []
    if ind.get("target_value") is not None:
        parts.append(f"Στόχος: {fmtnum_filter(ind['target_value'])}")
    if ind.get("direction") == "higher_better":
        if ind.get("limit_low") is not None:
            parts.append(f"Όριο: ≥{fmtnum_filter(ind['limit_low'])}")
    elif ind.get("direction") == "range":
        if ind.get("limit_low") is not None or ind.get("limit_high") is not None:
            parts.append(f"Όρια: {fmtnum_filter(ind.get('limit_low'))}–{fmtnum_filter(ind.get('limit_high'))}")
    else:
        if ind.get("limit_high") is not None:
            parts.append(f"Όριο: ≤{fmtnum_filter(ind['limit_high'])}")
    return " · ".join(parts)


def latest_period_alerts():
    """Τιμές εκτός στόχου/ορίων στην πιο πρόσφατη καταχωρημένη περίοδο κάθε
    (δείκτη, νοσηλευτηρίου). Επιστρέφει λίστα dicts για dashboard/ειδοποιήσεις."""
    rows = db_execute("""
        SELECT iv.*, i.code AS ind_code, i.name AS ind_name, i.unit, i.direction,
               i.target_value, i.limit_low, i.limit_high, i.category
        FROM indicator_values iv
        JOIN indicators i ON i.id = iv.indicator_id
        WHERE i.active = 1 AND (iv.no_data IS NULL OR iv.no_data = 0)
        ORDER BY iv.year DESC, iv.month DESC
    """, fetch=True) or []
    seen = set()
    alerts = []
    for r in rows:
        key = (r["indicator_id"], r["hospital_code"])
        if key in seen:
            continue
        seen.add(key)
        st = value_status(r, r["value"])
        if st in ("warn", "alert"):
            r["status"] = st
            alerts.append(r)
    alerts.sort(key=lambda r: (r["status"] != "alert", r["ind_code"], r["hospital_code"]))
    return alerts


def latest_compliance_matrix():
    """Τελευταία αξιολόγηση ανά (διαδικασία, νοσηλευτήριο) → dict[(proc_id, hosp)] = row"""
    rows = db_execute("""
        SELECT ca.* FROM compliance_assessments ca
        ORDER BY ca.assess_date DESC, ca.id DESC
    """, fetch=True) or []
    latest = {}
    for r in rows:
        key = (r["procedure_id"], r["hospital_code"])
        if key not in latest:
            latest[key] = r
    return latest


# ---------------------------------------------------------------------------
# Εξαγωγή αριθμητικών δεδομένων από έγγραφα (Excel / Word)
# ---------------------------------------------------------------------------
MAX_METRICS_PER_DOC = 800
_NUM_RE = re.compile(r"^[-+]?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d+)?%?$|^[-+]?\d+(?:[.,]\d+)?%?$")


def _to_number(v):
    """Μετατροπή τιμής κελιού σε float — δέχεται και ελληνική μορφή (1.234,56 / 12,5%)."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().replace(" ", "")
    if not s or not _NUM_RE.match(s):
        return None
    s = s.rstrip("%").strip()
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")   # 1.234,56 → 1234.56
    elif "," in s:
        s = s.replace(",", ".")                     # 12,5 → 12.5
    try:
        return float(s)
    except ValueError:
        return None


def _clean_label(v):
    if v is None:
        return ""
    return re.sub(r"\s+", " ", str(v)).strip()[:300]


def parse_xlsx(path):
    """Εξάγει (grp, label, value) από όλα τα φύλλα ενός Excel.
    Εντοπίζει γραμμές-κεφαλίδες (όλα κείμενο) και τις συνδυάζει με τις ετικέτες
    γραμμών ώστε κάθε αριθμητικό κελί να πάρει περιγραφικό όνομα."""
    import openpyxl
    wb = openpyxl.load_workbook(path, data_only=True, read_only=True)
    metrics = []
    for ws in wb.worksheets[:10]:
        header = {}
        for row_no, row in enumerate(ws.iter_rows(min_row=1, max_row=500, max_col=30, values_only=True), 1):
            cells = list(row)
            non_empty = [(i, c) for i, c in enumerate(cells) if c is not None and str(c).strip() != ""]
            if not non_empty:
                continue
            numbers = [(i, _to_number(c)) for i, c in non_empty]
            numeric = [(i, n) for i, n in numbers if n is not None]
            texts = [(i, c) for (i, c), (_, n) in zip(non_empty, numbers) if n is None]
            # Γραμμή-κεφαλίδα: ≥2 κείμενα, κανένας αριθμός
            if len(texts) >= 2 and not numeric:
                header = {i: _clean_label(c) for i, c in texts}
                continue
            if not numeric or not texts:
                continue
            label = _clean_label(texts[0][1])
            if not label:
                continue
            for col_idx, num in numeric:
                col_name = header.get(col_idx, "")
                full = f"{label} — {col_name}" if col_name else label
                metrics.append((ws.title, full[:300], num, row_no))
                if len(metrics) >= MAX_METRICS_PER_DOC:
                    wb.close()
                    return metrics
    wb.close()
    return metrics


_PARA_METRIC_RE = re.compile(r"^(.{3,120}?)[:：]\s*([-+]?[\d.,]+\s*%?)\s*$")


def parse_docx(path):
    """Εξάγει (grp, label, value) από πίνακες & παραγράφους 'Ετικέτα: αριθμός' ενός Word."""
    import docx
    doc = docx.Document(path)
    metrics = []
    for ti, table in enumerate(doc.tables[:20], 1):
        rows = table.rows
        if not rows:
            continue
        header_cells = [_clean_label(c.text) for c in rows[0].cells]
        header_is_text = all(_to_number(h) is None for h in header_cells if h)
        start = 1 if (len(rows) > 1 and header_is_text) else 0
        grp = f"Πίνακας {ti}"
        for row_no, row in enumerate(rows[start:], start + 1):
            cells = [_clean_label(c.text) for c in row.cells]
            if not cells:
                continue
            label = cells[0]
            if not label or _to_number(label) is not None:
                continue
            for col_idx, cell in enumerate(cells[1:], 1):
                num = _to_number(cell)
                if num is None:
                    continue
                col_name = header_cells[col_idx] if start == 1 and col_idx < len(header_cells) else ""
                full = f"{label} — {col_name}" if col_name else label
                metrics.append((grp, full[:300], num, row_no))
                if len(metrics) >= MAX_METRICS_PER_DOC:
                    return metrics
    for para in doc.paragraphs[:500]:
        m = _PARA_METRIC_RE.match(para.text.strip())
        if m:
            num = _to_number(m.group(2))
            if num is not None:
                metrics.append(("Κείμενο", _clean_label(m.group(1)), num, 0))
                if len(metrics) >= MAX_METRICS_PER_DOC:
                    return metrics
    return metrics


def parse_document(doc_id):
    """Εξάγει metrics από αποθηκευμένο έγγραφο και τα γράφει στη DB.
    Ενημερώνει parse_status: parsed / no_data / unsupported / error."""
    docs = db_execute("SELECT * FROM documents WHERE id=%s", (doc_id,), fetch=True)
    if not docs:
        return
    d = docs[0]
    path = os.path.join(UPLOAD_FOLDER, d["filename"])
    ext = d["filename"].rsplit(".", 1)[-1].lower()
    db_execute("DELETE FROM document_metrics WHERE document_id=%s", (doc_id,))
    try:
        if ext == "xlsx":
            metrics = parse_xlsx(path)
        elif ext == "docx":
            metrics = parse_docx(path)
        else:
            db_execute("UPDATE documents SET parse_status='unsupported', parse_error=%s WHERE id=%s",
                       ("Η εξαγωγή δεδομένων υποστηρίζεται μόνο για .xlsx και .docx", doc_id))
            return
        for grp, label, value, row_no in metrics:
            db_execute("INSERT INTO document_metrics (document_id, grp, label, value, row_no) VALUES (%s,%s,%s,%s,%s)",
                       (doc_id, grp, label, value, row_no))
        status = "parsed" if metrics else "no_data"
        db_execute("UPDATE documents SET parse_status=%s, parse_error=NULL WHERE id=%s", (status, doc_id))
    except Exception as e:
        logger.error(f"parse_document {doc_id}: {e}")
        db_execute("UPDATE documents SET parse_status='error', parse_error=%s WHERE id=%s", (str(e)[:500], doc_id))


# ---------------------------------------------------------------------------
# Παραγωγή περιοδικής έκθεσης (Word)
# ---------------------------------------------------------------------------
STATUS_MARK = {"ok": "✔", "warn": "▲", "alert": "✖", None: "—"}


def generate_report_docx(year, month_from, month_to, hosp_codes):
    """Δημιουργεί .docx έκθεση δεικτών/συμμόρφωσης/επιθεωρήσεων για την περίοδο.
    Επιστρέφει το path του αρχείου."""
    import docx
    from docx.shared import Pt
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    settings = load_settings()
    hnames = hospital_names()
    hosp_codes = [h for h in hosp_codes if h in hnames]
    period_label = f"{MONTHS[month_from]} – {MONTHS[month_to]} {year}" if month_from != month_to \
        else f"{MONTHS[month_from]} {year}"

    doc = docx.Document()
    doc.styles["Normal"].font.size = Pt(10)

    h = doc.add_heading(settings.get("org_name", "ΟΚΥπΥ"), level=2)
    h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    t = doc.add_heading("Περιοδική Έκθεση Διασφάλισης Ποιότητας", level=0)
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p = doc.add_paragraph(f"Περίοδος αναφοράς: {period_label}")
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p = doc.add_paragraph("Νοσηλευτήρια: " + ", ".join(hnames[c] for c in hosp_codes))
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph(f"Ημερομηνία έκδοσης: {date.today().strftime('%d/%m/%Y')}").alignment = WD_ALIGN_PARAGRAPH.CENTER

    # --- 1. Δείκτες ποιότητας ---
    doc.add_heading("1. Δείκτες Ποιότητας", level=1)
    doc.add_paragraph("Μέση τιμή περιόδου ανά νοσηλευτήριο. Σήμανση: ✔ εντός στόχου, "
                      "▲ εκτός στόχου, ✖ εκτός ορίων, — χωρίς δεδομένα.")
    indicators = db_execute("SELECT * FROM indicators WHERE active=1 ORDER BY category, sort_order, code", fetch=True) or []
    values = db_execute("""
        SELECT indicator_id, hospital_code, AVG(value) AS avg_val, COUNT(*) AS cnt
        FROM indicator_values
        WHERE year=%s AND month BETWEEN %s AND %s AND (no_data IS NULL OR no_data=0)
        GROUP BY indicator_id, hospital_code
    """, (year, month_from, month_to), fetch=True) or []
    vmap = {(v["indicator_id"], v["hospital_code"]): v["avg_val"] for v in values}

    alerts_txt = []
    by_cat = {}
    for ind in indicators:
        by_cat.setdefault(ind["category"] or "Γενικοί", []).append(ind)
    for cat, inds in by_cat.items():
        doc.add_heading(cat, level=2)
        table = doc.add_table(rows=1, cols=2 + len(hosp_codes))
        table.style = "Table Grid"
        hdr = table.rows[0].cells
        hdr[0].text = "Δείκτης"
        hdr[1].text = "Στόχος/Όριο"
        for i, hc in enumerate(hosp_codes):
            hdr[2 + i].text = hc
        for ind in inds:
            row = table.add_row().cells
            unit = f" ({ind['unit']})" if ind.get("unit") else ""
            row[0].text = f"{ind['code']} {ind['name']}{unit}"
            row[1].text = limits_text(ind) or "—"
            for i, hc in enumerate(hosp_codes):
                v = vmap.get((ind["id"], hc))
                if v is None:
                    row[2 + i].text = "—"
                    continue
                st = value_status(ind, v)
                row[2 + i].text = f"{fmtnum_filter(v)} {STATUS_MARK.get(st, '')}"
                if st in ("warn", "alert"):
                    alerts_txt.append(
                        f"{ind['code']} {ind['name']} — {hnames.get(hc, hc)}: "
                        f"{fmtnum_filter(v)}{unit} ({'εκτός ορίων' if st == 'alert' else 'εκτός στόχου'}, {limits_text(ind)})")

    # --- 2. Επισημάνσεις ---
    doc.add_heading("2. Επισημάνσεις — Δείκτες εκτός στόχου/ορίων", level=1)
    if alerts_txt:
        for a in alerts_txt:
            doc.add_paragraph(a, style="List Bullet")
    else:
        doc.add_paragraph("Δεν εντοπίστηκαν δείκτες εκτός στόχου ή ορίων στην περίοδο αναφοράς.")

    # --- 3. Συμμόρφωση με πρότυπες διαδικασίες ---
    doc.add_heading("3. Συμμόρφωση με Πρότυπες Διαδικασίες", level=1)
    doc.add_paragraph("Τελευταία αξιολόγηση ανά διαδικασία. Π = πλήρης, Μ = μερική, Χ = μη συμμόρφωση, — = μη αξιολογημένη.")
    procedures = db_execute("SELECT * FROM procedures WHERE active=1 ORDER BY sort_order, code", fetch=True) or []
    latest = latest_compliance_matrix()
    comp_mark = {"compliant": "Π", "partial": "Μ", "non_compliant": "Χ"}
    table = doc.add_table(rows=1, cols=1 + len(hosp_codes))
    table.style = "Table Grid"
    hdr = table.rows[0].cells
    hdr[0].text = "Διαδικασία"
    for i, hc in enumerate(hosp_codes):
        hdr[1 + i].text = hc
    for proc in procedures:
        row = table.add_row().cells
        row[0].text = f"{proc['code']} {proc['name']}"
        for i, hc in enumerate(hosp_codes):
            a = latest.get((proc["id"], hc))
            row[1 + i].text = comp_mark.get(a["status"], "—") if a else "—"

    # --- 4. Επιθεωρήσεις ---
    doc.add_heading("4. Επιθεωρήσεις Περιόδου", level=1)
    date_from = f"{year}-{month_from:02d}-01"
    date_to = f"{year}-{month_to:02d}-31"
    placeholders = ",".join(["%s"] * len(hosp_codes))
    inspections = db_execute(
        f"""SELECT * FROM inspections
            WHERE inspection_date BETWEEN %s AND %s AND hospital_code IN ({placeholders})
            ORDER BY inspection_date""",
        tuple([date_from, date_to] + hosp_codes), fetch=True) or []
    if inspections:
        table = doc.add_table(rows=1, cols=6)
        table.style = "Table Grid"
        hdr = table.rows[0].cells
        for i, txt in enumerate(["Ημερομηνία", "Νοσηλευτήριο", "Τύπος", "Αντικείμενο", "Ευρήματα (Σ/Δ)", "Κατάσταση"]):
            hdr[i].text = txt
        for ins in inspections:
            row = table.add_row().cells
            row[0].text = fmtdate_filter(ins["inspection_date"])
            row[1].text = hnames.get(ins["hospital_code"], ins["hospital_code"])
            row[2].text = ins.get("itype") or ""
            row[3].text = ins.get("scope") or ""
            row[4].text = f"{ins.get('findings_major') or 0}/{ins.get('findings_minor') or 0}"
            row[5].text = INSPECTION_STATUS.get(ins.get("status"), ("", ""))[0]
    else:
        doc.add_paragraph("Δεν καταγράφηκαν επιθεωρήσεις στην περίοδο αναφοράς.")

    fname = f"ekthesi_poiotitas_{year}_{month_from:02d}-{month_to:02d}_{datetime.now().strftime('%Y%m%d%H%M%S')}.docx"
    out_path = os.path.join(REPORTS_FOLDER, fname)
    doc.save(out_path)
    return out_path


# ---------------------------------------------------------------------------
# Context processor — κοινά δεδομένα για όλα τα templates
# ---------------------------------------------------------------------------
@app.context_processor
def inject_globals():
    ctx = {
        "ROLES": ROLES,
        "MONTHS": MONTHS,
        "MONTHS_SHORT": MONTHS_SHORT,
        "DIRECTIONS": DIRECTIONS,
        "FREQUENCIES": FREQUENCIES,
        "STATUS_META": STATUS_META,
        "COMPLIANCE_STATUS": COMPLIANCE_STATUS,
        "INSPECTION_STATUS": INSPECTION_STATUS,
        "APP_SETTINGS": load_settings(),
        "CURRENT_YEAR": date.today().year,
        "alert_count": 0,
    }
    if session.get("user_id"):
        try:
            ctx["alert_count"] = len(latest_period_alerts())
        except Exception:
            pass
    return ctx


# ---------------------------------------------------------------------------
# Routes: Auth
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        users = db_execute("SELECT * FROM users WHERE username=%s AND active=1", (username,), fetch=True)
        if users and check_password_hash(users[0]["password_hash"], password):
            u = users[0]
            session.clear()
            session["user_id"] = u["id"]
            session["username"] = u["username"]
            session["full_name"] = u["full_name"]
            session["role"] = u["role"]
            session["hospital_code"] = u["hospital_code"]
            log_action("login", "user", u["id"])
            return redirect(url_for("dashboard"))
        flash("Λάθος όνομα χρήστη ή κωδικός.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    log_action("logout", "user", session.get("user_id", ""))
    session.clear()
    flash("Αποσυνδεθήκατε.", "info")
    return redirect(url_for("login"))


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old = request.form.get("old_password") or ""
        new = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""
        users = db_execute("SELECT * FROM users WHERE id=%s", (session["user_id"],), fetch=True)
        if not users or not check_password_hash(users[0]["password_hash"], old):
            flash("Ο τρέχων κωδικός δεν είναι σωστός.", "danger")
        elif len(new) < 6:
            flash("Ο νέος κωδικός πρέπει να έχει τουλάχιστον 6 χαρακτήρες.", "warning")
        elif new != confirm:
            flash("Οι νέοι κωδικοί δεν ταιριάζουν.", "warning")
        else:
            db_execute("UPDATE users SET password_hash=%s WHERE id=%s",
                       (generate_password_hash(new), session["user_id"]))
            log_action("change_password", "user", session["user_id"])
            flash("Ο κωδικός άλλαξε.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html")


@app.route("/api/heartbeat")
def api_heartbeat():
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Dashboard & Ειδοποιήσεις
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    hnames = hospital_names()
    alerts = latest_period_alerts()
    n_alert = sum(1 for a in alerts if a["status"] == "alert")
    n_warn = sum(1 for a in alerts if a["status"] == "warn")

    latest = latest_compliance_matrix()
    procs = {p["id"]: p for p in db_execute("SELECT * FROM procedures WHERE active=1", fetch=True) or []}
    comp_counts = {"compliant": 0, "partial": 0, "non_compliant": 0}
    non_compliant = []
    for (proc_id, hc), a in latest.items():
        if proc_id not in procs:
            continue
        if a["status"] in comp_counts:
            comp_counts[a["status"]] += 1
        if a["status"] == "non_compliant":
            non_compliant.append({"proc": procs[proc_id], "hospital_code": hc, "a": a})

    open_inspections = db_execute(
        "SELECT COUNT(*) AS c FROM inspections WHERE status='open'", fetch=True)[0]["c"]
    recent_inspections = db_execute(
        "SELECT * FROM inspections ORDER BY inspection_date DESC, id DESC LIMIT 5", fetch=True) or []
    recent_documents = db_execute(
        "SELECT * FROM documents ORDER BY uploaded_at DESC, id DESC LIMIT 5", fetch=True) or []

    # Επισημάνσεις ανά νοσηλευτήριο (bar chart)
    per_hosp = {}
    for a in alerts:
        per_hosp.setdefault(a["hospital_code"], {"alert": 0, "warn": 0})
        per_hosp[a["hospital_code"]][a["status"]] += 1
    hosp_chart = {
        "labels": [hnames.get(hc, hc) for hc in per_hosp],
        "alert": [v["alert"] for v in per_hosp.values()],
        "warn": [v["warn"] for v in per_hosp.values()],
    }

    return render_template(
        "dashboard.html", alerts=alerts[:15], n_alert=n_alert, n_warn=n_warn,
        comp_counts=comp_counts, non_compliant=non_compliant[:10],
        open_inspections=open_inspections, recent_inspections=recent_inspections,
        recent_documents=recent_documents, hosp_chart=hosp_chart, hnames=hnames)


@app.route("/alerts")
@login_required
def alerts_list():
    return render_template("alerts_list.html", alerts=latest_period_alerts(), hnames=hospital_names())


# ---------------------------------------------------------------------------
# Δείκτες Ποιότητας — ορισμοί
# ---------------------------------------------------------------------------
@app.route("/indicators")
@login_required
def indicators_list():
    category = request.args.get("category") or ""
    grp = request.args.get("grp") or ""
    conds, params = [], []
    if category:
        conds.append("category=%s")
        params.append(category)
    if grp:
        conds.append("grp=%s")
        params.append(grp)
    sql = "SELECT * FROM indicators"
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    # Ομάδες (grp) πρώτα (π.χ. ΤΑΕΠ), μετά οι γενικοί δείκτες χωρίς ομάδα
    sql += " ORDER BY (grp IS NULL OR grp=''), grp, category, sort_order, code"
    indicators = db_execute(sql, tuple(params), fetch=True) or []
    for ind in indicators:
        ind["limits"] = limits_text(ind)
    cat_rows = db_execute("SELECT DISTINCT category FROM indicators ORDER BY category", fetch=True) or []
    categories = [r["category"] for r in cat_rows if r["category"]]
    grp_rows = db_execute(
        "SELECT DISTINCT grp FROM indicators WHERE grp IS NOT NULL AND grp<>'' ORDER BY grp", fetch=True) or []
    groups = [r["grp"] for r in grp_rows]
    return render_template("indicators_list.html", indicators=indicators, categories=categories,
                           sel_category=category, sel_grp=grp, groups=groups)


def _indicator_from_form():
    def fnum(name):
        v = (request.form.get(name) or "").strip().replace(",", ".")
        return float(v) if v else None
    return {
        "code": (request.form.get("code") or "").strip(),
        "name": (request.form.get("name") or "").strip(),
        "category": (request.form.get("category") or "Γενικοί").strip(),
        "description": (request.form.get("description") or "").strip(),
        "unit": (request.form.get("unit") or "").strip(),
        "direction": request.form.get("direction") or "lower_better",
        "target_value": fnum("target_value"),
        "limit_low": fnum("limit_low"),
        "limit_high": fnum("limit_high"),
        "frequency": request.form.get("frequency") or "monthly",
        "sort_order": int(request.form.get("sort_order") or 0),
        "active": 1 if request.form.get("active") else 0,
        "grp": (request.form.get("grp") or "").strip() or None,
        "max_score": fnum("max_score"),
    }


@app.route("/indicators/new", methods=["GET", "POST"])
@role_required("admin", "central")
def indicator_new():
    if request.method == "POST":
        d = _indicator_from_form()
        if not d["code"] or not d["name"]:
            flash("Ο κωδικός και το όνομα είναι υποχρεωτικά.", "warning")
        elif db_execute("SELECT id FROM indicators WHERE code=%s", (d["code"],), fetch=True):
            flash("Υπάρχει ήδη δείκτης με αυτόν τον κωδικό.", "warning")
        else:
            rid = db_execute(
                """INSERT INTO indicators (code, name, category, description, unit, direction,
                   target_value, limit_low, limit_high, frequency, sort_order, active, grp, max_score)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (d["code"], d["name"], d["category"], d["description"], d["unit"], d["direction"],
                 d["target_value"], d["limit_low"], d["limit_high"], d["frequency"],
                 d["sort_order"], d["active"], d["grp"], d["max_score"]), lastrowid=True)
            log_action("create", "indicator", rid, d["code"])
            flash("Ο δείκτης δημιουργήθηκε.", "success")
            return redirect(url_for("indicators_list"))
    return render_template("indicator_form.html", ind=None)


@app.route("/indicators/<int:ind_id>/edit", methods=["GET", "POST"])
@role_required("admin", "central")
def indicator_edit(ind_id):
    rows = db_execute("SELECT * FROM indicators WHERE id=%s", (ind_id,), fetch=True)
    if not rows:
        abort(404)
    if request.method == "POST":
        d = _indicator_from_form()
        if not d["code"] or not d["name"]:
            flash("Ο κωδικός και το όνομα είναι υποχρεωτικά.", "warning")
        else:
            db_execute(
                """UPDATE indicators SET code=%s, name=%s, category=%s, description=%s, unit=%s,
                   direction=%s, target_value=%s, limit_low=%s, limit_high=%s, frequency=%s,
                   sort_order=%s, active=%s, grp=%s, max_score=%s WHERE id=%s""",
                (d["code"], d["name"], d["category"], d["description"], d["unit"], d["direction"],
                 d["target_value"], d["limit_low"], d["limit_high"], d["frequency"],
                 d["sort_order"], d["active"], d["grp"], d["max_score"], ind_id))
            log_action("update", "indicator", ind_id, d["code"])
            flash("Ο δείκτης ενημερώθηκε.", "success")
            return redirect(url_for("indicators_list"))
    return render_template("indicator_form.html", ind=rows[0])


@app.route("/indicators/<int:ind_id>")
@login_required
def indicator_view(ind_id):
    rows = db_execute("SELECT * FROM indicators WHERE id=%s", (ind_id,), fetch=True)
    if not rows:
        abort(404)
    ind = rows[0]
    year = int(request.args.get("year") or date.today().year)
    hospitals = get_hospitals()
    values = db_execute(
        "SELECT * FROM indicator_values WHERE indicator_id=%s AND year=%s", (ind_id, year), fetch=True) or []
    vmap = {(v["hospital_code"], v["month"]): v["value"] for v in values if not v.get("no_data")}
    datasets = []
    for h in hospitals:
        data = [vmap.get((h["code"], m)) for m in range(1, 13)]
        if any(v is not None for v in data):
            datasets.append({"label": h["name_el"], "data": data})
    # Πίνακας πρόσφατων καταχωρήσεων με κατάσταση
    recent = db_execute("""
        SELECT * FROM indicator_values WHERE indicator_id=%s
        ORDER BY year DESC, month DESC, hospital_code LIMIT 60""", (ind_id,), fetch=True) or []
    for r in recent:
        r["status"] = None if r.get("no_data") else value_status(ind, r["value"])
    years = [r["year"] for r in db_execute(
        "SELECT DISTINCT year FROM indicator_values WHERE indicator_id=%s ORDER BY year DESC",
        (ind_id,), fetch=True) or []]
    return render_template("indicator_view.html", ind=ind, datasets=datasets, year=year,
                           years=years or [year], recent=recent, hnames=hospital_names(),
                           limits=limits_text(ind))


# ---------------------------------------------------------------------------
# Καταχώρηση τιμών δεικτών
# ---------------------------------------------------------------------------
def _indicators_for_month(month):
    """Δείκτες που καταχωρούνται τον συγκεκριμένο μήνα (βάσει συχνότητας)."""
    inds = db_execute("SELECT * FROM indicators WHERE active=1 ORDER BY category, sort_order, code",
                      fetch=True) or []
    out = []
    for i in inds:
        f = i.get("frequency") or "monthly"
        if f == "monthly" or (f == "quarterly" and month in (3, 6, 9, 12)) or (f == "yearly" and month == 12):
            out.append(i)
    return out


@app.route("/values", methods=["GET", "POST"])
@login_required
def values_entry():
    today = date.today()
    # Διαθέσιμες ομάδες δεικτών (π.χ. ΤΑΕΠ Ενηλίκων / ΤΑΕΠ Παίδων)
    grp_rows = db_execute(
        "SELECT DISTINCT grp FROM indicators WHERE grp IS NOT NULL AND grp<>'' ORDER BY grp", fetch=True) or []
    groups = [r["grp"] for r in grp_rows]
    grp = request.values.get("grp") or ""
    if grp and grp not in groups:
        grp = ""

    # Το σύστημα λειτουργεί προς το παρόν μόνο για το Γενικό Νοσοκομείο Λευκωσίας — χωρίς επιλογή νοσηλευτηρίου
    hosp = "NGH"
    hosp_name = hospital_names().get(hosp, "Γενικό Νοσοκομείο Λευκωσίας")
    year = int(request.values.get("year") or today.year)

    # Χρονικό διάστημα (Από/Μέχρι μήνα). Fallback στο παλιό 'month' για συμβατότητα.
    def _m(name):
        try:
            return min(12, max(1, int(request.values.get(name) or request.values.get("month") or today.month)))
        except (TypeError, ValueError):
            return today.month
    month_from = _m("month_from")
    month_to = _m("month_to")
    if month_from > month_to:
        month_from, month_to = month_to, month_from
    month = month_to  # κλειδί περιόδου (τέλος διαστήματος) για μοναδικότητα & γραφήματα
    can_edit = can_edit_hospital(hosp)   # τροποποίηση/διαγραφή υπαρχόντων
    can_add = can_add_hospital(hosp)     # προσθήκη νέων (π.χ. ρόλος quality_add)
    editable = can_add                   # μπορεί να αλληλεπιδράσει με τη φόρμα

    # Όλοι οι ενεργοί δείκτες της επιλεγμένης ομάδας ('' = γενικοί)· η περίοδος επιλέγεται χειροκίνητα
    indicators = [i for i in (db_execute(
        "SELECT * FROM indicators WHERE active=1 ORDER BY category, sort_order, code", fetch=True) or [])
        if (i.get("grp") or "") == grp]
    scored = bool(grp)  # οι ομάδες ΤΑΕΠ έχουν σύστημα βαθμολογίας (Αποτέλεσμα + Βαθμολογία)

    if request.method == "POST":
        if not editable:
            flash("Δεν έχετε δικαίωμα καταχώρησης.", "danger")
            return redirect(url_for("values_entry", year=year, month_from=month_from, month_to=month_to, grp=grp))
        ref_no = (request.form.get("ref_no") or "").strip()[:50]
        saved = deleted = skipped = 0
        for ind in indicators:
            raw = (request.form.get(f"val_{ind['id']}") or "").strip()
            score_raw = (request.form.get(f"score_{ind['id']}") or "").strip().replace(",", ".")
            comment = (request.form.get(f"com_{ind['id']}") or "").strip()[:500]
            existing = db_execute(
                "SELECT id FROM indicator_values WHERE indicator_id=%s AND hospital_code=%s AND year=%s AND month=%s",
                (ind["id"], hosp, year, month), fetch=True)
            if raw == "" and score_raw == "":
                if existing and can_edit:
                    db_execute("DELETE FROM indicator_values WHERE id=%s", (existing[0]["id"],))
                    deleted += 1
                continue
            # Αριθμητική τιμή (για χρωματισμό/γραφήματα)· μη-αριθμητικό αποτέλεσμα (π.χ. «NO DATA»)
            # γίνεται δεκτό ως «χωρίς δεδομένα» (no_data=1) και ΔΕΝ μετράει ως 0 σε στατιστικά/ειδοποιήσεις.
            num = raw.replace(",", ".").rstrip("%").strip()
            no_data = 0
            try:
                value = float(num)
            except ValueError:
                value = 0.0
                if raw != "":
                    no_data = 1
            result_text = raw[:100] or None
            try:
                score = float(score_raw) if score_raw else None
            except ValueError:
                score = None
            if existing:
                if not can_edit:
                    skipped += 1  # ρόλος «προσθήκη»: δεν τροποποιεί υπάρχοντα δεδομένα
                    continue
                db_execute(
                    "UPDATE indicator_values SET value=%s, result_text=%s, score=%s, no_data=%s, comment=%s, "
                    "month_from=%s, month_to=%s, created_by=%s, updated_at=" + NOW + " WHERE id=%s",
                    (value, result_text, score, no_data, comment, month_from, month_to, session["username"], existing[0]["id"]))
            else:
                db_execute(
                    "INSERT INTO indicator_values (indicator_id, hospital_code, year, month, month_from, month_to, "
                    "value, result_text, score, no_data, comment, created_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (ind["id"], hosp, year, month, month_from, month_to, value, result_text, score, no_data, comment, session["username"]))
            saved += 1
        # Αριθμός αναφοράς εγγράφου — εφαρμόζεται σε όλες τις γραμμές της περιόδου της ομάδας
        ids = [i["id"] for i in indicators]
        if ids:
            ph = ",".join(["%s"] * len(ids))
            ref_sql = (f"UPDATE indicator_values SET ref_no=%s WHERE hospital_code=%s AND year=%s AND month=%s "
                       f"AND indicator_id IN ({ph})")
            if not can_edit:
                ref_sql += " AND (ref_no IS NULL OR ref_no='')"  # ρόλος «προσθήκη»: μόνο σε νέες γραμμές
            db_execute(ref_sql, tuple([ref_no or None, hosp, year, month] + ids))
        log_action("save_values", "indicator_values",
                   f"{hosp}/{year}-{month_from:02d}..{month_to:02d}" + (f" · {grp}" if grp else "")
                   + (f" · {ref_no}" if ref_no else ""),
                   f"{saved} τιμές, {deleted} διαγραφές, {skipped} χωρίς αλλαγή")
        msg = f"Αποθηκεύτηκαν {saved} τιμές" + (f", διαγράφηκαν {deleted}" if deleted else "") + "."
        if skipped:
            msg += f" {skipped} υπάρχουσες τιμές δεν τροποποιήθηκαν (δικαίωμα μόνο προσθήκης)."
        flash(msg, "warning" if skipped else "success")
        return redirect(url_for("values_entry", year=year, month_from=month_from, month_to=month_to, grp=grp))

    existing = db_execute(
        "SELECT * FROM indicator_values WHERE hospital_code=%s AND year=%s AND month=%s",
        (hosp, year, month), fetch=True) or []
    vmap = {v["indicator_id"]: v for v in existing}
    ref_no = ""
    for ind in indicators:
        v = vmap.get(ind["id"])
        if v and v.get("ref_no") and not ref_no:
            ref_no = v["ref_no"]
        ind["value"] = v["value"] if v else None
        ind["result_text"] = v.get("result_text") if v else None
        ind["score"] = v.get("score") if v else None
        ind["no_data"] = v.get("no_data") if v else 0
        ind["comment"] = v["comment"] if v else ""
        ind["status"] = None if (v and v.get("no_data")) else (value_status(ind, ind["value"]) if v else None)
        ind["limits"] = limits_text(ind)
        # Κλείδωμα υπαρχόντων για ρόλο «προσθήκη» (δεν τροποποιεί ήδη καταχωρημένα)
        ind["locked"] = (v is not None) and (not can_edit)
    years = list(range(today.year - 5, today.year + 1))[::-1]
    return render_template("values_entry.html", hosp=hosp, hosp_name=hosp_name, year=year,
                           month_from=month_from, month_to=month_to, years=years, indicators=indicators,
                           editable=editable, can_edit=can_edit, groups=groups, grp=grp,
                           scored=scored, ref_no=ref_no)


# ---------------------------------------------------------------------------
# Σύγκριση & τάσεις
# ---------------------------------------------------------------------------
@app.route("/compare")
@login_required
def compare_view():
    grp_rows = db_execute(
        "SELECT DISTINCT grp FROM indicators WHERE grp IS NOT NULL AND grp<>'' ORDER BY grp", fetch=True) or []
    groups = [r["grp"] for r in grp_rows]
    grp = request.args.get("grp") or ""
    if grp and grp not in groups:
        grp = ""
    inds = [i for i in (db_execute(
        "SELECT * FROM indicators WHERE active=1 ORDER BY category, sort_order, code", fetch=True) or [])
        if (i.get("grp") or "") == grp]
    scored = bool(grp)
    options = []
    if scored:
        options.append({"id": "total", "label": "Ολική Βαθμολογία (σύνολο)"})
    for i in inds:
        options.append({"id": str(i["id"]), "label": f"{i['code']} — {i['name']}"})
    sel = request.args.get("indicator") or (options[0]["id"] if options else "")
    is_total = scored and sel == "total"

    def plabel(y, mf, mt):
        try:
            return f"{MONTHS_SHORT[mf]} {y}" if mf == mt else f"{MONTHS_SHORT[mf]}–{MONTHS_SHORT[mt]} {y}"
        except Exception:
            return str(y)

    hnames = hospital_names()
    labels, datasets, series = [], [], []
    title, unit, max_score = "", "", None
    lim_target = lim_low = lim_high = None

    if is_total:
        rows = db_execute(
            "SELECT iv.year AS y, iv.month AS m, iv.month_from AS mf, iv.month_to AS mt, iv.score AS score "
            "FROM indicator_values iv JOIN indicators i ON i.id = iv.indicator_id "
            "WHERE i.grp=%s AND iv.hospital_code='NGH' AND i.code NOT LIKE %s", (grp, "%.%"), fetch=True) or []
        agg = {}
        for r in rows:
            if r["score"] is None:
                continue
            mf = r["mf"] or r["m"]; mt = r["mt"] or r["m"]
            agg[(r["y"], mf, mt)] = agg.get((r["y"], mf, mt), 0) + r["score"]
        periods = sorted(agg, key=lambda k: (k[0], k[2], k[1]))
        labels = [plabel(*pp) for pp in periods]
        datasets = [{"label": "Ολική Βαθμολογία", "data": [round(agg[pp], 2) for pp in periods]}]
        title = f"Ολική Βαθμολογία — {grp}"
        unit = "βαθμοί (σύνολο)"
    elif sel:
        ind = next((i for i in inds if str(i["id"]) == str(sel)), inds[0] if inds else None)
        if ind:
            rows = db_execute(
                "SELECT hospital_code AS hc, year AS y, month AS m, month_from AS mf, month_to AS mt, "
                "value AS v, score AS sc, comment AS cm, result_text AS rt, no_data AS nd "
                "FROM indicator_values WHERE indicator_id=%s", (ind["id"],), fetch=True) or []
            pset = {}
            for r in rows:
                mf = r["mf"] or r["m"]; mt = r["mt"] or r["m"]
                pset[(r["y"], mf, mt)] = True
            periods = sorted(pset, key=lambda k: (k[0], k[2], k[1]))
            pidx = {pp: idx for idx, pp in enumerate(periods)}
            labels = [plabel(*pp) for pp in periods]
            byhc = {}
            for r in rows:
                mf = r["mf"] or r["m"]; mt = r["mt"] or r["m"]
                j = pidx[(r["y"], mf, mt)]
                d = byhc.setdefault(r["hc"], {"values": [None] * len(periods), "scores": [None] * len(periods),
                                             "comments": [""] * len(periods), "results": [""] * len(periods)})
                d["values"][j] = None if r.get("nd") else r["v"]
                d["scores"][j] = r["sc"]
                d["comments"][j] = r.get("cm") or ""
                d["results"][j] = r.get("rt") or ("" if r["v"] is None else fmtnum_filter(r["v"]))
            series = [dict(label=hnames.get(hc, hc), **d) for hc, d in byhc.items()]
            title = f"{ind['code']} — {ind['name']}"
            unit = ind.get("unit") or ""
            max_score = ind.get("max_score")
            lim_target = ind.get("target_value"); lim_low = ind.get("limit_low"); lim_high = ind.get("limit_high")

    return render_template("compare.html", groups=groups, grp=grp, options=options, sel=str(sel),
                           labels=labels, datasets=datasets, series=series, is_total=is_total,
                           title=title, unit=unit, scored=scored, max_score=max_score,
                           lim_target=lim_target, lim_low=lim_low, lim_high=lim_high)


# ---------------------------------------------------------------------------
# Πρότυπες διαδικασίες & Συμμόρφωση
# ---------------------------------------------------------------------------
@app.route("/procedures")
@login_required
def procedures_list():
    procedures = db_execute("SELECT * FROM procedures ORDER BY category, sort_order, code", fetch=True) or []
    return render_template("procedures_list.html", procedures=procedures)


@app.route("/procedures/new", methods=["GET", "POST"])
@role_required("admin", "central")
def procedure_new():
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        name = (request.form.get("name") or "").strip()
        if not code or not name:
            flash("Ο κωδικός και το όνομα είναι υποχρεωτικά.", "warning")
        elif db_execute("SELECT id FROM procedures WHERE code=%s", (code,), fetch=True):
            flash("Υπάρχει ήδη διαδικασία με αυτόν τον κωδικό.", "warning")
        else:
            rid = db_execute(
                "INSERT INTO procedures (code, name, category, description, sort_order, active) VALUES (%s,%s,%s,%s,%s,%s)",
                (code, name, (request.form.get("category") or "Γενικές").strip(),
                 (request.form.get("description") or "").strip(),
                 int(request.form.get("sort_order") or 0),
                 1 if request.form.get("active") else 0), lastrowid=True)
            log_action("create", "procedure", rid, code)
            flash("Η διαδικασία δημιουργήθηκε.", "success")
            return redirect(url_for("procedures_list"))
    return render_template("procedure_form.html", proc=None)


@app.route("/procedures/<int:proc_id>/edit", methods=["GET", "POST"])
@role_required("admin", "central")
def procedure_edit(proc_id):
    rows = db_execute("SELECT * FROM procedures WHERE id=%s", (proc_id,), fetch=True)
    if not rows:
        abort(404)
    if request.method == "POST":
        db_execute(
            "UPDATE procedures SET code=%s, name=%s, category=%s, description=%s, sort_order=%s, active=%s WHERE id=%s",
            ((request.form.get("code") or "").strip(), (request.form.get("name") or "").strip(),
             (request.form.get("category") or "Γενικές").strip(),
             (request.form.get("description") or "").strip(),
             int(request.form.get("sort_order") or 0),
             1 if request.form.get("active") else 0, proc_id))
        log_action("update", "procedure", proc_id)
        flash("Η διαδικασία ενημερώθηκε.", "success")
        return redirect(url_for("procedures_list"))
    return render_template("procedure_form.html", proc=rows[0])


@app.route("/compliance")
@login_required
def compliance_matrix():
    procedures = db_execute("SELECT * FROM procedures WHERE active=1 ORDER BY category, sort_order, code",
                            fetch=True) or []
    hospitals = get_hospitals()
    latest = latest_compliance_matrix()
    matrix = []
    for p in procedures:
        cells = []
        for h in hospitals:
            a = latest.get((p["id"], h["code"]))
            cells.append({"hospital": h["code"], "a": a})
        matrix.append({"proc": p, "cells": cells})
    return render_template("compliance_matrix.html", matrix=matrix, hospitals=hospitals)


@app.route("/compliance/list")
@login_required
def compliance_list():
    hosp = request.args.get("hospital") or ""
    proc = request.args.get("procedure") or ""
    sql = """SELECT ca.*, p.code AS proc_code, p.name AS proc_name
             FROM compliance_assessments ca JOIN procedures p ON p.id = ca.procedure_id WHERE 1=1"""
    params = []
    if hosp:
        sql += " AND ca.hospital_code=%s"
        params.append(hosp)
    if proc:
        sql += " AND ca.procedure_id=%s"
        params.append(int(proc))
    sql += " ORDER BY ca.assess_date DESC, ca.id DESC LIMIT 300"
    assessments = db_execute(sql, tuple(params), fetch=True) or []
    procedures = db_execute("SELECT * FROM procedures ORDER BY code", fetch=True) or []
    return render_template("compliance_list.html", assessments=assessments,
                           hospitals=get_hospitals(), procedures=procedures,
                           sel_hospital=hosp, sel_procedure=proc, hnames=hospital_names())


@app.route("/compliance/new", methods=["GET", "POST"])
@login_required
def compliance_new():
    procedures = db_execute("SELECT * FROM procedures WHERE active=1 ORDER BY code", fetch=True) or []
    if request.method == "POST":
        hosp = request.form.get("hospital_code") or ""
        if not can_add_hospital(hosp):
            flash("Δεν έχετε δικαίωμα καταχώρησης για αυτό το νοσηλευτήριο.", "danger")
            return redirect(url_for("compliance_matrix"))
        score = (request.form.get("score") or "").strip()
        rid = db_execute(
            """INSERT INTO compliance_assessments
               (procedure_id, hospital_code, assess_date, status, score, findings, actions, created_by)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (int(request.form.get("procedure_id")), hosp,
             request.form.get("assess_date") or date.today().isoformat(),
             request.form.get("status") or "compliant",
             int(score) if score else None,
             (request.form.get("findings") or "").strip(),
             (request.form.get("actions") or "").strip(),
             session["username"]), lastrowid=True)
        log_action("create", "compliance", rid)
        flash("Η αξιολόγηση καταχωρήθηκε.", "success")
        return redirect(url_for("compliance_matrix"))
    preselect = {
        "procedure_id": request.args.get("procedure", type=int),
        "hospital_code": request.args.get("hospital") or session.get("hospital_code"),
    }
    return render_template("compliance_form.html", a=None, procedures=procedures,
                           hospitals=get_hospitals(), preselect=preselect, today=date.today().isoformat())


@app.route("/compliance/<int:a_id>/edit", methods=["GET", "POST"])
@login_required
def compliance_edit(a_id):
    rows = db_execute("SELECT * FROM compliance_assessments WHERE id=%s", (a_id,), fetch=True)
    if not rows:
        abort(404)
    a = rows[0]
    if not can_edit_hospital(a["hospital_code"]):
        flash("Δεν έχετε δικαίωμα επεξεργασίας.", "danger")
        return redirect(url_for("compliance_list"))
    procedures = db_execute("SELECT * FROM procedures ORDER BY code", fetch=True) or []
    if request.method == "POST":
        score = (request.form.get("score") or "").strip()
        db_execute(
            """UPDATE compliance_assessments SET procedure_id=%s, hospital_code=%s, assess_date=%s,
               status=%s, score=%s, findings=%s, actions=%s WHERE id=%s""",
            (int(request.form.get("procedure_id")), request.form.get("hospital_code"),
             request.form.get("assess_date") or date.today().isoformat(),
             request.form.get("status") or "compliant",
             int(score) if score else None,
             (request.form.get("findings") or "").strip(),
             (request.form.get("actions") or "").strip(), a_id))
        log_action("update", "compliance", a_id)
        flash("Η αξιολόγηση ενημερώθηκε.", "success")
        return redirect(url_for("compliance_list"))
    return render_template("compliance_form.html", a=a, procedures=procedures,
                           hospitals=get_hospitals(), preselect={}, today=date.today().isoformat())


# ---------------------------------------------------------------------------
# Επιθεωρήσεις
# ---------------------------------------------------------------------------
@app.route("/inspections")
@login_required
def inspections_list():
    hosp = request.args.get("hospital") or ""
    status = request.args.get("status") or ""
    sql = "SELECT * FROM inspections WHERE 1=1"
    params = []
    if hosp:
        sql += " AND hospital_code=%s"
        params.append(hosp)
    if status:
        sql += " AND status=%s"
        params.append(status)
    sql += " ORDER BY inspection_date DESC, id DESC LIMIT 300"
    inspections = db_execute(sql, tuple(params), fetch=True) or []
    return render_template("inspections_list.html", inspections=inspections,
                           hospitals=get_hospitals(), sel_hospital=hosp, sel_status=status,
                           hnames=hospital_names(), types=INSPECTION_TYPES)


def _inspection_from_form():
    def fint(name):
        v = (request.form.get(name) or "").strip()
        return int(v) if v else 0
    score = (request.form.get("score") or "").strip().replace(",", ".")
    return (
        request.form.get("hospital_code") or "",
        request.form.get("inspection_date") or date.today().isoformat(),
        (request.form.get("itype") or "Εσωτερική").strip(),
        (request.form.get("body") or "").strip(),
        (request.form.get("scope") or "").strip(),
        float(score) if score else None,
        fint("findings_major"), fint("findings_minor"), fint("observations"),
        request.form.get("status") or "open",
        (request.form.get("summary") or "").strip(),
        (request.form.get("actions") or "").strip(),
    )


@app.route("/inspections/new", methods=["GET", "POST"])
@login_required
def inspection_new():
    if request.method == "POST":
        vals = _inspection_from_form()
        if not can_add_hospital(vals[0]):
            flash("Δεν έχετε δικαίωμα καταχώρησης για αυτό το νοσηλευτήριο.", "danger")
            return redirect(url_for("inspections_list"))
        rid = db_execute(
            """INSERT INTO inspections (hospital_code, inspection_date, itype, body, scope, score,
               findings_major, findings_minor, observations, status, summary, actions, created_by)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            vals + (session["username"],), lastrowid=True)
        log_action("create", "inspection", rid)
        flash("Η επιθεώρηση καταχωρήθηκε.", "success")
        return redirect(url_for("inspection_view", ins_id=rid))
    return render_template("inspection_form.html", ins=None, hospitals=get_hospitals(),
                           types=INSPECTION_TYPES, today=date.today().isoformat())


@app.route("/inspections/<int:ins_id>")
@login_required
def inspection_view(ins_id):
    rows = db_execute("SELECT * FROM inspections WHERE id=%s", (ins_id,), fetch=True)
    if not rows:
        abort(404)
    return render_template("inspection_view.html", ins=rows[0], hnames=hospital_names(),
                           can_edit=can_edit_hospital(rows[0]["hospital_code"]))


@app.route("/inspections/<int:ins_id>/edit", methods=["GET", "POST"])
@login_required
def inspection_edit(ins_id):
    rows = db_execute("SELECT * FROM inspections WHERE id=%s", (ins_id,), fetch=True)
    if not rows:
        abort(404)
    if not can_edit_hospital(rows[0]["hospital_code"]):
        flash("Δεν έχετε δικαίωμα επεξεργασίας.", "danger")
        return redirect(url_for("inspection_view", ins_id=ins_id))
    if request.method == "POST":
        vals = _inspection_from_form()
        db_execute(
            """UPDATE inspections SET hospital_code=%s, inspection_date=%s, itype=%s, body=%s,
               scope=%s, score=%s, findings_major=%s, findings_minor=%s, observations=%s,
               status=%s, summary=%s, actions=%s WHERE id=%s""",
            vals + (ins_id,))
        log_action("update", "inspection", ins_id)
        flash("Η επιθεώρηση ενημερώθηκε.", "success")
        return redirect(url_for("inspection_view", ins_id=ins_id))
    return render_template("inspection_form.html", ins=rows[0], hospitals=get_hospitals(),
                           types=INSPECTION_TYPES, today=date.today().isoformat())


# ---------------------------------------------------------------------------
# Έγγραφα (Word/Excel) & εξαγωγή δεδομένων
# ---------------------------------------------------------------------------
@app.route("/documents")
@login_required
def documents_list():
    hosp = request.args.get("hospital") or ""
    category = request.args.get("category") or ""
    sql = """SELECT d.*, (SELECT COUNT(*) FROM document_metrics m WHERE m.document_id = d.id) AS metrics_count
             FROM documents d WHERE 1=1"""
    params = []
    if hosp:
        sql += " AND d.hospital_code=%s"
        params.append(hosp)
    if category:
        sql += " AND d.category=%s"
        params.append(category)
    sql += " ORDER BY d.uploaded_at DESC, d.id DESC LIMIT 300"
    documents = db_execute(sql, tuple(params), fetch=True) or []
    return render_template("documents_list.html", documents=documents, hospitals=get_hospitals(),
                           categories=DOCUMENT_CATEGORIES, sel_hospital=hosp, sel_category=category,
                           hnames=hospital_names(), can_upload=session.get("role") != "viewer")


@app.route("/documents/upload", methods=["POST"])
@login_required
def document_upload():
    hosp = request.form.get("hospital_code") or ""
    if not can_add_hospital(hosp):
        flash("Δεν έχετε δικαίωμα καταχώρησης εγγράφων για αυτό το νοσηλευτήριο.", "danger")
        return redirect(url_for("documents_list"))
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Δεν επιλέχθηκε αρχείο.", "warning")
        return redirect(url_for("documents_list"))
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        flash(f"Μη αποδεκτός τύπος αρχείου (.{ext}). Αποδεκτοί: {', '.join(sorted(ALLOWED_EXTENSIONS))}", "warning")
        return redirect(url_for("documents_list"))
    stored = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}.{ext}"
    f.save(os.path.join(UPLOAD_FOLDER, stored))
    title = (request.form.get("title") or "").strip() or os.path.splitext(f.filename)[0]
    year = request.form.get("year", type=int)
    month = request.form.get("month", type=int)
    doc_id = db_execute(
        """INSERT INTO documents (hospital_code, title, category, year, month, filename, orig_name, uploaded_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (hosp, title[:300], request.form.get("category") or "Γενικά", year, month,
         stored, secure_filename(f.filename)[:300], session["username"]), lastrowid=True)
    parse_document(doc_id)
    log_action("upload", "document", doc_id, title)
    flash("Το έγγραφο ανέβηκε και αναλύθηκε.", "success")
    return redirect(url_for("document_view", doc_id=doc_id))


@app.route("/documents/<int:doc_id>")
@login_required
def document_view(doc_id):
    rows = db_execute("SELECT * FROM documents WHERE id=%s", (doc_id,), fetch=True)
    if not rows:
        abort(404)
    d = rows[0]
    metrics = db_execute("SELECT * FROM document_metrics WHERE document_id=%s ORDER BY grp, row_no, id",
                         (doc_id,), fetch=True) or []
    groups = {}
    for m in metrics:
        groups.setdefault(m["grp"] or "Δεδομένα", []).append(m)
    charts = []
    for grp, items in list(groups.items())[:6]:
        subset = items[:40]
        charts.append({"grp": grp, "labels": [m["label"] for m in subset],
                       "data": [m["value"] for m in subset]})
    return render_template("document_view.html", d=d, groups=groups, charts=charts,
                           hnames=hospital_names(),
                           can_edit=can_edit_hospital(d["hospital_code"]))


@app.route("/documents/<int:doc_id>/download")
@login_required
def document_download(doc_id):
    rows = db_execute("SELECT * FROM documents WHERE id=%s", (doc_id,), fetch=True)
    if not rows:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, rows[0]["filename"], as_attachment=True,
                               download_name=rows[0]["orig_name"] or rows[0]["filename"])


@app.route("/documents/<int:doc_id>/reparse", methods=["POST"])
@login_required
def document_reparse(doc_id):
    rows = db_execute("SELECT * FROM documents WHERE id=%s", (doc_id,), fetch=True)
    if not rows:
        abort(404)
    if not can_edit_hospital(rows[0]["hospital_code"]):
        flash("Δεν έχετε δικαίωμα.", "danger")
        return redirect(url_for("document_view", doc_id=doc_id))
    parse_document(doc_id)
    log_action("reparse", "document", doc_id)
    flash("Το έγγραφο αναλύθηκε ξανά.", "success")
    return redirect(url_for("document_view", doc_id=doc_id))


@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def document_delete(doc_id):
    rows = db_execute("SELECT * FROM documents WHERE id=%s", (doc_id,), fetch=True)
    if not rows:
        abort(404)
    d = rows[0]
    if not (can_edit_hospital(d["hospital_code"]) or d["uploaded_by"] == session.get("username")):
        flash("Δεν έχετε δικαίωμα διαγραφής.", "danger")
        return redirect(url_for("document_view", doc_id=doc_id))
    db_execute("DELETE FROM document_metrics WHERE document_id=%s", (doc_id,))
    db_execute("DELETE FROM documents WHERE id=%s", (doc_id,))
    try:
        os.remove(os.path.join(UPLOAD_FOLDER, d["filename"]))
    except OSError:
        pass
    log_action("delete", "document", doc_id, d["title"])
    flash("Το έγγραφο διαγράφηκε.", "success")
    return redirect(url_for("documents_list"))


# ---------------------------------------------------------------------------
# Εκθέσεις προς τη διοίκηση
# ---------------------------------------------------------------------------
@app.route("/reports", methods=["GET", "POST"])
@login_required
def reports_page():
    hospitals = get_hospitals()
    today = date.today()
    if request.method == "POST":
        year = int(request.form.get("year") or today.year)
        month_from = int(request.form.get("month_from") or 1)
        month_to = int(request.form.get("month_to") or 12)
        if month_from > month_to:
            month_from, month_to = month_to, month_from
        hosp_codes = request.form.getlist("hospitals") or [h["code"] for h in hospitals]
        path = generate_report_docx(year, month_from, month_to, hosp_codes)
        log_action("generate_report", "report", "", f"{year} {month_from}-{month_to}")
        return send_file(path, as_attachment=True, download_name=os.path.basename(path))
    years = list(range(today.year - 5, today.year + 1))[::-1]
    return render_template("reports.html", hospitals=hospitals, years=years, today=today)


# ---------------------------------------------------------------------------
# Διαχείριση: Νοσηλευτήρια
# ---------------------------------------------------------------------------
@app.route("/admin/hospitals")
@role_required("admin", "central")
def admin_hospitals():
    return render_template("hospitals_list.html", hospitals=get_hospitals(active_only=False))


@app.route("/admin/hospitals/save", methods=["POST"])
@role_required("admin", "central")
def admin_hospital_save():
    code = (request.form.get("code") or "").strip().upper()
    name_el = (request.form.get("name_el") or "").strip()
    if not code or not name_el:
        flash("Ο κωδικός και το όνομα είναι υποχρεωτικά.", "warning")
        return redirect(url_for("admin_hospitals"))
    existing = db_execute("SELECT code FROM hospitals WHERE code=%s", (code,), fetch=True)
    if existing:
        db_execute("UPDATE hospitals SET name_el=%s, sort_order=%s, active=%s WHERE code=%s",
                   (name_el, int(request.form.get("sort_order") or 0),
                    1 if request.form.get("active") else 0, code))
        log_action("update", "hospital", code)
        flash("Το νοσηλευτήριο ενημερώθηκε.", "success")
    else:
        db_execute("INSERT INTO hospitals (code, name_el, sort_order, active) VALUES (%s,%s,%s,%s)",
                   (code, name_el, int(request.form.get("sort_order") or 0), 1))
        log_action("create", "hospital", code)
        flash("Το νοσηλευτήριο δημιουργήθηκε.", "success")
    return redirect(url_for("admin_hospitals"))


# ---------------------------------------------------------------------------
# Διαχείριση: Χρήστες
# ---------------------------------------------------------------------------
@app.route("/admin/users")
@role_required("admin")
def users_list():
    users = db_execute("SELECT * FROM users ORDER BY username", fetch=True) or []
    return render_template("users_list.html", users=users, hnames=hospital_names())


@app.route("/admin/users/new", methods=["GET", "POST"])
@role_required("admin")
def user_new():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        full_name = (request.form.get("full_name") or "").strip()
        if not username or not full_name or len(password) < 6:
            flash("Συμπληρώστε όνομα χρήστη, ονοματεπώνυμο και κωδικό (≥6 χαρακτήρες).", "warning")
        elif db_execute("SELECT id FROM users WHERE username=%s", (username,), fetch=True):
            flash("Υπάρχει ήδη χρήστης με αυτό το όνομα.", "warning")
        else:
            rid = db_execute(
                """INSERT INTO users (username, password_hash, full_name, email, role, hospital_code, phone)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (username, generate_password_hash(password), full_name,
                 (request.form.get("email") or "").strip(),
                 request.form.get("role") or "quality_officer",
                 request.form.get("hospital_code") or None,
                 (request.form.get("phone") or "").strip()), lastrowid=True)
            log_action("create", "user", rid, username)
            flash("Ο χρήστης δημιουργήθηκε.", "success")
            return redirect(url_for("users_list"))
    return render_template("user_form.html", u=None, hospitals=get_hospitals(active_only=False))


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def user_edit(user_id):
    rows = db_execute("SELECT * FROM users WHERE id=%s", (user_id,), fetch=True)
    if not rows:
        abort(404)
    if request.method == "POST":
        active = 1 if request.form.get("active") else 0
        if user_id == session["user_id"] and not active:
            flash("Δεν μπορείτε να απενεργοποιήσετε τον εαυτό σας.", "warning")
            return redirect(url_for("user_edit", user_id=user_id))
        db_execute(
            "UPDATE users SET full_name=%s, email=%s, role=%s, hospital_code=%s, phone=%s, active=%s WHERE id=%s",
            ((request.form.get("full_name") or "").strip(),
             (request.form.get("email") or "").strip(),
             request.form.get("role") or "quality_officer",
             request.form.get("hospital_code") or None,
             (request.form.get("phone") or "").strip(), active, user_id))
        password = request.form.get("password") or ""
        if password:
            if len(password) < 6:
                flash("Ο νέος κωδικός πρέπει να έχει τουλάχιστον 6 χαρακτήρες — δεν άλλαξε.", "warning")
            else:
                db_execute("UPDATE users SET password_hash=%s WHERE id=%s",
                           (generate_password_hash(password), user_id))
        log_action("update", "user", user_id)
        flash("Ο χρήστης ενημερώθηκε.", "success")
        return redirect(url_for("users_list"))
    return render_template("user_form.html", u=rows[0], hospitals=get_hospitals(active_only=False))


# ---------------------------------------------------------------------------
# Διαχείριση: Ρυθμίσεις & Ιστορικό
# ---------------------------------------------------------------------------
@app.route("/admin/settings", methods=["GET", "POST"])
@role_required("admin")
def admin_settings():
    settings = load_settings()
    if request.method == "POST":
        for key in ("org_name", "org_short", "app_title", "session_timeout"):
            if request.form.get(key) is not None:
                settings[key] = request.form.get(key).strip()
        save_settings(settings)
        log_action("update", "settings", "")
        flash("Οι ρυθμίσεις αποθηκεύτηκαν.", "success")
        return redirect(url_for("admin_settings"))
    return render_template("settings.html", settings=settings, use_mysql=USE_MYSQL)


@app.route("/admin/audit")
@role_required("admin", "central")
def audit_trail():
    q = (request.args.get("q") or "").strip()
    sql = "SELECT * FROM audit_log"
    params = []
    if q:
        sql += " WHERE username LIKE %s OR action LIKE %s OR entity LIKE %s OR details LIKE %s"
        like = f"%{q}%"
        params = [like, like, like, like]
    sql += " ORDER BY id DESC LIMIT 300"
    entries = db_execute(sql, tuple(params), fetch=True) or []
    return render_template("audit_trail.html", entries=entries, q=q)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
