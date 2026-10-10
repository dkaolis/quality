"""
eQuality - Πλατφόρμα Διασφάλισης Ποιότητας ΟΚΥπΥ
Καταχώρηση & απεικόνιση δεικτών ποιότητας, αξιολογήσεων συμμόρφωσης και
επιθεωρήσεων από τις Μονάδες Διασφάλισης Ποιότητας των νοσηλευτηρίων.
"""

import os
import re
import json
import secrets
import calendar
import hashlib
import logging
from datetime import datetime, timedelta, date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_from_directory, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import smtplib
from email.message import EmailMessage

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
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
VIDEO_EXTENSIONS = {"mp4", "webm", "ogg", "mov", "m4v"}
DIPLOMA_EXTENSIONS = IMAGE_EXTENSIONS | {"pdf"}

@app.after_request
def _no_html_cache(resp):
    """Αποτρέπει caching των δυναμικών HTML σελίδων (browser/proxy) ώστε να μη δείχνουν παλιά δεδομένα."""
    try:
        if resp.headers.get("Content-Type", "").startswith("text/html"):
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
    except Exception:
        pass
    return resp
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB (φωτο/βίντεο δραστηριοτήτων)

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
        "base_url": "",
        "smtp_host": "", "smtp_port": "587", "smtp_user": "", "smtp_pass": "",
        "smtp_from": "", "smtp_tls": "1",
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


def send_email(to_addr, subject, body):
    """Αποστολή απλού email μέσω SMTP (ρυθμίσεις στο settings.json). Επιστρέφει (ok, error)."""
    cfg = load_settings()
    host = (cfg.get("smtp_host") or "").strip()
    if not host:
        return False, "Το SMTP δεν έχει ρυθμιστεί (Ρυθμίσεις → Email)."
    if not to_addr:
        return False, "Δεν δόθηκε διεύθυνση email."
    try:
        port = int(cfg.get("smtp_port") or 587)
        msg = EmailMessage()
        msg["From"] = (cfg.get("smtp_from") or cfg.get("smtp_user") or "no-reply@equality").strip()
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)
        user = (cfg.get("smtp_user") or "").strip()
        pwd = cfg.get("smtp_pass") or ""
        use_tls = str(cfg.get("smtp_tls", "1")) not in ("0", "", "false", "False")
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as srv:
                if user:
                    srv.login(user, pwd)
                srv.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as srv:
                if use_tls:
                    srv.starttls()
                if user:
                    srv.login(user, pwd)
                srv.send_message(msg)
        return True, ""
    except Exception as e:
        logger.warning(f"send_email failed: {e}")
        return False, str(e)


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

    # Προγραμματισμός επιθεωρήσεων (ημερολόγιο)
    f"""CREATE TABLE IF NOT EXISTS scheduled_inspections (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        hospital_code VARCHAR(10) NOT NULL DEFAULT 'NGH',
        insp_date DATE NOT NULL,
        all_day TINYINT DEFAULT 0,
        start_time VARCHAR(5),
        end_time VARCHAR(5),
        department VARCHAR(200),
        scope VARCHAR(500),
        itype VARCHAR(150),
        inspector1 VARCHAR(150),
        inspector2 VARCHAR(150),
        inspector3 VARCHAR(150),
        status VARCHAR(20) DEFAULT 'planned',
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Επιθεωρούμενα τμήματα (μόνιμη λίστα για το dropdown)
    f"""CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        name VARCHAR(200) NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Επιθεωρητές (μόνιμη λίστα για το dropdown)
    f"""CREATE TABLE IF NOT EXISTS inspectors (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        name VARCHAR(200) NOT NULL UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Λίστες ελέγχου (Audit Tools): πρότυπα & συμπληρωμένα αντίγραφα
    f"""CREATE TABLE IF NOT EXISTS checklist_templates (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        code VARCHAR(20) UNIQUE NOT NULL,
        title VARCHAR(300) NOT NULL,
        structure TEXT,
        active TINYINT DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    f"""CREATE TABLE IF NOT EXISTS checklist_instances (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        template_id INTEGER NOT NULL,
        inspection_id INTEGER,
        title VARCHAR(300),
        status VARCHAR(20) DEFAULT 'draft',
        data TEXT,
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    f"""CREATE TABLE IF NOT EXISTS checklist_signatures (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        instance_id INTEGER NOT NULL,
        signer_name VARCHAR(200),
        signer_user VARCHAR(100),
        content_hash VARCHAR(64),
        signed_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Αποκαταστάσεις αποκλίσεων εσωτερικών επιθεωρήσεων
    f"""CREATE TABLE IF NOT EXISTS deviation_remediations (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        instance_id INTEGER NOT NULL,
        si INTEGER NOT NULL,
        ci INTEGER NOT NULL,
        remediated_date DATE,
        note TEXT,
        officer VARCHAR(200),
        officer_user VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Γενικό key-value store (π.χ. διάταξη κτιρίου κλινικών)
    f"""CREATE TABLE IF NOT EXISTS kv_store (
        k VARCHAR(100) PRIMARY KEY,
        v TEXT
    ){ENGINE}""",

    f"""CREATE TABLE IF NOT EXISTS activities (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        title VARCHAR(300) NOT NULL,
        activity_date DATE,
        organizer VARCHAR(200),
        description TEXT,
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    f"""CREATE TABLE IF NOT EXISTS activity_photos (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        activity_id INTEGER NOT NULL,
        stored_name VARCHAR(255),
        orig_name VARCHAR(255),
        media_type VARCHAR(10) DEFAULT 'image',
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    f"""CREATE TABLE IF NOT EXISTS org_nodes (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        parent_id INTEGER,
        level INTEGER DEFAULT 1,
        role_title VARCHAR(300),
        person_name VARCHAR(200),
        person_title VARCHAR(200),
        photo VARCHAR(255),
        sort_order INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    f"""CREATE TABLE IF NOT EXISTS staff_trainings (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        node_id INTEGER NOT NULL,
        train_date DATE,
        start_date DATE,
        end_date DATE,
        year INTEGER,
        title VARCHAR(300),
        provider VARCHAR(300),
        diploma VARCHAR(255),
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    f"""CREATE TABLE IF NOT EXISTS scheduled_trainings (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        node_id INTEGER NOT NULL,
        start_date DATE,
        end_date DATE,
        title VARCHAR(300),
        provider VARCHAR(300),
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Έγγραφα Υπευθύνων Ποιότητας (Παρουσιολόγιο / Ατζέντα) — αρχείο
    f"""CREATE TABLE IF NOT EXISTS qo_documents (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        doc_type VARCHAR(20) NOT NULL,
        title VARCHAR(300),
        doc_date VARCHAR(20),
        officer_name VARCHAR(200),
        status VARCHAR(20) DEFAULT 'open',
        source_id INTEGER,
        data TEXT,
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",

    # Δραστηριότητες Υπευθύνων Ποιότητας (wizard)
    f"""CREATE TABLE IF NOT EXISTS qo_activities (
        id INTEGER PRIMARY KEY {AUTO_INCREMENT},
        code VARCHAR(40),
        title VARCHAR(300),
        act_date VARCHAR(20),
        officer_name VARCHAR(200),
        kind VARCHAR(20) DEFAULT 'Τακτική',
        frequency VARCHAR(20) DEFAULT 'Μηνιαία',
        status VARCHAR(20) DEFAULT 'open',
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ){ENGINE}""",
]

# Idempotent ALTERs για μελλοντικές migrations — τρέχουν στο boot, αγνοούνται αν υπάρχουν ήδη
ALTER_STATEMENTS = [
    "ALTER TABLE qo_documents ADD COLUMN status VARCHAR(20) DEFAULT 'open'",
    "ALTER TABLE qo_documents ADD COLUMN source_id INTEGER",
    "ALTER TABLE qo_documents ADD COLUMN activity_id INTEGER",
    "ALTER TABLE qo_documents ADD COLUMN signed_file VARCHAR(300)",
    "ALTER TABLE qo_documents ADD COLUMN signed_orig VARCHAR(300)",
    "ALTER TABLE qo_documents ADD COLUMN esign_by VARCHAR(200)",
    "ALTER TABLE qo_documents ADD COLUMN esign_at VARCHAR(30)",
    "ALTER TABLE qo_activities ADD COLUMN kind VARCHAR(20) DEFAULT 'Τακτική'",
    "ALTER TABLE qo_activities ADD COLUMN frequency VARCHAR(20) DEFAULT 'Μηνιαία'",
    "ALTER TABLE qo_activities ADD COLUMN domain VARCHAR(10) DEFAULT 'qo'",
    "ALTER TABLE inspections ADD COLUMN instance_id INTEGER",
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
    # Πρώτη σύνδεση: υπόμνηση αλλαγής προσωρινού κωδικού (π.χ. 1234)
    "ALTER TABLE users ADD COLUMN must_change_pw INTEGER DEFAULT 0",
    # Ευρύτερη κατηγορία (τίτλοι KPI + «(αποστέλλεται στον ΟΑΥ)» ξεπερνούν τα 100 στη MySQL)
    "ALTER TABLE indicators MODIFY COLUMN category VARCHAR(255)",
    # Κατηγορία επιθεώρησης: «Διαπίστευσης» / «Πιστοποίησης»
    "ALTER TABLE inspections ADD COLUMN category VARCHAR(50)",
    # Σύνδεση εγγράφου (report) με ομάδα δεικτών & περίοδο (Καταχώρηση Τιμών)
    "ALTER TABLE documents ADD COLUMN grp VARCHAR(100)",
    "ALTER TABLE documents ADD COLUMN month_from INTEGER",
    "ALTER TABLE documents ADD COLUMN month_to INTEGER",
    "ALTER TABLE checklist_templates ADD COLUMN created_by VARCHAR(100)",
    "ALTER TABLE documents ADD COLUMN inspection_id INTEGER",
    "ALTER TABLE activity_photos ADD COLUMN media_type VARCHAR(10) DEFAULT 'image'",
    "ALTER TABLE org_nodes ADD COLUMN level INTEGER DEFAULT 1",
    "ALTER TABLE staff_trainings ADD COLUMN start_date DATE",
    "ALTER TABLE staff_trainings ADD COLUMN end_date DATE",
    "ALTER TABLE staff_trainings ADD COLUMN year INTEGER",
]


# ---------------------------------------------------------------------------
# Ρόλοι & λεξικά αναφοράς
# ---------------------------------------------------------------------------
ROLES = {
    "admin": "Διαχειριστής",
    "central": "Κεντρική Μονάδα Ποιότητας",
    "quality_officer": "Λειτουργός Διασφάλισης Ποιότητας Γ Ν Λευκωσίας",
    "quality_add": "Καταχώρηση (χωρίς τροποποίηση)",
    "q_add": "View / Add",
    "q_edit": "View / Add / Edit",
    "q_delete": "View / Add / Edit / Delete",
    "ic_nurse": "Μονάδα Λοιμώξεων (ΑΤ.03)",
    "viewer": "Διοίκηση (Προβολή)",
}
EDIT_ALL_ROLES = ("admin", "central")  # επεξεργάζονται δεδομένα όλων των νοσηλευτηρίων
ADD_ROLES = ("admin", "central", "quality_officer", "quality_add")  # μπορούν να προσθέτουν δεδομένα
ROLE_PERMISSIONS = {
    "admin": "Πλήρη δικαιώματα· διαχείριση χρηστών & ρυθμίσεων",
    "central": "Επεξεργασία όλων των νοσηλευτηρίων· ορισμοί δεικτών/διαδικασιών",
    "quality_officer": "Προβολή, προσθήκη, τροποποίηση & διαγραφή για το Γ.Ν. Λευκωσίας (NGH)",
    "quality_add": "Μόνο προσθήκη νέων δεδομένων (όχι τροποποίηση)· προβολή",
    "q_add": "Προβολή & προσθήκη νέων δεδομένων",
    "q_edit": "Προβολή, προσθήκη & τροποποίηση δεδομένων",
    "q_delete": "Προβολή, προσθήκη, τροποποίηση & διαγραφή δεδομένων",
    "ic_nurse": "Προβολή όλων· διαχείριση μόνο επιθεωρήσεων Ελέγχου Λοιμώξεων (ΑΤ.03)",
    "viewer": "Μόνο προβολή",
}

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
# Είδη προγραμματισμένης επιθεώρησης (μπορούν να προστεθούν κι άλλα)
SCHEDULE_TYPES = ["Εσωτερική Επιθεώρηση Διαπίστευσης", "Εσωτερική Επιθεώρηση Πιστοποίησης ISO9001 - EN15224", "Εσωτερική Επιθεώρηση Ελέγχου Λοιμώξεων", "Εξωτερική Επιθεώρηση Διαπίστευσης", "Εξωτερική Επιθεώρηση ISO9001 - EN15224", "Επιθεώρηση ISBAR"]
# Αντιστοίχιση είδους επιθεώρησης -> κωδικός audit tool
ITYPE_TEMPLATE = {
    "Εσωτερική Επιθεώρηση Διαπίστευσης": "ΑΤ.01",
    "Εσωτερική Επιθεώρηση Πιστοποίησης ISO9001 - EN15224": "ΑΤ.02",
    "Εσωτερική Επιθεώρηση Ελέγχου Λοιμώξεων": "ΑΤ.03",
}
# Αντιστοίχιση κατηγορίας λίστας -> κωδικός audit tool (επεκτάσιμο)
CATEGORY_TEMPLATE = {
    "Διαπίστευσης": "ΑΤ.01",
    "Πιστοποίησης": "ΑΤ.02",
    "Ελέγχου Λοιμώξεων": "ΑΤ.03",
}

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
    """Ο χρήστης μπορεί να ΤΡΟΠΟΠΟΙΗΣΕΙ υπάρχοντα δεδομένα (όχι διαγραφή)."""
    role = session.get("role")
    if role in ("admin", "central", "q_edit", "q_delete"):
        return True
    if role == "quality_officer":
        return hospital_code == "NGH"
    return False


def can_delete_hospital(hospital_code):
    """Ο χρήστης μπορεί να ΔΙΑΓΡΑΨΕΙ υπάρχοντα δεδομένα."""
    role = session.get("role")
    if role in ("admin", "central", "q_delete"):
        return True
    if role == "quality_officer":
        return hospital_code == "NGH"
    return False


def can_add_hospital(hospital_code):
    """Ο χρήστης μπορεί να ΠΡΟΣΘΕΣΕΙ νέα δεδομένα."""
    role = session.get("role")
    if role in ("admin", "central", "quality_add", "q_add", "q_edit", "q_delete"):
        return True
    if role == "quality_officer":
        return hospital_code == "NGH"
    return False


# --- Περιορισμένοι ρόλοι: βλέπουν τα πάντα, αλλά ΓΡΑΦΟΥΝ μόνο στο δικό τους πεδίο ---
# Προσθήκη νέου περιορισμένου ρόλου = ΜΙΑ εγγραφή εδώ (+ στο ROLES/ROLE_PERMISSIONS).
# Κάθε ρόλος ορίζει "scope" ανά διάσταση· άδειο scope σε μια διάσταση = κανένα δικαίωμα εκεί.
RESTRICTED_ROLES = {
    "ic_nurse": {
        "label": "Μονάδα Λοιμώξεων (ΑΤ.03)",
        "scope": {"checklist_codes": {"ΑΤ.03"}, "indicator_cats": {"Μονάδα Ελέγχου Λοιμώξεων"}},
    },
    # Παράδειγμα μελλοντικού ρόλου (ενεργοποιείται όταν: (α) προστεθεί εδώ & στο ROLES,
    # (β) συρματωθούν τα routes δεικτών με can_manage_indicator, (γ) κρυφτούν τα κουμπιά στις σελίδες δεικτών):
    # "physio_nurse": {
    #     "label": "Φυσιοθεραπεία (Δείκτες)",
    #     "scope": {"indicator_depts": {"Φυσιοθεραπεία"}},
    # },
}

# Ποια write-endpoints ανήκουν σε κάθε διάσταση scope (για το κεντρικό default-deny).
SCOPE_ENDPOINTS = {
    "checklist_codes": {
        "checklist_create", "checklist_save", "checklist_delete",
        "checklist_sign", "checklist_sign_revoke",
        "inspection_schedule_add", "inspection_schedule_edit",
        "inspection_schedule_delete", "inspection_signed_upload",
    },
    "indicator_cats": {
        "values_entry", "values_report_upload",
        "indicator_new", "indicator_edit", "indicator_delete",
    },
}

# Write-endpoints πάντα επιτρεπτά σε κάθε συνδεδεμένο χρήστη.
ALWAYS_WRITE_OK = {"change_password", "logout", "login", "static"}


def restricted_spec():
    """Spec του τρέχοντος περιορισμένου ρόλου, ή None για κανονικό (πλήρη) ρόλο."""
    return RESTRICTED_ROLES.get(session.get("role"))


def _ic_nurse():
    """Συμβατότητα: True αν ο χρήστης είναι Μονάδα Λοιμώξεων."""
    return session.get("role") == "ic_nurse"


def _role_scope(dim):
    spec = restricted_spec()
    return (spec["scope"].get(dim, set()) if spec else set())


def can_manage_checklist(code):
    """Διαχείριση λιστών ελέγχου (ΑΤ.0x). Περιορισμένος ρόλος: μόνο οι κωδικοί του· κανονικός: όπως πριν."""
    spec = restricted_spec()
    if not spec:
        return True
    return code in spec["scope"].get("checklist_codes", set())


def can_manage_indicator_cat(category):
    """Διαχείριση δεικτών ποιότητας ανά κατηγορία. Περιορισμένος ρόλος: μόνο οι κατηγορίες του· κανονικός: όπως πριν."""
    spec = restricted_spec()
    if not spec:
        return True
    return (category or "") in spec["scope"].get("indicator_cats", set())


def _indicator_cats():
    """Επιτρεπόμενες κατηγορίες δεικτών για περιορισμένο ρόλο (λίστα), ή None για κανονικό."""
    spec = restricted_spec()
    if not spec:
        return None
    return sorted(spec["scope"].get("indicator_cats", set())) or None


def can_schedule_itype(itype):
    """Προγραμματισμός επιθεώρησης επιτρεπτός αν ο ρόλος διαχειρίζεται τον αντίστοιχο κωδικό ΑΤ."""
    return can_manage_checklist(ITYPE_TEMPLATE.get((itype or "").strip()))


def scoped_schedule_types():
    """Είδη επιθεώρησης που επιτρέπεται να προγραμματίσει ο χρήστης (φιλτράρισμα dropdown)."""
    spec = restricted_spec()
    if not spec:
        return SCHEDULE_TYPES
    codes = spec["scope"].get("checklist_codes", set())
    return [t for t in SCHEDULE_TYPES if ITYPE_TEMPLATE.get(t) in codes]


def _inst_code(inst):
    """Κωδικός audit tool (ΑΤ.0x) μιας λίστας ελέγχου."""
    tpl = db_execute("SELECT code FROM checklist_templates WHERE id=%s", (inst.get("template_id"),), fetch=True)
    return (tpl[0]["code"] or "") if tpl else ""


@app.before_request
def _restricted_write_guard():
    """Κεντρικό δίχτυ ασφαλείας: περιορισμένοι ρόλοι ΒΛΕΠΟΥΝ τα πάντα αλλά οι εγγραφές
    (POST/PUT/PATCH/DELETE) απορρίπτονται by default — εκτός αν το endpoint ανήκει σε διάσταση
    όπου ο ρόλος έχει scope (οπότε ο λεπτομερής έλεγχος γίνεται μέσα στο route).
    Έτσι κάθε ΝΕΑ σελίδα είναι αυτόματα μη-διαχειρίσιμη από περιορισμένους ρόλους."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    spec = restricted_spec()
    if not spec:
        return  # κανονικοί ρόλοι: καμία αλλαγή
    ep = request.endpoint or ""
    if ep in ALWAYS_WRITE_OK:
        return
    dims = [d for d, eps in SCOPE_ENDPOINTS.items() if ep in eps]
    if any(_role_scope(d) for d in dims):
        return  # εντός πεδίου -> ο λεπτομερής έλεγχος γίνεται στο route
    if request.is_json or "application/json" in (request.headers.get("Accept") or ""):
        return {"ok": False, "error": "forbidden"}, 403
    flash("Δεν έχετε δικαίωμα τροποποίησης σε αυτή τη σελίδα.", "danger")
    return redirect(request.referrer or url_for("dashboard"))


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
               i.target_value, i.limit_low, i.limit_high, i.category, i.grp
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
        "ROLE_PERMISSIONS": ROLE_PERMISSIONS,
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
        "deviation_alert_count": 0,
        "notif_count": 0,
        "notif_danger": False,
        "nav_groups": [],
    }
    if session.get("user_id"):
        try:
            ctx["alert_count"] = len(latest_period_alerts())
        except Exception:
            pass
        try:
            ctx["deviation_alert_count"] = sum(1 for d in _all_deviations() if not (d["rem"] and d["rem"].get("remediated_date")))
        except Exception:
            pass
        try:
            _nl = _notifications_get()
            ctx["notif_count"] = len(_nl)
            ctx["notif_danger"] = any(n.get("level") == "danger" for n in _nl)
        except Exception:
            pass
        try:
            ctx["nav_groups"] = [r["grp"] for r in (db_execute(
                "SELECT DISTINCT grp FROM indicators WHERE grp IS NOT NULL AND grp<>'' ORDER BY grp",
                fetch=True) or [])]
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
            _refresh_notifications()
            if u.get("must_change_pw"):
                session["must_change_pw"] = True
                flash("Ο προσωρινός σας κωδικός είναι «1234». Για την ασφάλειά σας, ορίστε τώρα νέο κωδικό.", "warning")
                return redirect(url_for("change_password"))
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
            db_execute("UPDATE users SET password_hash=%s, must_change_pw=0 WHERE id=%s",
                       (generate_password_hash(new), session["user_id"]))
            session.pop("must_change_pw", None)
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
    _refresh_notifications()
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
        "dashboard.html", notifications=sorted(_notifications_get(), key=lambda n: 0 if n.get("level") == "danger" else 1), alerts=alerts[:15], n_alert=n_alert, n_warn=n_warn,
        comp_counts=comp_counts, non_compliant=non_compliant[:10],
        open_inspections=open_inspections, recent_inspections=recent_inspections,
        recent_documents=recent_documents, hosp_chart=hosp_chart, hnames=hnames)


@app.route("/alerts")
@login_required
def alerts_list():
    all_alerts = latest_period_alerts()
    grps = sorted({(a.get("grp") or "Γενικοί Δείκτες") for a in all_alerts})
    sel_grp = (request.args.get("grp") or "").strip()
    alerts = [a for a in all_alerts if (not sel_grp or (a.get("grp") or "Γενικοί Δείκτες") == sel_grp)]
    for _a in alerts:
        _a["grp_label"] = _a.get("grp") or "Γενικοί Δείκτες"
    return render_template("alerts_list.html", alerts=alerts, hnames=hospital_names(),
                           grps=grps, sel_grp=sel_grp)


def _to_num(x):
    try:
        return float(str(x).replace(",", "."))
    except (TypeError, ValueError):
        return None


def _parse_date(s):
    """Ευέλικτη ανάλυση ημερομηνίας -> date | None."""
    if isinstance(s, date):
        return s
    txt = (str(s) if s is not None else "").strip()
    if not txt:
        return None
    txt = txt.split(" ")[0].split("T")[0]
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(txt, fmt).date()
        except (ValueError, TypeError):
            pass
    return None


def _all_deviations():
    """Όλες οι αποκλίσεις από εσωτερικές επιθεωρήσεις (checklist instances)."""
    insts = db_execute(
        "SELECT ci.id AS id, ci.template_id AS template_id, ci.title AS title, "
        "ci.data AS data, ci.inspection_id AS inspection_id, i.inspection_date AS inspection_date "
        "FROM checklist_instances ci LEFT JOIN inspections i ON ci.inspection_id=i.id",
        (), fetch=True) or []
    rems = db_execute("SELECT * FROM deviation_remediations", (), fetch=True) or []
    remmap = {(r["instance_id"], r["si"], r["ci"]): r for r in rems}
    tpl_cache = {}
    out = []
    for inst in insts:
        data = json.loads(inst["data"] or "{}")
        tid = inst["template_id"]
        if tid not in tpl_cache:
            row = db_execute("SELECT structure FROM checklist_templates WHERE id=%s", (tid,), fetch=True)
            tpl_cache[tid] = json.loads(row[0]["structure"] or "{}") if row else {}
        structure = tpl_cache[tid]
        dept = data.get("meta_department") or ""
        insp_date = data.get("meta_date") or (
            inst["inspection_date"].isoformat() if isinstance(inst.get("inspection_date"), date) else (inst.get("inspection_date") or ""))
        for si, sec in enumerate(structure.get("sections", [])):
            stype = sec.get("type")
            if stype == "iso":
                for ci, cl in enumerate(sec.get("clauses", []) or []):
                    k = "iso%d_%d" % (si, ci)
                    if (data.get(k + "_comp") or "").strip() == "ΟΧΙ":
                        nc = (data.get(k + "_nc") or "").strip() or "Δευτερεύουσα"
                        out.append({
                            "instance_id": inst["id"], "si": si, "ci": ci,
                            "title": inst["title"] or "", "dept": dept, "insp_date": insp_date,
                            "proc": cl.get("clause", ""), "criterion": data.get(k + "_desc", "") or "",
                            "corr": data.get(k + "_corr", "") or "",
                            "target": data.get(k + "_time", "") or "",
                            "resp": data.get(k + "_resp", "") or "",
                            "dev_pct": None, "nc": nc,
                            "rem": remmap.get((inst["id"], si, ci)),
                        })
                continue
            if stype != "checklist":
                continue
            procs = sec.get("procedures") or []
            for ci, c in enumerate(sec.get("criteria", []) or []):
                k = "s%dc%d" % (si, ci)
                sv = _to_num(data.get(k + "_sample", ""))
                cv = _to_num(data.get(k + "_comp", ""))
                if sv is not None and sv > 0 and cv is not None and cv < sv:
                    pidx = c.get("pidx")
                    proc = procs[pidx] if (pidx is not None and 0 <= pidx < len(procs)) else ""
                    corr = data.get(k + "_corr") or data.get("dev_%d_%d_corr" % (si, ci)) or ""
                    out.append({
                        "instance_id": inst["id"], "si": si, "ci": ci,
                        "title": inst["title"] or "", "dept": dept, "insp_date": insp_date,
                        "proc": proc, "criterion": c.get("criterion", ""),
                        "corr": corr,
                        "target": data.get(k + "_time") or data.get("dev_%d_%d_time" % (si, ci)) or "",
                        "resp": data.get(k + "_resp") or data.get("dev_%d_%d_resp" % (si, ci)) or "",
                        "dev_pct": round((sv - cv) / sv * 1000) / 10,
                        "rem": remmap.get((inst["id"], si, ci)),
                    })
    return out


def _dev_term(d):
    """Ορολογία ευρήματος: «μη συμμόρφωση» για εργαλεία ISO (ΑΤ.02/ΑΤ.03), «απόκλιση» για Qmentum."""
    return "μη συμμόρφωση" if (d and d.get("dev_pct") is None) else "απόκλιση"


def _dev_term_gen(d):
    """Γενική πτώση: «της μη συμμόρφωσης» / «της απόκλισης»."""
    return "μη συμμόρφωσης" if (d and d.get("dev_pct") is None) else "απόκλισης"


def _one_deviation(inst_id, si, ci):
    for d in _all_deviations():
        if d["instance_id"] == inst_id and d["si"] == si and d["ci"] == ci:
            return d
    return None


@app.route("/flags/deviations")
@login_required
def flag_deviations():
    all_devs = _all_deviations()
    depts = sorted({d["dept"] for d in all_devs if d["dept"]})
    sel_dept = (request.args.get("dept") or "").strip()
    devs = [d for d in all_devs if (not sel_dept or d["dept"] == sel_dept)]
    today = date.today()
    total = len(devs)
    remediated = overdue = late_done = 0
    for d in devs:
        tgt = _parse_date(d["target"])
        d["target_date"] = tgt
        d["insp_date_date"] = _parse_date(d["insp_date"])
        if d["rem"] and d["rem"].get("remediated_date"):
            d["state"] = "done"
            d["rem_date_disp"] = _parse_date(d["rem"].get("remediated_date"))
            remediated += 1
            rdd = _parse_date(d["rem"].get("remediated_date"))
            d["late"] = bool(tgt and rdd and rdd > tgt)
            if d["late"]:
                late_done += 1
        elif tgt and tgt < today:
            d["state"] = "overdue"
            d["late"] = True
            overdue += 1
        else:
            d["state"] = "pending"
            d["late"] = False
    pending = total - remediated
    devs.sort(key=lambda d: (d["target_date"] is None, d["target_date"] or date.max))

    def _pct(n):
        return round(n / total * 1000) / 10 if total else 0

    stats = {
        "total": total,
        "remediated": remediated, "remediated_pct": _pct(remediated),
        "remediated_late": late_done, "remediated_late_pct": _pct(late_done),
        "pending": pending, "pending_pct": _pct(pending),
        "overdue": overdue, "overdue_pct": _pct(overdue),
    }
    return render_template("flag_deviations.html", devs=devs, stats=stats, today=today,
                           depts=depts, sel_dept=sel_dept)


@app.route("/flags/deviations/<int:inst_id>/<int:si>/<int:ci>/remediate", methods=["GET", "POST"])
@login_required
def flag_remediate(inst_id, si, ci):
    dev = _one_deviation(inst_id, si, ci)
    if not dev:
        flash("Η απόκλιση δεν βρέθηκε.", "warning")
        return redirect(url_for("flag_deviations"))
    me = db_execute("SELECT full_name FROM users WHERE username=%s", (session.get("username", ""),), fetch=True)
    officer = (me[0]["full_name"] if me and me[0]["full_name"] else session.get("username", "")) or ""
    if request.method == "POST":
        action = request.form.get("action") or "save"
        note = request.form.get("note") or ""
        existing = db_execute("SELECT * FROM deviation_remediations WHERE instance_id=%s AND si=%s AND ci=%s",
                              (inst_id, si, ci), fetch=True)
        if action == "cancel":
            rdate = existing[0]["remediated_date"] if existing else None
        else:
            rdate = (request.form.get("remediated_date") or "").strip() or date.today().isoformat()
        db_execute("DELETE FROM deviation_remediations WHERE instance_id=%s AND si=%s AND ci=%s", (inst_id, si, ci))
        db_execute("INSERT INTO deviation_remediations (instance_id, si, ci, remediated_date, note, officer, officer_user) "
                   "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                   (inst_id, si, ci, rdate, note, officer, session.get("username", "")))
        if action == "cancel":
            flash("Η σημείωση αποθηκεύτηκε.", "info")
        else:
            log_action("remediate", "checklist_instance", inst_id, "s%dc%d" % (si, ci))
            flash("Η αποκατάσταση της %s καταχωρήθηκε." % _dev_term_gen(dev), "success")
        return redirect(url_for("flag_deviations"))
    return render_template("flag_remediate.html", dev=dev, officer=officer, today=date.today().isoformat())


@app.route("/flags/deviations/<int:inst_id>/<int:si>/<int:ci>/undo", methods=["POST"])
@login_required
def flag_remediate_undo(inst_id, si, ci):
    dev = _one_deviation(inst_id, si, ci)
    db_execute("DELETE FROM deviation_remediations WHERE instance_id=%s AND si=%s AND ci=%s", (inst_id, si, ci))
    log_action("remediate_undo", "checklist_instance", inst_id, "s%dc%d" % (si, ci))
    flash("Η αποκατάσταση αναιρέθηκε — η %s επέστρεψε σε εκκρεμούσα." % _dev_term(dev), "info")
    return redirect(url_for("flag_deviations"))


@app.route("/flags/patient-safety")
@login_required
def flag_patient_safety():
    return render_template("flag_patient_safety.html")


CLINIC_TYPE_META = {
    "emergency": ("Επείγοντα", "#fd7e14", "bi-truck-front-fill"),
    "clinical": ("Παθολογικός Τομέας", "#0d6efd", "bi-heart-pulse-fill"),
    "surgical": ("Χειρουργικός Τομέας", "#6f42c1", "bi-scissors"),
    "icu": ("Εντατική / Αυξημένη Φροντίδα", "#dc3545", "bi-activity"),
    "maternity": ("Μητέρα & Παιδί", "#d63384", "bi-person-hearts"),
    "diagnostic": ("Διαγνωστικά / Εργαστήρια", "#0dcaf0", "bi-clipboard2-pulse-fill"),
    "support": ("Υποστηρικτικές Υπηρεσίες", "#6c757d", "bi-gear-fill"),
}

CLINIC_CERTS = ["ISO 9001 - EN 15224", "ISO 17025", "ISO 15189", "ISO 22000"]

CLINIC_FLOORS = [
    {"level": "4ος Όροφος", "depts": [
        {"name": "Γενική Χειρουργική", "type": "surgical"},
        {"name": "Ορθοπαιδική", "type": "surgical"},
        {"name": "Ουρολογική", "type": "surgical"},
        {"name": "ΩΡΛ", "type": "surgical"},
        {"name": "Οφθαλμολογική", "type": "surgical"},
    ]},
    {"level": "3ος Όροφος", "depts": [
        {"name": "Παθολογική", "type": "clinical"},
        {"name": "Καρδιολογική", "type": "clinical"},
        {"name": "Πνευμονολογική", "type": "clinical"},
        {"name": "Νεφρολογική", "type": "clinical"},
        {"name": "Γαστρεντερολογική", "type": "clinical"},
    ]},
    {"level": "2ος Όροφος", "depts": [
        {"name": "ΜΕΘ", "type": "icu"},
        {"name": "ΜΑΦ", "type": "icu"},
        {"name": "Χειρουργεία", "type": "surgical"},
        {"name": "Αναισθησιολογικό", "type": "surgical"},
    ]},
    {"level": "1ος Όροφος", "depts": [
        {"name": "Μαιευτική / Γυναικολογική", "type": "maternity"},
        {"name": "Νεογνολογική (ΜΕΝΝ)", "type": "maternity"},
        {"name": "Παιδιατρική", "type": "maternity"},
    ]},
    {"level": "Ισόγειο", "depts": [
        {"name": "ΤΑΕΠ", "type": "emergency"},
        {"name": "Ακτινολογικό", "type": "diagnostic"},
        {"name": "Μικροβιολογικό", "type": "diagnostic"},
        {"name": "Βιοχημικό", "type": "diagnostic"},
        {"name": "Αιμοδοσία", "type": "diagnostic"},
        {"name": "Εξωτερικά Ιατρεία", "type": "clinical"},
    ]},
]


def _kv_get(key, default=None):
    r = db_execute("SELECT v FROM kv_store WHERE k=%s", (key,), fetch=True)
    if r and r[0]["v"]:
        try:
            return json.loads(r[0]["v"])
        except Exception:
            return default
    return default


def _kv_set(key, value):
    db_execute("DELETE FROM kv_store WHERE k=%s", (key,))
    db_execute("INSERT INTO kv_store (k, v) VALUES (%s, %s)", (key, json.dumps(value, ensure_ascii=False)))


def _notifications_get():
    return _kv_get("notifications", []) or []


def _set_notification(topic, level, message):
    """Μία ειδοποίηση ανά θέμα: σβήνει τυχόν προηγούμενη ίδιου θέματος, προσθέτει τη νέα."""
    lst = [n for n in _notifications_get() if n.get("topic") != topic]
    if level and message:
        lst.append({"topic": topic, "level": level, "message": message,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")})
    _kv_set("notifications", lst)


def _check_qo_review_notification():
    """Έλεγχος ημ/νίας αναθεώρησης λίστας Υπευθύνων Ποιότητας -> ειδοποίηση (πορτοκαλί/κόκκινη)."""
    review = _kv_get("quality_review", {}) or {}
    nxt = str(review.get("next") or "").strip()
    level = None
    message = None
    nd = None
    if nxt:
        try:
            nd = datetime.strptime(nxt, "%Y-%m-%d").date()
        except Exception:
            nd = None
    if nd:
        delta = (nd - date.today()).days
        if delta < 0:
            level = "danger"
            message = "Η ημερομηνία αναθεώρησης της λίστας Υπευθύνων Ποιότητας έχει περάσει εδώ και %d ημέρες." % abs(delta)
        elif delta < 14:
            level = "warning"
            message = "Η λίστα των Υπευθύνων Ποιότητας πρέπει να ανανεωθεί εντός %d ημερών." % delta
    _set_notification("qo_review", level, message)


def _parse_date_strict(s):
    """Επιστρέφει date μόνο για πραγματικές ημερομηνίες, αλλιώς None (σε αντίθεση με _as_date)."""
    txt = (str(s) if s is not None else "").strip()
    if not txt:
        return None
    txt = txt.split(" ")[0].split("T")[0]
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(txt, fmt).date()
        except (ValueError, TypeError):
            pass
    return None


def _check_deviation_notifications():
    """Αποκλίσεις που λήγουν σε <2 εβδομάδες (πορτοκαλί) ή έληξαν (κόκκινο) -> ειδοποιήσεις."""
    try:
        devs = _all_deviations()
    except Exception:
        devs = []
    today = date.today()
    new_items = []
    for d in devs:
        rem = d.get("rem")
        if rem and rem.get("remediated_date"):
            continue
        td = _parse_date_strict(d.get("target"))
        if not td:
            continue
        delta = (td - today).days
        if delta < 0:
            level = "danger"
        elif delta < 14:
            level = "warning"
        else:
            continue
        label = (d.get("criterion") or d.get("proc") or d.get("title") or "").strip()
        if len(label) > 80:
            label = label[:77] + "…"
        term = _dev_term(d)
        if not label:
            label = term.capitalize()
        dept = (d.get("dept") or "").strip()
        loc = " (%s)" % dept if dept else ""
        if level == "danger":
            message = "Η %s «%s»%s έχει ξεπεράσει το χρονοδιάγραμμα αποκατάστασης εδώ και %d ημέρες και πρέπει να ελεγχθεί άμεσα." % (term, label, loc, abs(delta))
        else:
            message = "Η %s «%s»%s πρέπει να ελεγχθεί ως προς την αποκατάστασή της εντός %d ημερών." % (term, label, loc, delta)
        new_items.append({
            "topic": "deviation:%s:%s:%s" % (d.get("instance_id"), d.get("si"), d.get("ci")),
            "level": level, "message": message,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        })
    lst = [n for n in _notifications_get() if not str(n.get("topic", "")).startswith("deviation:")]
    lst.extend(new_items)
    _kv_set("notifications", lst)


def _check_signature_notifications():
    """Προχειρες (draft) επιθεωρησεις που χρειαζονται υπογραφη -> ειδοποιηση ανα ανυπογραφο υπογραφοντα."""
    lst = [n for n in _notifications_get() if not str(n.get("topic", "")).startswith("sign:")]
    try:
        insts = db_execute("SELECT id, data FROM checklist_instances WHERE status='draft'", fetch=True) or []
        sigrows = db_execute("SELECT instance_id, signer_name FROM checklist_signatures", fetch=True) or []
    except Exception:
        insts, sigrows = [], []
    signed_by = {}
    for sg in sigrows:
        signed_by.setdefault(sg["instance_id"], set()).add(_norm_name(sg["signer_name"]))
    try:
        _comp = db_execute("SELECT data FROM checklist_instances WHERE status IN ('signed','final')", fetch=True) or []
    except Exception:
        _comp = []
    done_keys = set()
    for _cc in _comp:
        _cd = json.loads(_cc["data"] or "{}")
        done_keys.add((_norm_name(_cd.get("meta_department") or ""), str(_cd.get("meta_date") or ""), str(_cd.get("meta_itype") or "")))
    seen = set()
    for inst in insts:
        data = json.loads(inst["data"] or "{}")
        if not (data.get("meta_inspectors") or "").strip():
            continue
        if (_norm_name(data.get("meta_department") or ""), str(data.get("meta_date") or ""), str(data.get("meta_itype") or "")) in done_keys:
            continue
        signers = _signers(data)
        if not signers:
            continue
        done = signed_by.get(inst["id"], set())
        dept = (data.get("meta_department") or "—").strip()
        _d = _parse_date(data.get("meta_date"))
        dstr = _d.strftime("%d/%m/%Y") if _d else (data.get("meta_date") or "")
        itype = (data.get("meta_itype") or "").strip()
        ident = dept + ((" – " + dstr) if dstr else "") + ((" · " + itype) if itype else "")
        for sgn in signers:
            if _norm_name(sgn["name"]) in done:
                continue
            _dk = (ident, _norm_name(sgn["name"]))
            if _dk in seen:
                continue
            seen.add(_dk)
            lst.append({"topic": "sign:%d:%s" % (inst["id"], _norm_name(sgn["name"])),
                        "level": "warning",
                        "message": "Η επιθεώρηση «%s» εκκρεμεί και χρειάζεται υπογραφή από: %s." % (ident, sgn["name"]),
                        "url": url_for("checklist_fill", inst_id=inst["id"]),
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")})
    _kv_set("notifications", lst)


def _refresh_notifications():
    _check_qo_review_notification()
    _check_deviation_notifications()
    _check_signature_notifications()


@app.route("/clinics-departments")
@login_required
def clinics_departments():
    floors = _kv_get("clinic_layout", CLINIC_FLOORS)
    departments = [r["name"] for r in (db_execute("SELECT name FROM departments ORDER BY name", fetch=True) or [])]
    certified = sum(1 for f in floors for d in (f.get("depts") or []) if d.get("certs"))
    return render_template("clinics_building.html", floors=floors, type_meta=CLINIC_TYPE_META, departments=departments, clinic_certs=CLINIC_CERTS, certified=certified, can_edit=(restricted_spec() is None))


@app.route("/clinics-departments/save", methods=["POST"])
@login_required
def clinics_departments_save():
    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return {"ok": False, "error": "bad payload"}, 400
    clean = []
    for fl in data:
        if not isinstance(fl, dict):
            continue
        depts = []
        for d in (fl.get("depts") or []):
            name = (str(d.get("name") or "")).strip()
            typ = d.get("type") if d.get("type") in CLINIC_TYPE_META else "support"
            dept = (str(d.get("department") or "")).strip()
            if " ".join(dept.split()).lower() == " ".join(name.split()).lower():
                dept = ""  # κενό = τμήμα επιθεώρησης ίδιο με το όνομα της κάρτας
            certs = [c for c in (d.get("certs") or []) if c in CLINIC_CERTS]
            if name:
                depts.append({"name": name[:120], "type": typ, "department": dept[:120], "certs": certs})
        clean.append({"level": (str(fl.get("level") or "")).strip()[:60], "depts": depts})
    existing_deps = {" ".join((r["name"] or "").split()).lower() for r in (db_execute("SELECT name FROM departments", (), fetch=True) or [])}
    for fl in clean:
        for d in fl["depts"]:
            for nm in ((d.get("name") or "").strip(), (d.get("department") or "").strip()):
                key = " ".join(nm.split()).lower()
                if nm and key not in existing_deps:
                    try:
                        db_execute("INSERT INTO departments (name) VALUES (%s)", (nm,))
                        existing_deps.add(key)
                    except Exception:
                        pass
    _kv_set("clinic_layout", clean)
    return {"ok": True}


@app.route("/clinics-departments/dept-data")
@login_required
def clinics_dept_data():
    name = (request.args.get("name") or "").strip()
    nm = " ".join(name.split()).lower()
    # Τμήμα επιθεώρησης (Audit Tools): μπορεί να είναι κοινό σε πολλές κάρτες (π.χ. Παθολογική Α΄/Β΄ → «Παθολογική»).
    insp_nm = " ".join((request.args.get("dept") or "").split()).lower() or nm
    out = {"indicators": [], "accreditation": None, "certification": None}
    if not nm:
        return out
    inds = db_execute("SELECT * FROM indicators WHERE active=1", (), fetch=True) or []
    for i in inds:
        if " ".join((i.get("grp") or "").split()).lower() != nm:
            continue
        v = db_execute("SELECT value, month, year FROM indicator_values WHERE indicator_id=%s "
                       "AND (no_data IS NULL OR no_data=0) ORDER BY year DESC, month DESC LIMIT 1",
                       (i["id"],), fetch=True)
        row = {"code": i.get("code"), "name": i.get("name"), "unit": i.get("unit") or "",
               "value": None, "period": "", "st_color": "secondary", "st_label": "—"}
        if v:
            vv = v[0]
            st = value_status(i, vv["value"])
            meta = STATUS_META.get(st)
            row["value"] = vv["value"]
            try:
                row["period"] = "%02d/%s" % (int(vv["month"]), vv["year"])
            except (TypeError, ValueError):
                row["period"] = ""
            if meta:
                row["st_color"], row["st_label"] = meta[0], meta[1]
        out["indicators"].append(row)
    insts = db_execute("SELECT ci.id AS id, ci.data AS data, t.code AS code FROM checklist_instances ci "
                       "JOIN checklist_templates t ON t.id=ci.template_id", (), fetch=True) or []
    devs = _all_deviations()
    open_by = {}
    for d in devs:
        if not (d["rem"] and d["rem"].get("remediated_date")):
            open_by.setdefault(d["instance_id"], []).append(d)
    def pick(code):
        best = None
        for ci in insts:
            if ci["code"] != code:
                continue
            data = json.loads(ci["data"] or "{}")
            if " ".join((data.get("meta_department") or "").split()).lower() != insp_nm:
                continue
            dt = _parse_date(data.get("meta_date"))
            k = dt or date.min
            if best is None or k > best[0]:
                best = (k, ci, data, dt)
        if not best:
            return None
        _, ci, data, dt = best
        opens = open_by.get(ci["id"], [])
        return {
            "date": dt.strftime("%d/%m/%Y") if dt else (data.get("meta_date") or ""),
            "open_count": len(opens),
            "open": [{"proc": o.get("proc") or "", "criterion": o.get("criterion") or "",
                      "target": o.get("target") or ""} for o in opens[:25]],
        }
    out["accreditation"] = pick("ΑΤ.01")
    out["certification"] = pick("ΑΤ.02")
    return out


@app.route("/quality-officers")
@login_required
def quality_officers():
    floors = _kv_get("clinic_layout", CLINIC_FLOORS)
    info = _kv_get("quality_officers", {}) or {}
    clinics = []
    for f in floors:
        for d in (f.get("depts") or []):
            nm = d.get("name")
            clinics.append({"name": nm, "floor": f.get("level"), "info": info.get(nm, {})})
    clinics.sort(key=lambda c: (c.get("name") or "").strip().lower())
    qo_map = {c["name"]: c["info"] for c in clinics}
    review = _kv_get("quality_review", {}) or {}
    _ru = review.get("reviewed_by_user")
    if _ru:
        _me = db_execute("SELECT full_name FROM users WHERE username=%s", (_ru,), fetch=True)
        if _me and _me[0]["full_name"]:
            review = dict(review); review["reviewed_by"] = _me[0]["full_name"]
    _check_qo_review_notification()
    _qa = [r["full_name"] for r in (db_execute("SELECT full_name FROM users WHERE role='quality_officer' AND active=1 AND full_name IS NOT NULL ORDER BY full_name", fetch=True) or []) if (r["full_name"] or "").strip()]
    _cc = {}
    for _d in (db_execute("SELECT data FROM qo_documents WHERE doc_type='attendance'", fetch=True) or []):
        try:
            _its = json.loads(_d["data"] or "[]")
        except Exception:
            _its = []
        for _p in _its:
            _cn = (_p or {}).get("clinic")
            if not _cn:
                continue
            _e = _cc.setdefault(_cn, {"inv": 0, "pres": 0})
            _e["inv"] += 1
            if (_p or {}).get("present"):
                _e["pres"] += 1
    return render_template("quality_officers.html", clinics=clinics, qo_map=qo_map, review=review, can_edit=(restricted_spec() is None), qa_officers=_qa, qa_head=QA_HEAD_NAME, clinic_counts=_cc)


@app.route("/quality-officers/save", methods=["POST"])
@login_required
def quality_officers_save():
    payload = request.get_json(silent=True) or {}
    clean = {}
    for name, d in payload.items():
        if not isinstance(d, dict):
            continue
        officers = []
        for o in (d.get("officers") or [])[:4]:
            if not isinstance(o, dict):
                continue
            nm = str(o.get("name") or "").strip()[:120]
            emails = [str(e).strip()[:120] for e in (o.get("emails") or []) if str(e).strip()][:2]
            if nm or emails:
                officers.append({"name": nm, "emails": emails})
        phones = [str(p).strip()[:60] for p in (d.get("phones") or []) if str(p).strip()][:3]
        clean[str(name)[:200]] = {"officers": officers, "phones": phones}
    _kv_set("quality_officers", clean)
    return {"ok": True}


@app.route("/quality-officers/doc-save", methods=["POST"])
@login_required
def qo_doc_save():
    payload = request.get_json(silent=True) or {}
    doc_type = (payload.get("type") or "").strip()
    if doc_type not in ("attendance", "agenda", "contacts"):
        return {"ok": False, "error": "bad type"}, 400
    title = (payload.get("title") or "").strip()[:300]
    doc_date = (payload.get("date") or "").strip()[:20]
    officer = (payload.get("officer") or "").strip()[:200]
    status = (payload.get("status") or "open").strip()[:20]
    try:
        source_id = int(payload.get("source_id")) if payload.get("source_id") not in (None, "", 0, "0") else None
    except (ValueError, TypeError):
        source_id = None
    data = payload.get("data")
    def _pid(v):
        try:
            return int(v) if v not in (None, "", 0, "0") else None
        except (ValueError, TypeError):
            return None
    doc_id = _pid(payload.get("id"))
    link_agenda_id = _pid(payload.get("link_agenda_id"))
    activity_id = _pid(payload.get("activity_id"))
    if doc_id and db_execute("SELECT id FROM qo_documents WHERE id=%s", (doc_id,), fetch=True):
        db_execute("UPDATE qo_documents SET title=%s, doc_date=%s, officer_name=%s, data=%s WHERE id=%s",
                   (title, doc_date, officer, json.dumps(data, ensure_ascii=False), doc_id))
        saved_id, act = doc_id, "update"
    else:
        saved_id = db_execute(
            "INSERT INTO qo_documents (doc_type, title, doc_date, officer_name, status, source_id, activity_id, data, created_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (doc_type, title, doc_date, officer, status, source_id, activity_id, json.dumps(data, ensure_ascii=False), session.get("username", "")),
            lastrowid=True)
        act = "save"
    if doc_type == "attendance" and link_agenda_id:
        db_execute("UPDATE qo_documents SET source_id=%s WHERE id=%s AND doc_type='agenda'", (saved_id, link_agenda_id))
    log_action(act, "qo_document", saved_id, doc_type)
    return {"ok": True, "id": saved_id}


@app.route("/quality-officers/open-attendance")
@login_required
def qo_open_attendance():
    rows = db_execute(
        "SELECT id, title, doc_date, officer_name, data, created_at FROM qo_documents "
        "WHERE doc_type='attendance' AND status='open' ORDER BY id DESC", fetch=True) or []
    ag = db_execute("SELECT id, title, doc_date, source_id FROM qo_documents "
                    "WHERE doc_type='agenda' AND source_id IS NOT NULL", fetch=True) or []
    agmap = {}
    for a in ag:
        agmap.setdefault(a["source_id"], {"id": a["id"], "title": a["title"], "date": a["doc_date"]})
    items = [{"id": r["id"], "title": r["title"], "date": r["doc_date"], "officer": r["officer_name"],
              "data": json.loads(r["data"] or "[]"), "created_at": str(r["created_at"])[:19],
              "agenda": agmap.get(r["id"])} for r in rows]
    return {"ok": True, "items": items}


@app.route("/quality-officers/unlinked-agendas")
@login_required
def qo_unlinked_agendas():
    rows = db_execute("SELECT id, title, doc_date, officer_name FROM qo_documents "
                      "WHERE doc_type='agenda' AND (source_id IS NULL OR source_id=0) ORDER BY id DESC", fetch=True) or []
    items = [{"id": r["id"], "title": r["title"], "date": r["doc_date"], "officer": r["officer_name"]} for r in rows]
    return {"ok": True, "items": items}


QO_DOMAINS = {
    "qo": {"label": "Υπευθύνων Ποιότητας", "home": "quality_officers", "list_title": "Δραστηριότητες", "code": "ΔΥΠ", "store": "quality_officers"},
    "cc": {"label": "Κλινικών Συντονιστών", "home": "clinical_coordinators", "list_title": "Δραστηριότητες Κλινικών Συντονιστών", "code": "ΔΚΣ", "store": "clinical_coordinators"},
}


def _dom():
    d = request.values.get("domain") or "qo"
    return d if d in QO_DOMAINS else "qo"


def _activity_domain(aid):
    r = db_execute("SELECT domain FROM qo_activities WHERE id=%s", (aid,), fetch=True)
    return (r[0]["domain"] if r and r[0].get("domain") else "qo")


@app.route("/quality-officers/activity/new")
@login_required
def qo_activity_new():
    qa = [r["full_name"] for r in (db_execute("SELECT full_name FROM users WHERE role='quality_officer' AND active=1 AND full_name IS NOT NULL ORDER BY full_name", fetch=True) or []) if (r["full_name"] or "").strip()]
    floors = _kv_get("clinic_layout", CLINIC_FLOORS)
    _d = _dom(); _cfg = QO_DOMAINS[_d]
    info = _kv_get(_cfg["store"], {}) or {}
    qo_map = {}
    for f in floors:
        for d in (f.get("depts") or []):
            nm = d.get("name")
            if nm:
                qo_map[nm] = info.get(nm, {})
    return render_template("qo_activity.html", qa_officers=qa, qo_map=qo_map, domain=_d, label=_cfg["label"], back_url=url_for(_cfg["home"]))


@app.route("/quality-officers/activity/save", methods=["POST"])
@login_required
def qo_activity_save():
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip()[:300]
    act_date = (payload.get("date") or "").strip()[:20]
    officer = (payload.get("officer") or "").strip()[:200]
    kind = (payload.get("kind") or "Τακτική").strip()[:20]
    if kind not in ("Τακτική", "Έκτακτη"):
        kind = "Τακτική"
    freq = (payload.get("frequency") or "").strip()[:20] if kind == "Τακτική" else ""
    try:
        aid = int(payload.get("id")) if payload.get("id") not in (None, "", 0, "0") else None
    except (ValueError, TypeError):
        aid = None
    if aid and db_execute("SELECT id FROM qo_activities WHERE id=%s", (aid,), fetch=True):
        db_execute("UPDATE qo_activities SET title=%s, act_date=%s, officer_name=%s, kind=%s, frequency=%s WHERE id=%s",
                   (title, act_date, officer, kind, freq, aid))
        db_execute("UPDATE qo_documents SET title=%s, doc_date=%s, officer_name=%s WHERE activity_id=%s",
                   (title, act_date, officer, aid))
        _c = db_execute("SELECT code FROM qo_activities WHERE id=%s", (aid,), fetch=True)
        return {"ok": True, "id": aid, "code": (_c[0]["code"] if _c else "")}
    dom = payload.get("domain") if payload.get("domain") in QO_DOMAINS else "qo"
    rid = db_execute("INSERT INTO qo_activities (code, title, act_date, officer_name, kind, frequency, domain, created_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                     ("", title, act_date, officer, kind, freq, dom, session.get("username", "")), lastrowid=True)
    code = "%s-%d" % (QO_DOMAINS[dom]["code"], rid)
    db_execute("UPDATE qo_activities SET code=%s WHERE id=%s", (code, rid))
    log_action("create", "qo_activity", rid, title)
    return {"ok": True, "id": rid, "code": code}


@app.route("/quality-officers/activities")
@login_required
def qo_activities_list():
    _d = _dom()
    acts = db_execute("SELECT * FROM qo_activities WHERE domain=%s ORDER BY id DESC", (_d,), fetch=True) or []
    docs = db_execute("SELECT id, doc_type, activity_id, signed_file, signed_orig, data, esign_at FROM qo_documents WHERE activity_id IS NOT NULL", fetch=True) or []
    att = {}; ag = {}
    for d in docs:
        if d["doc_type"] == "attendance":
            att.setdefault(d["activity_id"], d)
        elif d["doc_type"] == "agenda":
            ag.setdefault(d["activity_id"], d)
    open_rows = []; done_rows = []
    for a in acts:
        _att = att.get(a["id"]); _ag = ag.get(a["id"])
        calls = present = 0
        if _att:
            try:
                _its = json.loads(_att["data"] or "[]")
            except Exception:
                _its = []
            calls = len(_its)
            present = sum(1 for p in _its if isinstance(p, dict) and p.get("present"))
        att_signed = bool(_att and _att.get("esign_at"))
        ag_signed = bool(_ag and _ag.get("esign_at"))
        row = {"a": a, "att": _att, "agenda": _ag, "att_signed": att_signed, "ag_signed": ag_signed,
               "calls": calls, "present": present, "absences": (calls - present)}
        (done_rows if (att_signed and ag_signed) else open_rows).append(row)
    _cfg = QO_DOMAINS[_d]
    return render_template("qo_activities_list.html", open_rows=open_rows, done_rows=done_rows, is_admin=(session.get("role") == "admin"), domain=_d, list_title=_cfg["list_title"], back_url=url_for(_cfg["home"]), new_url=url_for("qo_activity_new", domain=_d))


@app.route("/quality-officers/activity/<int:aid>/signed", methods=["POST"])
@login_required
def qo_activity_signed_upload(aid):
    att = db_execute("SELECT id FROM qo_documents WHERE activity_id=%s AND doc_type='attendance' ORDER BY id LIMIT 1", (aid,), fetch=True)
    if not att:
        flash("Δεν υπάρχει παρουσιολόγιο για αυτή τη δραστηριότητα.", "warning")
        return redirect(request.form.get("next") or url_for("qo_activities_list"))
    f = request.files.get("signed")
    if not f or not f.filename:
        flash("Δεν επιλέχθηκε αρχείο.", "warning")
        return redirect(request.form.get("next") or url_for("qo_activities_list"))
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        flash("Μη αποδεκτός τύπος αρχείου (.%s). Αποδεκτά: %s" % (ext, ", ".join(sorted(ALLOWED_EXTENSIONS))), "warning")
        return redirect(request.form.get("next") or url_for("qo_activities_list"))
    stored = "%s_%s.%s" % (datetime.now().strftime("%Y%m%d%H%M%S"), secrets.token_hex(4), ext)
    f.save(os.path.join(UPLOAD_FOLDER, stored))
    db_execute("UPDATE qo_documents SET signed_file=%s, signed_orig=%s WHERE id=%s",
               (stored, secure_filename(f.filename)[:300], att[0]["id"]))
    log_action("upload", "qo_signed", aid)
    flash("Το υπογεγραμμένο παρουσιολόγιο ανέβηκε.", "success")
    return redirect(request.form.get("next") or url_for("qo_activities_list"))


@app.route("/quality-officers/activity/<int:aid>/signed-file")
@login_required
def qo_activity_signed_file(aid):
    r = db_execute("SELECT signed_file, signed_orig FROM qo_documents WHERE activity_id=%s AND doc_type='attendance' AND signed_file IS NOT NULL ORDER BY id LIMIT 1", (aid,), fetch=True)
    if not r:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, r[0]["signed_file"], as_attachment=False,
                               download_name=r[0]["signed_orig"] or r[0]["signed_file"])


@app.route("/quality-officers/activity/<int:aid>/close", methods=["POST"])
@login_required
def qo_activity_close(aid):
    db_execute("UPDATE qo_activities SET status='closed' WHERE id=%s", (aid,))
    db_execute("UPDATE qo_documents SET status='closed' WHERE activity_id=%s", (aid,))
    log_action("close", "qo_activity", aid)
    flash("Η δραστηριότητα έκλεισε.", "success")
    return redirect(url_for("qo_activities_list", domain=_activity_domain(aid)))


@app.route("/quality-officers/activity/<int:aid>/delete", methods=["POST"])
@role_required("admin")
def qo_activity_delete(aid):
    _dm = _activity_domain(aid)
    db_execute("DELETE FROM qo_documents WHERE activity_id=%s", (aid,))
    db_execute("DELETE FROM qo_activities WHERE id=%s", (aid,))
    log_action("delete", "qo_activity", aid)
    flash("Η δραστηριότητα διαγράφηκε.", "info")
    return redirect(url_for("qo_activities_list", domain=_dm))


@app.route("/quality-officers/doc/<int:did>/view")
@login_required
def qo_doc_view(did):
    r = db_execute("SELECT * FROM qo_documents WHERE id=%s", (did,), fetch=True)
    if not r:
        abort(404)
    d = r[0]
    try:
        data = json.loads(d["data"] or "null")
    except Exception:
        data = None
    import html as _html
    e = lambda t: _html.escape("" if t is None else str(t))
    L1 = url_for("static", filename="img/logo_okypy.png", _external=True)
    L2 = url_for("static", filename="img/logo_audit.png", _external=True)
    dd = (d.get("doc_date") or "")
    ddf = ("/".join(reversed(dd.split("-"))) if dd.count("-") == 2 else dd)
    title = e(d.get("title") or "Έγγραφο")
    if d["doc_type"] == "agenda":
        _adom = _activity_domain(d["activity_id"]) if d.get("activity_id") else "qo"
        return render_template("qo_agenda_edit.html", doc=d, items=(data or []), datef=ddf, save_url=url_for("qo_doc_save"), sign_url=url_for("qo_doc_sign", did=d["id"]), back_url=url_for("qo_activities_list", domain=_adom))
    if d["doc_type"] == "attendance":
        body = '<table><thead><tr><th>Κλινική / Τμήμα</th><th>Συμμετέχων</th><th>Τηλέφωνα</th><th>Email</th><th style="width:170px">Υπογραφή</th></tr></thead><tbody>'
        for p in (data or []):
            p = p or {}
            ph = "<br>".join(e(x) for x in (p.get("phones") or [])) or "—"
            em = "<br>".join(e(x) for x in (p.get("emails") or [])) or "—"
            body += "<tr><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td><td style=\"height:38px\"></td></tr>" % (e(p.get("clinic")), e(p.get("officer") or "—"), ph, em)
        body += "</tbody></table>"
    else:
        emails = (data or {}).get("emails") if isinstance(data, dict) else []
        body = "<p style='font-size:0.95rem'>%s</p>" % e("; ".join(emails or []))
    page = ("<!doctype html><html><head><meta charset='utf-8'><title>%s</title>"
            "<style>@page{size:A4;margin:14mm} body{font-family:Arial,sans-serif;color:#000;padding:16px} table{border-collapse:collapse;width:100%%;font-size:0.85rem;margin-top:6px} th,td{border:1px solid #999;padding:6px;text-align:left;vertical-align:top} th{background:#eee} @media print{.noprint{display:none}}</style></head><body>"
            "<div style='display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid #333;padding-bottom:8px;margin-bottom:6px'>"
            "<img src='%s' style='height:58px'><div style='text-align:center'><div style='font-size:1.25rem;font-weight:bold'>%s</div>"
            "<div>Γενικό Νοσοκομείο Λευκωσίας</div><div>Ημερομηνία: %s</div></div><img src='%s' style='height:58px'></div>"
            "<div style='text-align:center;color:#555;font-size:0.78rem;margin-bottom:10px'>Accreditation Canada - Platinum</div>"
            "%s"
            "<div style='margin-top:34px'><div>Υπεύθυνος: <strong>%s</strong></div><div style='margin-top:30px'>Υπογραφή: ______________________________</div></div>"
            "<div class='noprint' style='margin-top:16px'><button onclick='window.print()'>Εκτύπωση</button></div>"
            "</body></html>") % (title, L1, title, e(ddf), L2, body, e(d.get("officer_name")))
    return page


@app.route("/quality-officers/doc/<int:did>/sign", methods=["POST"])
@login_required
def qo_doc_sign(did):
    r = db_execute("SELECT * FROM qo_documents WHERE id=%s", (did,), fetch=True)
    if not r:
        return {"ok": False, "message": "Δεν βρέθηκε το έγγραφο."}, 404
    d = r[0]
    if d.get("esign_at"):
        return {"ok": False, "message": "Έχει ήδη υπογραφεί."}
    signer = (d.get("officer_name") or "").strip()
    if not signer:
        return {"ok": False, "message": "Δεν έχει οριστεί υπεύθυνος για υπογραφή."}
    password = (request.get_json(silent=True) or {}).get("password") or ""
    norm = _norm_name(signer)
    users = db_execute("SELECT password_hash, full_name FROM users WHERE active=1", fetch=True) or []
    ok = any(_norm_name(u["full_name"]) == norm and check_password_hash(u["password_hash"], password) for u in users)
    if not ok:
        return {"ok": False, "message": "Λάθος κωδικός ή δεν αντιστοιχεί στον υπεύθυνο."}
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    db_execute("UPDATE qo_documents SET esign_by=%s, esign_at=%s WHERE id=%s", (signer, now, did))
    log_action("esign", "qo_document", did, signer)
    return {"ok": True, "by": signer, "at": now}


@app.route("/quality-officers/activity/<int:aid>/attendance")
@login_required
def qo_attendance_record(aid):
    r = db_execute("SELECT * FROM qo_documents WHERE activity_id=%s AND doc_type='attendance' ORDER BY id LIMIT 1", (aid,), fetch=True)
    if not r:
        flash("Δεν υπάρχει παρουσιολόγιο για αυτή τη δραστηριότητα.", "warning")
        return redirect(url_for("qo_activities_list"))
    d = r[0]
    try:
        items = json.loads(d["data"] or "[]")
    except Exception:
        items = []
    dd = d.get("doc_date") or ""
    ddf = "/".join(reversed(dd.split("-"))) if dd.count("-") == 2 else dd
    return render_template("qo_attendance_record.html", doc=d, items=items, datef=ddf,
                           save_url=url_for("qo_presence_save", did=d["id"]),
                           signed_url=(url_for("qo_activity_signed_file", aid=aid) if d.get("signed_file") else None),
                           upload_url=url_for("qo_activity_signed_upload", aid=aid),
                           next_url=url_for("qo_attendance_record", aid=aid))


@app.route("/quality-officers/doc/<int:did>/presence", methods=["POST"])
@login_required
def qo_presence_save(did):
    r = db_execute("SELECT * FROM qo_documents WHERE id=%s", (did,), fetch=True)
    if not r:
        return {"ok": False, "message": "Δεν βρέθηκε το έγγραφο."}, 404
    d = r[0]
    if d.get("esign_at"):
        return {"ok": False, "message": "Έχει ήδη υπογραφεί."}
    signer = (d.get("officer_name") or "").strip()
    if not signer:
        return {"ok": False, "message": "Δεν έχει οριστεί υπεύθυνος."}
    payload = request.get_json(silent=True) or {}
    present = payload.get("present") or []
    password = payload.get("password") or ""
    try:
        items = json.loads(d["data"] or "[]")
    except Exception:
        items = []
    for i, p in enumerate(items):
        if isinstance(p, dict):
            p["present"] = bool(present[i]) if i < len(present) else False
    norm = _norm_name(signer)
    users = db_execute("SELECT password_hash, full_name FROM users WHERE active=1", fetch=True) or []
    ok = any(_norm_name(u["full_name"]) == norm and check_password_hash(u["password_hash"], password) for u in users)
    if not ok:
        return {"ok": False, "message": "Λάθος κωδικός ή δεν αντιστοιχεί στον υπεύθυνο."}
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    db_execute("UPDATE qo_documents SET data=%s, esign_by=%s, esign_at=%s WHERE id=%s",
               (json.dumps(items, ensure_ascii=False), signer, now, did))
    log_action("presence_esign", "qo_document", did, signer)
    pres = sum(1 for p in items if isinstance(p, dict) and p.get("present"))
    return {"ok": True, "present": pres, "total": len(items), "by": signer, "at": now}


@app.route("/quality-officers/review-save", methods=["POST"])
@login_required
def quality_review_save():
    d = request.get_json(silent=True) or {}
    uname = session.get("username", "")
    me = db_execute("SELECT full_name FROM users WHERE username=%s", (uname,), fetch=True)
    reviewer = (me[0]["full_name"] if me and me[0]["full_name"] else "") or uname
    _kv_set("quality_review", {"last": str(d.get("last") or "")[:20], "next": str(d.get("next") or "")[:20], "reviewed_by": reviewer, "reviewed_by_user": uname})
    return {"ok": True, "reviewed_by": reviewer}


@app.route("/work-scheduling")
@login_required
def work_scheduling():
    today = date.today()
    try:
        _y, _m = [int(x) for x in (request.args.get("ym") or "").split("-")]
        first = date(_y, _m, 1)
    except Exception:
        first = date(today.year, today.month, 1)
    y, m = first.year, first.month
    nextfirst = date(y + 1, 1, 1) if m == 12 else date(y, m + 1, 1)
    last = nextfirst - timedelta(days=1)
    start = first - timedelta(days=first.weekday())
    weeks = []
    cur = start
    while cur <= last:
        days = []
        for i in range(7):
            dd = cur + timedelta(days=i)
            days.append({"day": dd.day, "iso": dd.isoformat(), "in_month": dd.month == m, "today": dd == today})
        weeks.append({"monday": cur.isoformat(), "days": days})
        cur = cur + timedelta(days=7)
    prev_first = (first - timedelta(days=1)).replace(day=1)
    month_label = "%s %d" % (MONTHS.get(m, str(m)), y)
    return render_template("work_scheduling.html", weeks=weeks, month_label=month_label,
                           prev_ym="%04d-%02d" % (prev_first.year, prev_first.month),
                           next_ym="%04d-%02d" % (nextfirst.year, nextfirst.month))


def _work_week_label(monday_iso):
    try:
        mon = datetime.strptime(monday_iso, "%Y-%m-%d").date()
    except Exception:
        return monday_iso
    sun = mon + timedelta(days=6)
    return "%02d/%02d/%d – %02d/%02d/%d" % (mon.day, mon.month, mon.year, sun.day, sun.month, sun.year)


@app.route("/work-scheduling/week")
@login_required
def work_scheduling_week():
    week = (request.args.get("week") or "").strip()
    if not week:
        return redirect(url_for("work_scheduling"))
    officers = _kv_get("work_officers", []) or []
    officer = (request.args.get("officer") or "").strip()
    if officer and officer not in officers:
        officer = ""
    if not officer and officers:
        officer = officers[0]
    plans = _kv_get("work_plans", {}) or {}
    plan = plans.get(week + "||" + officer, {}) if officer else {}
    activities = (list(plan.get("activities") or []) + [{"text": "", "overtime": False}] * 8)[:8]
    pending = (list(plan.get("pending") or []) + [""] * 8)[:8]
    return render_template("work_scheduling_week.html", week=week, week_label=_work_week_label(week),
                           officers=officers, officer=officer, activities=activities, pending=pending)


@app.route("/work-scheduling/add-officer", methods=["POST"])
@login_required
def work_scheduling_add_officer():
    week = (request.form.get("week") or "").strip()
    name = (request.form.get("officer_name") or "").strip()[:120]
    officers = _kv_get("work_officers", []) or []
    if name and name not in officers:
        officers.append(name)
        _kv_set("work_officers", officers)
    return redirect(url_for("work_scheduling_week", week=week, officer=name))


@app.route("/work-scheduling/save", methods=["POST"])
@login_required
def work_scheduling_save():
    week = (request.form.get("week") or "").strip()
    officer = (request.form.get("officer") or "").strip()
    if not week or not officer:
        flash("Επίλεξε εβδομάδα και Λειτουργό Μονάδας.", "warning")
        return redirect(url_for("work_scheduling_week", week=week, officer=officer))
    officers = _kv_get("work_officers", []) or []
    if officer not in officers:
        officers.append(officer)
        _kv_set("work_officers", officers)
    activities = []
    for i in range(1, 9):
        activities.append({"text": (request.form.get("activity_%d" % i) or "").strip()[:500],
                           "overtime": bool(request.form.get("overtime_%d" % i))})
    pending = [(request.form.get("pending_%d" % i) or "").strip()[:500] for i in range(1, 9)]
    plans = _kv_get("work_plans", {}) or {}
    plans[week + "||" + officer] = {"activities": activities, "pending": pending}
    _kv_set("work_plans", plans)
    log_action("save", "work_plan", week + "/" + officer)
    flash("Ο προγραμματισμός αποθηκεύτηκε.", "success")
    return redirect(url_for("work_scheduling_week", week=week, officer=officer))


@app.route("/task-entry", methods=["GET", "POST"])
@login_required
def task_entry():
    categories = _kv_get("task_categories", []) or []
    assignees = _kv_get("task_assignees", []) or []
    if request.method == "POST":
        category = (request.form.get("category") or "").strip()[:120]
        kind = (request.form.get("kind") or "").strip()[:200]
        description = (request.form.get("description") or "").strip()[:1000]
        assignee = (request.form.get("assignee") or "").strip()[:120]
        deadline = (request.form.get("deadline") or "").strip()[:20]
        if not category and not description:
            flash("Συμπλήρωσε τουλάχιστον Κατηγορία ή Περιγραφή.", "warning")
            return redirect(url_for("task_entry"))
        if category and category not in categories:
            categories.append(category); _kv_set("task_categories", categories)
        if assignee and assignee not in assignees:
            assignees.append(assignee); _kv_set("task_assignees", assignees)
        file_stored = ""; file_orig = ""
        f = request.files.get("attachment")
        if f and f.filename:
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
            if ext not in ALLOWED_EXTENSIONS:
                flash("Μη αποδεκτός τύπος αρχείου (.%s). Αποδεκτοί: %s" % (ext, ", ".join(sorted(ALLOWED_EXTENSIONS))), "warning")
                return redirect(url_for("task_entry"))
            file_stored = "%s_%s.%s" % (datetime.now().strftime("%Y%m%d%H%M%S"), secrets.token_hex(4), ext)
            f.save(os.path.join(UPLOAD_FOLDER, file_stored))
            file_orig = secure_filename(f.filename)[:300] or file_stored
        tasks = _kv_get("tasks", []) or []
        tasks.append({"id": secrets.token_hex(8), "category": category, "kind": kind, "description": description,
                      "assignee": assignee, "deadline": deadline,
                      "file_stored": file_stored, "file_orig": file_orig,
                      "created_by": session.get("username", ""),
                      "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")})
        _kv_set("tasks", tasks)
        log_action("create", "task", "", (category + " · " + assignee).strip(" ·"))
        flash("Η εργασία καταχωρήθηκε.", "success")
        return redirect(url_for("task_entry"))
    tasks = _kv_get("tasks", []) or []
    recent = list(reversed(tasks))[:15]
    return render_template("task_entry.html",
                           categories=sorted(categories, key=lambda x: (x or "").lower()),
                           assignees=sorted(assignees, key=lambda x: (x or "").lower()),
                           recent=recent)


@app.route("/task-entry/file/<path:stored>")
@login_required
def task_file(stored):
    tasks = _kv_get("tasks", []) or []
    match = next((t for t in tasks if t.get("file_stored") == stored), None)
    if not match:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, stored, as_attachment=False,
                               download_name=match.get("file_orig") or stored)


@app.route("/task-list")
@login_required
def task_list():
    tasks = _kv_get("tasks", []) or []
    dirty = False
    for t in tasks:
        if not t.get("id"):
            t["id"] = secrets.token_hex(8); dirty = True
    if dirty:
        _kv_set("tasks", tasks)
    return render_template("task_list.html", tasks=list(reversed(tasks)),
                           is_admin=(session.get("role") == "admin"))


@app.route("/task-list/<tid>/delete", methods=["POST"])
@role_required("admin")
def task_delete(tid):
    tasks = _kv_get("tasks", []) or []
    keep = []
    removed = None
    for t in tasks:
        if t.get("id") == tid:
            removed = t
        else:
            keep.append(t)
    if removed is not None:
        if removed.get("file_stored"):
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, removed["file_stored"]))
            except OSError:
                pass
        _kv_set("tasks", keep)
        log_action("delete", "task", tid, removed.get("category", ""))
        flash("Η εργασία διαγράφηκε.", "info")
    return redirect(url_for("task_list"))


@app.route("/clinical-coordinators")
@login_required
def clinical_coordinators():
    floors = _kv_get("clinic_layout", CLINIC_FLOORS)
    info = _kv_get("clinical_coordinators", {}) or {}
    clinics = []
    for f in floors:
        for d in (f.get("depts") or []):
            nm = d.get("name")
            clinics.append({"name": nm, "floor": f.get("level"), "info": info.get(nm, {})})
    clinics.sort(key=lambda c: (c.get("name") or "").strip().lower())
    cc_map = {c["name"]: c["info"] for c in clinics}
    review = _kv_get("clinical_coordinators_review", {}) or {}
    _ru = review.get("reviewed_by_user")
    if _ru:
        _me = db_execute("SELECT full_name FROM users WHERE username=%s", (_ru,), fetch=True)
        if _me and _me[0]["full_name"]:
            review = dict(review); review["reviewed_by"] = _me[0]["full_name"]
    _qa = [r["full_name"] for r in (db_execute("SELECT full_name FROM users WHERE role='quality_officer' AND active=1 AND full_name IS NOT NULL ORDER BY full_name", fetch=True) or []) if (r["full_name"] or "").strip()]
    return render_template("clinical_coordinators.html", clinics=clinics, qo_map=cc_map, review=review,
                           can_edit=(restricted_spec() is None), qa_officers=_qa, qa_head=QA_HEAD_NAME, clinic_counts={})


@app.route("/clinical-coordinators/save", methods=["POST"])
@login_required
def clinical_coordinators_save():
    payload = request.get_json(silent=True) or {}
    clean = {}
    for name, d in payload.items():
        if not isinstance(d, dict):
            continue
        officers = []
        for ofc in (d.get("officers") or [])[:4]:
            if not isinstance(ofc, dict):
                continue
            nm = str(ofc.get("name") or "").strip()[:120]
            emails = [str(e).strip()[:120] for e in (ofc.get("emails") or []) if str(e).strip()][:2]
            if nm or emails:
                officers.append({"name": nm, "emails": emails})
        phones = [str(p).strip()[:60] for p in (d.get("phones") or []) if str(p).strip()][:3]
        clean[str(name)[:200]] = {"officers": officers, "phones": phones}
    _kv_set("clinical_coordinators", clean)
    return {"ok": True}


@app.route("/clinical-coordinators/review-save", methods=["POST"])
@login_required
def clinical_coordinators_review_save():
    d = request.get_json(silent=True) or {}
    uname = session.get("username", "")
    me = db_execute("SELECT full_name FROM users WHERE username=%s", (uname,), fetch=True)
    reviewer = (me[0]["full_name"] if me and me[0]["full_name"] else "") or uname
    _kv_set("clinical_coordinators_review", {"last": str(d.get("last") or "")[:20], "next": str(d.get("next") or "")[:20], "reviewed_by": reviewer, "reviewed_by_user": uname})
    return {"ok": True, "reviewed_by": reviewer}


@app.route("/patient-safety/reports")
@login_required
def psafety_reports():
    return render_template("placeholder.html", ptitle="Αναφορές Ασφάλειας Ασθενών", picon="bi-file-medical")


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
    _role = session.get("role")
    can_add_ind = _role in ("admin", "central", "q_add", "q_edit", "q_delete")
    can_delete_ind = _role in ("admin", "central", "q_delete")
    return render_template("indicators_list.html", indicators=indicators, categories=categories,
                           sel_category=category, sel_grp=grp, groups=groups,
                           can_add=can_add_ind, can_delete=can_delete_ind)


def _clinic_dept_names():
    """Λίστα Κλινικών/Τμημάτων από τη διάταξη κτιρίου (ίδια με το dropdown Κλινικές/Τμήματα)."""
    floors = _kv_get("clinic_layout", CLINIC_FLOORS)
    names = [d.get("name") for f in floors for d in (f.get("depts") or []) if d.get("name")]
    return sorted(set(names), key=lambda x: (x or "").strip().lower())


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
        "grp": (request.form.get("category") or "").strip() or None,
        "max_score": fnum("max_score"),
    }


@app.route("/indicators/new", methods=["GET", "POST"])
@role_required("admin", "central", "q_add", "q_edit", "q_delete", "ic_nurse")
def indicator_new():
    if request.method == "POST":
        d = _indicator_from_form()
        if not can_manage_indicator_cat(d["category"]):
            flash("Μπορείτε να προσθέσετε δείκτες μόνο στην επιτρεπόμενη κατηγορία σας.", "danger")
        elif not d["code"] or not d["name"]:
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
    return render_template("indicator_form.html", ind=None, dept_list=_clinic_dept_names(), force_cats=_indicator_cats())


@app.route("/indicators/<int:ind_id>/edit", methods=["GET", "POST"])
@login_required
def indicator_edit(ind_id):
    rows = db_execute("SELECT * FROM indicators WHERE id=%s", (ind_id,), fetch=True)
    if not rows:
        abort(404)
    can_edit = session.get("role") in ("admin", "central", "q_edit", "q_delete") or (restricted_spec() is not None and can_manage_indicator_cat(rows[0]["category"]))
    if request.method == "POST":
        if not can_edit:
            flash("Δεν έχετε δικαίωμα τροποποίησης δεικτών ποιότητας.", "danger")
            return redirect(url_for("indicator_view", ind_id=ind_id))
        d = _indicator_from_form()
        if restricted_spec() is not None and not can_manage_indicator_cat(d["category"]):
            flash("Δεν επιτρέπεται αλλαγή σε κατηγορία εκτός αρμοδιότητάς σας.", "danger")
            return redirect(url_for("indicator_edit", ind_id=ind_id))
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
    return render_template("indicator_form.html", ind=rows[0], can_edit=can_edit, dept_list=_clinic_dept_names(), force_cats=_indicator_cats())


@app.route("/indicators/<int:ind_id>/delete", methods=["POST"])
@login_required
def indicator_delete(ind_id):
    row = db_execute("SELECT code, category FROM indicators WHERE id=%s", (ind_id,), fetch=True)
    if not row:
        abort(404)
    if session.get("role") not in ("admin", "central", "q_delete") and not (restricted_spec() is not None and can_manage_indicator_cat(row[0]["category"])):
        flash("Δεν έχετε δικαίωμα διαγραφής δεικτών.", "danger")
        return redirect(url_for("indicators_list"))
    db_execute("DELETE FROM indicator_values WHERE indicator_id=%s", (ind_id,))
    db_execute("DELETE FROM indicators WHERE id=%s", (ind_id,))
    log_action("delete", "indicator", ind_id, row[0]["code"])
    flash("Ο δείκτης διαγράφηκε.", "info")
    return redirect(url_for("indicators_list"))


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
    # Διαθέσιμες ομάδες δεικτών (π.χ. ΤΑΕΠ Ενηλίκων / ΤΑΕΠ Παίδων) + τμήματα/κλινικές
    grp_rows = db_execute(
        "SELECT DISTINCT grp FROM indicators WHERE grp IS NOT NULL AND grp<>'' ORDER BY grp", fetch=True) or []
    groups = [r["grp"] for r in grp_rows]
    grp = request.values.get("grp")
    if grp is None:
        grp = groups[0] if groups else ""
    elif grp and grp not in groups:
        grp = groups[0] if groups else ""

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
    can_edit = can_edit_hospital(hosp)   # τροποποίηση υπαρχόντων
    can_delete = can_delete_hospital(hosp)  # διαγραφή υπαρχόντων
    can_add = can_add_hospital(hosp)     # προσθήκη νέων (π.χ. ρόλος quality_add)
    editable = can_add                   # μπορεί να αλληλεπιδράσει με τη φόρμα

    # Όλοι οι ενεργοί δείκτες της επιλεγμένης ομάδας ('' = γενικοί)· η περίοδος επιλέγεται χειροκίνητα
    indicators = [i for i in (db_execute(
        "SELECT * FROM indicators WHERE active=1 ORDER BY category, sort_order, code", fetch=True) or [])
        if grp == "" or (i.get("grp") or "") == grp]
    scored = any(i.get("max_score") is not None for i in indicators)  # «βαθμολογούμενη» ομάδα = δείκτες με μέγιστη βαθμολογία
    if restricted_spec() is not None:
        _cats = set(_indicator_cats() or [])
        indicators = [i for i in (db_execute("SELECT * FROM indicators WHERE active=1 ORDER BY category, sort_order, code", fetch=True) or []) if (i.get("category") or "") in _cats]
        can_edit = can_delete = can_add = editable = True
        scored = any(i.get("max_score") is not None for i in indicators)

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
                "SELECT id, value, result_text, score FROM indicator_values "
                "WHERE indicator_id=%s AND hospital_code=%s AND year=%s AND month=%s",
                (ind["id"], hosp, year, month), fetch=True)
            if raw == "" and score_raw == "":
                if existing:
                    if can_delete:
                        db_execute("DELETE FROM indicator_values WHERE id=%s", (existing[0]["id"],))
                        deleted += 1
                    else:
                        skipped += 1  # προσπάθεια διαγραφής αποθηκευμένου (δεν επιτρέπεται)
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
                    # Ρόλος «προσθήκη»: δεν τροποποιεί αποθηκευμένα· μέτρα ως προσπάθεια μόνο αν άλλαξε κάτι
                    ev = existing[0]
                    cur_res = ev.get("result_text") or (fmtnum_filter(ev["value"]) if ev["value"] is not None else "")
                    cur_score = fmtnum_filter(ev["score"]) if ev.get("score") is not None else ""
                    if raw != cur_res or (score_raw != "" and score_raw != cur_score):
                        skipped += 1
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
        if skipped:
            flash(f"Δεν μπορείτε να τροποποιήσετε αποθηκευμένα στοιχεία — {skipped} υπάρχουσες τιμές "
                  f"έμειναν αμετάβλητες." + (f" Αποθηκεύτηκαν {saved} νέες τιμές." if saved else ""), "warning")
        else:
            flash(f"Αποθηκεύτηκαν {saved} τιμές" + (f", διαγράφηκαν {deleted}." if deleted else "."), "success")
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
    # Λίστα αποθηκευμένων περιόδων (καταχωρήσεων) της τρέχουσας ομάδας — για γρήγορο άνοιγμα
    entry_rows = db_execute(
        "SELECT iv.year AS year, iv.month AS month, iv.month_from AS mf, iv.month_to AS mt, "
        "COUNT(*) AS n, MAX(iv.ref_no) AS ref_no "
        "FROM indicator_values iv JOIN indicators i ON i.id = iv.indicator_id "
        "WHERE i.active=1 AND COALESCE(i.grp,'')=%s AND iv.hospital_code=%s "
        "GROUP BY iv.year, iv.month, iv.month_from, iv.month_to "
        "ORDER BY iv.year DESC, iv.month DESC", (grp, hosp), fetch=True) or []
    entries = []
    for r in entry_rows:
        mf = r["mf"] or r["month"]; mt = r["mt"] or r["month"]
        entries.append({"year": r["year"], "month_from": mf, "month_to": mt,
                        "n": r["n"], "ref_no": r["ref_no"]})
    # Reports (ανεβασμένα έγγραφα) ανά περίοδο της ομάδας — κράτα το πιο πρόσφατο ανά (έτος, μήνας λήξης)
    rep_map = {}
    for rr in (db_execute(
            "SELECT id, year, month, month_to, orig_name FROM documents "
            "WHERE hospital_code=%s AND COALESCE(grp,'')=%s ORDER BY id DESC", (hosp, grp), fetch=True) or []):
        key = (rr["year"], rr["month_to"] or rr["month"])
        if key not in rep_map:
            rep_map[key] = rr
    for e in entries:
        rr = rep_map.get((e["year"], e["month_to"]))
        e["report_id"] = rr["id"] if rr else None
        e["report_name"] = rr["orig_name"] if rr else None
    cur_report = rep_map.get((year, month_to))
    return render_template("values_entry.html", hosp=hosp, hosp_name=hosp_name, year=year,
                           month_from=month_from, month_to=month_to, years=years, indicators=indicators,
                           editable=editable, can_edit=can_edit, groups=groups, grp=grp,
                           scored=scored, ref_no=ref_no, entries=entries, cur_report=cur_report)


# ---------------------------------------------------------------------------
# Σύγκριση & τάσεις
# ---------------------------------------------------------------------------
@app.route("/compare")
@login_required
def compare_view():
    grp_rows = db_execute(
        "SELECT DISTINCT grp FROM indicators WHERE grp IS NOT NULL AND grp<>'' ORDER BY grp", fetch=True) or []
    groups = [r["grp"] for r in grp_rows]
    grp = request.args.get("grp")
    if grp is None:
        grp = groups[0] if groups else ""
    elif grp and grp not in groups:
        grp = groups[0] if groups else ""
    inds = [i for i in (db_execute(
        "SELECT * FROM indicators WHERE active=1 ORDER BY category, sort_order, code", fetch=True) or [])
        if grp == "" or (i.get("grp") or "") == grp]
    scored = any(i.get("max_score") is not None for i in inds)
    options = []
    if scored and grp:
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
    sel_type = (request.args.get("itype") or "").strip()
    date_from = (request.args.get("from") or "").strip()
    date_to = (request.args.get("to") or "").strip()
    sel_code = CATEGORY_TEMPLATE.get(sel_type) if sel_type else None
    df = _parse_date(date_from) if date_from else None
    dtt = _parse_date(date_to) if date_to else None
    code_to_cat = {v: k for k, v in CATEGORY_TEMPLATE.items()}
    insts = db_execute("SELECT ci.id AS id, ci.data AS data, t.code AS code "
                       "FROM checklist_instances ci JOIN checklist_templates t ON t.id=ci.template_id "
                       "WHERE ci.status='signed'", fetch=True) or []
    pend = {}
    for _dd in _all_deviations():
        if not (_dd["rem"] and _dd["rem"].get("remediated_date")):
            pend[_dd["instance_id"]] = pend.get(_dd["instance_id"], 0) + 1
    audits = []
    n_open = n_closed = 0
    for ci in insts:
        if sel_code and ci["code"] != sel_code:
            continue
        data = json.loads(ci["data"] or "{}")
        dd = _parse_date(data.get("meta_date"))
        if df and (dd is None or dd < df):
            continue
        if dtt and (dd is None or dd > dtt):
            continue
        opens = pend.get(ci["id"], 0)
        if opens:
            n_open += 1
        else:
            n_closed += 1
        audits.append({
            "id": ci["id"], "date": dd,
            "date_str": dd.strftime("%d/%m/%Y") if dd else (data.get("meta_date") or "—"),
            "department": data.get("meta_department") or "—",
            "itype": data.get("meta_itype") or code_to_cat.get(ci["code"], "—"),
            "inspectors": data.get("meta_inspectors") or "—",
            "open_count": opens,
            "kat_label": "Ανοικτή" if opens else "Κλειστή",
            "kat_color": "warning" if opens else "success",
        })
    audits.sort(key=lambda a: (a["date"] or date.min), reverse=True)
    return render_template("inspections_list.html", audits=audits,
                           categories=list(CATEGORY_TEMPLATE.keys()),
                           sel_type=sel_type, date_from=date_from, date_to=date_to,
                           n_total=len(audits), n_open=n_open, n_closed=n_closed)


def _audit_instances():
    return db_execute("SELECT ci.id, ci.title, t.code FROM checklist_instances ci "
                      "JOIN checklist_templates t ON t.id=ci.template_id ORDER BY ci.id DESC", (), fetch=True) or []


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
        (request.form.get("category") or "").strip(),
        request.form.get("instance_id", type=int),
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
               findings_major, findings_minor, observations, status, summary, actions, category, instance_id, created_by)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            vals + (session["username"],), lastrowid=True)
        log_action("create", "inspection", rid)
        flash("Η επιθεώρηση καταχωρήθηκε.", "success")
        return redirect(url_for("inspection_view", ins_id=rid))
    return render_template("inspection_form.html", ins=None, hospitals=get_hospitals(),
                           types=INSPECTION_TYPES, today=date.today().isoformat(),
                           instances=_audit_instances(),
                           category=request.args.get("category") or "")


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
               status=%s, summary=%s, actions=%s, category=%s, instance_id=%s WHERE id=%s""",
            vals + (ins_id,))
        log_action("update", "inspection", ins_id)
        flash("Η επιθεώρηση ενημερώθηκε.", "success")
        return redirect(url_for("inspection_view", ins_id=ins_id))
    return render_template("inspection_form.html", ins=rows[0], hospitals=get_hospitals(),
                           types=INSPECTION_TYPES, today=date.today().isoformat(),
                           instances=_audit_instances(),
                           category=rows[0].get("category") or "")


# ---------------------------------------------------------------------------
# Προγραμματισμός Επιθεωρήσεων (ημερολόγιο)
# ---------------------------------------------------------------------------
def _sched_from_form():
    all_day = 1 if request.form.get("all_day") else 0
    def _tf(hk, mk):
        h = (request.form.get(hk) or "").strip()
        mm = (request.form.get(mk) or "").strip()
        if not h and not mm:
            return None
        return f"{h or '00'}:{mm or '00'}"
    return {
        "insp_date": (request.form.get("insp_date") or date.today().isoformat()).strip(),
        "all_day": all_day,
        "start_time": None if all_day else _tf("start_h", "start_m"),
        "end_time": None if all_day else _tf("end_h", "end_m"),
        "department": (request.form.get("department") or "").strip(),
        "scope": (request.form.get("scope") or "").strip(),
        "itype": (request.form.get("itype") or "").strip(),
        "inspectors": [(request.form.get(f"inspector{i}") or "").strip() or None for i in (1, 2, 3)],
    }


def _sched_conflict(v, exclude_id=None):
    """Επιστρέφει (επιθεωρητής, εγγραφή) αν υπάρχει επικάλυψη χρόνου με κοινό επιθεωρητή· αλλιώς None."""
    mine = {i.strip().lower() for i in v["inspectors"] if i}
    if not mine:
        return None

    def _iv(all_day, st, et):
        return None if (all_day or not st or not et) else (st, et)

    a = _iv(v["all_day"], v["start_time"], v["end_time"])
    rows = db_execute("SELECT * FROM scheduled_inspections WHERE insp_date=%s", (v["insp_date"],), fetch=True) or []
    for r in rows:
        if exclude_id and r["id"] == exclude_id:
            continue
        theirs = {(r.get(f"inspector{i}") or "").strip().lower() for i in (1, 2, 3)}
        theirs.discard("")
        common = mine & theirs
        if not common:
            continue
        b = _iv(r.get("all_day"), r.get("start_time"), r.get("end_time"))
        if (a is None or b is None) or (a[0] < b[1] and b[0] < a[1]):
            return (next(iter(common)), r)
    return None


def _sched_redirect(v):
    try:
        return redirect(url_for("inspection_schedule", year=int(v["insp_date"][:4]), month=int(v["insp_date"][5:7])))
    except (ValueError, IndexError):
        return redirect(url_for("inspection_schedule"))


@app.route("/inspections/schedule")
@login_required
def inspection_schedule():
    today = date.today()
    try:
        year = int(request.args.get("year") or today.year)
        month = int(request.args.get("month") or today.month)
    except (TypeError, ValueError):
        year, month = today.year, today.month
    month = min(12, max(1, month))
    weeks = calendar.Calendar(firstweekday=0).monthdayscalendar(year, month)
    last = calendar.monthrange(year, month)[1]
    rows = db_execute(
        "SELECT * FROM scheduled_inspections WHERE insp_date BETWEEN %s AND %s ORDER BY insp_date, start_time",
        (f"{year:04d}-{month:02d}-01", f"{year:04d}-{month:02d}-{last:02d}"), fetch=True) or []
    by_day = {}
    for r in rows:
        d = r["insp_date"]
        day = d.day if hasattr(d, "day") else int(str(d)[8:10])
        by_day.setdefault(day, []).append(r)
    prev_y, prev_m = (year, month - 1) if month > 1 else (year - 1, 12)
    next_y, next_m = (year, month + 1) if month < 12 else (year + 1, 1)
    departments = [r["name"] for r in (db_execute(
        "SELECT name FROM departments ORDER BY name", fetch=True) or [])]
    inspectors = [r["name"] for r in (db_execute(
        "SELECT name FROM inspectors ORDER BY name", fetch=True) or [])]
    # Μετρητές: υπόλοιπη τρέχουσα εβδομάδα, επόμενη εβδομάδα, σύνολο εκκρεμών (>= σήμερα)
    eow = today + timedelta(days=(6 - today.weekday()))          # Κυριακή τρέχουσας εβδ.
    nmon = today + timedelta(days=(7 - today.weekday()))         # Δευτέρα επόμενης
    nsun = nmon + timedelta(days=6)
    def _cnt(d1, d2):
        return db_execute("SELECT COUNT(*) c FROM scheduled_inspections WHERE insp_date BETWEEN %s AND %s",
                          (d1.isoformat(), d2.isoformat()), fetch=True)[0]["c"]
    cnt_week = _cnt(today, eow)
    cnt_next = _cnt(nmon, nsun)
    cnt_pending = db_execute("SELECT COUNT(*) c FROM scheduled_inspections WHERE insp_date >= %s",
                             (today.isoformat(),), fetch=True)[0]["c"]
    # Επιθεωρήσεις που έγιναν φέτος (ημ/νία < σήμερα, εντός τρέχοντος έτους) + ανά είδος
    done_rows = db_execute(
        "SELECT itype, COUNT(*) c FROM scheduled_inspections "
        "WHERE insp_date >= %s AND insp_date < %s GROUP BY itype",
        (f"{today.year}-01-01", today.isoformat()), fetch=True) or []
    done_by_type = [((r["itype"] or "—"), r["c"]) for r in sorted(done_rows, key=lambda x: -x["c"])]
    done_total = sum(r["c"] for r in done_rows)
    # Κατάσταση επιθεωρήσεων (βάσει υπογεγραμμένης λίστας ελέγχου + ανοικτών αποκλίσεων)
    all_sched = db_execute("SELECT id, insp_date FROM scheduled_inspections", fetch=True) or []
    _ci = db_execute("SELECT inspection_id, id, status FROM checklist_instances WHERE inspection_id IS NOT NULL", fetch=True) or []
    _signed = {}
    for _c in _ci:
        if _c["status"] == "signed":
            _signed.setdefault(_c["inspection_id"], _c["id"])
    _pend = {}
    for _d in _all_deviations():
        if not (_d["rem"] and _d["rem"].get("remediated_date")):
            _pend[_d["instance_id"]] = _pend.get(_d["instance_id"], 0) + 1
    n_planned = n_open = n_closed = 0
    for _s in all_sched:
        _iid = _signed.get(_s["id"])
        if not _iid:
            n_planned += 1
        elif _pend.get(_iid, 0) > 0:
            n_open += 1
        else:
            n_closed += 1
    n_total = n_planned + n_open + n_closed
    _sy = {}
    for _s in all_sched:
        if _signed.get(_s["id"]):
            continue  # ολοκληρωμένη (υπογεγραμμένη) -> δεν μετρά στις προγραμματισμένες
        _d = _as_date(_s["insp_date"])
        if _d:
            _sy[_d.year] = _sy.get(_d.year, 0) + 1
    sched_by_year = sorted(_sy.items(), key=lambda x: -x[0])
    sched_total = sum(_sy.values())
    sched_years = [str(_y) for _y, _ in sched_by_year]
    return render_template("inspection_schedule.html", year=year, month=month,
                           month_name=MONTHS[month], weeks=weeks, by_day=by_day,
                           prev_y=prev_y, prev_m=prev_m, next_y=next_y, next_m=next_m,
                           sched_types=scoped_schedule_types(), departments=departments, inspectors=inspectors,
                           cnt_week=cnt_week, cnt_next=cnt_next, cnt_pending=cnt_pending,
                           done_total=done_total, done_by_type=done_by_type,
                           n_planned=n_planned, n_open=n_open, n_closed=n_closed, n_total=n_total,
                           sched_by_year=sched_by_year, sched_total=sched_total, sched_years=sched_years)


def _sched_save_department(v):
    if v["department"]:
        try:
            db_execute(f"{INSERT_IGNORE} departments (name) VALUES (%s)", (v["department"],))
        except Exception:
            pass
    for _nm in v["inspectors"]:
        if _nm:
            try:
                db_execute(f"{INSERT_IGNORE} inspectors (name) VALUES (%s)", (_nm,))
            except Exception:
                pass


@app.route("/inspections/schedule/add", methods=["POST"])
@login_required
def inspection_schedule_add():
    v = _sched_from_form()
    if not (can_add_hospital("NGH") or (restricted_spec() and can_schedule_itype(v.get("itype")))):
        flash("Δεν έχετε δικαίωμα προγραμματισμού.", "danger")
        return redirect(url_for("inspection_schedule"))
    if not request.form.get("confirm_conflict"):
        conflict = _sched_conflict(v)
        if conflict:
            insp, r = conflict
            return render_template("inspection_schedule_confirm.html", insp=insp, other=r,
                                   action=url_for("inspection_schedule_add"),
                                   cancel=url_for("inspection_schedule"),
                                   formdata=request.form.to_dict(flat=True))
    db_execute(
        """INSERT INTO scheduled_inspections (hospital_code, insp_date, all_day, start_time, end_time,
           department, scope, itype, inspector1, inspector2, inspector3, created_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        ("NGH", v["insp_date"], v["all_day"], v["start_time"], v["end_time"], v["department"], v["scope"], v["itype"],
         v["inspectors"][0], v["inspectors"][1], v["inspectors"][2], session["username"]))
    _sched_save_department(v)
    log_action("schedule", "inspection", "", f"{v['insp_date']} · {v['department']} · {v['itype']}")
    flash("Η επιθεώρηση προγραμματίστηκε.", "success")
    return _sched_redirect(v)


@app.route("/inspections/schedule/<int:sid>/edit", methods=["POST"])
@login_required
def inspection_schedule_edit(sid):
    _rec = db_execute("SELECT itype FROM scheduled_inspections WHERE id=%s", (sid,), fetch=True)
    if not _rec:
        abort(404)
    v = _sched_from_form()
    _ic_ok = bool(restricted_spec()) and can_schedule_itype(v.get("itype")) and can_manage_checklist(ITYPE_TEMPLATE.get((_rec[0].get("itype") or "").strip()))
    if not (can_edit_hospital("NGH") or _ic_ok):
        flash("Δεν έχετε δικαίωμα τροποποίησης.", "danger")
        return redirect(url_for("inspection_schedule"))
    if not request.form.get("confirm_conflict"):
        conflict = _sched_conflict(v, exclude_id=sid)
        if conflict:
            insp, r = conflict
            return render_template("inspection_schedule_confirm.html", insp=insp, other=r,
                                   action=url_for("inspection_schedule_edit", sid=sid),
                                   cancel=url_for("inspection_schedule"),
                                   formdata=request.form.to_dict(flat=True))
    db_execute(
        """UPDATE scheduled_inspections SET insp_date=%s, all_day=%s, start_time=%s, end_time=%s,
           department=%s, scope=%s, itype=%s, inspector1=%s, inspector2=%s, inspector3=%s WHERE id=%s""",
        (v["insp_date"], v["all_day"], v["start_time"], v["end_time"], v["department"], v["scope"], v["itype"],
         v["inspectors"][0], v["inspectors"][1], v["inspectors"][2], sid))
    _sched_save_department(v)
    log_action("update", "scheduled_inspection", sid)
    flash("Η επιθεώρηση ενημερώθηκε.", "success")
    return _sched_redirect(v)


def _as_date(v):
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v)[:10])
    except (ValueError, TypeError):
        return date.min


@app.route("/inspections/schedule/list")
@login_required
def inspection_schedule_list():
    rows = db_execute("SELECT * FROM scheduled_inspections ORDER BY insp_date DESC, start_time", fetch=True) or []
    today = date.today()
    # Προσωρινός κωδικός (δυναμικός): 3 γράμματα τμήματος + 2ψήφιο έτος + αύξων αριθμός.
    # Μετρά μόνο τις έγκυρες (σημερινές/μελλοντικές)· οι περασμένες & μη-πραγματοποιημένες χάνουν κωδικό.
    # Δεν αποθηκεύεται — σε διαγραφή οι υπόλοιπες επαναριθμούνται αυτόματα.
    valid = sorted((r for r in rows if _as_date(r["insp_date"]) >= today),
                   key=lambda r: (_as_date(r["insp_date"]), r["start_time"] or "", r["id"]))
    counters, codes = {}, {}
    for r in valid:
        d = _as_date(r["insp_date"])
        key = ((r["department"] or "").strip().lower(), d.year)
        counters[key] = counters.get(key, 0) + 1
        codes[r["id"]] = f"{(r['department'] or '')[:3].upper()}{str(d.year)[-2:]}{counters[key]:03d}"
    for r in rows:
        r["code"] = codes.get(r["id"])
    signed = {}
    for d in (db_execute("SELECT id, inspection_id, orig_name FROM documents "
                         "WHERE category=%s AND inspection_id IS NOT NULL ORDER BY id DESC",
                         ("Υπογεγραμμένη Αναφορά",), fetch=True) or []):
        if d["inspection_id"] not in signed:
            signed[d["inspection_id"]] = d
    for r in rows:
        sd = signed.get(r["id"])
        r["signed_id"] = sd["id"] if sd else None
        r["signed_name"] = sd["orig_name"] if sd else None
    ci_rows = db_execute("SELECT id, inspection_id, status, updated_at FROM checklist_instances "
                         "WHERE inspection_id IS NOT NULL", fetch=True) or []
    by_sched = {}
    for ci in ci_rows:
        by_sched.setdefault(ci["inspection_id"], []).append(ci)
    visible = []
    for r in rows:
        cis = by_sched.get(r["id"], [])
        if any(ci["status"] == "signed" for ci in cis):
            continue  # ολοκληρώθηκε -> εμφανίζεται στις Εσωτερικές Επιθεωρήσεις
        drafts = [ci for ci in cis if ci["status"] == "draft"]
        if drafts:
            drafts.sort(key=lambda c: (str(c.get("updated_at") or ""), c["id"]), reverse=True)
            r["draft_id"] = drafts[0]["id"]
        else:
            r["draft_id"] = None
        visible.append(r)
    rows = visible
    return render_template("inspection_schedule_list.html", rows=rows)


@app.route("/inspections/schedule/<int:sid>/signed", methods=["POST"])
@login_required
def inspection_signed_upload(sid):
    ins = db_execute("SELECT * FROM scheduled_inspections WHERE id=%s", (sid,), fetch=True)
    if not ins:
        abort(404)
    if restricted_spec() and not can_manage_checklist(ITYPE_TEMPLATE.get((ins[0].get("itype") or "").strip())):
        flash("Δεν έχετε δικαίωμα.", "danger")
        return redirect(url_for("inspection_schedule_list"))
    f = request.files.get("signed")
    if not f or not f.filename:
        flash("Δεν επιλέχθηκε αρχείο.", "warning")
        return redirect(url_for("inspection_schedule_list"))
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        flash(f"Μη αποδεκτός τύπος αρχείου (.{ext}). Αποδεκτοί: {', '.join(sorted(ALLOWED_EXTENSIONS))}", "warning")
        return redirect(url_for("inspection_schedule_list"))
    stored = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}.{ext}"
    f.save(os.path.join(UPLOAD_FOLDER, stored))
    title = f"Υπογεγραμμένη Αναφορά — {ins[0].get('department') or ''}"
    db_execute(
        "INSERT INTO documents (hospital_code, title, category, inspection_id, filename, orig_name, parse_status, uploaded_by) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        ("NGH", title[:300], "Υπογεγραμμένη Αναφορά", sid, stored,
         secure_filename(f.filename)[:300], "skipped", session["username"]))
    log_action("upload", "signed_report", sid)
    flash("Η υπογεγραμμένη αναφορά ανέβηκε.", "success")
    return redirect(url_for("inspection_schedule_list"))


@app.route("/inspections/schedule/<int:sid>/start")
@login_required
def inspection_schedule_start(sid):
    ins = db_execute("SELECT * FROM scheduled_inspections WHERE id=%s", (sid,), fetch=True)
    if not ins:
        abort(404)
    all_templates = db_execute("SELECT id, code, title FROM checklist_templates WHERE active=1 ORDER BY code", fetch=True) or []
    _code = ITYPE_TEMPLATE.get((ins[0].get("itype") or "").strip())
    templates = [t for t in all_templates if t["code"] == _code] if _code else all_templates
    if not templates:
        templates = all_templates
    existing = db_execute(
        "SELECT ci.id, ci.title, ci.status, t.code FROM checklist_instances ci "
        "JOIN checklist_templates t ON t.id=ci.template_id "
        "WHERE ci.inspection_id=%s AND ci.status='draft' "
        "ORDER BY ci.updated_at DESC, ci.id DESC LIMIT 1",
        (sid,), fetch=True) or []
    return render_template("checklist_start.html", ins=ins[0], templates=templates, existing=existing)


@app.route("/checklists")
@login_required
def checklists_list():
    templates = db_execute("SELECT id, code, title, created_by, created_at FROM checklist_templates WHERE active=1 ORDER BY code", fetch=True) or []
    return render_template("checklists_list.html", templates=templates)


@app.route("/checklists/template/<int:tpl_id>")
@login_required
def checklist_template_view(tpl_id):
    tpl = db_execute("SELECT * FROM checklist_templates WHERE id=%s", (tpl_id,), fetch=True)
    if not tpl:
        abort(404)
    structure = json.loads(tpl[0]["structure"] or "{}")
    return render_template("checklist_template_view.html", tpl=tpl[0], structure=structure)


@app.route("/checklists/template/<int:tpl_id>/delete", methods=["POST"])
@role_required("admin")
def checklist_template_delete(tpl_id):
    n = db_execute("SELECT COUNT(*) c FROM checklist_instances WHERE template_id=%s", (tpl_id,), fetch=True)[0]["c"]
    if n:
        flash(f"Δεν διαγράφεται: υπάρχουν {n} συμπληρωμένες λίστες που τη χρησιμοποιούν.", "warning")
        return redirect(url_for("checklists_list"))
    db_execute("DELETE FROM checklist_templates WHERE id=%s", (tpl_id,))
    log_action("delete", "checklist_template", tpl_id)
    flash("Το πρότυπο λίστας ελέγχου διαγράφηκε.", "info")
    return redirect(url_for("checklists_list"))


@app.route("/checklists/create", methods=["POST"])
@login_required
def checklist_create():
    tpl_id = request.form.get("template_id", type=int)
    sid = request.form.get("inspection_id", type=int)
    tpl = db_execute("SELECT * FROM checklist_templates WHERE id=%s", (tpl_id,), fetch=True)
    ins = db_execute("SELECT * FROM scheduled_inspections WHERE id=%s", (sid,), fetch=True)
    if not tpl or not ins:
        abort(404)
    tpl = tpl[0]; ins = ins[0]
    if not can_manage_checklist((tpl.get("code") or "")):
        flash("Δεν έχετε δικαίωμα διαχείρισης αυτής της λίστας ελέγχου.", "danger")
        return redirect(url_for("inspection_schedule_start", sid=sid))
    dup = db_execute(
        "SELECT id FROM checklist_instances WHERE inspection_id=%s AND template_id=%s AND status='draft' "
        "ORDER BY updated_at DESC, id DESC LIMIT 1", (sid, tpl_id), fetch=True)
    if dup:
        return redirect(url_for("checklist_fill", inst_id=dup[0]["id"]))
    inspectors = ", ".join([x for x in (ins.get("inspector1"), ins.get("inspector2"), ins.get("inspector3")) if x])
    d = _as_date(ins["insp_date"]); d_iso = d.isoformat() if d else ""
    prefill = {
        "meta_department": ins.get("department") or "",
        "meta_date": d_iso,
        "meta_inspectors": inspectors,
        "meta_itype": ins.get("itype") or "",
    }
    title = f"{tpl['title']} — {ins.get('department') or ''} {d_iso}".strip()
    rid = db_execute(
        "INSERT INTO checklist_instances (template_id, inspection_id, title, status, data, created_by) "
        "VALUES (%s,%s,%s,%s,%s,%s)",
        (tpl_id, sid, title[:300], "draft", json.dumps(prefill, ensure_ascii=False), session["username"]),
        lastrowid=True)
    log_action("create", "checklist_instance", rid)
    return redirect(url_for("checklist_fill", inst_id=rid))


def _checklist_hash(data):
    """SHA-256 του περιεχομένου της λίστας — «σφραγίδα» ακεραιότητας για την υπογραφή."""
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _proc_compliance(structure, data):
    """Ανά ενότητα checklist: ποσοστό συμμόρφωσης ανά διαδικασία (από τα δείγματα/συμμορφώσεις)."""
    def _num(x):
        try:
            return float(str(x).replace(",", "."))
        except (TypeError, ValueError):
            return None
    out = []
    for si, sec in enumerate(structure.get("sections", [])):
        if sec.get("type") != "checklist":
            continue
        procs = sec.get("procedures") or []
        agg = {}
        for ci, c in enumerate(sec.get("criteria", []) or []):
            pidx = c.get("pidx")
            if pidx is None:
                continue
            k = "s%dc%d" % (si, ci)
            sv = _num(data.get(k + "_sample", ""))
            cv = _num(data.get(k + "_comp", ""))
            ag = agg.setdefault(pidx, [0.0, 0.0])
            if sv is not None:
                ag[0] += sv
            if cv is not None:
                ag[1] += cv
        rows = []
        sec_s = 0.0
        sec_c = 0.0
        for pidx, pname in enumerate(procs):
            ag = agg.get(pidx)
            pct = (round(ag[1] / ag[0] * 1000) / 10) if (ag and ag[0] > 0) else None
            rows.append({"proc": pname, "pct": pct,
                         "sample": round(ag[0], 2) if ag else 0,
                         "comp": round(ag[1], 2) if ag else 0,
                         "dev": round(ag[0] - ag[1], 2) if ag else 0})
            if ag:
                sec_s += ag[0]
                sec_c += ag[1]
        evaluated = [r for r in rows if r["pct"] is not None]
        section_pct = (round(sec_c / sec_s * 1000) / 10) if sec_s > 0 else None
        full_count = len([r for r in evaluated if r["pct"] >= 100])
        out.append({"name": sec.get("name"), "rows": rows,
                    "section_pct": section_pct, "full_count": full_count,
                    "total_count": len(evaluated)})
    return out


LOW_COMPLIANCE_PCT = 75
LOW_COMPLIANCE_TEXT = ("Η συμμόρφωση στις παρακάτω διαδικασίες είναι σημαντικά μειωμένη και "
                       "θα πρέπει να δοθεί ιδιαίτερη προσοχή στην αναβάθμισή της:")


def _low_compliance(full_compliance):
    """Διαδικασίες με ποσοστό συμμόρφωσης < LOW_COMPLIANCE_PCT (για τις Παρατηρήσεις)."""
    return [{"section": fc["name"], "proc": r["proc"], "pct": r["pct"]}
            for fc in full_compliance for r in fc["rows"]
            if r["pct"] is not None and r["pct"] < LOW_COMPLIANCE_PCT]


def _deviations(structure, data):
    """Ανά ενότητα checklist: κριτήρια με απόκλιση (συμμόρφωση < δείγμα)."""
    def _num(x):
        try:
            return float(str(x).replace(",", "."))
        except (TypeError, ValueError):
            return None
    out = []
    for si, sec in enumerate(structure.get("sections", [])):
        if sec.get("type") != "checklist":
            continue
        procs = sec.get("procedures") or []
        devs = []
        for ci, c in enumerate(sec.get("criteria", []) or []):
            k = "s%dc%d" % (si, ci)
            sv = _num(data.get(k + "_sample", ""))
            cv = _num(data.get(k + "_comp", ""))
            if sv is not None and sv > 0 and cv is not None and cv < sv:
                dev_pct = round((sv - cv) / sv * 1000) / 10
                pidx = c.get("pidx")
                proc = procs[pidx] if (pidx is not None and 0 <= pidx < len(procs)) else ""
                devs.append({"si": si, "ci": ci, "proc": proc,
                             "criterion": c.get("criterion", ""), "dev_pct": dev_pct,
                             "corr": data.get(k + "_corr", ""),
                             "resp": data.get(k + "_resp") or data.get("dev_%d_%d_resp" % (si, ci)) or "",
                             "time": data.get(k + "_time") or data.get("dev_%d_%d_time" % (si, ci)) or ""})
        out.append({"name": sec.get("name"), "deviations": devs})
    return out


QA_HEAD_NAME = "Δρ Χαράλαμπος Γιαννακκαράς"
QA_HEAD_ROLE = "Υπεύθυνος Μονάδας Διασφάλισης Ποιότητας"


def _norm_name(s):
    """Κανονικοποίηση ονόματος για αντιστοίχιση υπογραφής↔λογαριασμού."""
    return " ".join((s or "").split()).casefold()


def _signers(data):
    """Λίστα υπογραφόντων: επιθεωρητές + Υπεύθυνος ΜΔΠ."""
    inspectors = [x.strip() for x in (data.get("meta_inspectors") or "").split(",") if x.strip()]
    lst = [{"name": n, "role": "Επιθεωρητής"} for n in inspectors]
    lst.append({"name": QA_HEAD_NAME, "role": QA_HEAD_ROLE})
    return lst


def _audit_struct(structure):
    """Metadata ενοτήτων checklist για client-side υπολογισμό της Αναφοράς."""
    out = []
    for si, sec in enumerate(structure.get("sections", [])):
        if sec.get("type") != "checklist":
            continue
        out.append({
            "si": si,
            "name": sec.get("name"),
            "procedures": sec.get("procedures") or [],
            "criteria": [{"ci": ci, "pidx": c.get("pidx"), "criterion": c.get("criterion", "")}
                         for ci, c in enumerate(sec.get("criteria", []) or [])],
        })
    return out


def _iso_findings(structure, data):
    """ISO/EN audit: ανά ενότητα iso -> συμμορφώσεις + μη συμμορφώσεις (κύριες/δευτ.)."""
    out = []
    for si, sec in enumerate(structure.get("sections", [])):
        if sec.get("type") != "iso":
            continue
        compliant, major, minor = [], [], []
        for ci, cl in enumerate(sec.get("clauses", []) or []):
            k = "iso%d_%d" % (si, ci)
            comp = (data.get(k + "_comp") or "").strip()
            rec = {"si": si, "ci": ci, "clause": cl.get("clause", ""),
                   "desc": data.get(k + "_desc", ""), "corr": data.get(k + "_corr", ""),
                   "time": data.get(k + "_time", ""), "resp": data.get(k + "_resp", ""),
                   "nc": (data.get(k + "_nc") or "").strip()}
            if comp == "ΝΑΙ":
                compliant.append(rec)
            elif comp == "ΟΧΙ":
                (major if rec["nc"] == "Κύρια" else minor).append(rec)
        out.append({"name": sec.get("name"), "compliant": compliant,
                    "major": major, "minor": minor,
                    "total_nc": len(major) + len(minor),
                    "total_compliant": len(compliant),
                    "no_nc": sec.get("no_nc", False)})
    return out


def _iso_struct(structure):
    """Metadata ρητρών iso για client-side rebuild της Αναφοράς."""
    out = []
    for si, sec in enumerate(structure.get("sections", [])):
        if sec.get("type") != "iso":
            continue
        out.append({"si": si, "name": sec.get("name"), "no_nc": sec.get("no_nc", False),
                    "clauses": [{"ci": ci, "clause": cl.get("clause", "")}
                                for ci, cl in enumerate(sec.get("clauses", []) or [])]})
    return out


@app.route("/checklists/instance/<int:inst_id>")
@login_required
def checklist_fill(inst_id):
    inst = db_execute("SELECT * FROM checklist_instances WHERE id=%s", (inst_id,), fetch=True)
    if not inst:
        abort(404)
    inst = inst[0]
    tpl = db_execute("SELECT * FROM checklist_templates WHERE id=%s", (inst["template_id"],), fetch=True)
    if not tpl:
        abort(404)
    structure = json.loads(tpl[0]["structure"] or "{}")
    data = json.loads(inst["data"] or "{}")
    sigs = db_execute("SELECT * FROM checklist_signatures WHERE instance_id=%s ORDER BY id",
                      (inst_id,), fetch=True) or []
    signed_map = {s["signer_name"]: s for s in sigs}
    inspectors_list = [x.strip() for x in (data.get("meta_inspectors") or "").split(",") if x.strip()]
    signers = _signers(data)
    me = db_execute("SELECT full_name FROM users WHERE username=%s", (session.get("username", ""),), fetch=True)
    my_name = _norm_name(me[0]["full_name"]) if me else ""
    for sg in signers:
        sg["is_me"] = bool(my_name) and _norm_name(sg["name"]) == my_name
    signed_count = len(sigs)
    signer_count = len(signers)
    all_signed = signer_count > 0 and signed_count >= signer_count
    permalocked = (inst["status"] == "signed")
    editable = (not permalocked) and (signed_count == 0)
    can_finalize = all_signed and not permalocked
    locked = permalocked
    unsigned_labels = ["ο Υπεύθυνος Ποιότητας" if sg["name"] == QA_HEAD_NAME else ("ο Επιθεωρητής " + sg["name"]) for sg in signers if sg["name"] not in signed_map]
    full_compliance = _proc_compliance(structure, data)
    return render_template("checklist_fill.html", inst=inst, structure=structure, data=data,
                           inspectors_list=inspectors_list, signatures=sigs, signed_map=signed_map,
                           locked=locked, permalocked=permalocked, editable=editable,
                           can_finalize=can_finalize, all_signed=all_signed,
                           is_admin=(session.get("role") == "admin"),
                           full_compliance=full_compliance,
                           low_compliance=_low_compliance(full_compliance),
                           low_pct=LOW_COMPLIANCE_PCT, low_text=LOW_COMPLIANCE_TEXT,
                           deviations=_deviations(structure, data),
                           signers=signers, unsigned_labels=unsigned_labels,
                           audit_struct=_audit_struct(structure),
                           is_iso=any(sec.get("type") == "iso" for sec in structure.get("sections", [])),
                           iso_findings=_iso_findings(structure, data),
                           iso_struct=_iso_struct(structure))


@app.route("/checklists/instance/<int:inst_id>/save", methods=["POST"])
@login_required
def checklist_save(inst_id):
    inst = db_execute("SELECT * FROM checklist_instances WHERE id=%s", (inst_id,), fetch=True)
    if not inst:
        abort(404)
    inst = inst[0]
    if not can_manage_checklist(_inst_code(inst)):
        flash("Δεν έχετε δικαίωμα διαχείρισης αυτής της λίστας ελέγχου.", "danger")
        return redirect(url_for("checklist_fill", inst_id=inst_id))
    if inst["status"] == "signed":
        flash("Η λίστα είναι οριστικά κλειδωμένη και δεν τροποποιείται.", "warning")
        return redirect(url_for("checklist_fill", inst_id=inst_id))
    sig_count = db_execute("SELECT COUNT(*) c FROM checklist_signatures WHERE instance_id=%s",
                           (inst_id,), fetch=True)[0]["c"]
    final = request.form.get("_save") == "final"
    if final:
        stored = json.loads(inst["data"] or "{}")
        signer_names = [s["name"] for s in _signers(stored)]
        if not signer_names or sig_count < len(signer_names):
            flash("Δεν επιτρέπεται μόνιμη αποθήκευση: πρέπει να έχουν υπογράψει και οι %d υπογράφοντες." % len(signer_names), "warning")
            return redirect(url_for("checklist_fill", inst_id=inst_id))
        db_execute("UPDATE checklist_instances SET status='signed', updated_at=" + NOW + " WHERE id=%s",
                   (inst_id,))
        log_action("finalize", "checklist_instance", inst_id, "signed")
        flash("Η λίστα αποθηκεύτηκε οριστικά και κλειδώθηκε.", "success")
        return redirect(url_for("checklist_fill", inst_id=inst_id))
    if sig_count > 0:
        flash("Έχουν καταχωρηθεί υπογραφές — δεν επιτρέπεται τροποποίηση της λίστας.", "warning")
        return redirect(url_for("checklist_fill", inst_id=inst_id))
    data = {k: v for k, v in request.form.items() if k != "_save"}
    db_execute("UPDATE checklist_instances SET data=%s, status='draft', updated_at=" + NOW + " WHERE id=%s",
               (json.dumps(data, ensure_ascii=False), inst_id))
    log_action("save", "checklist_instance", inst_id, "draft")
    flash("Η λίστα ελέγχου αποθηκεύτηκε προσωρινά.", "success")
    return redirect(url_for("checklist_fill", inst_id=inst_id))


@app.route("/checklists/instance/<int:inst_id>/report")
@login_required
def checklist_report(inst_id):
    inst = db_execute("SELECT * FROM checklist_instances WHERE id=%s", (inst_id,), fetch=True)
    if not inst:
        abort(404)
    inst = inst[0]
    tpl = db_execute("SELECT * FROM checklist_templates WHERE id=%s", (inst["template_id"],), fetch=True)[0]
    structure = json.loads(tpl["structure"] or "{}")
    data = json.loads(inst["data"] or "{}")
    inspectors_list = [x.strip() for x in (data.get("meta_inspectors") or "").split(",") if x.strip()]
    printed_date = datetime.now().strftime("%d/%m/%Y")
    _md = data.get("meta_date") or ""
    _dt = _as_date(_md) if _md else None
    insp_date_display = _dt.strftime("%d/%m/%Y") if (_dt and _dt != date.min) else _md
    sigs = db_execute("SELECT * FROM checklist_signatures WHERE instance_id=%s ORDER BY id",
                      (inst_id,), fetch=True) or []
    current_hash = _checklist_hash(data)
    for s in sigs:
        s["valid"] = (s.get("content_hash") == current_hash)
    return render_template("checklist_report.html", inst=inst, structure=structure, data=data,
                           inspectors_list=inspectors_list, printed_date=printed_date,
                           insp_date_display=insp_date_display,
                           signatures=sigs, current_hash=current_hash)


@app.route("/checklists/instance/<int:inst_id>/report2")
@login_required
def checklist_report2(inst_id):
    inst = db_execute("SELECT * FROM checklist_instances WHERE id=%s", (inst_id,), fetch=True)
    if not inst:
        abort(404)
    inst = inst[0]
    tpl = db_execute("SELECT * FROM checklist_templates WHERE id=%s", (inst["template_id"],), fetch=True)[0]
    structure = json.loads(tpl["structure"] or "{}")
    data = json.loads(inst["data"] or "{}")
    inspectors_list = [x.strip() for x in (data.get("meta_inspectors") or "").split(",") if x.strip()]
    printed_date = datetime.now().strftime("%d/%m/%Y")
    _md = data.get("meta_date") or ""
    _dt = _as_date(_md) if _md else None
    insp_date_display = _dt.strftime("%d/%m/%Y") if (_dt and _dt != date.min) else _md
    sigs = db_execute("SELECT * FROM checklist_signatures WHERE instance_id=%s ORDER BY id",
                      (inst_id,), fetch=True) or []
    current_hash = _checklist_hash(data)
    for s in sigs:
        s["valid"] = (s.get("content_hash") == current_hash)
    full_compliance = _proc_compliance(structure, data)
    return render_template("checklist_report2.html", inst=inst, structure=structure, data=data,
                           inspectors_list=inspectors_list, printed_date=printed_date,
                           insp_date_display=insp_date_display,
                           signatures=sigs, current_hash=current_hash,
                           full_compliance=full_compliance,
                           low_compliance=_low_compliance(full_compliance),
                           low_text=LOW_COMPLIANCE_TEXT,
                           deviations=_deviations(structure, data))


@app.route("/checklists/instance/<int:inst_id>/iso-report")
@login_required
def checklist_iso_report(inst_id):
    inst = db_execute("SELECT * FROM checklist_instances WHERE id=%s", (inst_id,), fetch=True)
    if not inst:
        abort(404)
    inst = inst[0]
    tpl = db_execute("SELECT * FROM checklist_templates WHERE id=%s", (inst["template_id"],), fetch=True)[0]
    structure = json.loads(tpl["structure"] or "{}")
    data = json.loads(inst["data"] or "{}")
    inspectors_list = [x.strip() for x in (data.get("meta_inspectors") or "").split(",") if x.strip()]
    printed_date = datetime.now().strftime("%d/%m/%Y")
    _md = data.get("meta_date") or ""
    _dt = _as_date(_md) if _md else None
    insp_date_display = _dt.strftime("%d/%m/%Y") if (_dt and _dt != date.min) else _md
    sigs = db_execute("SELECT * FROM checklist_signatures WHERE instance_id=%s ORDER BY id",
                      (inst_id,), fetch=True) or []
    current_hash = _checklist_hash(data)
    for s in sigs:
        s["valid"] = (s.get("content_hash") == current_hash)
    return render_template("checklist_iso_report.html", inst=inst, structure=structure, data=data,
                           inspectors_list=inspectors_list, printed_date=printed_date,
                           insp_date_display=insp_date_display,
                           signatures=sigs, current_hash=current_hash,
                           iso_findings=_iso_findings(structure, data))


@app.route("/checklists/instance/<int:inst_id>/delete", methods=["POST"])
@role_required("admin")
def checklist_delete(inst_id):
    _ci = db_execute("SELECT * FROM checklist_instances WHERE id=%s", (inst_id,), fetch=True)
    if not _ci:
        abort(404)
    if not can_manage_checklist(_inst_code(_ci[0])):
        flash("Δεν έχετε δικαίωμα διαγραφής αυτής της λίστας ελέγχου.", "danger")
        return redirect(url_for("checklist_fill", inst_id=inst_id))
    db_execute("DELETE FROM checklist_signatures WHERE instance_id=%s", (inst_id,))
    db_execute("DELETE FROM deviation_remediations WHERE instance_id=%s", (inst_id,))
    db_execute("DELETE FROM checklist_instances WHERE id=%s", (inst_id,))
    log_action("delete", "checklist_instance", inst_id)
    flash("Η λίστα ελέγχου διαγράφηκε.", "info")
    return redirect(url_for("checklists_list"))

@app.route("/checklists/instance/<int:inst_id>/sign", methods=["POST"])
@login_required
def checklist_sign(inst_id):
    inst = db_execute("SELECT * FROM checklist_instances WHERE id=%s", (inst_id,), fetch=True)
    if not inst:
        abort(404)
    inst = inst[0]
    MISMATCH = "Πρέπει να υπογράψει ο επιθεωρητής ή η επιθεωρήτρια που διενήργησε την επιθεώρηση"
    if inst["status"] == "signed":
        return {"ok": False, "message": "Η λίστα είναι οριστικά κλειδωμένη και δεν υπογράφεται ξανά."}
    data = json.loads(inst["data"] or "{}")
    signer_names = [s["name"] for s in _signers(data)]
    payload = request.get_json(silent=True) or {}
    signer = (payload.get("signer_name") or request.form.get("signer_name") or "").strip()
    password = payload.get("password") or request.form.get("password") or ""
    if signer not in signer_names:
        return {"ok": False, "message": "Μη έγκυρος υπογράφων."}
    if db_execute("SELECT id FROM checklist_signatures WHERE instance_id=%s AND signer_name=%s",
                  (inst_id, signer), fetch=True):
        return {"ok": False, "already": True, "message": "Ο υπογράφων έχει ήδη υπογράψει."}
    if not password:
        return {"ok": False, "message": MISMATCH}
    norm = _norm_name(signer)
    users = db_execute("SELECT username, password_hash, full_name FROM users WHERE active=1", fetch=True) or []
    matched = None
    for u in users:
        if _norm_name(u["full_name"]) == norm and check_password_hash(u["password_hash"], password):
            matched = u
            break
    if not matched:
        return {"ok": False, "message": MISMATCH}
    chash = _checklist_hash(data)
    db_execute("INSERT INTO checklist_signatures (instance_id, signer_name, signer_user, content_hash) "
               "VALUES (%s,%s,%s,%s)", (inst_id, signer, matched["username"], chash))
    log_action("sign", "checklist_instance", inst_id, signer)
    total = db_execute("SELECT COUNT(*) c FROM checklist_signatures WHERE instance_id=%s",
                       (inst_id,), fetch=True)[0]["c"]
    finalized = False
    if signer_names and total >= len(signer_names):
        db_execute("UPDATE checklist_instances SET status='signed', updated_at=" + NOW + " WHERE id=%s",
                   (inst_id,))
        log_action("finalize", "checklist_instance", inst_id, "signed (auto)")
        finalized = True
    return {"ok": True, "finalized": finalized}


@app.route("/checklists/instance/<int:inst_id>/sign/<int:sig_id>/revoke", methods=["POST"])
@login_required
def checklist_sign_revoke(inst_id, sig_id):
    inst = db_execute("SELECT status FROM checklist_instances WHERE id=%s", (inst_id,), fetch=True)
    if not inst:
        abort(404)
    if inst[0]["status"] == "signed" and session.get("role") != "admin":
        flash("Η λίστα είναι οριστικά κλειδωμένη — μόνο διαχειριστής μπορεί να ακυρώσει υπογραφή.", "warning")
        return redirect(url_for("checklist_fill", inst_id=inst_id))
    db_execute("DELETE FROM checklist_signatures WHERE id=%s AND instance_id=%s", (sig_id, inst_id))
    db_execute("UPDATE checklist_instances SET status='draft', updated_at=" + NOW + " WHERE id=%s AND status='signed'",
               (inst_id,))
    log_action("revoke_sign", "checklist_instance", inst_id, str(sig_id))
    flash("Η υπογραφή ακυρώθηκε — η λίστα είναι ξανά επεξεργάσιμη μόλις αφαιρεθούν όλες οι υπογραφές.", "info")
    return redirect(url_for("checklist_fill", inst_id=inst_id))


@app.route("/inspections/schedule/<int:sid>/delete", methods=["POST"])
@login_required
def inspection_schedule_delete(sid):
    _rec = db_execute("SELECT itype FROM scheduled_inspections WHERE id=%s", (sid,), fetch=True)
    _ic_ok = bool(restricted_spec()) and bool(_rec) and can_manage_checklist(ITYPE_TEMPLATE.get((_rec[0].get("itype") or "").strip()))
    if not (can_edit_hospital("NGH") or _ic_ok):
        flash("Δεν έχετε δικαίωμα διαγραφής.", "danger")
        return redirect(url_for("inspection_schedule_list"))
    db_execute("DELETE FROM scheduled_inspections WHERE id=%s", (sid,))
    log_action("delete", "scheduled_inspection", sid)
    flash("Ο προγραμματισμός διαγράφηκε.", "info")
    return redirect(request.referrer or url_for("inspection_schedule_list"))


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


@app.route("/documents/<int:doc_id>/open")
@login_required
def document_open(doc_id):
    """Άνοιγμα εγγράφου inline (π.χ. PDF στον browser) αντί για κατέβασμα."""
    rows = db_execute("SELECT * FROM documents WHERE id=%s", (doc_id,), fetch=True)
    if not rows:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, rows[0]["filename"], as_attachment=False,
                               download_name=rows[0]["orig_name"] or rows[0]["filename"])


@app.route("/values/report", methods=["POST"])
@login_required
def values_report_upload():
    """Ανέβασμα σχετικού report για μια ομάδα/περίοδο από τη σελίδα Καταχώρησης Τιμών."""
    grp = request.form.get("grp") or ""
    hosp = "NGH"
    try:
        year = int(request.form.get("year") or date.today().year)
        mf = int(request.form.get("month_from") or 1)
        mt = int(request.form.get("month_to") or mf)
    except (TypeError, ValueError):
        year, mf, mt = date.today().year, 1, 1
    back = url_for("values_entry", grp=grp, year=year, month_from=mf, month_to=mt)
    if not can_add_hospital(hosp):
        flash("Δεν έχετε δικαίωμα καταχώρησης.", "danger")
        return redirect(back)
    f = request.files.get("report")
    if not f or not f.filename:
        flash("Δεν επιλέχθηκε αρχείο.", "warning")
        return redirect(back)
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        flash(f"Μη αποδεκτός τύπος αρχείου (.{ext}). Αποδεκτοί: {', '.join(sorted(ALLOWED_EXTENSIONS))}", "warning")
        return redirect(back)
    stored = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}.{ext}"
    f.save(os.path.join(UPLOAD_FOLDER, stored))
    plabel = f"{MONTHS_SHORT.get(mf, mf)}" + (f"-{MONTHS_SHORT.get(mt, mt)}" if mt != mf else "") + f" {year}"
    title = (f"Report {grp} {plabel}" if grp else f"Report {plabel}")
    db_execute(
        """INSERT INTO documents (hospital_code, title, category, year, month, month_from, month_to, grp,
           filename, orig_name, parse_status, uploaded_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (hosp, title[:300], grp or "Γενικά", year, mt, mf, mt, grp,
         stored, secure_filename(f.filename)[:300], "skipped", session["username"]))
    log_action("upload", "report", grp, title)
    flash("Το report ανέβηκε και συνδέθηκε με την περίοδο.", "success")
    return redirect(back)


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


@app.route("/reviews")
@login_required
def reviews_page():
    category = request.args.get("category") or "Διαπίστευσης"
    if category not in ("Διαπίστευσης", "Πιστοποίησης"):
        category = "Διαπίστευσης"
    return render_template("reviews.html", category=category)


@app.route("/activities")
@login_required
def activities_list():
    rows = db_execute(
        "SELECT a.*, "
        "(SELECT COUNT(*) FROM activity_photos p WHERE p.activity_id=a.id AND COALESCE(p.media_type,'image')<>'video') AS nphotos, "
        "(SELECT COUNT(*) FROM activity_photos p WHERE p.activity_id=a.id AND p.media_type='video') AS nvideos "
        "FROM activities a ORDER BY a.activity_date DESC, a.id DESC", fetch=True) or []
    return render_template("activities_list.html", activities=rows)


def _save_activity_media(aid):
    """Αποθηκεύει τα ανεβασμένα αρχεία (photos/videos) για μια δραστηριότητα."""
    saved = {"image": 0, "video": 0}
    limit = {"image": 10, "video": 999}
    for field, allowed, mtype in (("photos", IMAGE_EXTENSIONS, "image"), ("videos", VIDEO_EXTENSIONS, "video")):
        for f in request.files.getlist(field):
            if saved[mtype] >= limit[mtype]:
                break
            if not f or not f.filename:
                continue
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
            if ext not in allowed:
                continue
            stored = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}.{ext}"
            f.save(os.path.join(UPLOAD_FOLDER, stored))
            db_execute(
                "INSERT INTO activity_photos (activity_id, stored_name, orig_name, media_type) VALUES (%s,%s,%s,%s)",
                (aid, stored, secure_filename(f.filename)[:255], mtype))
            saved[mtype] += 1
    return saved


@app.route("/activities/new", methods=["GET", "POST"])
@login_required
def activity_new():
    if request.method == "POST":
        if not can_add_hospital("NGH"):
            flash("Δεν έχετε δικαίωμα καταχώρησης δραστηριότητας.", "danger")
            return redirect(url_for("activities_list"))
        title = (request.form.get("title") or "").strip()
        if not title:
            flash("Ο τίτλος είναι υποχρεωτικός.", "warning")
            return redirect(url_for("activity_new"))
        adate = request.form.get("activity_date") or None
        organizer = (request.form.get("organizer") or "").strip()
        description = (request.form.get("description") or "").strip()
        aid = db_execute(
            "INSERT INTO activities (title, activity_date, organizer, description, created_by) "
            "VALUES (%s,%s,%s,%s,%s)",
            (title[:300], adate, organizer[:200], description, session["username"]), lastrowid=True)
        added = _save_activity_media(aid)
        log_action("create", "activity", aid, title)
        flash(f"Η δραστηριότητα καταχωρήθηκε ({added['image']} φωτογραφίες, {added['video']} βίντεο).", "success")
        return redirect(url_for("activity_view", act_id=aid))
    return render_template("activity_new.html")


@app.route("/activities/<int:act_id>")
@login_required
def activity_view(act_id):
    a = db_execute("SELECT * FROM activities WHERE id=%s", (act_id,), fetch=True)
    if not a:
        abort(404)
    photos = db_execute("SELECT * FROM activity_photos WHERE activity_id=%s ORDER BY id",
                        (act_id,), fetch=True) or []
    return render_template("activity_view.html", a=a[0], photos=photos,
                           can_edit=can_edit_hospital("NGH"), can_delete=can_delete_hospital("NGH"))


@app.route("/activities/photo/<int:photo_id>")
@login_required
def activity_photo(photo_id):
    rows = db_execute("SELECT * FROM activity_photos WHERE id=%s", (photo_id,), fetch=True)
    if not rows:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, rows[0]["stored_name"], as_attachment=False,
                               download_name=rows[0]["orig_name"] or rows[0]["stored_name"])


@app.route("/activities/<int:act_id>/delete", methods=["POST"])
@login_required
def activity_delete(act_id):
    if not can_delete_hospital("NGH"):
        flash("Δεν έχετε δικαίωμα διαγραφής.", "danger")
        return redirect(url_for("activity_view", act_id=act_id))
    for p in (db_execute("SELECT stored_name FROM activity_photos WHERE activity_id=%s", (act_id,), fetch=True) or []):
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, p["stored_name"]))
        except OSError:
            pass
    db_execute("DELETE FROM activity_photos WHERE activity_id=%s", (act_id,))
    db_execute("DELETE FROM activities WHERE id=%s", (act_id,))
    log_action("delete", "activity", act_id)
    flash("Η δραστηριότητα διαγράφηκε.", "info")
    return redirect(url_for("activities_list"))

@app.route("/activities/<int:act_id>/edit", methods=["GET", "POST"])
@login_required
def activity_edit(act_id):
    a = db_execute("SELECT * FROM activities WHERE id=%s", (act_id,), fetch=True)
    if not a:
        abort(404)
    a = a[0]
    if request.method == "POST":
        if not can_edit_hospital("NGH"):
            flash("Δεν έχετε δικαίωμα τροποποίησης.", "danger")
            return redirect(url_for("activity_view", act_id=act_id))
        title = (request.form.get("title") or "").strip()
        if not title:
            flash("Ο τίτλος είναι υποχρεωτικός.", "warning")
            return redirect(url_for("activity_edit", act_id=act_id))
        adate = request.form.get("activity_date") or None
        organizer = (request.form.get("organizer") or "").strip()
        description = (request.form.get("description") or "").strip()
        db_execute("UPDATE activities SET title=%s, activity_date=%s, organizer=%s, description=%s WHERE id=%s",
                   (title[:300], adate, organizer[:200], description, act_id))
        ndel = 0
        for mid in request.form.getlist("delete_media"):
            try:
                mid = int(mid)
            except (TypeError, ValueError):
                continue
            row = db_execute("SELECT stored_name FROM activity_photos WHERE id=%s AND activity_id=%s",
                             (mid, act_id), fetch=True)
            if row:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER, row[0]["stored_name"]))
                except OSError:
                    pass
                db_execute("DELETE FROM activity_photos WHERE id=%s AND activity_id=%s", (mid, act_id))
                ndel += 1
        added = _save_activity_media(act_id)
        log_action("update", "activity", act_id, title)
        flash(f"Η δραστηριότητα ενημερώθηκε (+{added['image']} φωτο, +{added['video']} βίντεο, −{ndel} διαγραφές).", "success")
        return redirect(url_for("activity_view", act_id=act_id))
    photos = db_execute("SELECT * FROM activity_photos WHERE activity_id=%s ORDER BY id", (act_id,), fetch=True) or []
    return render_template("activity_edit.html", a=a, photos=photos)


def _ensure_org_structure():
    """Δημιουργεί τη βασική δομή οργανογράμματος αν λείπει (1 Υπεύθυνος, 3 Λειτουργοί, 1 Γραμματειακό)."""
    def cnt(level):
        return db_execute("SELECT COUNT(*) c FROM org_nodes WHERE level=%s", (level,), fetch=True)[0]["c"]
    if cnt(1) == 0:
        db_execute("INSERT INTO org_nodes (parent_id, level, role_title, sort_order) VALUES (%s,%s,%s,%s)",
                   (None, 1, "Υπεύθυνος Μονάδας Διασφάλισης Ποιότητας", 0))
    existing2 = cnt(2)
    for i in range(existing2, 4):
        db_execute("INSERT INTO org_nodes (parent_id, level, role_title, sort_order) VALUES (%s,%s,%s,%s)",
                   (None, 2, "", i))
    if cnt(3) == 0:
        db_execute("INSERT INTO org_nodes (parent_id, level, role_title, sort_order) VALUES (%s,%s,%s,%s)",
                   (None, 3, "", 0))


@app.route("/quality-unit/orgchart")
@login_required
def quality_unit_orgchart():
    _ensure_org_structure()
    head = db_execute("SELECT * FROM org_nodes WHERE level=1 ORDER BY sort_order, id LIMIT 1", fetch=True)[0]
    officers = db_execute("SELECT * FROM org_nodes WHERE level=2 ORDER BY sort_order, id", fetch=True) or []
    secretariat = db_execute("SELECT * FROM org_nodes WHERE level=3 ORDER BY sort_order, id", fetch=True) or []
    return render_template("org_chart.html", head=head, officers=officers, secretariat=secretariat,
                           can_edit=can_add_hospital("NGH"))


@app.route("/quality-unit/orgchart/<int:node_id>", methods=["POST"])
@login_required
def org_node_update(node_id):
    if not can_add_hospital("NGH"):
        flash("Δεν έχετε δικαίωμα τροποποίησης.", "danger")
        return redirect(url_for("quality_unit_orgchart"))
    node = db_execute("SELECT * FROM org_nodes WHERE id=%s", (node_id,), fetch=True)
    if not node:
        abort(404)
    node = node[0]
    role = (request.form.get("role_title") or "").strip() or node["role_title"]
    name = (request.form.get("person_name") or "").strip()
    title = (request.form.get("person_title") or "").strip()
    stored = node["photo"]
    f = request.files.get("photo")
    if f and f.filename:
        ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
        if ext in IMAGE_EXTENSIONS:
            newname = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}.{ext}"
            f.save(os.path.join(UPLOAD_FOLDER, newname))
            if stored:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER, stored))
                except OSError:
                    pass
            stored = newname
    db_execute("UPDATE org_nodes SET role_title=%s, person_name=%s, person_title=%s, photo=%s WHERE id=%s",
               (role[:300], name[:200], title[:200], stored, node_id))
    log_action("update", "org_node", node_id)
    flash("Το οργανόγραμμα ενημερώθηκε.", "success")
    return redirect(url_for("quality_unit_orgchart"))


@app.route("/quality-unit/orgchart/photo/<int:node_id>")
@login_required
def org_node_photo(node_id):
    r = db_execute("SELECT photo FROM org_nodes WHERE id=%s", (node_id,), fetch=True)
    if not r or not r[0]["photo"]:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, r[0]["photo"], as_attachment=False)


@app.route("/quality-unit/training")
@login_required
def quality_unit_training():
    return render_template("training.html")


def _unit_role(level):
    return {1: "Υπεύθυνος Μονάδας Διασφάλισης Ποιότητας",
            2: "Λειτουργός Μονάδας Διασφάλισης Ποιότητας",
            3: "Γραμματειακό Προσωπικό"}.get(level or 1, "")


def _org_staff():
    rows = db_execute("SELECT * FROM org_nodes ORDER BY level, sort_order, id", fetch=True) or []
    for r in rows:
        r["unit_role"] = _unit_role(r.get("level"))
    return rows


@app.route("/quality-unit/training/staff")
@login_required
def training_staff():
    staff = _org_staff()
    counts = {}
    for r in (db_execute("SELECT node_id, COUNT(*) c FROM staff_trainings GROUP BY node_id", fetch=True) or []):
        counts[r["node_id"]] = r["c"]
    for s in staff:
        s["ntrain"] = counts.get(s["id"], 0)
    return render_template("training_staff.html", staff=staff, can_edit=can_add_hospital("NGH"))


@app.route("/quality-unit/training/staff/person/<int:node_id>")
@login_required
def training_staff_person(node_id):
    node = db_execute("SELECT * FROM org_nodes WHERE id=%s", (node_id,), fetch=True)
    if not node:
        abort(404)
    node = node[0]
    node["unit_role"] = _unit_role(node.get("level"))
    rows = db_execute("SELECT * FROM staff_trainings WHERE node_id=%s ORDER BY year DESC, start_date DESC, id DESC",
                      (node_id,), fetch=True) or []
    return render_template("training_staff_person.html", node=node, rows=rows,
                           can_edit=can_add_hospital("NGH"), can_delete=can_delete_hospital("NGH"))


@app.route("/quality-unit/training/staff/new", methods=["GET", "POST"])
@login_required
def training_staff_new():
    if not can_add_hospital("NGH"):
        flash("Δεν έχετε δικαίωμα καταχώρησης.", "danger")
        return redirect(url_for("training_staff"))
    if request.method == "POST":
        node_id = request.form.get("node_id", type=int)
        if not node_id or not db_execute("SELECT id FROM org_nodes WHERE id=%s", (node_id,), fetch=True):
            flash("Επίλεξε έγκυρο άτομο προσωπικού.", "warning")
            return redirect(url_for("training_staff_new"))
        sd = request.form.get("start_date") or None
        ed = request.form.get("end_date") or None
        yr = request.form.get("year", type=int)
        title = (request.form.get("title") or "").strip()
        provider = (request.form.get("provider") or "").strip()
        diploma = None
        f = request.files.get("diploma")
        if f and f.filename:
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
            if ext in DIPLOMA_EXTENSIONS:
                diploma = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}.{ext}"
                f.save(os.path.join(UPLOAD_FOLDER, diploma))
        rid = db_execute(
            "INSERT INTO staff_trainings (node_id, start_date, end_date, year, title, provider, diploma, created_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (node_id, sd, ed, yr, title[:300], provider[:300], diploma, session["username"]), lastrowid=True)
        fs = request.form.get("from_sched", type=int)
        if fs:
            db_execute("DELETE FROM scheduled_trainings WHERE id=%s", (fs,))
        log_action("create", "staff_training", rid)
        flash("Η εκπαίδευση καταχωρήθηκε." + (" Αφαιρέθηκε από τις προγραμματισμένες." if fs else ""), "success")
        return redirect(url_for("training_staff_person", node_id=node_id))
    sel = request.args.get("node", type=int)
    from_sched = request.args.get("from_sched", type=int)
    prefill = None
    if from_sched:
        s = db_execute("SELECT * FROM scheduled_trainings WHERE id=%s", (from_sched,), fetch=True)
        if s:
            s = s[0]
            sel = s["node_id"]
            yr = None
            if s["start_date"]:
                try:
                    yr = int(str(s["start_date"])[:4])
                except (ValueError, TypeError):
                    yr = None
            prefill = {"start_date": s["start_date"], "end_date": s["end_date"],
                       "title": s["title"], "provider": s["provider"], "year": yr}
    return render_template("training_staff_form.html", staff=_org_staff(), rec=None,
                           sel_node=sel, prefill=prefill, from_sched=from_sched)


@app.route("/quality-unit/training/staff/<int:rec_id>/edit", methods=["GET", "POST"])
@login_required
def training_staff_edit(rec_id):
    rec = db_execute("SELECT * FROM staff_trainings WHERE id=%s", (rec_id,), fetch=True)
    if not rec:
        abort(404)
    rec = rec[0]
    if request.method == "POST":
        if not can_add_hospital("NGH"):
            flash("Δεν έχετε δικαίωμα τροποποίησης.", "danger")
            return redirect(url_for("training_staff"))
        node_id = request.form.get("node_id", type=int) or rec["node_id"]
        sd = request.form.get("start_date") or None
        ed = request.form.get("end_date") or None
        yr = request.form.get("year", type=int)
        title = (request.form.get("title") or "").strip()
        provider = (request.form.get("provider") or "").strip()
        diploma = rec["diploma"]
        f = request.files.get("diploma")
        if f and f.filename:
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
            if ext in DIPLOMA_EXTENSIONS:
                newname = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}.{ext}"
                f.save(os.path.join(UPLOAD_FOLDER, newname))
                if diploma:
                    try:
                        os.remove(os.path.join(UPLOAD_FOLDER, diploma))
                    except OSError:
                        pass
                diploma = newname
        db_execute("UPDATE staff_trainings SET node_id=%s, start_date=%s, end_date=%s, year=%s, title=%s, provider=%s, diploma=%s WHERE id=%s",
                   (node_id, sd, ed, yr, title[:300], provider[:300], diploma, rec_id))
        log_action("update", "staff_training", rec_id)
        flash("Η εκπαίδευση ενημερώθηκε.", "success")
        return redirect(url_for("training_staff_person", node_id=node_id))
    return render_template("training_staff_form.html", staff=_org_staff(), rec=rec, sel_node=None, prefill=None, from_sched=None)


@app.route("/quality-unit/training/staff/<int:rec_id>/diploma")
@login_required
def training_staff_diploma(rec_id):
    r = db_execute("SELECT diploma FROM staff_trainings WHERE id=%s", (rec_id,), fetch=True)
    if not r or not r[0]["diploma"]:
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, r[0]["diploma"], as_attachment=False)


@app.route("/quality-unit/training/staff/<int:rec_id>/delete", methods=["POST"])
@login_required
def training_staff_delete(rec_id):
    if not can_delete_hospital("NGH"):
        flash("Δεν έχετε δικαίωμα διαγραφής.", "danger")
        return redirect(url_for("training_staff"))
    r = db_execute("SELECT node_id, diploma FROM staff_trainings WHERE id=%s", (rec_id,), fetch=True)
    node_id = r[0]["node_id"] if r else None
    if r and r[0]["diploma"]:
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, r[0]["diploma"]))
        except OSError:
            pass
    db_execute("DELETE FROM staff_trainings WHERE id=%s", (rec_id,))
    log_action("delete", "staff_training", rec_id)
    flash("Η εκπαίδευση διαγράφηκε.", "info")
    return redirect(url_for("training_staff_person", node_id=node_id) if node_id else url_for("training_staff"))


@app.route("/quality-unit/training/scheduled")
@login_required
def training_scheduled():
    rows = db_execute(
        "SELECT t.*, n.person_name, n.person_title, n.level "
        "FROM scheduled_trainings t JOIN org_nodes n ON n.id=t.node_id "
        "ORDER BY t.start_date DESC, t.id DESC", fetch=True) or []
    for r in rows:
        r["unit_role"] = _unit_role(r.get("level"))
    return render_template("training_scheduled.html", rows=rows,
                           can_edit=can_add_hospital("NGH"), can_delete=can_delete_hospital("NGH"))


@app.route("/quality-unit/training/scheduled/new", methods=["GET", "POST"])
@login_required
def training_scheduled_new():
    if not can_add_hospital("NGH"):
        flash("Δεν έχετε δικαίωμα καταχώρησης.", "danger")
        return redirect(url_for("training_scheduled"))
    if request.method == "POST":
        node_id = request.form.get("node_id", type=int)
        if not node_id or not db_execute("SELECT id FROM org_nodes WHERE id=%s", (node_id,), fetch=True):
            flash("Επίλεξε έγκυρο άτομο προσωπικού.", "warning")
            return redirect(url_for("training_scheduled_new"))
        sd = request.form.get("start_date") or None
        ed = request.form.get("end_date") or None
        title = (request.form.get("title") or "").strip()
        provider = (request.form.get("provider") or "").strip()
        rid = db_execute(
            "INSERT INTO scheduled_trainings (node_id, start_date, end_date, title, provider, created_by) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (node_id, sd, ed, title[:300], provider[:300], session["username"]), lastrowid=True)
        log_action("create", "scheduled_training", rid)
        flash("Η προγραμματισμένη εκπαίδευση καταχωρήθηκε.", "success")
        return redirect(url_for("training_scheduled"))
    return render_template("training_scheduled_form.html", staff=_org_staff(), rec=None)


@app.route("/quality-unit/training/scheduled/<int:rec_id>/edit", methods=["GET", "POST"])
@login_required
def training_scheduled_edit(rec_id):
    rec = db_execute("SELECT * FROM scheduled_trainings WHERE id=%s", (rec_id,), fetch=True)
    if not rec:
        abort(404)
    rec = rec[0]
    if request.method == "POST":
        if not can_add_hospital("NGH"):
            flash("Δεν έχετε δικαίωμα τροποποίησης.", "danger")
            return redirect(url_for("training_scheduled"))
        node_id = request.form.get("node_id", type=int) or rec["node_id"]
        sd = request.form.get("start_date") or None
        ed = request.form.get("end_date") or None
        title = (request.form.get("title") or "").strip()
        provider = (request.form.get("provider") or "").strip()
        db_execute("UPDATE scheduled_trainings SET node_id=%s, start_date=%s, end_date=%s, title=%s, provider=%s WHERE id=%s",
                   (node_id, sd, ed, title[:300], provider[:300], rec_id))
        log_action("update", "scheduled_training", rec_id)
        flash("Η προγραμματισμένη εκπαίδευση ενημερώθηκε.", "success")
        return redirect(url_for("training_scheduled"))
    return render_template("training_scheduled_form.html", staff=_org_staff(), rec=rec)


@app.route("/quality-unit/training/scheduled/<int:rec_id>/delete", methods=["POST"])
@login_required
def training_scheduled_delete(rec_id):
    if not can_add_hospital("NGH"):
        flash("Δεν έχετε δικαίωμα διαγραφής.", "danger")
        return redirect(url_for("training_scheduled"))
    db_execute("DELETE FROM scheduled_trainings WHERE id=%s", (rec_id,))
    log_action("delete", "scheduled_training", rec_id)
    flash("Η προγραμματισμένη εκπαίδευση διαγράφηκε.", "info")
    return redirect(url_for("training_scheduled"))


@app.route("/quality-unit/training/scheduled/calendar")
@login_required
def training_scheduled_calendar():
    today = date.today()
    try:
        year = int(request.args.get("year") or today.year)
        month = int(request.args.get("month") or today.month)
    except (TypeError, ValueError):
        year, month = today.year, today.month
    month = min(12, max(1, month))
    weeks = calendar.Calendar(firstweekday=0).monthdayscalendar(year, month)
    rows = db_execute(
        "SELECT t.*, n.person_name FROM scheduled_trainings t JOIN org_nodes n ON n.id=t.node_id",
        fetch=True) or []
    first = date(year, month, 1)
    last = date(year, month, calendar.monthrange(year, month)[1])
    by_day = {}
    for r in rows:
        sd = _as_date(r["start_date"])
        ed = _as_date(r["end_date"])
        if not sd or sd == date.min:
            continue
        if not ed or ed == date.min:
            ed = sd
        d = max(sd, first)
        end = min(ed, last)
        while d <= end:
            by_day.setdefault(d.day, []).append(r)
            d = d + timedelta(days=1)
    prev_y, prev_m = (year, month - 1) if month > 1 else (year - 1, 12)
    next_y, next_m = (year, month + 1) if month < 12 else (year + 1, 1)
    return render_template("training_calendar.html", year=year, month=month,
                           month_name=MONTHS[month], weeks=weeks, by_day=by_day,
                           prev_y=prev_y, prev_m=prev_m, next_y=next_y, next_m=next_m, today=today)


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
        for key in ("org_name", "org_short", "app_title", "session_timeout",
                    "base_url", "smtp_host", "smtp_port", "smtp_user", "smtp_from"):
            if request.form.get(key) is not None:
                settings[key] = request.form.get(key).strip()
        if (request.form.get("smtp_pass") or "").strip():
            settings["smtp_pass"] = request.form.get("smtp_pass").strip()
        settings["smtp_tls"] = "1" if request.form.get("smtp_tls") else "0"
        save_settings(settings)
        log_action("update", "settings", "")
        flash("Οι ρυθμίσεις αποθηκεύτηκαν.", "success")
        return redirect(url_for("admin_settings"))
    return render_template("settings.html", settings=settings, use_mysql=USE_MYSQL)


@app.route("/admin/audit")
@role_required("admin", "central")
def audit_trail():
    if not _admin_unlocked():
        return redirect(url_for("administrator_unlock", next=url_for("audit_trail")))
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
# Administrator — προστατευμένη ενότητα (ξεκλείδωμα με τον κωδικό του admin)
# ---------------------------------------------------------------------------
def _admin_unlocked():
    return session.get("admin_unlocked") is True


@app.route("/administrator/unlock", methods=["GET", "POST"])
@role_required("admin")
def administrator_unlock():
    nxt = request.values.get("next") or url_for("administrator_users")
    if request.method == "POST":
        pwd = request.form.get("password") or ""
        u = db_execute("SELECT password_hash FROM users WHERE id=%s", (session["user_id"],), fetch=True)
        if u and check_password_hash(u[0]["password_hash"], pwd):
            session["admin_unlocked"] = True
            log_action("admin_unlock", "admin", session["user_id"])
            return redirect(nxt)
        flash("Λάθος κωδικός.", "danger")
    return render_template("administrator_unlock.html", next=nxt)


@app.route("/administrator")
@role_required("admin")
def administrator():
    if not _admin_unlocked():
        return redirect(url_for("administrator_unlock"))
    return redirect(url_for("administrator_users"))


@app.route("/administrator/users")
@role_required("admin")
def administrator_users():
    if not _admin_unlocked():
        return redirect(url_for("administrator_unlock", next=url_for("administrator_users")))
    users = db_execute("SELECT * FROM users ORDER BY username", fetch=True) or []
    return render_template("administrator_users.html", users=users, hnames=hospital_names())


@app.route("/administrator/users/<int:user_id>/password", methods=["POST"])
@role_required("admin")
def administrator_set_password(user_id):
    if not _admin_unlocked():
        return redirect(url_for("administrator_unlock"))
    new = request.form.get("new_password") or ""
    if len(new) < 6:
        flash("Ο κωδικός πρέπει να έχει τουλάχιστον 6 χαρακτήρες.", "warning")
    else:
        db_execute("UPDATE users SET password_hash=%s WHERE id=%s", (generate_password_hash(new), user_id))
        log_action("set_password", "user", user_id, f"reset by admin")
        flash("Ο κωδικός ενημερώθηκε.", "success")
    return redirect(url_for("administrator_users"))


@app.route("/administrator/users/<int:user_id>/role", methods=["POST"])
@role_required("admin")
def administrator_set_role(user_id):
    if not _admin_unlocked():
        return redirect(url_for("administrator_unlock"))
    if user_id == session["user_id"]:
        flash("Δεν μπορείτε να αλλάξετε τον δικό σας ρόλο.", "warning")
        return redirect(url_for("administrator_users"))
    role = request.form.get("role") or ""
    if role not in ROLES:
        flash("Μη έγκυρος ρόλος.", "warning")
        return redirect(url_for("administrator_users"))
    db_execute("UPDATE users SET role=%s WHERE id=%s", (role, user_id))
    log_action("set_role", "user", user_id, role)
    flash("Ο ρόλος του χρήστη ενημερώθηκε.", "success")
    return redirect(url_for("administrator_users"))


@app.route("/administrator/users/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def administrator_delete_user(user_id):
    if not _admin_unlocked():
        return redirect(url_for("administrator_unlock"))
    if user_id == session["user_id"]:
        flash("Δεν μπορείτε να διαγράψετε τον εαυτό σας.", "warning")
        return redirect(url_for("administrator_users"))
    rows = db_execute("SELECT username FROM users WHERE id=%s", (user_id,), fetch=True)
    if not rows:
        flash("Ο χρήστης δεν βρέθηκε.", "warning")
        return redirect(url_for("administrator_users"))
    uname = rows[0]["username"]
    db_execute("DELETE FROM users WHERE id=%s", (user_id,))
    log_action("delete", "user", user_id, uname)
    flash(f"Ο χρήστης «{uname}» διαγράφηκε.", "success")
    return redirect(url_for("administrator_users"))


@app.route("/administrator/users/create", methods=["POST"])
@role_required("admin")
def administrator_create_user():
    """Γρήγορη δημιουργία χρήστη (dialog): username + προσωρινός κωδικός 1234 + επίπεδο δικαιωμάτων."""
    username = (request.form.get("username") or "").strip().lower()
    full_name = (request.form.get("full_name") or "").strip()
    role = request.form.get("role") or ""
    back = request.referrer or url_for("dashboard")
    if role not in ("q_add", "q_edit", "q_delete"):
        flash("Επιλέξτε έγκυρη λειτουργικότητα (View/Add, View/Add/Edit ή View/Add/Edit/Delete).", "warning")
        return redirect(back)
    if not username:
        flash("Συμπληρώστε όνομα χρήστη.", "warning")
        return redirect(back)
    if not full_name:
        flash("Συμπληρώστε το ονοματεπώνυμο.", "warning")
        return redirect(back)
    if db_execute("SELECT id FROM users WHERE username=%s", (username,), fetch=True):
        flash("Υπάρχει ήδη χρήστης με αυτό το όνομα.", "warning")
        return redirect(back)
    email = (request.form.get("email") or "").strip()
    rid = db_execute(
        "INSERT INTO users (username, password_hash, full_name, email, role, hospital_code, must_change_pw) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (username, generate_password_hash("1234"), full_name, email, role, "NGH", 1), lastrowid=True)
    log_action("create", "user", rid, f"{username} · {role}")
    base = f"Δημιουργήθηκε ο χρήστης «{username}» με προσωρινό κωδικό «1234» — {ROLES.get(role, role)}."
    if email:
        login_url = (load_settings().get("base_url") or request.url_root).rstrip("/") + url_for("login")
        body = (
            "Καλωσορίσατε στο σύστημα eQuality!\n\n"
            "Δημιουργήθηκε λογαριασμός για εσάς με τα παρακάτω στοιχεία:\n\n"
            f"\u2022 Όνομα χρήστη (username): {username}\n"
            f"\u2022 Προσωρινός κωδικός: 1234\n"
            f"\u2022 Δικαιώματα: {ROLES.get(role, role)}\n\n"
            f"Σύνδεση: {login_url}\n\n"
            "ΣΗΜΑΝΤΙΚΟ: Κατά την πρώτη σας σύνδεση, το σύστημα θα σας ζητήσει να αντικαταστήσετε "
            "τον προσωρινό κωδικό «1234» με έναν δικό σας κωδικό της επιλογής σας.\n\n"
            "Με εκτίμηση,\nΜονάδα Διασφάλισης Ποιότητας — eQuality"
        )
        ok, err = send_email(email, "Καλωσορίσατε στο eQuality — Στοιχεία λογαριασμού", body)
        if ok:
            flash(base + f" Στάλθηκε email στο {email}.", "success")
        else:
            flash(base + f" ΠΡΟΣΟΧΗ: το email ΔΕΝ στάλθηκε — {err}", "warning")
    else:
        flash(base, "success")
    return redirect(back)


_LIST_TABLES = {"departments": "departments", "inspectors": "inspectors"}


@app.route("/administrator/lists")
@role_required("admin")
def administrator_lists():
    if not _admin_unlocked():
        return redirect(url_for("administrator_unlock", next=url_for("administrator_lists")))
    departments = db_execute("SELECT id, name FROM departments ORDER BY name", fetch=True) or []
    inspectors = db_execute("SELECT id, name FROM inspectors ORDER BY name", fetch=True) or []
    return render_template("administrator_lists.html", departments=departments, inspectors=inspectors)


@app.route("/administrator/lists/<which>/clear", methods=["POST"])
@role_required("admin")
def administrator_list_clear(which):
    if not _admin_unlocked():
        return redirect(url_for("administrator_unlock"))
    table = _LIST_TABLES.get(which)
    if not table:
        abort(404)
    db_execute(f"DELETE FROM {table}")
    log_action("clear", "list", which)
    flash("Η λίστα καθαρίστηκε.", "info")
    return redirect(url_for("administrator_lists"))


@app.route("/administrator/lists/<which>/<int:item_id>/delete", methods=["POST"])
@role_required("admin")
def administrator_list_delete(which, item_id):
    if not _admin_unlocked():
        return redirect(url_for("administrator_unlock"))
    table = _LIST_TABLES.get(which)
    if not table:
        abort(404)
    db_execute(f"DELETE FROM {table} WHERE id=%s", (item_id,))
    log_action("delete", "list_item", f"{which}/{item_id}")
    flash("Η εγγραφή διαγράφηκε.", "info")
    return redirect(url_for("administrator_lists"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
