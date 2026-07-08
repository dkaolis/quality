"""
Smoke tests για το eQuality — τρέχουν με το flask test client πάνω στην τοπική
SQLite DB (quality.db). Εκτέλεση: /opt/quality/venv/bin/python3 test_quality.py
"""

import io
import sys

import app as appmod
from app import app


PASS = FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✔ {name}")
    else:
        FAIL += 1
        print(f"  ✖ {name} {extra}")


def main():
    app.config["TESTING"] = True
    c = app.test_client()

    print("— Auth —")
    r = c.get("/login")
    check("GET /login → 200", r.status_code == 200)
    r = c.post("/login", data={"username": "admin", "password": "wrong"}, follow_redirects=True)
    check("Λάθος κωδικός → παραμένει στο login", "Λάθος όνομα χρήστη".encode() in r.data)
    r = c.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=True)
    check("Σωστό login → dashboard", r.status_code == 200 and "Πίνακας Ελέγχου".encode() in r.data)

    print("— Σελίδες —")
    for path in ("/", "/alerts", "/indicators", "/values", "/compare", "/procedures",
                 "/compliance", "/compliance/list", "/inspections", "/documents",
                 "/reports", "/admin/hospitals", "/admin/users", "/admin/settings", "/admin/audit"):
        r = c.get(path)
        check(f"GET {path} → 200", r.status_code == 200, f"(got {r.status_code})")

    print("— Καταχώρηση τιμών —")
    inds = appmod.db_execute("SELECT * FROM indicators WHERE active=1 ORDER BY id LIMIT 1", fetch=True)
    ind = inds[0]
    r = c.post("/values?hospital=NGH&year=2026&month=1",
               data={"hospital": "NGH", "year": "2026", "month": "1",
                     f"val_{ind['id']}": "7,5", f"com_{ind['id']}": "δοκιμή"},
               follow_redirects=True)
    check("POST τιμής (ελληνικό δεκαδικό 7,5)", r.status_code == 200)
    rows = appmod.db_execute(
        "SELECT * FROM indicator_values WHERE indicator_id=%s AND hospital_code='NGH' AND year=2026 AND month=1",
        (ind["id"],), fetch=True)
    check("Η τιμή γράφτηκε στη DB (7.5)", rows and abs(rows[0]["value"] - 7.5) < 1e-9)

    print("— Λογική κατάστασης (value_status) —")
    fake = {"direction": "lower_better", "target_value": 3, "limit_low": None, "limit_high": 5}
    check("lower_better: 2 → ok", appmod.value_status(fake, 2) == "ok")
    check("lower_better: 4 → warn", appmod.value_status(fake, 4) == "warn")
    check("lower_better: 6 → alert", appmod.value_status(fake, 6) == "alert")
    fake = {"direction": "higher_better", "target_value": 85, "limit_low": 75, "limit_high": None}
    check("higher_better: 90 → ok", appmod.value_status(fake, 90) == "ok")
    check("higher_better: 80 → warn", appmod.value_status(fake, 80) == "warn")
    check("higher_better: 70 → alert", appmod.value_status(fake, 70) == "alert")

    print("— Έγγραφα: upload & parsing xlsx —")
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Δείκτες"
    ws.append(["Δείκτης", "Ιαν", "Φεβ"])
    ws.append(["Λοιμώξεις", 3.2, 2.9])
    ws.append(["Πτώσεις", 1, 2])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    r = c.post("/documents/upload",
               data={"hospital_code": "NGH", "title": "Δοκιμαστικό", "category": "Στατιστικά Στοιχεία",
                     "year": "2026", "month": "1", "file": (buf, "test.xlsx")},
               content_type="multipart/form-data", follow_redirects=True)
    check("Upload xlsx → 200", r.status_code == 200)
    docs = appmod.db_execute("SELECT * FROM documents WHERE title='Δοκιμαστικό' ORDER BY id DESC LIMIT 1", fetch=True)
    check("Έγγραφο parsed", docs and docs[0]["parse_status"] == "parsed",
          f"(status={docs[0]['parse_status'] if docs else '—'})")
    if docs:
        metrics = appmod.db_execute("SELECT * FROM document_metrics WHERE document_id=%s", (docs[0]["id"],), fetch=True)
        check("Εξήχθησαν 4 τιμές (2×2 κελιά)", len(metrics) == 4, f"(got {len(metrics)})")
        labels = {m["label"] for m in metrics}
        check("Ετικέτα 'Λοιμώξεις — Ιαν' υπάρχει", "Λοιμώξεις — Ιαν" in labels)
        # Καθάρισμα
        r = c.post(f"/documents/{docs[0]['id']}/delete", follow_redirects=True)
        check("Διαγραφή εγγράφου", r.status_code == 200)

    print("— Έκθεση Word —")
    r = c.post("/reports", data={"year": "2026", "month_from": "1", "month_to": "3"})
    check("POST /reports → .docx", r.status_code == 200 and
          r.mimetype == "application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    print("— Δικαιώματα (quality_officer άλλου νοσηλευτηρίου) —")
    appmod.db_execute("DELETE FROM users WHERE username='test_lgh'")
    appmod.db_execute(
        "INSERT INTO users (username, password_hash, full_name, role, hospital_code) VALUES (%s,%s,%s,%s,%s)",
        ("test_lgh", appmod.generate_password_hash("test123"), "Δοκιμή ΛΓΝ", "quality_officer", "LGH"))
    c2 = app.test_client()
    c2.post("/login", data={"username": "test_lgh", "password": "test123"})
    r = c2.post("/values?hospital=NGH&year=2026&month=2",
                data={"hospital": "NGH", "year": "2026", "month": "2", f"val_{ind['id']}": "1"},
                follow_redirects=True)
    check("Δεν γράφει σε ξένο νοσηλευτήριο", "Δεν έχετε δικαίωμα".encode() in r.data)
    rows = appmod.db_execute(
        "SELECT * FROM indicator_values WHERE indicator_id=%s AND hospital_code='NGH' AND year=2026 AND month=2",
        (ind["id"],), fetch=True)
    check("Η ξένη τιμή ΔΕΝ γράφτηκε", not rows)
    r = c2.get("/admin/users")
    check("quality_officer δεν βλέπει /admin/users", "Χρήστες</h2>".encode() not in r.data)
    appmod.db_execute("DELETE FROM users WHERE username='test_lgh'")

    # Καθάρισμα δοκιμαστικής τιμής
    appmod.db_execute("DELETE FROM indicator_values WHERE hospital_code='NGH' AND year=2026 AND month=1 AND indicator_id=%s",
                      (ind["id"],))

    print(f"\nΣύνολο: {PASS} πέρασαν, {FAIL} απέτυχαν")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
