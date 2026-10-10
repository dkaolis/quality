# 2026-10-10 — «Υπεύθυνος Υλοποίησης» ως πεδίο μεταβλητού μεγέθους στα audit tools

- templates/checklist_fill.html: το πεδίο Υπεύθυνος Υλοποίησης (_resp) έγινε textarea με auto-expand (class ag),
  όπως Τεκμήριο/Σημειώσεις/Διορθωτικές — στις κάρτες Qmentum (ΑΤ.01, rows=2) και ISO/Infection Control (ΑΤ.02/ΑΤ.03, rows=3).
- templates/checklist_report2.html, checklist_iso_report.html: white-space:pre-wrap στον Υπεύθυνο ώστε οι αλλαγές γραμμής να φαίνονται στο PDF.
- Έλεγχος: dev instance 23 → 107 textarea (0 input)· ΑΤ.02 26, ΑΤ.03 9 (συνθετικά δεδομένα)· πολυγραμμική τιμή διατηρείται σε φόρμα & PDF.
- Backups: templates/*.bak_resp_*
