# CHANGELOG 2026-07-21 — Αφαίρεση συχνότητας «Τετράμηνο»

## Τι

Αφαιρέθηκε η λέξη/συχνότητα «Τετράμηνο» (`four_monthly`) από το UI. Οι δείκτες ΤΑΕΠ
μεταφέρθηκαν σε συχνότητα «Μηνιαία». Η περίοδος καταχώρησης επιλέγεται ούτως ή άλλως
με τα πεδία «Από/Μέχρι», οπότε η συχνότητα είναι πλέον απλή ετικέτα.

## Αλλαγές (app.py)

- Αφαιρέθηκε το `"four_monthly": "Τετράμηνο"` από `FREQUENCIES`.
- Seed δεικτών ΤΑΕΠ: συχνότητα `monthly` (αντί four_monthly).
- Migration (idempotent): `UPDATE indicators SET frequency='monthly' WHERE grp IN (ΤΑΕΠ...) AND frequency='four_monthly'`.
- Αφαιρέθηκε ο κλάδος `four_monthly` από `_indicators_for_month`.

## Έλεγχοι

- ΒΔ: 24 δείκτες ΤΑΕΠ → `monthly`.
- `test_quality.py`: 35/35.
- Served pages (indicators/values/indicator_form): 0 εμφανίσεις «Τετράμηνο».
