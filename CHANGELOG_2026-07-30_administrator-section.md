# CHANGELOG 2026-07-30 — Ενότητα «Administrator» (step-up) & πίνακας Users

## Τι

Νέα ενότητα **«Administrator»** στο πλαϊνό μενού (μόνο ρόλος admin), που **ξεκλειδώνει
μόνο αφού ο admin ξαναβάλει τον κωδικό του** (step-up authentication, ανά session).
Υπομενού **«Users»** → πίνακας με usernames, δικαιώματα (ρόλο + περιγραφή), κατάσταση,
και **ορισμό νέου κωδικού** ανά χρήστη.

## Ασφάλεια κωδικών

Οι κωδικοί ΔΕΝ εμφανίζονται (αποθηκεύονται μονόδρομα/hashed — αδύνατο & επικίνδυνο να
δειχτούν). Η στήλη «Κωδικός» δείχνει •••••• + πεδίο «νέος κωδικός» με κουμπί ορισμού.

## Υλοποίηση

- `app.py`: `ROLE_PERMISSIONS` (περιγραφές δικαιωμάτων)· routes `administrator_unlock`
  (έλεγχος κωδικού admin → `session['admin_unlocked']`), `administrator`, `administrator_users`,
  `administrator_set_password`. Το logout καθαρίζει το ξεκλείδωμα (session.clear).
- `templates/administrator_unlock.html`, `administrator_users.html` (νέα).
- `templates/base.html`: πτυσσόμενο «Administrator» με υπομενού «Users» (admin only).

## Έλεγχοι

- test_quality.py 35/35. Επαληθεύτηκε: κλείδωμα→ανακατεύθυνση, λάθος/σωστός κωδικός,
  πίνακας users (••••••, δικαιώματα), ορισμός νέου κωδικού, αποκλεισμός μη-admin.
