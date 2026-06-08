<p align="right">
  <a href="README.md">English</a> ·
  <a href="README.ru.md">Русский</a> ·
  <a href="README.he.md">עברית</a>
</p>

<div dir="rtl">

# Pico HSM Manager (hsm_guir.py)

ממשק גרפי אוניברסלי ל-Windows לניהול התקני **Pico HSM** ו-**Pico FIDO2**.

## תכונות

### Pico HSM
- חיבור באמצעות PIN
- יצירת מפתחות: RSA (2048/3072/4096), EC (secp256r1/384r1/521r1/256k1, brainpoolP256r1/384r1/512r1, Ed25519, Ed448), ECDH (X25519, X448), AES (128/192/256)
- הצגת מפתחות ציבוריים (PEM, SSH)
- ייצוא מפתחות SSH (ללוח / לקובץ)
- הגדרת תוויות (labels) למפתחות
- הצגת תעודות EE (CVC)
- כתיבת תעודות CA (CVC)
- מחיקת מפתחות
- איפוס התקן (Factory Reset) עם החלפת PIN/SO PIN
- החלפת PIN / SO PIN
- מידע התקן (גרסת קושחה, זיכרון, ניסיונות PIN)
- שליטה ב-Press-to-Confirm

### Pico FIDO2
- חיבור דרך HID
- רישום WebAuthn credentials
- אימות (get assertion)
- ניהול מפתחות תושבים (resident)
- ייצוא מפתחות SSH (sk-ecdsa-sha2-nistp256@openssh.com / sk-ed25519@openssh.com)
- החלפת PIN FIDO2
- איפוס התקן

### סוכן SSH
- סוכן SSH מובנה התואם ל-**Pageant** (WM_COPYDATA) ול-**OpenSSH** (named pipe `\\.\pipe\openssh-ssh-agent`)
- תומך במפתחות Pico HSM ו-Pico FIDO2
- בחירת מפתחות מרובים לסוכן
- אישור חתימה לכל בקשה (אופציונלי)
- הפעלה אוטומטית בחיבור
- בדיקת סוכן מובנית (רשימת מפתחות, חתימת בדיקה)

### ממשק
- שפות: עברית, English, Русский
- ערכות נושא כהות ובהירות
- שמירת מיקום החלון והגדרות

## תלויות

- Python 3.7+
- `picohsm` — ספרייה לעבודה עם Pico HSM
- `cryptography` — פעולות קריפטוגרפיות
- `cvc` — טיפול בתעודות CVC
- `tkinter` — כלול ב-Python (Windows)
- `fido2` (אופציונלי) — תמיכה ב-Pico FIDO2
- `cbor2` או `cbor` (אופציונלי, עבור fido2)

התקנת תלויות:

```bash
pip install picohsm cryptography cvc fido2 cbor2
```

## שימוש

### גרסת EXE מוכנה

הורד את `PicoHSMManager.exe` מ-[Releases](../../releases) — הפעל ישירות (ללא Python).

### מקוד מקור

```bash
pip install picohsm cryptography cvc fido2 cbor2
python hsm_guir.py
```

בהפעלה ללא הרשאות מנהל, הסקריפט מבקש אוטומטית הרשאה (נדרש לגישת HID ל-FIDO2 ולהפעלת סוכן SSH).

### מצבים

החלף בין מצבי **Pico HSM** ו-**Pico FIDO2** דרך התפריט הנפתח בלוח העליון. האפליקציה מזהה אוטומטית את ההתקן המחובר.

### סוכן SSH

1. התחבר להתקן.
2. עבור ללשונית **SSH Agent**.
3. בחר מפתחות מהרשימה (Ctrl+Click / Shift+Click לבחירה מרובה).
4. לחץ **Start**.

הסוכן זמין מ:
- PuTTY / Kitty / NetBox / WinSCP — דרך Pageant (WM_COPYDATA)
- OpenSSH (ssh.exe) — דרך named pipe `\\.\pipe\openssh-ssh-agent`

אם Pageant אמיתי פועל, עצור אותו קודם:
```
taskkill /f /im pageant.exe
```

## תצורה

קובץ הגדרות: `hsm_guir.json` (נוצר אוטומטית בתיקיית הסקריפט).

פרמטרים:
- `geometry` — מיקום וגודל החלון
- `theme` — "light" או "dark"
- `lang` — "en", "ru", "he"

לוגים:
- `%TEMP%\hsm_agent.log` — לוג ראשי
- `%TEMP%\hsm_agent_crash.log` — לוג שגיאות סוכן SSH

## בניית EXE

```bash
pip install pyinstaller
python -m PyInstaller --clean --onefile --uac-admin --windowed --name "PicoHSMManager" hsm_guir.py
```

הקובץ `.exe` ייווצר ב-`dist/`.

## תלויות היקפיות

- **pkcs11-tool.exe** (מ-[OpenSC](https://github.com/OpenSC/OpenSC/wiki)) — אופציונלי, משמש לעידון שמות עקומות EC. נתיב ברירת מחדל: `C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe`. אם חסר, סוגי המפתחות נקבעים מתעודות CVC.

## הערות

- גישת HID ל-FIDO2 דורשת הרשאות מנהל.
- סוכן SSH דרך named pipe של OpenSSH דורש Windows 10 1809+ עם רכיב OpenSSH Client מותקן.
- עלולים להיווצר התנגשויות בשימוש לצד Pageant אמיתי — הפעל עותק אחד בלבד.

## רישיון

MIT

</div>
