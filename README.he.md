<p align="right">
  <a href="README.md">English</a> ·
  <a href="README.ru.md">Русский</a> ·
  <a href="README.he.md">עברית</a>
</p>

<div dir="rtl">

# Pico HSM Manager

יישום GUI חלונאי לניהול התקני **Pico HSM** ו-**Pico FIDO2** — מפתחות, תעודות וסוכן SSH מובנה.

## התחלה מהירה

1. הורד את `PicoHSMManager.exe` מ-[Releases](../../releases)
2. הפעל (נדרשות הרשאות מנהל עבור FIDO2 וסוכן SSH)
3. חבר את ההתקן, הזן PIN
4. נהל מפתחות, תעודות וסוכן SSH

## תכונות

### Pico HSM
- **יצירת מפתחות**: RSA (2048–4096), EC (secp256r1/384r1/521r1/256k1, brainpoolP256r1/384r1/512r1, Ed25519, Ed448), ECDH (X25519, X448), AES (128–256)
- הצגה וייצוא מפתחות ציבוריים (PEM, SSH authorized_keys)
- הגדרת תוויות (labels) למפתחות
- הצגת תעודות EE (CVC), כתיבת תעודות CA (CVC)
- איפוס התקן (Factory Reset) עם PIN/SO PIN חדש
- החלפת PIN ו-SO PIN
- מידע התקן (גרסת קושחה, זיכרון, ניסיונות PIN)
- הפעלה/כיבוי של Press-to-Confirm

### Pico FIDO2
- רישום ואימות WebAuthn credentials
- ניהול מפתחות תושבים (resident/discoverable)
- ייצוא מפתחות SSH (`sk-ecdsa-sha2-nistp256@openssh.com` / `sk-ed25519@openssh.com`)
- החלפת PIN FIDO2, איפוס התקן
- מידע התקן

### סוכן SSH מובנה
- תואם ל-**Pageant** (WM_COPYDATA) — PuTTY, KiTTY, NetBox, WinSCP
- תואם ל-**OpenSSH** (named pipe `\\.\pipe\openssh-ssh-agent`) — `ssh.exe`
- תומך במפתחות Pico HSM ו-Pico FIDO2
- בחירת מפתחות מרובים, אישור חתימה לכל בקשה
- הפעלה אוטומטית בחיבור התקן
- כלי בדיקה מובנה לסוכן

### ממשק
- שפות: עברית, English, Русский
- ערכות נושא כהות ובהירות
- שמירת מיקום וגודל החלון

## דרישות מערכת
- Windows 10 / 11 (x64)
- OpenSSH Client (מובנה ב-Windows 10 1809+) — נדרש רק לשילוב עם `ssh.exe`
- הרשאות מנהל (לגישת HID ל-FIDO2 ולהפעלת סוכן SSH דרך named pipe)

## הערות
- אם Pageant אמיתי פועל, סגור אותו קודם: `taskkill /f /im pageant.exe`
- לוגים: `%TEMP%\hsm_agent.log` ו-`%TEMP%\hsm_agent_crash.log`
- קובץ הגדרות: `hsm_guir.json` (נוצר ליד הקובץ ההרצה)

## רישיון
MIT

</div>
