import sys, os, struct, base64, threading, tempfile, subprocess, re, json, time, webbrowser, ctypes, ctypes.wintypes, hashlib, tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from picohsm import PicoHSM, KeyType, DOPrefixes, Algorithm
from picohsm.PicoHSM import EncryptionMode
from picohsm.Algorithm import AES as AESMode
from cvc.certificates import CVC
from cvc import oid as cvcoid
from cvc.ec_curves import EcCurve, Curve25519, Curve448
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519, ed448, x448, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from picohsm import Padding

try:
    from fido2.hid import CtapHidDevice
    from fido2.client import Fido2Client, DefaultClientDataCollector
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
        UserVerificationRequirement,
    )
    from fido2.ctap2 import Ctap2, CredentialManagement
    from fido2.ctap2.pin import ClientPin
    HAS_FIDO2 = True
except ImportError:
    HAS_FIDO2 = False

try:
    import cbor2 as _cbor2
except ImportError:
    try:
        import cbor as _cbor2
    except ImportError:
        _cbor2 = None

# Workaround: patch fido2 HID backend to try GENERIC_READ if ACCESS=0 fails
if HAS_FIDO2:
    try:
        import fido2.hid.windows as _f2w
        _orig_get_descriptor = _f2w.get_descriptor
        def _patched_get_descriptor(path):
            try:
                return _orig_get_descriptor(path)
            except PermissionError:
                dev = _f2w.kernel32.CreateFileA(
                    path,
                    0x80000000,  # GENERIC_READ
                    0x00000003,  # FILE_SHARE_READ | FILE_SHARE_WRITE
                    None,
                    3,  # OPEN_EXISTING
                    0,
                    None,
                )
                if dev == 0 or dev == _f2w.INVALID_HANDLE_VALUE:
                    raise
                try:
                    import ctypes
                    pp = ctypes.c_void_p(0)
                    ret = _f2w.hid.HidD_GetPreparsedData(dev, ctypes.byref(pp))
                    if not ret:
                        raise ctypes.WinError()
                    try:
                        caps = _f2w.HidCapabilities()
                        ret = _f2w.hid.HidP_GetCaps(pp, ctypes.byref(caps))
                        if ret != 0x00110000:
                            raise ctypes.WinError()
                        if caps.UsagePage == 0xF1D0 and caps.Usage == 0x01:
                            vid, pid = _f2w.get_vid_pid(dev)
                            name = _f2w.get_product_name(dev)
                            serial = _f2w.get_serial(dev)
                            size_in = caps.InputReportByteLength - 1
                            size_out = caps.OutputReportByteLength - 1
                            return _f2w.HidDescriptor(path, vid, pid, size_in, size_out, name, serial)
                        raise ValueError("Not a CTAP device")
                    finally:
                        _f2w.hid.HidD_FreePreparsedData(pp)
                finally:
                    _f2w.kernel32.CloseHandle(dev)
        _f2w.get_descriptor = _patched_get_descriptor
        import fido2.hid as _f2hid
        _f2hid.get_descriptor = _patched_get_descriptor
    except Exception:
        pass  # patch failed, use original

if ctypes.sizeof(ctypes.c_void_p) == 8:
    LRESULT = ctypes.c_longlong
else:
    LRESULT = ctypes.c_long

# wintypes.HCURSOR/HICON/HBRUSH отсутствуют в некоторых версиях Python
for _WTYPE in ('HCURSOR', 'HICON', 'HBRUSH'):
    if not hasattr(ctypes.wintypes, _WTYPE):
        setattr(ctypes.wintypes, _WTYPE, ctypes.wintypes.HANDLE)

ERROR_LOG = os.path.join(tempfile.gettempdir(), "hsm_agent_crash.log")
AGENT_LOG  = os.path.join(tempfile.gettempdir(), "hsm_agent.log")
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hsm_guir.json")
KEY_ALGOS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "key_algos.json")
STATS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stats.json")

import logging as _logging
_agent_logger = _logging.getLogger("pico_hsm_agent")
_agent_logger.setLevel(_logging.DEBUG)
_log_handler = _logging.FileHandler(AGENT_LOG, encoding="utf-8")
_log_handler.setFormatter(_logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", datefmt="%H:%M:%S"))
_agent_logger.addHandler(_log_handler)

def alog(msg, level="INFO"):
    """Пишет в hsm_agent.log и не падает никогда."""
    try:
        getattr(_agent_logger, level.lower(), _agent_logger.info)(msg)
    except Exception:
        pass

PKCS11_TOOL = r'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe'

OID_RI_ECDH  = bytes.fromhex('04007f00070202050203')
OID_TA_ECDSA = bytes.fromhex('04007f00070202020203')
OID_TA_RSA   = bytes.fromhex('04007f0007020205020c')

SKIP_IDS = {0}

_LANG = "en"
_LANG_CB = None

_TR = {
    "en": {},
    "ru": {
        "SSH / Sign (NIST EC)": "SSH / Подпись (NIST EC)",
        "SSH / Sign (Brainpool EC)": "SSH / Подпись (Brainpool EC)",
        "SSH / Sign (Montgomery)": "SSH / Подпись (Монтгомери)",
        "Key Exchange (ECDH)": "Обмен ключами (ECDH)",
        "SSH / Sign (RSA)": "SSH / Подпись (RSA)",
        "AES (symmetric)": "AES (симметричный)",
        "Connect": "Подключиться",
        "Keys on device": "Ключи на устройстве",
        "Actions": "Действия",
        "Refresh list": "Обновить список",
        "Create key": "Создать ключ",
        "Show public key": "Показать публичный ключ",
        "Export SSH": "Экспорт SSH",
        "Delete key": "Удалить ключ",
        "Delete selected": "Удалить выбранные",
        "Delete all keys": "Удалить все ключи",
        "Set label": "Задать метку",
        "Show EE cert": "Показать EE-сертификат",
        "Write CA cert": "Записать CA-сертификат",
        "Factory reset": "Сброс устройства",
        "Output": "Вывод",
        "EE certificate": "EE-сертификат",
        "Disconnected": "Отключено",
        "Key type:": "Тип ключа:",
        "Create": "Создать",
        "Cancel": "Отмена",
        "Warning": "Внимание",
        "Select a key type from the list.": "Выберите тип ключа из списка.",
        "Confirm": "Подтверждение",
        "Generate": "Генерация",
        "No keys with public part (Ed25519/EC/RSA).": "Нет ключей с публичной частью (Ed25519/EC/RSA).",
        "Control": "Управление",
        "Start": "Запустить",
        "Stop": "Остановить",
        "Test": "Тест",
        "Stopped": "Остановлен",
        "Running (Pageant)": "Запущен (Pageant)",
        "Keys for agent:": "Ключи для агента:",
        "No keys for agent.": "Нет ключей для агента.",
        "Export SSH key": "Экспорт SSH",
        "Copy to clipboard?": "Скопировать в буфер обмена?",
        "Save to file?": "Сохранить в файл?",
        "Factory Reset": "Сброс устройства",
        "All keys and certificates will be deleted.": "ВСЕ ключи и сертификаты будут удалены.",
        "Continue?": "Продолжить?",
        "New PIN:": "Новый PIN:",
        "Confirm PIN:": "Подтверждение PIN:",
        "SO PIN = User PIN (default)": "SO PIN = PIN (по умолчанию)",
        "New SO PIN:": "Новый SO PIN:",
        "Confirm SO PIN:": "Подтверждение SO PIN:",
        "Reset": "Сбросить",
        "PIN cannot be empty": "PIN не может быть пустым",
        "PINs do not match": "PIN и подтверждение не совпадают",
        "PIN length must be 4-16 characters": "Длина PIN от 4 до 16 символов",
        "SO PIN cannot be empty": "SO PIN не может быть пустым",
        "SO PINs do not match": "SO PIN и подтверждение не совпадают",
        "SO PIN length must be 4-16 characters": "Длина SO PIN от 4 до 16 символов",
        "Resetting device...": "Сброс устройства...",
        "Device reset. New PIN: ": "Устройство сброшено. Новый PIN: ",
        "Reset error: ": "Ошибка сброса: ",
        "Scanning keys...": "Сканирование ключей...",
        "Keys found: ": "Найдено ключей: ",
        "No key selected.": "Выберите ключ из списка.",
        "Public key unavailable (AES or read error).": "Публичный ключ недоступен (AES или ошибка чтения).",
        "SSH not supported for this key type.": "SSH не поддерживается для этого типа ключа.",
        "SSH Agent": "SSH-агент",
        "PIN:": "PIN:",
        "ID": "ID",
        "Type": "Тип",
        "Label": "Метка",
        "Error": "Ошибка",
        "Enter PIN": "Введите PIN",
        "Connecting...": "Подключение...",
        "Connection cancelled": "Подключение отменено",
        "Connected (PIN: ": "Подключено (PIN: ",
        "Connection to Pico-HSM established.": "Подключение к Pico-HSM установлено.",
        "Error: ": "Ошибка: ",
        "Connection error: ": "Ошибка подключения: ",
        "Selected key ID ": "Выбран ключ ID ",
        "ID: ": "ID: ",
        "Type: ": "Тип: ",
        "Key ID: ": "Ключ ID: ",
        "Key: ": "Ключ: ",
        "PEM:": "PEM:",
        "PEM unavailable: ": "PEM недоступен: ",
        "SSH (authorized_keys):": "SSH (authorized_keys):",
        "Public key unavailable.": "Публичный ключ недоступен.",
        "SSH format not supported for this key type.": "SSH формат не поддерживается для этого типа ключа.",
        "SSH key ID ": "SSH-ключ ID ",
        "Copied to clipboard.": "Скопировано в буфер обмена.",
        "Saved: ": "Сохранён: ",
        "Save error: ": "Ошибка сохранения: ",
        "EE certificate for ID ": "EE-сертификат для ID ",
        "not found.": "не найден.",
        "Error:": "Ошибка:",
        "bytes": "байт",
        "ID (CA slot number):": "ID (номер слота CA):",
        "Occupied IDs:": "Занятые ID:",
        "CVC certificate file:": "Файл CVC-сертификата:",
        "Select CVC certificate": "Выберите CVC-сертификат",
        "Browse...": "Обзор...",
        "ID must be a number": "ID должен быть числом",
        "Select a file": "Выберите файл",
        "Could not read file: ": "Не удалось прочитать файл: ",
        "Writing CA certificate ID ": "Запись CA-сертификата ID ",
        "Write": "Записать",
        "CA certificate ID ": "CA-сертификат ID ",
        "written.": "записан.",
        "CA certificate write error: ": "Ошибка записи CA-сертификата: ",
        "Could not write CA certificate: ": "Не удалось записать CA-сертификат: ",
        "Key label ID ": "Метка ключа ID ",
        "Setting label for ID ": "Установка метки для ID ",
        "Save": "Сохранить",
        "Label for ID ": "Метка для ID ",
        "Label set error: ": "Ошибка установки метки: ",
        "Could not set label: ": "Не удалось установить метку: ",
        "Select a key type.": "Выберите тип ключа.",
        "Key created! ID =": "Ключ создан! ID =",
        "Type =": "Тип =",
        "Generation error: ": "Ошибка генерации: ",
        "Delete key ID ": "Удалить ключ ID ",
        "Deleting key ID ": "Удаление ключа ID ",
        "Key ID ": "Ключ ID ",
        "deleted.": "удалён.",
        "Delete error: ": "Ошибка удаления: ",
        "Copy": "Копировать",
        "Copy all": "Копировать всё",
        "Starting SSH agent...": "Запуск SSH-агента...",
        "Stopping agent...": "Остановка агента...",
        "Agent stopped.": "Агент остановлен.",
        "Running test (background thread)...": "Запуск теста (фоновый поток)...",
        "Agent started. Running as Pageant (WM_COPYDATA) + named pipe (OpenSSH).": "Агент запущен. Работает как Pageant (WM_COPYDATA) + named pipe (OpenSSH).",
        "Open for PuTTY/Kitty/NetBox/WinSCP via Pageant/OpenSSH agent.": "Открыт для PuTTY/Kitty/NetBox/WinSCP через Pageant/OpenSSH-агент.",
        "Close real Pageant: taskkill /f /im pageant.exe": "Закройте настоящий Pageant: taskkill /f /im pageant.exe",
        "Agent log: ": "Лог агента: ",
        "Agent log": "Лог агента",
        "Change PIN": "Сменить PIN",
        "Old PIN:": "Старый PIN:",
        "Changing PIN...": "Смена PIN...",
        "PIN changed successfully.": "PIN успешно изменён.",
        "User PIN changed.": "User PIN изменён.",
        "SO PIN changed.": "SO PIN изменён.",
        "SO PIN change error: ": "Ошибка смены SO PIN: ",
        "Also change SO PIN": "Также сменить SO PIN",
        "Enter SO PIN": "Введите SO PIN",
        "PIN change error: ": "Ошибка смены PIN: ",
        "Change": "Сменить",
        "Device info": "Информация",
        "Loading device info...": "Загрузка информации...",
        "Firmware version:": "Версия прошивки:",
        "Memory:": "Память:",
        "bytes free": "байт свободно",
        "free": "свободно",
        "used": "использовано",
        "total": "всего",
        "Files:": "Файлы:",
        "PIN retries:": "Осталось попыток PIN:",
        "Press-to-confirm": "Подтверждение кнопкой",
        "Press-to-confirm enabled.": "Подтверждение кнопкой включено.",
        "Press-to-confirm disabled.": "Подтверждение кнопкой выключено.",
        "Refresh": "Обновить",
        "Close": "Закрыть",
        "Language": "Язык",
        "Keys": "Ключи",
        "Device": "Устройство",
        "Disconnect": "Отключиться",
        "Clear log": "Очистить лог",
        "Device mode:": "Режим:",
        "Pico HSM": "Pico HSM",
        "Pico FIDO2": "Pico FIDO2",
        "FIDO2 device": "FIDO2-устройство",
        "No FIDO2 device": "Нет FIDO2-устройства",
        "Detect FIDO2": "Найти FIDO2",
        "FIDO2 Keys": "FIDO2-ключи",
        "Register credential": "Зарегистрировать",
        "Verify": "Проверить",
        "Resident Keys": "Встроенные ключи",
        "List resident keys": "Список ключей",
        "RP ID": "RP ID",
        "Username": "Пользователь",
        "Key Type": "Тип ключа",
        "Credential registered": "Ключ зарегистрирован",
        "Registration error": "Ошибка регистрации",
        "Verification OK": "Проверка пройдена",
        "Verification error": "Ошибка проверки",
        "Enumerating resident keys": "Сканирование ключей",
        "Resident keys found": "Найдено ключей",
        "Cred mgmt error": "Ошибка управления",
        "PIN required": "Требуется PIN",
        "FIDO2 PIN changed": "PIN FIDO2 изменён",
        "FIDO2 PIN error": "Ошибка PIN FIDO2",
        "Enter FIDO2 PIN": "Введите PIN FIDO2",
        "Export SSH": "Экспорт SSH",
        "Fingerprint": "Отпечаток",
        "Delete credential for ": "Удалить учётную запись для ",
        "Delete error": "Ошибка удаления",
        "Create FIDO2 credential": "Создать учётную запись FIDO2",
        "RP ID:": "RP ID:",
        "RP Name:": "Имя RP:",
        "User Name:": "Имя пользователя:",
        "Display Name:": "Отображаемое имя:",
        "Algorithm:": "Алгоритм:",
        "Require touch": "Требовать касание",
        "Purpose": "Назначение",
        "Sign": "Подпись",
        "Encrypt": "Шифрование",
        "Export all SSH": "Экспорт всех SSH",
        "Saved:": "Сохранено: ",
        "Export authorized_keys": "Экспорт authorized_keys",
        "keys": "ключей",
        "All keys already in ": "Все ключи уже есть в ",
        "Minimize to tray": "Сворачивать в трей",
        "FIDO2 only": "Только FIDO2",
        "Show": "Показать",
        "Encrypt file": "Зашифровать файл",
        "Decrypt file": "Расшифровать файл",
        "RSA key required for encryption": "Для шифрования требуется RSA-ключ",
        "Key does not support ECDH. Use an RSA key or create an ECDH key.": "Ключ не поддерживает ECDH. Используйте RSA-ключ или создайте ECDH-ключ.",
        "RSA key does not have decrypt permission. Create a new RSA key with the fix.": "RSA-ключ не имеет права на расшифровку. Создайте новый RSA-ключ.",
        "This RSA key cannot decrypt. Encrypted file will NOT be recoverable. Continue?": "Этот RSA-ключ не умеет расшифровывать. Зашифрованный файл НЕВОЗМОЖНО будет восстановить. Продолжить?",
        "Select file to encrypt": "Выберите файл для шифрования",
        "Select file to decrypt": "Выберите файл для расшифровки",
        "Fill required fields": "Заполните обязательные поля",
        "Edit user info": "Редактировать пользователя",
        "Credential updated": "Учётная запись обновлена",
        "Update error": "Ошибка обновления",
        "User ID (hex):": "ID пользователя (hex):",
        "User ID must be hex": "ID пользователя должен быть hex",
        "Start FIDO2 Agent": "Запустить FIDO2-агент",
        "Stop FIDO2 Agent": "Остановить FIDO2-агент",
        "Auto-start on connect": "Автостарт при подключении",
        "Auto-start: no keys selected for agent": "Автостарт: не выбрано ключей для агента",
        "Light": "Светлая",
        "Dark": "Тёмная",
        "Theme": "Тема",
        "Disconnected from Pico HSM.": "Отключено от Pico HSM.",
        "Disconnected from Pico FIDO2.": "Отключено от Pico FIDO2.",
        "All credentials and PIN will be deleted.": "Все учётные записи и PIN будут удалены.",
        "FIDO2 device reset.": "FIDO2-устройство сброшено.",
        "About": "О программе",
        "Statistics": "Статистика",
        "Session uptime:": "Время сессии:",
        "Keys created:": "Ключей создано:",
        "Keys deleted:": "Ключей удалено:",
        "SSH signatures:": "SSH-подписей:",
        "File encryptions:": "Файлов зашифровано:",
        "File decryptions:": "Файлов расшифровано:",
        "HSM connections:": "HSM-подключений:",
        "FIDO2 connections:": "FIDO2-подключений:",
        "Help": "Помощь",
    },
    "he": {
        "SSH / Sign (NIST EC)": "SSH / חתימה (NIST EC)",
        "SSH / Sign (Brainpool EC)": "SSH / חתימה (Brainpool EC)",
        "SSH / Sign (Montgomery)": "SSH / חתימה (Montgomery)",
        "Key Exchange (ECDH)": "החלפת מפתחות (ECDH)",
        "SSH / Sign (RSA)": "SSH / חתימה (RSA)",
        "AES (symmetric)": "AES (סימטרי)",
        "Connect": "התחבר",
        "Keys on device": "מפתחות בהתקן",
        "Actions": "פעולות",
        "Refresh list": "רענן רשימה",
        "Create key": "צור מפתח",
        "Show public key": "הצג מפתח ציבורי",
        "Export SSH": "ייצוא SSH",
        "Delete key": "מחק מפתח",
        "Delete selected": "מחק מפתחות נבחרים",
        "Delete all keys": "מחק את כל המפתחות",
        "Set label": "הגדר תווית",
        "Show EE cert": "הצג תעודת EE",
        "Write CA cert": "כתוב תעודת CA",
        "Factory reset": "איפוס להגדרות יצרן",
        "Output": "פלט",
        "EE certificate": "תעודת EE",
        "Disconnected": "מנותק",
        "Key type:": "סוג מפתח:",
        "Create": "צור",
        "Cancel": "ביטול",
        "Warning": "אזהרה",
        "Select a key type from the list.": "בחר סוג מפתח מהרשימה.",
        "Confirm": "אישור",
        "Generate": "צור",
        "No keys with public part (Ed25519/EC/RSA).": "אין מפתחות עם חלק ציבורי (Ed25519/EC/RSA).",
        "Control": "שליטה",
        "Start": "התחל",
        "Stop": "עצור",
        "Test": "בדיקה",
        "Stopped": "עצור",
        "Running (Pageant)": "פועל (Pageant)",
        "Keys for agent:": "מפתחות לסוכן:",
        "No keys for agent.": "אין מפתחות לסוכן.",
        "Export SSH key": "ייצוא מפתח SSH",
        "Copy to clipboard?": "להעתיק ללוח?",
        "Save to file?": "לשמור לקובץ?",
        "Factory Reset": "איפוס להגדרות יצרן",
        "All keys and certificates will be deleted.": "כל המפתחות והתעודות יימחקו.",
        "Continue?": "להמשיך?",
        "New PIN:": "PIN חדש:",
        "Confirm PIN:": "אישור PIN:",
        "SO PIN = User PIN (default)": "SO PIN = PIN משתמש (ברירת מחדל)",
        "New SO PIN:": "SO PIN חדש:",
        "Confirm SO PIN:": "אישור SO PIN:",
        "Reset": "איפוס",
        "PIN cannot be empty": "PIN לא יכול להיות ריק",
        "PINs do not match": "ה-PINים אינם תואמים",
        "PIN length must be 4-16 characters": "אורך PIN חייב להיות 4-16 תווים",
        "SO PIN cannot be empty": "SO PIN לא יכול להיות ריק",
        "SO PINs do not match": "ה-SO PINים אינם תואמים",
        "SO PIN length must be 4-16 characters": "אורך SO PIN חייב להיות 4-16 תווים",
        "Resetting device...": "מאפס התקן...",
        "Device reset. New PIN: ": "התקן אופס. PIN חדש: ",
        "Reset error: ": "שגיאת איפוס: ",
        "Scanning keys...": "סורק מפתחות...",
        "Keys found: ": "נמצאו מפתחות: ",
        "No key selected.": "לא נבחר מפתח.",
        "Public key unavailable (AES or read error).": "מפתח ציבורי לא זמין (AES או שגיאת קריאה).",
        "SSH not supported for this key type.": "SSH לא נתמך לסוג מפתח זה.",
        "SSH Agent": "סוכן SSH",
        "PIN:": "PIN:",
        "ID": "מזהה",
        "Type": "סוג",
        "Label": "תווית",
        "Error": "שגיאה",
        "Enter PIN": "הכנס PIN",
        "Connecting...": "מתחבר...",
        "Connection cancelled": "התחברות בוטלה",
        "Connected (PIN: ": "מחובר (PIN: ",
        "Connection to Pico-HSM established.": "התחברות ל-Pico-HSM הושלמה.",
        "Error: ": "שגיאה: ",
        "Connection error: ": "שגיאת התחברות: ",
        "Selected key ID ": "נבחר מפתח מזהה ",
        "ID: ": "מזהה: ",
        "Type: ": "סוג: ",
        "Key ID: ": "מזהה מפתח: ",
        "Key: ": "מפתח: ",
        "PEM:": "PEM:",
        "PEM unavailable: ": "PEM לא זמין: ",
        "SSH (authorized_keys):": "SSH (authorized_keys):",
        "Public key unavailable.": "מפתח ציבורי לא זמין.",
        "SSH format not supported for this key type.": "פורמט SSH לא נתמך לסוג מפתח זה.",
        "SSH key ID ": "מפתח SSH מזהה ",
        "Copied to clipboard.": "הועתק ללוח.",
        "Saved: ": "נשמר: ",
        "Save error: ": "שגיאת שמירה: ",
        "EE certificate for ID ": "תעודת EE עבור מזהה ",
        "not found.": "לא נמצא.",
        "Error:": "שגיאה:",
        "bytes": "בתים",
        "ID (CA slot number):": "מזהה (מספר משבצת CA):",
        "Occupied IDs:": "מזהים תפוסים:",
        "CVC certificate file:": "קובץ תעודת CVC:",
        "Select CVC certificate": "בחר תעודת CVC",
        "Browse...": "עיון...",
        "ID must be a number": "מזהה חייב להיות מספר",
        "Select a file": "בחר קובץ",
        "Could not read file: ": "לא ניתן לקרוא קובץ: ",
        "Writing CA certificate ID ": "כותב תעודת CA מזהה ",
        "Write": "כתוב",
        "CA certificate ID ": "תעודת CA מזהה ",
        "written.": "נכתב.",
        "CA certificate write error: ": "שגיאת כתיבת תעודת CA: ",
        "Could not write CA certificate: ": "לא ניתן לכתוב תעודת CA: ",
        "Key label ID ": "תווית מפתח מזהה ",
        "Setting label for ID ": "מגדיר תווית למזהה ",
        "Save": "שמור",
        "Label for ID ": "תווית עבור מזהה ",
        "Label set error: ": "שגיאת הגדרת תווית: ",
        "Could not set label: ": "לא ניתן להגדיר תווית: ",
        "Select a key type.": "בחר סוג מפתח.",
        "Key created! ID =": "מפתח נוצר! מזהה =",
        "Type =": "סוג =",
        "Generation error: ": "שגיאת יצירה: ",
        "Delete key ID ": "מחק מפתח מזהה ",
        "Deleting key ID ": "מוחק מפתח מזהה ",
        "Key ID ": "מפתח מזהה ",
        "deleted.": "נמחק.",
        "Delete error: ": "שגיאת מחיקה: ",
        "Copy": "העתק",
        "Copy all": "העתק הכל",
        "Starting SSH agent...": "מפעיל סוכן SSH...",
        "Stopping agent...": "עוצר סוכן...",
        "Agent stopped.": "סוכן נעצר.",
        "Running test (background thread)...": "מריץ בדיקה (רקע)...",
        "Agent started. Running as Pageant (WM_COPYDATA) + named pipe (OpenSSH).": "סוכן הופעל. רץ כ-Pageant (WM_COPYDATA) + pipe (OpenSSH).",
        "Open for PuTTY/Kitty/NetBox/WinSCP via Pageant/OpenSSH agent.": "פתוח עבור PuTTY/Kitty/NetBox/WinSCP דרך Pageant/סוכן OpenSSH.",
        "Close real Pageant: taskkill /f /im pageant.exe": "סגור Pageant אמיתי: taskkill /f /im pageant.exe",
        "Agent log: ": "יומן סוכן: ",
        "Agent log": "יומן סוכן",
        "Pageant window not found. Agent not running.": "חלון Pageant לא נמצא. הסוכן לא פועל.",
        "Pageant window found: HWND 0x": "חלון Pageant נמצא: HWND 0x",
        "No response - agent did not process request": "אין תגובה - הסוכן לא עיבד את הבקשה",
        "Response: length=": "תגובה: אורך=",
        "message_type=": "סוג_הודעה=",
        "Keys on device: ": "מפתחות בהתקן: ",
        "No keys with public part for SSH": "אין מפתחות עם חלק ציבורי ל-SSH",
        "Algorithm: ": "אלגוריתם: ",
        "signature: ": "חתימה: ",
        "Signature successful!": "חתימה הצליחה!",
        "Unexpected response type: ": "סוג תגובה לא צפוי: ",
        "No response to sign request": "אין תגובה לבקשת חתימה",
        "Test completed": "בדיקה הושלמה",
        "CreateFileMapping failed (err=": "CreateFileMapping נכשל (err=",
        "MapViewOfFile failed (err=": "MapViewOfFile נכשל (err=",
        "Unexpected type: ": "סוג לא צפוי: ",
        "Label:": "תווית:",
        "No keys for SSH agent.": "אין מפתחות לסוכן SSH.",
        "Requesting key list...": "מבקש רשימת מפתחות...",
        "Signature test...": "בדיקת חתימה...",
        "Select a key from the list.": "בחר מפתח מהרשימה.",
        "Confirm signing": "אשר חתימה",
        "Allow these keys for SSH authentication?": "לאשר מפתחות אלו לאימות SSH?",
        "Agent keys not confirmed.": "מפתחות הסוכן לא אושרו.",
        "Change PIN": "החלף PIN",
        "Old PIN:": "PIN ישן:",
        "Changing PIN...": "מחליף PIN...",
        "PIN changed successfully.": "PIN הוחלף בהצלחה.",
        "User PIN changed.": "PIN משתמש הוחלף.",
        "SO PIN changed.": "SO PIN הוחלף.",
        "SO PIN change error: ": "שגיאת החלפת SO PIN: ",
        "Also change SO PIN": "החלף גם SO PIN",
        "Enter SO PIN": "הכנס SO PIN",
        "PIN change error: ": "שגיאת החלפת PIN: ",
        "Change": "החלף",
        "Device info": "מידע התקן",
        "Loading device info...": "טוען מידע...",
        "Firmware version:": "גרסת קושחה:",
        "Memory:": "זיכרון:",
        "bytes free": "בתים פנויים",
        "free": "פנוי",
        "used": "בשימוש",
        "total": "סה״כ",
        "Files:": "קבצים:",
        "PIN retries:": "ניסיונות PIN:",
        "Press-to-confirm": "אישור בלחיצה",
        "Press-to-confirm enabled.": "אישור בלחיצה הופעל.",
        "Press-to-confirm disabled.": "אישור בלחיצה כובה.",
        "Refresh": "רענן",
        "Close": "סגור",
        "Language": "שפה",
        "Keys": "מפתחות",
        "Device": "התקן",
        "Disconnect": "נתק",
        "Clear log": "נקה יומן",
        "Device mode:": "מצב:",
        "Pico HSM": "Pico HSM",
        "Pico FIDO2": "Pico FIDO2",
        "FIDO2 device": "התקן FIDO2",
        "No FIDO2 device": "אין התקן FIDO2",
        "Detect FIDO2": "זיהוי FIDO2",
        "FIDO2 Keys": "מפתחות FIDO2",
        "Register credential": "רישום מזהה",
        "Verify": "אימות",
        "Resident Keys": "מפתחות מובנים",
        "List resident keys": "רשימת מפתחות",
        "RP ID": "RP ID",
        "Username": "שם משתמש",
        "Key Type": "סוג מפתח",
        "Credential registered": "המזהה נרשם",
        "Registration error": "שגיאת רישום",
        "Verification OK": "אימות הצליח",
        "Verification error": "שגיאת אימות",
        "Enumerating resident keys": "סורק מפתחות",
        "Resident keys found": "נמצאו מפתחות",
        "Cred mgmt error": "שגיאת ניהול",
        "PIN required": "נדרש PIN",
        "FIDO2 PIN changed": "PIN FIDO2 שונה",
        "FIDO2 PIN error": "שגיאת PIN FIDO2",
        "Enter FIDO2 PIN": "הכנס PIN FIDO2",
        "Export SSH": "ייצוא SSH",
        "Fingerprint": "טביעת אצבע",
        "Delete credential for ": "מחק חשבון עבור ",
        "Delete error": "שגיאת מחיקה",
        "Create FIDO2 credential": "צור חשבון FIDO2",
        "RP ID:": "RP ID:",
        "RP Name:": "שם RP:",
        "User Name:": "שם משתמש:",
        "Display Name:": "שם תצוגה:",
        "Algorithm:": "אלגוריתם:",
        "Fill required fields": "מלא שדות חובה",
        "Edit user info": "ערוך משתמש",
        "Credential updated": "החשבון עודכן",
        "Update error": "שגיאת עדכון",
        "User ID (hex):": "מזהה משתמש (hex):",
        "User ID must be hex": "מזהה משתמש חייב להיות hex",
        "Start FIDO2 Agent": "הפעל סוכן FIDO2",
        "Stop FIDO2 Agent": "עצור סוכן FIDO2",
        "Auto-start on connect": "הפעלה אוטומטית בהתחברות",
        "Auto-start: no keys selected for agent": "הפעלה אוטומטית: לא נבחרו מפתחות לסוכן",
        "Light": "בהיר",
        "Dark": "כהה",
        "Theme": "ערכת נושא",
        "Disconnected from Pico HSM.": "מנותק מ-Pico HSM.",
        "Disconnected from Pico FIDO2.": "מנותק מ-Pico FIDO2.",
        "All credentials and PIN will be deleted.": "כל האישורים וה-PIN יימחקו.",
        "FIDO2 device reset.": "התקן FIDO2 אופס.",
        "About": "אודות",
        "Help": "עזרה",
    }
}

def T(text):
    return _TR.get(_LANG, {}).get(text, text)

KEY_CATEGORIES = [
    ("SSH / Sign (NIST EC)", [
        ('EC secp256r1',       KeyType.ECC, 'secp256r1'),
        ('EC secp384r1',       KeyType.ECC, 'secp384r1'),
        ('EC secp521r1',       KeyType.ECC, 'secp521r1'),
        ('EC secp256k1',       KeyType.ECC, 'secp256k1'),
    ]),
    ("SSH / Sign (Brainpool EC)", [
        ('EC brainpoolP256r1', KeyType.ECC, 'brainpoolP256r1'),
        ('EC brainpoolP384r1', KeyType.ECC, 'brainpoolP384r1'),
        ('EC brainpoolP512r1', KeyType.ECC, 'brainpoolP512r1'),
    ]),
    ("SSH / Sign (Montgomery)", [
        ('Ed25519',            KeyType.ECC, 'ed25519'),
        ('Ed448',              KeyType.ECC, 'ed448'),
    ]),
    ("Key Exchange (ECDH)", [
        ('X25519',             KeyType.ECC, 'curve25519'),
        ('X448',               KeyType.ECC, 'curve448'),
    ]),
    ("SSH / Sign (RSA)", [
        ('RSA 2048',           KeyType.RSA, 2048),
        ('RSA 3072',           KeyType.RSA, 3072),
        ('RSA 4096',           KeyType.RSA, 4096),
    ]),
    ("AES (symmetric)", [
        ('AES-128',            KeyType.AES, 128),
        ('AES-192',            KeyType.AES, 192),
        ('AES-256',            KeyType.AES, 256),
    ]),
]

def _flat_key_types():
    result = []
    for cat_name, items in KEY_CATEGORIES:
        for item in items:
            result.append(item)
    return result

KEY_TYPES = _flat_key_types()

class PicoHSMGUI:
    def __init__(self, root, fido2_only=False):
        self.root = root
        self._fido2_only = fido2_only
        self._fido2_only_var = tk.BooleanVar(value=self._fido2_only)
        self.root.title("Pico FIDO2 Manager" if fido2_only else "Pico HSM Manager")
        self.root.minsize(640, 540)

        self.hsm = None
        self.pin = tk.StringVar(value="648219")
        self.keys = {}
        self._key_algos = {}
        self._load_key_algos()
        self.status_var = tk.StringVar(value=T("Disconnected"))
        self._device_mode = tk.StringVar(value="Pico FIDO2" if fido2_only else "Pico HSM")

        self.root.configure(bg="#2b2b2b")

        # FIDO2 state
        self._fido2_devices = []
        self._fido2_ctap2 = None
        self._fido2_info = None
        self._fido2_resident_keys = []
        self._fido2_pin_cache = None
        self._f2_dev_label = ""
        self._hsm_dev_name = ""
        self._f2_agent_creds = {}

        self._agent_auto_start_var = tk.BooleanVar(value=False)
        self._theme_var = tk.StringVar(value="light")
        self._auto_refresh_var = tk.BooleanVar(value=True)
        self._refresh_interval_var = tk.IntVar(value=300)
        self._refresh_timer = None
        self._pin_cache_timeout_var = tk.IntVar(value=5)
        self._pin_cache_ts = 0

        self._stats = self._load_stats()

        self._apply_style()
        self._build_ui()
        self._restore_geometry()
        if self._fido2_only:
            self._m_keys.entryconfig(1, state="disabled")
            self._switch_mode()
            self.root.after(200, self._auto_detect_mode)
            self.root.after(500, self._f2_connect)
        else:
            self.root.after(200, self._auto_detect_mode)

    def _apply_style(self):
        style = ttk.Style()
        available = style.theme_names()
        if "clam" in available:
            style.theme_use("clam")
        else:
            for pref in ("winnative", "vista", "xpnative"):
                if pref in available:
                    style.theme_use(pref)
                    break

        dark = self._theme_var.get() == "dark"

        if dark:
            bg = "#2b2b2b"
            fg = "#e0e0e0"
            sel_bg = "#094771"
            sel_fg = "#ffffff"
            heading_bg = "#333333"
            heading_fg = "#d0d0d0"
            active_bg = "#3c3c3c"
            field_bg = "#1e1e1e"
            btn_bg = "#383838"
            btn_active = "#4a4a4a"
            trough = "#1a1a1a"
            disabled_fg = "#666"
            success = "#4caf50"
            error = "#ef5350"
            muted = "#999"
        else:
            bg = "#f0f0f0"
            fg = "#1a1a1a"
            sel_bg = "#2b579a"
            sel_fg = "#ffffff"
            heading_bg = "#e8e8e8"
            heading_fg = "#1a1a1a"
            active_bg = "#d0d0d0"
            field_bg = "#ffffff"
            btn_bg = "#e0e0e0"
            btn_active = "#d0d0d0"
            trough = "#d0d0d0"
            disabled_fg = "#a0a0a0"
            success = "#1a8c1a"
            error = "#c00"
            muted = "#888"

        root_bg = bg

        style.configure(".",
                        background=root_bg,
                        foreground=fg,
                        fieldbackground=field_bg,
                        troughcolor=trough,
                        selectbackground=sel_bg,
                        selectforeground=sel_fg)

        style.configure("Treeview",
                        background=field_bg,
                        foreground=fg,
                        rowheight=26,
                        fieldbackground=field_bg,
                        borderwidth=0)
        style.map("Treeview",
                  background=[("selected", sel_bg)],
                  foreground=[("selected", sel_fg)])
        style.configure("Treeview.Heading",
                        background=heading_bg,
                        foreground=heading_fg,
                        relief="flat",
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview.Heading",
                  background=[("active", active_bg)])

        style.configure("TNotebook", background=root_bg, borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=heading_bg,
                        foreground=fg,
                        padding=[12, 3],
                        font=("Segoe UI", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", root_bg), ("active", active_bg)])

        style.configure("TButton",
                        background=btn_bg,
                        foreground=fg,
                        padding=[10, 4],
                        font=("Segoe UI", 9))
        style.map("TButton",
                  background=[("active", btn_active), ("pressed", sel_bg)],
                  foreground=[("disabled", disabled_fg)])

        style.configure("TLabel", background=root_bg, foreground=fg, font=("Segoe UI", 9))
        style.configure("TLabelframe", background=root_bg, foreground=fg)
        style.configure("TLabelframe.Label", background=root_bg, foreground=fg, font=("Segoe UI", 9, "bold"))

        style.configure("TEntry",
                        fieldbackground=field_bg,
                        foreground=fg,
                        background=root_bg,
                        padding=[4, 2])
        style.map("TEntry",
                  fieldbackground=[("focus", active_bg)])

        style.configure("TSpinbox",
                        fieldbackground=field_bg,
                        foreground=fg,
                        background=root_bg)

        style.configure("TCombobox",
                        fieldbackground=field_bg,
                        foreground=fg,
                        background=root_bg,
                        arrowcolor=fg)
        style.map("TCombobox",
                  fieldbackground=[("readonly", field_bg)],
                  background=[("readonly", btn_bg)])

        style.configure("TCheckbutton", background=root_bg, foreground=fg)
        style.map("TCheckbutton",
                  background=[("active", root_bg)])

        style.configure("TRadiobutton", background=root_bg, foreground=fg)

        style.configure("Header.TLabel", background=root_bg, foreground=sel_bg, font=("Segoe UI", 10, "bold"))

        style.configure("Success.TLabel", background=root_bg, foreground=success)
        style.configure("Error.TLabel", background=root_bg, foreground=error)
        style.configure("Muted.TLabel", background=root_bg, foreground=muted)

        style.configure("TFrame", background=root_bg)
        style.configure("TLabelframe", background=root_bg, foreground=fg)
        style.configure("TPanedWindow", background=root_bg)
        style.configure("Sash", background=root_bg, sashthickness=4)
        style.configure("TScrollbar",
                        background=btn_bg,
                        troughcolor=trough,
                        arrowcolor=fg)
        style.map("TScrollbar",
                  background=[("active", btn_active)])

        style.configure("Horizontal.TProgressbar", background=sel_bg, troughcolor=field_bg)
        style.configure("Vertical.TProgressbar", background=sel_bg, troughcolor=field_bg)

        style.configure("TScale", background=root_bg, troughcolor=field_bg)

        self.root.configure(bg=root_bg)
        self._apply_scrolled_theme()

    def _apply_scrolled_theme(self):
        if not hasattr(self, 'output') or not self.output:
            return
        dark = self._theme_var.get() == "dark"
        sc_bg = "#1e1e1e" if dark else "#ffffff"
        sc_fg = "#e0e0e0" if dark else "#1a1a1a"
        ins = sc_fg
        self.output.configure(bg=sc_bg, fg=sc_fg, insertbackground=ins)
        self.cert_text.configure(bg=sc_bg, fg=sc_fg, insertbackground=ins)
        if hasattr(self, '_agent_log') and self._agent_log:
            self._agent_log.configure(bg=sc_bg, fg=sc_fg, insertbackground=ins)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        self._menubar = menubar
        m_dev = tk.Menu(menubar, tearoff=0)
        m_dev.add_command(label=T("Device info"), command=self.device_info)
        m_dev.add_command(label=T("Change PIN"), command=self.change_pin_only)
        m_dev.add_separator()
        m_dev.add_command(label=T("Factory reset"), command=self.change_pin)
        m_dev.add_separator()
        m_dev.add_command(label=T("Exit"), command=self.root.quit)
        menubar.add_cascade(label=T("Device"), menu=m_dev)
        m_keys = tk.Menu(menubar, tearoff=0)
        m_keys.add_command(label=T("Delete selected"), command=self.delete_selected_keys)
        m_keys.add_command(label=T("Write CA cert"), command=self.write_ca_cert)
        m_keys.add_separator()
        m_keys.add_command(label=T("Delete all keys"), command=self._hsm_delete_all)
        menubar.add_cascade(label=T("Keys"), menu=m_keys)
        self._m_keys = m_keys
        self._m_dev = m_dev
        self._tray_var = tk.BooleanVar(value=False)
        m_settings = tk.Menu(menubar, tearoff=0)
        m_lang = tk.Menu(m_settings, tearoff=0)
        self._lang_var = tk.StringVar(value=_LANG)
        for code, name in [("en", "English"), ("ru", "Русский"), ("he", "עברית")]:
            m_lang.add_radiobutton(label=name, variable=self._lang_var, value=code,
                                   command=lambda: self._update_lang())
        m_settings.add_cascade(label=T("Language"), menu=m_lang)
        m_theme = tk.Menu(m_settings, tearoff=0)
        m_theme.add_radiobutton(label=T("Light"), variable=self._theme_var, value="light",
                                command=self._apply_theme)
        m_theme.add_radiobutton(label=T("Dark"), variable=self._theme_var, value="dark",
                                command=self._apply_theme)
        m_settings.add_cascade(label=T("Theme"), menu=m_theme)
        m_settings.add_checkbutton(label=T("Minimize to tray"), variable=self._tray_var,
                                   command=self._on_tray_toggle)
        m_settings.add_checkbutton(label=T("FIDO2 only"), variable=self._fido2_only_var,
                                   command=self._on_fido2_only_toggle)
        menubar.add_cascade(label="Settings", menu=m_settings)
        m_help = tk.Menu(menubar, tearoff=0)
        m_help.add_command(label=T("Statistics"), command=self._stats_dialog)
        m_help.add_command(label=T("About"), command=self._about_dialog)
        menubar.add_cascade(label=T("Help"), menu=m_help)
        self._menu_cmds = [(m_keys, 0), (m_keys, 1), (m_keys, 3), (m_dev, 0), (m_dev, 1), (m_dev, 3)]
        self._toggle_menu("disabled")

        top = ttk.Frame(self.root, padding=4)
        top.pack(fill=tk.X)

        ttk.Label(top, text=T("Device mode:")).pack(side=tk.LEFT, padx=(0,2))
        modes = ["Pico FIDO2"] if self._fido2_only else ["Pico HSM", "Pico FIDO2"]
        self._mode_combo = ttk.Combobox(top, textvariable=self._device_mode,
                                         values=modes, state="readonly", width=12)
        self._mode_combo.pack(side=tk.LEFT, padx=(0,6))
        self._mode_combo.bind("<<ComboboxSelected>>", self._switch_mode)

        self.connect_btn = ttk.Button(top, text=T("Connect"), command=self.connect)
        self.connect_btn.pack(side=tk.LEFT, padx=2)
        self.disconnect_btn = ttk.Button(top, text=T("Disconnect"), command=self.disconnect, state=["disabled"])
        self.disconnect_btn.pack(side=tk.LEFT, padx=1)
        self.clear_btn = ttk.Button(top, text=T("Clear log"), command=self.log_clear)
        self.clear_btn.pack(side=tk.LEFT, padx=1)
        ttk.Label(top, text="Auto:").pack(side=tk.LEFT, padx=(8,0))
        self._auto_refresh_cb = ttk.Checkbutton(top, variable=self._auto_refresh_var, command=self._on_auto_refresh_toggle)
        self._auto_refresh_cb.pack(side=tk.LEFT, padx=(0,0))
        self._refresh_spin = ttk.Spinbox(top, from_=10, to=300, increment=10,
            textvariable=self._refresh_interval_var, width=4, state="readonly")
        self._refresh_spin.pack(side=tk.LEFT, padx=(0,0))
        ttk.Label(top, text="s").pack(side=tk.LEFT, padx=(0,6))
        ttk.Label(top, text="PIN:").pack(side=tk.LEFT, padx=(4,0))
        self._pin_cache_spin = ttk.Spinbox(top, from_=1, to=60, increment=1,
            textvariable=self._pin_cache_timeout_var, width=3, state="readonly")
        self._pin_cache_spin.pack(side=tk.LEFT, padx=(0,0))
        ttk.Label(top, text="m").pack(side=tk.LEFT, padx=(0,6))
        ttk.Label(top, text="Filter:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(4,0))
        self._log_filter_var = tk.StringVar(value="All")
        self._log_filter_cb = ttk.Combobox(top, textvariable=self._log_filter_var,
            values=["All", "Errors only"], state="readonly", width=10)
        self._log_filter_cb.pack(side=tk.LEFT, padx=(2,0))
        self._log_filter_cb.bind("<<ComboboxSelected>>", self._log_apply_filter)

        # ── Main content area ──────────────────────────────────────────────
        self._content = ttk.Frame(self.root)
        self._content.pack(fill=tk.BOTH, expand=True)

        # ── Status bar ─────────────────────────────────────────────────────
        statusbar = ttk.Frame(self.root, padding=(4, 1))
        statusbar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_lbl = ttk.Label(statusbar, textvariable=self.status_var, style="Muted.TLabel")
        self.status_lbl.pack(side=tk.LEFT, padx=4)
        self.device_lbl = ttk.Label(statusbar, text="", style="Muted.TLabel")
        self.device_lbl.pack(side=tk.LEFT, padx=(8,0))
        self._retries_var = tk.StringVar(value="")
        self._retries_lbl = ttk.Label(statusbar, textvariable=self._retries_var, style="Muted.TLabel")
        self._retries_lbl.pack(side=tk.LEFT, padx=(8,0))

        # ═══ HSM panel ═══
        self._hsm_pane = ttk.PanedWindow(self._content, orient=tk.HORIZONTAL)
        hsm_left = ttk.Frame(self._hsm_pane)
        self._hsm_pane.add(hsm_left, weight=1)

        self._lbl_keys_title = ttk.Label(hsm_left, text=T("Keys on device"), style="Header.TLabel")
        self._lbl_keys_title.pack(anchor=tk.W)
        lf = ttk.Frame(hsm_left)
        lf.pack(fill=tk.BOTH, expand=True)
        self.keys_tree = ttk.Treeview(lf, columns=("type", "label"), show="tree headings", height=10, selectmode="extended")
        self.keys_tree.heading("#0", text=T("ID"))
        self.keys_tree.heading("type", text=T("Type"))
        self.keys_tree.column("#0", width=40, minwidth=30, stretch=False)
        self.keys_tree.column("type", width=120, minwidth=60, stretch=True)
        self.keys_tree.heading("label", text=T("Label"))
        self.keys_tree.column("label", width=80, minwidth=40, stretch=True)
        vsb = ttk.Scrollbar(lf, orient=tk.VERTICAL, command=self.keys_tree.yview)
        self.keys_tree.configure(yscrollcommand=vsb.set)
        self.keys_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.keys_tree.bind("<<TreeviewSelect>>", self._on_key_select)

        hsm_mid = ttk.Frame(self._hsm_pane)
        self._hsm_pane.add(hsm_mid, weight=0)

        self._lbl_actions_title = ttk.Label(hsm_mid, text=T("Actions"), style="Header.TLabel")
        self._lbl_actions_title.pack(pady=(0,4))
        self.btn_refresh = ttk.Button(hsm_mid, text=T("Refresh list"), command=self.refresh_keys, width=18)
        self.btn_refresh.pack(pady=1)
        self.btn_gen = ttk.Button(hsm_mid, text=T("Create key"), command=self.show_generate, width=18)
        self.btn_gen.pack(pady=1)
        self.btn_view = ttk.Button(hsm_mid, text=T("Show public key"), command=self.view_pubkey, width=18)
        self.btn_view.pack(pady=1)
        self.btn_ssh = ttk.Button(hsm_mid, text=T("Export SSH"), command=self.export_ssh, width=18)
        self.btn_ssh.pack(pady=1)
        self.btn_label = ttk.Button(hsm_mid, text=T("Set label"), command=self.set_label, width=18)
        self.btn_label.pack(pady=1)
        self.btn_cert = ttk.Button(hsm_mid, text=T("Show EE cert"), command=self.view_cert, width=18)
        self.btn_cert.pack(pady=1)
        self.btn_encrypt = ttk.Button(hsm_mid, text=T("Encrypt file"), command=self._encrypt_file, width=18)
        self.btn_encrypt.pack(pady=1)
        self.btn_decrypt = ttk.Button(hsm_mid, text=T("Decrypt file"), command=self._decrypt_file, width=18)
        self.btn_decrypt.pack(pady=1)
        self.btn_export_all_hsm = ttk.Button(hsm_mid, text=T("Export all SSH"), command=self._hsm_export_all_ssh, width=18)
        self.btn_export_all_hsm.pack(pady=1)
        for b in (self.btn_gen, self.btn_view, self.btn_ssh, self.btn_label, self.btn_cert, self.btn_encrypt, self.btn_decrypt, self.btn_refresh, self.btn_export_all_hsm):
            b.state(["disabled"])

        self._hsm_pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # ═══ FIDO2 panel (hidden by default) ═══
        self._fido2_pane = ttk.PanedWindow(self._content, orient=tk.HORIZONTAL)
        f2_left = ttk.Frame(self._fido2_pane)
        self._fido2_pane.add(f2_left, weight=2)

        self._f2_lbl = ttk.Label(f2_left, text=T("FIDO2 Keys"), style="Header.TLabel")
        self._f2_lbl.pack(anchor=tk.W)

        self._f2_tree = ttk.Treeview(f2_left, columns=("rp", "key_type", "username", "fingerprint", "cred_id"), show="tree headings", height=10, selectmode="extended")
        self._f2_tree.heading("#0", text="Name")
        self._f2_tree.heading("rp", text=T("RP ID"))
        self._f2_tree.heading("key_type", text=T("Key Type"))
        self._f2_tree.column("#0", width=100, minwidth=60, stretch=True)
        self._f2_tree.column("rp", width=120, minwidth=60, stretch=True)
        self._f2_tree.column("key_type", width=80, minwidth=50, stretch=False)
        self._f2_tree.heading("username", text=T("Username"))
        self._f2_tree.column("username", width=80, minwidth=40, stretch=True)
        self._f2_tree.heading("fingerprint", text=T("Fingerprint"))
        self._f2_tree.column("fingerprint", width=100, minwidth=60, stretch=False)
        self._f2_tree.heading("cred_id", text="Credential ID")
        self._f2_tree.column("cred_id", width=160, minwidth=80, stretch=True)
        vsb2 = ttk.Scrollbar(f2_left, orient=tk.VERTICAL, command=self._f2_tree.yview)
        self._f2_tree.configure(yscrollcommand=vsb2.set)
        self._f2_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb2.pack(side=tk.RIGHT, fill=tk.Y)
        self._f2_tree.bind("<<TreeviewSelect>>", self._on_f2_tree_select)

        f2_right = ttk.Frame(self._fido2_pane)
        self._fido2_pane.add(f2_right, weight=1)

        self._f2_lbl_actions = ttk.Label(f2_right, text=T("Actions"), style="Header.TLabel")
        self._f2_lbl_actions.pack(pady=(0,4))

        self._f2_list_btn = ttk.Button(f2_right, text=T("List resident keys"), command=self._f2_list_resident, width=20, state=["disabled"])
        self._f2_list_btn.pack(pady=1, fill=tk.X)

        self._f2_register_btn = ttk.Button(f2_right, text=T("Register credential"), command=self._f2_register, width=20, state=["disabled"])
        self._f2_register_btn.pack(pady=1, fill=tk.X)

        self._f2_verify_btn = ttk.Button(f2_right, text=T("Verify"), command=self._f2_verify, width=20, state=["disabled"])
        self._f2_verify_btn.pack(pady=1, fill=tk.X)

        self._f2_edit_btn = ttk.Button(f2_right, text=T("Edit"), command=self._f2_edit, width=20, state=["disabled"])
        self._f2_edit_btn.pack(pady=1, fill=tk.X)

        self._f2_ssh_btn = ttk.Button(f2_right, text=T("Export SSH"), command=self._f2_export_ssh, width=20, state=["disabled"])
        self._f2_ssh_btn.pack(pady=1, fill=tk.X)

        self._f2_export_all_btn = ttk.Button(f2_right, text=T("Export all SSH"), command=self._f2_export_all_ssh, width=20, state=["disabled"])
        self._f2_export_all_btn.pack(pady=1, fill=tk.X)

        # Bottom: notebook
        bottom = ttk.Frame(self.root)
        bottom.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0,6))

        self.nb = ttk.Notebook(bottom)
        self.nb.pack(fill=tk.BOTH, expand=True)

        self.output = scrolledtext.ScrolledText(self.nb, font=("Consolas", 10), wrap=tk.WORD, height=6)
        self._add_copy_menu(self.output)
        self.nb.add(self.output, text=T("Output"))
        self._log_lines = []

        self.cert_text = scrolledtext.ScrolledText(self.nb, font=("Consolas", 10), wrap=tk.WORD, height=6)
        self._add_copy_menu(self.cert_text)
        self.nb.add(self.cert_text, text=T("EE certificate"))

        self._build_agent_tab(self.nb)
        self._apply_scrolled_theme()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.bind('<Control-c>', self._on_ctrl_c)
        self.root.bind('<Control-C>', self._on_ctrl_c)
        self.root.bind('<Control-l>', self._on_ctrl_l)
        self.root.bind('<Control-L>', self._on_ctrl_l)
        self.root.bind('<F5>', lambda e: self.refresh_keys() if self.hsm else self._f2_list_resident() if self._fido2_ctap2 else None)

    def _save_geometry(self):
        try:
            geo = self.root.geometry()
            data = {
                "geometry": geo, "theme": self._theme_var.get(), "lang": _LANG,
                "auto_refresh": self._auto_refresh_var.get(),
                "refresh_interval": self._refresh_interval_var.get(),
                "pin_cache_timeout": self._pin_cache_timeout_var.get(),
                "minimize_to_tray": self._tray_var.get(),
                "fido2_only": self._fido2_only_var.get(),
            }
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def _restore_geometry(self):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "geometry" in data:
                self.root.geometry(data["geometry"])
            else:
                self.root.geometry("960x720")
            if "theme" in data:
                self._theme_var.set(data["theme"])
            if "auto_refresh" in data:
                self._auto_refresh_var.set(data["auto_refresh"])
            if "refresh_interval" in data:
                self._refresh_interval_var.set(data["refresh_interval"])
            if "pin_cache_timeout" in data:
                self._pin_cache_timeout_var.set(data["pin_cache_timeout"])
            if "minimize_to_tray" in data:
                self._tray_var.set(data["minimize_to_tray"])
        except Exception:
            self.root.geometry("960x720")

    def _auto_detect_mode(self):
        self._poll_device()

    def _poll_device(self):
        try:
            if self._fido2_only:
                if HAS_FIDO2 and ctypes.windll.shell32.IsUserAnAdmin() and not self._fido2_ctap2:
                    devs = list(CtapHidDevice.list_devices())
                    if devs:
                        self._f2_detect()
                if not self._fido2_ctap2:
                    self.root.after(3000, self._poll_device)
                return
            if HAS_FIDO2 and ctypes.windll.shell32.IsUserAnAdmin():
                devs = list(CtapHidDevice.list_devices())
                f2_found = len(devs) > 0
                cur_mode = self._device_mode.get()
                if f2_found and cur_mode != 'Pico FIDO2':
                    self._device_mode.set('Pico FIDO2')
                    self._switch_mode()
                    self._f2_detect()
                elif not f2_found and cur_mode == 'Pico FIDO2' and not self._fido2_ctap2:
                    self._device_mode.set('Pico HSM')
                    self._switch_mode()
        except Exception:
            pass
        if not self.hsm and not self._fido2_ctap2:
            self.root.after(3000, self._poll_device)

    def _start_periodic_refresh(self):
        self._stop_periodic_refresh()
        interval = self._refresh_interval_var.get() * 1000
        self._refresh_timer = self.root.after(interval, self._periodic_refresh)

    def _stop_periodic_refresh(self):
        if self._refresh_timer:
            self.root.after_cancel(self._refresh_timer)
            self._refresh_timer = None

    def _on_auto_refresh_toggle(self):
        if self._auto_refresh_var.get():
            self._start_periodic_refresh()
        else:
            self._stop_periodic_refresh()

    def _periodic_refresh(self):
        if not self._auto_refresh_var.get() or (not self.hsm and not self._fido2_ctap2):
            self._refresh_timer = None
            return
        try:
            mode = self._device_mode.get()
            if mode == 'Pico HSM' and self.hsm:
                self._update_retries()
                self.refresh_keys()
            elif mode == 'Pico FIDO2' and self._fido2_ctap2:
                self._update_retries()
                self._f2_list_resident()
        except Exception:
            pass
        interval = self._refresh_interval_var.get() * 1000
        self._refresh_timer = self.root.after(interval, self._periodic_refresh)

    def _switch_mode(self, event=None):
        mode = self._device_mode.get()
        if mode == 'Pico HSM':
            self._fido2_pane.pack_forget()
            self._hsm_pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
            self.nb.tab(1, state="normal")
            if self.hsm:
                self._m_keys.entryconfig(1, state="normal")
                self.refresh_keys()
            self.connect_btn.config(text=T("Connect"), command=self.connect)
            self.disconnect_btn.config(text=T("Disconnect"), command=self.disconnect)
            if self.hsm:
                self.disconnect_btn.state(["!disabled"])
                self.connect_btn.state(["disabled"])
            else:
                self.connect_btn.state(["!disabled"])
                self.disconnect_btn.state(["disabled"])
        else:
            self._hsm_pane.pack_forget()
            self._fido2_pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
            self.nb.tab(1, state="hidden")
            self.connect_btn.config(text=T("Connect"), command=self._f2_connect)
            self.disconnect_btn.config(text=T("Disconnect"), command=self._f2_disconnect)
            if self._fido2_ctap2:
                self.connect_btn.state(["disabled"])
                self.disconnect_btn.state(["!disabled"])
                self._f2_list_btn.state(['!disabled'])
                self._f2_register_btn.state(['!disabled'])
                self._f2_export_all_btn.state(['!disabled'])
                self._toggle_menu("normal")
                self._m_keys.entryconfig(1, state="disabled")
                self._m_keys.entryconfig(3, state="disabled")
                self._f2_list_resident()
            else:
                self.connect_btn.state(["!disabled"])
                self.disconnect_btn.state(["disabled"])
            self._m_keys.entryconfig(1, state="disabled")
            self._m_keys.entryconfig(3, state="disabled")
            self.root.after(100, self._f2_detect)

    def f2log(self, msg):
        self.log(f'[FIDO2] {msg}')

    def _f2_get_pin(self):
        if self._fido2_pin_cache:
            timeout_m = self._pin_cache_timeout_var.get()
            if timeout_m > 0 and time.time() - self._pin_cache_ts > timeout_m * 60:
                self._fido2_pin_cache = None
            else:
                return self._fido2_pin_cache
        d = tk.Toplevel(self.root)
        d.title(T('Enter PIN'))
        d.geometry("300x120")
        d.transient(self.root)
        d.attributes('-topmost', True)
        d.lift()
        self.root.deiconify()
        self.root.lift()
        self.root.update_idletasks()
        d.attributes('-topmost', False)
        self._center_dialog(d)
        f = ttk.Frame(d, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=T('PIN:')).pack(anchor=tk.W)
        e = ttk.Entry(f, show='*', width=30)
        e.pack(fill=tk.X, pady=(0,8))
        e.focus_set()
        e.bind('<Return>', lambda event: do_ok())
        d.bind('<Escape>', lambda event: d.destroy())
        result = [None]
        def do_ok():
            pin = e.get().strip()
            if not pin:
                return
            result[0] = pin
            d.destroy()
        bf = ttk.Frame(f)
        bf.pack(fill=tk.X)
        ttk.Button(bf, text=T("Connect"), command=do_ok).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text=T("Cancel"), command=d.destroy).pack(side=tk.RIGHT, padx=4)
        self.root.wait_window(d)
        pin = result[0]
        if pin:
            self._fido2_pin_cache = pin
            self._pin_cache_ts = time.time()
        return pin

    def _f2_detect(self):
        if not HAS_FIDO2:
            return
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return
        try:
            devs = list(CtapHidDevice.list_devices())
            if not devs:
                return
            dev = devs[0]
            self._fido2_devices = devs
            self._fido2_ctap2 = Ctap2(dev)
            self._fido2_info = self._fido2_ctap2.get_info()
            self.status_var.set(T('FIDO2 device'))
            if not self._fido2_pin_cache:
                self.disconnect_btn.state(['disabled'])
                self.connect_btn.state(['!disabled'])
        except Exception:
            pass

    def _f2_connect(self):
        if not HAS_FIDO2:
            messagebox.showerror(T('Error'), 'fido2 library not installed')
            return
        if not ctypes.windll.shell32.IsUserAnAdmin():
            self.f2log('FIDO2 HID access requires administrator privileges.')
            self.f2log('Please restart hsm_guir.py as Administrator.')
            self.status_var.set(T('Disconnected'))
            self.disconnect_btn.state(['disabled'])
            self.connect_btn.state(['!disabled'])
            return
        self.f2log(T('Connecting...'))
        self._fido2_devices = []
        self._fido2_ctap2 = None
        self._fido2_info = None
        self._fido2_resident_keys = []
        self._fido2_pin_cache = None
        for b in (self._f2_list_btn, self._f2_register_btn, self._f2_verify_btn, self._f2_edit_btn, self._f2_ssh_btn, self._f2_export_all_btn):
            b.state(['disabled'])
        self._f2_tree.delete(*self._f2_tree.get_children())
        try:
            devs = list(CtapHidDevice.list_devices())
            if not devs:
                self.f2log(T('No FIDO2 device'))
                self.status_var.set(T('Disconnected'))
                self.disconnect_btn.state(['disabled'])
                self.connect_btn.state(['!disabled'])
                return
            if len(devs) > 1:
                self.f2log(f'{len(devs)} FIDO2 devices found, selecting...')
                names = [f'{d.product_name} ({d.descriptor.path})' for d in devs]
                sel = self._combo_choice(T("Select FIDO2 device"), names)
                if sel is None:
                    self.f2log(T('Connection cancelled'))
                    self.disconnect_btn.state(['disabled'])
                    self.connect_btn.state(['!disabled'])
                    return
                dev = devs[sel]
            else:
                dev = devs[0]
            ctap2 = Ctap2(dev)
            info = ctap2.get_info()
            self._fido2_devices = devs
            self._fido2_ctap2 = ctap2
            self._fido2_info = info
            dev_label = f'{dev.product_name}'
            self.f2log(f'FIDO2: {dev_label} {" ".join(info.versions)}')
            if info.options:
                self.f2log(f'  Options: {info.options}')
            if info.pin_uv_protocols:
                self.f2log(f'  PIN/UV protocols: {list(info.pin_uv_protocols)}')
            if info.extensions:
                self.f2log(f'  Extensions: {info.extensions}')
            if info.aaguid:
                self.f2log(f'  AAGUID: {info.aaguid.hex()}')
            self._update_retries()
            pin = self._f2_get_pin()
            if not pin:
                self.f2log(T('Connection cancelled'))
                self._f2_disconnect()
                return
            self._f2_dev_label = dev_label
            self.status_var.set(T("Connected (PIN: ") + pin + ")" + f" [{dev_label}]")
            self._inc_stat('fido2_connects')
            self._save_stats()
            self.disconnect_btn.state(['!disabled'])
            self.connect_btn.state(['disabled'])
            self._f2_list_btn.state(['!disabled'])
            self._f2_register_btn.state(['!disabled'])
            self._f2_export_all_btn.state(['!disabled'])
            self._toggle_menu("normal")
            self._m_keys.entryconfig(1, state="disabled")
            self._f2_list_resident()
            self._start_periodic_refresh()
            self.root.after(500, self._agent_try_auto_start)
        except Exception as e:
            self.f2log(f'Connection error: {e}')
            self.disconnect_btn.state(['disabled'])
            self.connect_btn.state(['!disabled'])

    def _f2_disconnect(self):
        self._stop_periodic_refresh()
        self.f2log(T("Disconnected from Pico FIDO2."))
        self._fido2_devices = []
        self._fido2_ctap2 = None
        self._fido2_info = None
        self._fido2_resident_keys = []
        self._f2_dev_label = ""
        self._f2_agent_creds = {}
        self._f2_tree.delete(*self._f2_tree.get_children())
        self._agent_keys()
        for b in (self._f2_list_btn, self._f2_register_btn, self._f2_verify_btn, self._f2_edit_btn, self._f2_ssh_btn, self._f2_export_all_btn):
            b.state(['disabled'])
        self.disconnect_btn.state(['disabled'])
        self.connect_btn.state(['!disabled'])
        if not self.hsm:
            self._toggle_menu("disabled")
        self._retries_var.set("")
        self.status_var.set(T('Disconnected'))

    def _f2_list_resident(self):
        ctap2 = self._fido2_ctap2
        if not ctap2:
            return
        pin = self._f2_get_pin()
        if not pin:
            return
        self.f2log(T('Enumerating resident keys...'))
        self._f2_tree.delete(*self._f2_tree.get_children())
        try:
            client_pin = ClientPin(ctap2)
            token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
            cred_mgr = CredentialManagement(ctap2, client_pin.protocol, token)
            _RP_K = 0x03; _RP_H_K = 0x04; _U_K = 0x06; _C_K = 0x07; _P_K = 0x08
            rp_keys = {}
            for rp in cred_mgr.enumerate_rps():
                rp_id = rp[_RP_K]['id']
                creds = cred_mgr.enumerate_creds(rp[_RP_H_K])
                rp_keys[rp_id] = creds
            self._fido2_resident_keys = rp_keys
            count = 0
            self._f2_agent_creds = {}
            cred_index = 0
            for rp_id, creds in rp_keys.items():
                for cred in creds:
                    user_info = cred.get(_U_K, {})
                    name = user_info.get('name', '') or user_info.get('displayName', '') or ''
                    uname = user_info.get('name', '') or ''
                    cose_key = cred.get(_P_K, {})
                    kt = 'ES256'
                    fp = ''
                    if cose_key:
                        raw_pk = cose_key.get(-2, b'')
                        import hashlib
                        fp = hashlib.sha256(raw_pk).hexdigest()[:16]
                        ktid = cose_key.get(1)
                        curve = cose_key.get(-1)
                        if ktid == 1 and curve == 6:
                            kt = 'Ed25519'
                        elif ktid == 2 and curve == 1:
                            kt = 'ES256'
                    cred_id_obj = cred.get(0x07)
                    cred_id_hex = ''
                    if cred_id_obj:
                        if hasattr(cred_id_obj, 'id'):
                            cred_id_hex = bytes(cred_id_obj.id).hex()[:32]
                        elif isinstance(cred_id_obj, dict):
                            cid = cred_id_obj.get('id', b'')
                            cred_id_hex = bytes(cid).hex()[:32]
                    self._f2_tree.insert('', tk.END, text=name, values=(rp_id, kt, uname, fp, cred_id_hex))
                    # populate agent creds (sk-* format for OpenSSH)
                    if cose_key:
                        ktid = cose_key.get(1)
                        curve = cose_key.get(-1)
                        raw = cose_key.get(-2, b'')
                        if ktid == 2 and curve == 1:
                            algo = 'sk-ecdsa-sha2-nistp256@openssh.com'
                            raw = cose_key.get(-2, b'') + cose_key.get(-3, b'')
                            ssh_blob = _ssh_str(algo) + _ssh_str('nistp256') + _ssh_str(raw) + _ssh_str(rp_id)
                        else:
                            algo = 'sk-ed25519@openssh.com'
                            raw = cose_key.get(-2, b'')
                            ssh_blob = _ssh_str(algo) + _ssh_str(raw) + _ssh_str(rp_id)
                        cid = f'f2:{cred_index}'
                        self._f2_agent_creds[cid] = {
                            'rp_id': rp_id,
                            'user_name': uname or name,
                            'cose_key': cose_key,
                            'ssh_blob': ssh_blob,
                            'algo': algo,
                            'cred': cred,
                            'cred_id': cred.get(0x07, None),
                        }
                        cred_index += 1
                    count += 1
            self.f2log(f"{T('Resident keys found')}: {count}")
            self.status_var.set(f"{T('Resident keys found')}: {count}")
            self._agent_keys()
        except Exception as e:
            self.f2log(f"{T('Cred mgmt error')}: {e}")
            self._fido2_pin_cache = None

    def _f2_register(self):
        ctap2 = self._fido2_ctap2
        if not ctap2:
            return
        d = tk.Toplevel(self.root)
        d.title(T("Create FIDO2 credential"))
        d.transient(self.root)
        d.grab_set()
        self._center_dialog(d)
        f = ttk.Frame(d, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        row = 0
        ttk.Label(f, text=T("RP ID:")).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        rp_id_e = ttk.Entry(f, width=30)
        rp_id_e.insert(0, 'example.com')
        rp_id_e.grid(row=row, column=1, padx=4, pady=2); row += 1
        ttk.Label(f, text=T("RP Name:")).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        rp_name_e = ttk.Entry(f, width=30)
        rp_name_e.insert(0, 'Example')
        rp_name_e.grid(row=row, column=1, padx=4, pady=2); row += 1
        ttk.Label(f, text=T("User Name:")).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        user_name_e = ttk.Entry(f, width=30)
        user_name_e.insert(0, 'user')
        user_name_e.grid(row=row, column=1, padx=4, pady=2); row += 1
        ttk.Label(f, text=T("Display Name:")).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        user_disp_e = ttk.Entry(f, width=30)
        user_disp_e.insert(0, 'User 1')
        user_disp_e.grid(row=row, column=1, padx=4, pady=2); row += 1
        ttk.Label(f, text=T("User ID (hex):")).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        user_id_e = ttk.Entry(f, width=30)
        user_id_e.insert(0, '75736572')
        user_id_e.grid(row=row, column=1, padx=4, pady=2); row += 1
        ttk.Label(f, text=T("Algorithm:")).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        algo_var = tk.StringVar(value='ES256 (-7)')
        algo_cb = ttk.Combobox(f, textvariable=algo_var, values=['ES256 (-7)', 'EdDSA (-8)', 'RS256 (-257)'], state='readonly', width=18)
        algo_cb.grid(row=row, column=1, sticky=tk.W, padx=4, pady=2); row += 1
        hmac_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="HMAC-Secret", variable=hmac_var).grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=4, pady=2); row += 1
        touch_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text=T("Require touch"), variable=touch_var).grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=4, pady=2); row += 1
        err = ttk.Label(f, text="", foreground="red")
        err.grid(row=row, column=0, columnspan=2, pady=4); row += 1
        bf = ttk.Frame(f)
        bf.grid(row=row, column=0, columnspan=2, pady=(8,0))
        def do_register():
            rp_id = rp_id_e.get().strip()
            rp_name = rp_name_e.get().strip()
            user_name = user_name_e.get().strip()
            user_disp = user_disp_e.get().strip()
            user_id_hex = user_id_e.get().strip()
            if not rp_id or not user_name or not user_id_hex:
                err.config(text=T("Fill required fields"))
                return
            try:
                user_id = bytes.fromhex(user_id_hex)
            except ValueError:
                err.config(text=T("User ID must be hex"))
                return
            alg = algo_var.get()
            alg_map = {'ES256 (-7)': -7, 'EdDSA (-8)': -8, 'RS256 (-257)': -257}
            alg_val = alg_map.get(alg, -7)
            d.destroy()
            pin = self._f2_get_pin()
            if not pin:
                return
            self.f2log(T('Register credential...'))
            try:
                import json, hashlib
                client_pin = ClientPin(ctap2)
                token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL)
                protocol = client_pin.protocol
                challenge = os.urandom(32)
                client_data = json.dumps({
                    'type': 'webauthn.create',
                    'challenge': base64.b64encode(challenge).decode(),
                    'origin': 'https://example.com',
                }).encode()
                cd_hash = hashlib.sha256(client_data).digest()
                rp = {'id': rp_id, 'name': rp_name}
                user = {'id': user_id, 'name': user_name, 'displayName': user_disp}
                key_params = [{'type': 'public-key', 'alg': alg_val}]
                pin_auth = protocol.authenticate(token, cd_hash)
                extensions = {}
                if hmac_var.get():
                    extensions['hmac-secret'] = True
                ctap2.make_credential(
                    cd_hash, rp, user, key_params,
                    options={'rk': True, 'up': touch_var.get()},
                    extensions=extensions,
                    pin_uv_param=pin_auth,
                    pin_uv_protocol=protocol.VERSION,
                )
                self.f2log(T('Credential registered'))
                self._f2_list_resident()
            except Exception as e:
                self.f2log(f"{T('Registration error')}: {e}")
                self._fido2_pin_cache = None
        ttk.Button(bf, text=T("Create"), command=do_register, width=10).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text=T("Cancel"), command=d.destroy, width=10).pack(side=tk.LEFT, padx=4)

    def _f2_verify(self):
        ctap2 = self._fido2_ctap2
        if not ctap2:
            return
        sel = self._f2_tree.selection()
        if not sel:
            return
        self.f2log(T('Verifying...'))
        pin = self._f2_get_pin()
        if not pin:
            return
        try:
            import json, hashlib
            for item in sel:
                vals = self._f2_tree.item(item, 'values')
                rp_id = vals[0]
                uname = vals[2]
                if rp_id not in self._fido2_resident_keys:
                    continue
                for cred in self._fido2_resident_keys[rp_id]:
                    cred_user = cred.get(0x06, {}).get('name', '')
                    if uname and cred_user != uname:
                        continue
                    try:
                        client_pin = ClientPin(ctap2)
                        token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.GET_ASSERTION)
                        protocol = client_pin.protocol
                        challenge = os.urandom(32)
                        client_data = json.dumps({
                            'type': 'webauthn.get',
                            'challenge': base64.b64encode(challenge).decode(),
                            'origin': 'https://example.com',
                        }).encode()
                        cd_hash = hashlib.sha256(client_data).digest()
                        pin_auth = protocol.authenticate(token, cd_hash)
                        # Try with allow_list first
                        cred_id_obj = cred.get(0x07)
                        allow = None
                        if cred_id_obj:
                            if hasattr(cred_id_obj, 'id'):
                                allow = [{'id': bytes(cred_id_obj.id), 'type': 'public-key'}]
                            elif isinstance(cred_id_obj, dict):
                                cid = cred_id_obj.get('id', b'')
                                if cid:
                                    allow = [{'id': bytes(cid), 'type': 'public-key'}]
                        ok = False
                        if allow:
                            try:
                                ctap2.get_assertion(
                                    rp_id, cd_hash,
                                    allow_list=allow,
                                    options={'up': True},
                                    pin_uv_param=pin_auth,
                                    pin_uv_protocol=protocol.VERSION,
                                )
                                ok = True
                            except Exception:
                                pass
                        if not ok:
                            ctap2.get_assertion(
                                rp_id, cd_hash,
                                options={'up': True},
                                pin_uv_param=pin_auth,
                                pin_uv_protocol=protocol.VERSION,
                            )
                        self.f2log(T('Verification OK'))
                    except Exception as ex:
                        self.f2log(f"{T('Verification error')}: {ex}")
        except Exception as e:
            self.f2log(f"{T('Verification error')}: {e}")
            self._fido2_pin_cache = None

    def _f2_delete(self):
        ctap2 = self._fido2_ctap2
        if not ctap2:
            return
        sel = self._f2_tree.selection()
        if not sel:
            return
        item = sel[0]
        vals = self._f2_tree.item(item, 'values')
        rp_id = vals[0]
        if not self._confirm(T("Delete"), T("Delete credential for ") + rp_id + "?"):
            return
        pin = self._f2_get_pin()
        if not pin:
            return
        try:
            client_pin = ClientPin(ctap2)
            token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
            cred_mgr = CredentialManagement(ctap2, client_pin.protocol, token)
            for cred in self._fido2_resident_keys.get(rp_id, []):
                cred_id = cred.get(0x07)
                if cred_id:
                    cred_mgr.delete_cred(cred_id)
                    self.f2log(T('Deleted credential for ') + rp_id)
                    break
            self._f2_list_resident()
        except Exception as e:
            self.f2log(f"{T('Delete error')}: {e}")

    def _f2_edit(self):
        ctap2 = self._fido2_ctap2
        if not ctap2:
            return
        sel = self._f2_tree.selection()
        if not sel:
            return
        item = sel[0]
        vals = self._f2_tree.item(item, 'values')
        rp_id = vals[0]
        uname = vals[2]
        user_id = b''
        for cred in self._fido2_resident_keys.get(rp_id, []):
            user_info = cred.get(0x06, {})
            user_id = user_info.get('id', b'')
            uname = user_info.get('name', uname)
            break
        d = tk.Toplevel(self.root)
        d.title(T("Edit user info"))
        d.transient(self.root)
        d.grab_set()
        self._center_dialog(d)
        f = ttk.Frame(d, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        row = 0
        ttk.Label(f, text=T("User ID (hex):")).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        uid_e = ttk.Entry(f, width=30)
        uid_e.insert(0, user_id.hex() if user_id else '')
        uid_e.grid(row=row, column=1, padx=4, pady=2); row += 1
        ttk.Label(f, text=T("User Name:")).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        name_e = ttk.Entry(f, width=30)
        name_e.insert(0, uname)
        name_e.grid(row=row, column=1, padx=4, pady=2); row += 1
        ttk.Label(f, text=T("Display Name:")).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        disp_e = ttk.Entry(f, width=30)
        disp_e.insert(0, uname)
        disp_e.grid(row=row, column=1, padx=4, pady=2); row += 1
        err = ttk.Label(f, text="", foreground="red")
        err.grid(row=row, column=0, columnspan=2, pady=4); row += 1
        bf = ttk.Frame(f)
        bf.grid(row=row, column=0, columnspan=2, pady=(8,0))
        def do_update():
            new_uid_hex = uid_e.get().strip()
            new_name = name_e.get().strip()
            new_disp = disp_e.get().strip()
            if not new_uid_hex or not new_name:
                err.config(text=T("Fill required fields"))
                return
            try:
                new_uid = bytes.fromhex(new_uid_hex)
            except ValueError:
                err.config(text=T("User ID must be hex"))
                return
            d.destroy()
            pin = self._f2_get_pin()
            if not pin:
                return
            try:
                client_pin = ClientPin(ctap2)
                token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
                cred_mgr = CredentialManagement(ctap2, client_pin.protocol, token)
                for cred in self._fido2_resident_keys.get(rp_id, []):
                    cred_id = cred.get(0x07)
                    if cred_id:
                        user_info = {'id': new_uid, 'name': new_name, 'displayName': new_disp}
                        cred_mgr.update_user_info(cred_id, user_info)
                        self.f2log(T('Credential updated'))
                        break
                self._f2_list_resident()
            except Exception as e:
                self.f2log(f"{T('Update error')}: {e}")
                self._fido2_pin_cache = None
        ttk.Button(bf, text=T("Save"), command=do_update, width=10).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text=T("Cancel"), command=d.destroy, width=10).pack(side=tk.LEFT, padx=4)

    def _f2_export_ssh(self):
        sel = self._f2_tree.selection()
        if not sel:
            return
        lines = []
        for item in sel:
            vals = self._f2_tree.item(item, 'values')
            rp_id = vals[0]
            try:
                for cred in self._fido2_resident_keys.get(rp_id, []):
                    cose_key = cred.get(0x08, None)
                    if not cose_key:
                        continue
                    key_type_id = cose_key.get(1)
                    curve = cose_key.get(-1)
                    if key_type_id == 2 and curve == 1:
                        algo = 'sk-ecdsa-sha2-nistp256@openssh.com'
                        raw = cose_key.get(-2, b'') + cose_key.get(-3, b'')
                        blob = _ssh_str(algo) + _ssh_str('nistp256') + _ssh_str(raw) + _ssh_str(rp_id)
                    else:
                        algo = 'sk-ed25519@openssh.com'
                        raw = cose_key.get(-2, b'')
                        blob = _ssh_str(algo) + _ssh_str(raw) + _ssh_str(rp_id)
                    b64 = base64.b64encode(blob).decode()
                    ssh_line = f'{algo} {b64} FIDO2_{rp_id}'
                    lines.append(ssh_line)
                    break
            except Exception as e:
                self.f2log(f"{T('Error:')} {e}")
        if not lines:
            return
        text = "\n".join(lines)
        for line in lines:
            self.f2log(f'SSH: {line}')
        self.f2log('')
        r = self._confirm(T("Export SSH key"), text + "\n\n" + T("Copy to clipboard?"))
        if r:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.f2log(T("Copied to clipboard."))
        r2 = self._confirm(T("Export SSH key"), T("Save to file?"))
        if r2:
            fp = "fido2_keys.pub"
            try:
                with open(fp, "w", encoding="utf-8") as f:
                    f.write(text + "\n")
                self.f2log(T("Saved: ") + os.path.abspath(fp))
            except Exception as e:
                self.f2log(T("Save error: ") + str(e))

    def _f2_export_all_ssh(self):
        ssh_dir = os.path.expanduser("~/.ssh")
        try:
            os.makedirs(ssh_dir, exist_ok=True)
        except Exception as e:
            self.f2log(f"{T('Error:')} {ssh_dir}: {e}")
            return
        count = 0
        for rp_id, creds in self._fido2_resident_keys.items():
            for idx, cred in enumerate(creds):
                try:
                    cose_key = cred.get(0x08, None)
                    if not cose_key:
                        continue
                    key_type_id = cose_key.get(1)
                    curve = cose_key.get(-1)
                    if key_type_id == 2 and curve == 1:
                        algo = 'sk-ecdsa-sha2-nistp256@openssh.com'
                        raw = cose_key.get(-2, b'') + cose_key.get(-3, b'')
                        blob = _ssh_str(algo) + _ssh_str('nistp256') + _ssh_str(raw) + _ssh_str(rp_id)
                    else:
                        algo = 'sk-ed25519@openssh.com'
                        raw = cose_key.get(-2, b'')
                        blob = _ssh_str(algo) + _ssh_str(raw) + _ssh_str(rp_id)
                    b64 = base64.b64encode(blob).decode()
                    ssh_line = f'{algo} {b64} FIDO2_{rp_id}'
                    fname = f"id_f2_{rp_id}_{idx}.pub"
                    fpath = os.path.join(ssh_dir, fname)
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(ssh_line + "\n")
                    self.f2log(f"{T('Saved:')} {fpath}")
                    count += 1
                except Exception as e:
                    self.f2log(f"{T('Error:')} {e}")
        self.f2log(f"{T('total')} {count} {T('Files:')} {ssh_dir}")

    def _f2_change_pin(self):
        ctap2 = self._fido2_ctap2
        if not ctap2:
            return
        d = tk.Toplevel(self.root)
        d.title(T('Change PIN'))
        d.transient(self.root)
        d.grab_set()
        self._center_dialog(d)
        f = ttk.Frame(d, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=T('Old PIN:')).grid(row=0, column=0, sticky=tk.W, pady=2)
        old_e = ttk.Entry(f, show='*', width=30)
        old_e.grid(row=0, column=1, pady=2)
        ttk.Label(f, text=T('New PIN:')).grid(row=1, column=0, sticky=tk.W, pady=2)
        new_e = ttk.Entry(f, show='*', width=30)
        new_e.grid(row=1, column=1, pady=2)
        result = [None]
        def do_change():
            old = old_e.get().strip()
            new = new_e.get().strip()
            if not old or not new:
                return
            d.destroy()
            self.f2log(T('Changing PIN...'))
            try:
                client_pin = ClientPin(ctap2)
                client_pin.change_pin(old, new)
                self._fido2_pin_cache = new
                self.f2log(T('FIDO2 PIN changed'))
            except Exception as e:
                self.f2log(f"{T('FIDO2 PIN error')}: {e}")
        bf = ttk.Frame(f)
        bf.grid(row=2, column=0, columnspan=2, pady=(8,0))
        ttk.Button(bf, text=T('Change'), command=do_change, width=10).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text=T('Cancel'), command=d.destroy, width=10).pack(side=tk.LEFT, padx=4)

    def _f2_factory_reset(self):
        if not self._confirm(T("Factory Reset"),
            T("All credentials and PIN will be deleted.") + "\n\n"
            + T("Continue?")):
            return
        self.f2log(T("Resetting FIDO2 device..."))
        def _do():
            try:
                self._fido2_ctap2.reset()
                self.root.after(0, self._f2_disconnect)
                self.root.after(0, lambda: self.f2log(T("FIDO2 device reset.")))
            except Exception as e:
                self.root.after(0, lambda m=str(e): self.f2log(f"{T('Error:')} {m}"))
        threading.Thread(target=_do, daemon=True).start()

    def _f2_device_info(self):
        info = self._fido2_info
        if not info:
            self.f2log(T('No device connected'))
            return
        d = tk.Toplevel(self.root)
        d.title(T("Device info"))
        d.geometry("400x300")
        d.transient(self.root)
        self._center_dialog(d)
        d.grab_set()
        f = ttk.Frame(d, padding=14)
        f.pack(fill=tk.BOTH, expand=True)
        lines = []
        lines.append(f"{T('Versions:')} {' '.join(info.versions)}")
        lines.append(f"{T('Max message size:')} {info.max_msg_size}")
        if info.aaguid:
            lines.append(f"{T('AAGUID:')} {info.aaguid.hex()}")
        if info.options:
            lines.append(f"{T('Options:')}")
            for k, v in sorted(info.options.items()):
                lines.append(f"  {k}: {v}")
        if info.pin_uv_protocols:
            lines.append(f"{T('PIN/UV protocols:')} {list(info.pin_uv_protocols)}")
        if info.extensions:
            lines.append(f"{T('Extensions:')} {info.extensions}")
        if info.transports:
            lines.append(f"{T('Transports:')} {info.transports}")
        lines.append(f"{T('Min PIN length:')} {info.min_pin_length}")
        lbl = tk.Label(f, text='\n'.join(lines), font=("Consolas", 10),
                       bg="white", relief=tk.SUNKEN, padx=8, pady=8, anchor=tk.NW, justify=tk.LEFT)
        lbl.pack(fill=tk.BOTH, expand=True)
        ttk.Separator(f, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)
        ctrl = ttk.Frame(f)
        ctrl.pack(fill=tk.X)
        ttk.Button(ctrl, text=T("Close"), command=d.destroy).pack(side=tk.RIGHT)

    def _center_dialog(self, d):
        d.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - d.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - d.winfo_height()) // 2
        d.geometry(f"+{x}+{y}")

    def _combo_choice(self, title, options):
        d = tk.Toplevel(self.root)
        d.title(title)
        d.geometry("500x200")
        d.transient(self.root)
        d.grab_set()
        d.attributes('-topmost', True); d.lift()
        self.root.deiconify(); self.root.lift(); self.root.update_idletasks()
        d.attributes('-topmost', False)
        result = [None]
        def on_ok():
            sel = lb.curselection()
            if sel:
                result[0] = sel[0]
            d.destroy()
        def on_cancel():
            d.destroy()
        f = ttk.Frame(d, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=title).pack(anchor=tk.W)
        lb = tk.Listbox(f, height=6, selectmode=tk.SINGLE)
        for o in options:
            lb.insert(tk.END, o)
        lb.bind('<Double-Button-1>', lambda e: on_ok())
        lb.bind('<Return>', lambda e: on_ok())
        lb.pack(fill=tk.BOTH, expand=True, pady=8)
        lb.focus_set()
        bf = ttk.Frame(f)
        bf.pack(fill=tk.X)
        ttk.Button(bf, text=T("OK"), command=on_ok).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text=T("Cancel"), command=on_cancel).pack(side=tk.RIGHT, padx=4)
        self.root.wait_window(d)
        sel = result[0]
        if sel:
            return sel[0]
        return None

    def _confirm(self, title, message, btn_yes="Yes", btn_no="No"):
        d = tk.Toplevel(self.root)
        d.title(title)
        d.transient(self.root)
        d.grab_set()
        d.resizable(False, False)
        d.attributes('-topmost', True)
        d.lift()
        self.root.deiconify()
        self.root.lift()
        self.root.update_idletasks()
        d.attributes('-topmost', False)
        f = ttk.Frame(d, padding=16)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=message, wraplength=360).pack(fill=tk.X, pady=(0,16))
        bf = ttk.Frame(f)
        bf.pack()
        result = [False]
        def yes():
            result[0] = True
            d.destroy()
        def no():
            d.destroy()
        def on_key(event):
            if event.keysym == 'Return':
                yes()
            elif event.keysym == 'Escape':
                no()
        btn_y = ttk.Button(bf, text=btn_yes, command=yes, width=8)
        btn_y.pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text=btn_no, command=no, width=8).pack(side=tk.LEFT, padx=4)
        d.bind('<Return>', on_key)
        d.bind('<Escape>', on_key)
        btn_y.focus_set()
        self._center_dialog(d)
        self.root.wait_window(d)
        return result[0]

    def _info(self, title, message):
        d = tk.Toplevel(self.root)
        d.title(title)
        d.transient(self.root)
        d.grab_set()
        d.resizable(False, False)
        f = ttk.Frame(d, padding=16)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=message, wraplength=360).pack(fill=tk.X, pady=(0,12))
        bf = ttk.Frame(f)
        bf.pack()
        ttk.Button(bf, text="OK", command=d.destroy, width=8).pack()
        self._center_dialog(d)
        self.root.wait_window(d)

    def _add_copy_menu(self, widget):
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label=T("Copy"), command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label=T("Copy all"), command=lambda: (widget.tag_add(tk.SEL, "1.0", tk.END), widget.event_generate("<<Copy>>"), widget.tag_remove(tk.SEL, "1.0", tk.END)))

        def show_menu(event):
            menu.tk_popup(event.x_root, event.y_root)

        widget.bind("<Button-3>", show_menu)
        widget.bind("<Control-Key-c>", lambda e: widget.event_generate("<<Copy>>"))

    def _about_dialog(self):
        d = tk.Toplevel(self.root)
        d.title(T("About"))
        d.geometry("360x200")
        d.transient(self.root)
        d.resizable(False, False)
        d.attributes('-topmost', True)
        d.lift()
        self.root.deiconify()
        self.root.lift()
        self.root.update_idletasks()
        d.attributes('-topmost', False)
        self._center_dialog(d)
        f = ttk.Frame(d, padding=16)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="Pico HSM + FIDO2 Manager", font=("Segoe UI", 12, "bold")).pack(pady=(0,4))
        ttk.Label(f, text="v1.0 — Windows GUI").pack()
        ttk.Label(f, text="").pack()
        link = "https://github.com/13Agent/PicoHSM-Fido2-GUI"
        link_lbl = ttk.Label(f, text=link, foreground="#2b579a", cursor="hand2")
        link_lbl.pack()
        link_lbl.bind("<Button-1>", lambda e: webbrowser.open(link))
        ttk.Label(f, text="").pack(pady=(8,0))
        ttk.Label(f, text="Pico HSM + FIDO2 + SSH Agent").pack()
        ttk.Button(f, text=T("Close"), command=d.destroy).pack(pady=(8,0))

    def _load_stats(self):
        try:
            with open(STATS_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {'start_time': time.time(), 'keys_created': 0, 'keys_deleted': 0,
                    'ssh_signs': 0, 'file_encrypts': 0, 'file_decrypts': 0,
                    'hsm_connects': 0, 'fido2_connects': 0}

    def _save_stats(self):
        try:
            with open(STATS_PATH, 'w', encoding='utf-8') as f:
                json.dump(self._stats, f, ensure_ascii=False)
        except:
            pass

    def _inc_stat(self, name, count=1):
        self._stats.setdefault(name, 0)
        self._stats[name] += count

    def _stats_dialog(self):
        s = self._stats
        elapsed = time.time() - s.get('start_time', time.time())
        def fmt(t):
            h = int(t // 3600); m = int((t % 3600) // 60); s2 = int(t % 60)
            return f"{h}h {m:02d}m {s2:02d}s"
        lines = [
            f"{T('Session uptime:')} {fmt(elapsed)}",
            f"{T('Keys created:')} {s.get('keys_created', 0)}",
            f"{T('Keys deleted:')} {s.get('keys_deleted', 0)}",
            f"{T('SSH signatures:')} {s.get('ssh_signs', 0)}",
            f"{T('File encryptions:')} {s.get('file_encrypts', 0)}",
            f"{T('File decryptions:')} {s.get('file_decrypts', 0)}",
            f"{T('HSM connections:')} {s.get('hsm_connects', 0)}",
            f"{T('FIDO2 connections:')} {s.get('fido2_connects', 0)}",
        ]
        d = tk.Toplevel(self.root)
        d.title(T("Statistics"))
        d.geometry("300x260")
        d.transient(self.root)
        d.resizable(False, False)
        d.attributes('-topmost', True); d.lift(); self.root.deiconify(); self.root.lift()
        self.root.update_idletasks(); d.attributes('-topmost', False)
        self._center_dialog(d)
        f = ttk.Frame(d, padding=14)
        f.pack(fill=tk.BOTH, expand=True)
        for line in lines:
            ttk.Label(f, text=line, font=("Consolas", 10)).pack(anchor=tk.W, pady=1)
        ttk.Button(f, text=T("Close"), command=d.destroy).pack(pady=(8,0))

    def log(self, msg):
        if not hasattr(self, '_log_lines'):
            return
        self._log_lines.append(msg)
        if self._log_filter_var.get() == "Errors only" and "Error" not in msg and "error" not in msg and "Ошибк" not in msg:
            return
        self.output.insert(tk.END, msg + "\n")
        self.output.see(tk.END)
        self.root.update_idletasks()

    def log_clear(self):
        if hasattr(self, '_log_lines'):
            self._log_lines.clear()
        self.output.delete("1.0", tk.END)

    def _log_apply_filter(self, event=None):
        self.output.delete("1.0", tk.END)
        if not hasattr(self, '_log_lines'):
            return
        for line in self._log_lines:
            if self._log_filter_var.get() == "Errors only" and "Error" not in line and "error" not in line and "Ошибк" not in line:
                continue
            self.output.insert(tk.END, line + "\n")
        self.output.see(tk.END)

    def _update_retries(self):
        try:
            mode = self._device_mode.get()
            if mode == 'Pico HSM' and self.hsm:
                r = self.hsm.get_login_retries()
                self._retries_var.set(f"Retries: {r}")
            elif mode == 'Pico FIDO2' and self._fido2_info:
                r = getattr(self._fido2_info, 'pin_retries', None)
                if r is not None:
                    self._retries_var.set(f"Retries: {r}")
                else:
                    self._retries_var.set("")
            else:
                self._retries_var.set("")
        except Exception:
            self._retries_var.set("")

    def _on_ctrl_c(self, event=None):
        w = event.widget if event else None
        if hasattr(w, 'selection_get'):
            try:
                sel = w.selection_get()
                if sel:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(sel)
            except tk.TclError:
                pass
        return "break"

    def _on_ctrl_l(self, event=None):
        w = event.widget if event else None
        if w in (self.output, self.cert_text):
            self.log_clear()
        elif w == self._agent_log:
            self._agent_log.delete("1.0", tk.END)
        else:
            self.log_clear()
        return "break"

    def _apply_theme(self):
        self._apply_style()

    def _update_lang(self):
        global _LANG
        _LANG = self._lang_var.get()
        try:
            self.nb.tab(0, text=T("Output"))
            self.nb.tab(1, text=T("EE certificate"))
            self.nb.tab(2, text=T("SSH Agent"))
            self._f2_lbl.config(text=T("FIDO2 Keys"))
            self._f2_tree.heading("#0", text="Name")
            self._f2_tree.heading("rp", text=T("RP ID"))
            self._f2_tree.heading("key_type", text=T("Key Type"))
            self._f2_tree.heading("username", text=T("Username"))
            self._f2_tree.heading("fingerprint", text=T("Fingerprint"))
            self._f2_lbl_actions.config(text=T("Actions"))
            self._f2_list_btn.config(text=T("List resident keys"))
            self._f2_register_btn.config(text=T("Register credential"))
            self._f2_verify_btn.config(text=T("Verify"))
            self._f2_edit_btn.config(text=T("Edit"))
            self._f2_ssh_btn.config(text=T("Export SSH"))
            self._f2_export_all_btn.config(text=T("Export all SSH"))
            if self.hsm and self.hsm.is_logged():
                s = T("Connected (PIN: ") + self._pin + ")"
                if self._hsm_dev_name:
                    s += f" [{self._hsm_dev_name}]"
                self.status_var.set(s)
            elif self._fido2_ctap2 and self._fido2_pin_cache:
                s = T("Connected (PIN: ") + self._fido2_pin_cache + ")"
                if self._f2_dev_label:
                    s += f" [{self._f2_dev_label}]"
                self.status_var.set(s)
            else:
                self.status_var.set(T("Disconnected"))
            self.connect_btn.config(text=T("Connect"))
            self.disconnect_btn.config(text=T("Disconnect"))
            self.clear_btn.config(text=T("Clear log"))
            self._lbl_keys_title.config(text=T("Keys on device"))
            self.keys_tree.heading("#0", text=T("ID"))
            self.keys_tree.heading("type", text=T("Type"))
            self.keys_tree.heading("label", text=T("Label"))
            self._lbl_actions_title.config(text=T("Actions"))
            self.btn_refresh.config(text=T("Refresh list"))
            self.btn_gen.config(text=T("Create key"))
            self.btn_view.config(text=T("Show public key"))
            self.btn_ssh.config(text=T("Export SSH"))
            self.btn_label.config(text=T("Set label"))
            self.btn_cert.config(text=T("Show EE cert"))
            self.btn_encrypt.config(text=T("Encrypt file"))
            self.btn_decrypt.config(text=T("Decrypt file"))
            self._btn_agent_start.config(text=T("Start"))
            self._btn_agent_stop.config(text=T("Stop"))
            self._btn_agent_test.config(text=T("Test"))
            self._btn_agent_export.config(text=T("Export authorized_keys"))
            self._lbl_agent_title.config(text=T("Keys for agent:"))
            self._lbl_agent_log.config(text=T("Agent log"))
            self._agent_empty_lbl.config(text=T("No keys with public part (Ed25519/EC/RSA)."))
            self._agent_confirm_cb.config(text=T("Confirm signing"))
            self._agent_auto_start_cb.config(text=T("Auto-start on connect"))
            self._agent_tree.heading("#0", text=T("ID"))
            self._agent_tree.heading("type", text=T("Type"))
            self._agent_tree.heading("label", text=T("Label"))
            if not self._agent_running:
                self._agent_status.set(T("Stopped"))
            else:
                self._agent_status.set(T("Running (Pageant)"))
            self._m_keys.entryconfig(0, label=T("Delete selected"))
            self._m_keys.entryconfig(1, label=T("Write CA cert"))
            self._m_dev.entryconfig(0, label=T("Device info"))
            self._m_dev.entryconfig(1, label=T("Change PIN"))
            self._m_dev.entryconfig(3, label=T("Factory reset"))
            self._menubar.entryconfig(0, label=T("Keys"))
            self._menubar.entryconfig(1, label=T("Device"))
            self._menubar.entryconfig(2, label=T("Language"))
            self._menubar.entryconfig(3, label=T("Theme"))
            self._menubar.entryconfig(4, label=T("Help"))
        except Exception as e:
            alog(f"_update_lang error: {e}")

    def _on_close(self):
        self._save_geometry()
        if hasattr(self, '_tray_var') and self._tray_var.get():
            self._tray_create()
            self.root.withdraw()
            return
        if self._agent_running:
            self._agent_stop()
        self._tray_destroy()
        self.root.destroy()

    def _on_tray_toggle(self):
        if not hasattr(self, '_tray_var') or not self._tray_var.get():
            self._tray_destroy()

    def _on_fido2_only_toggle(self):
        self._save_geometry()
        script = os.path.abspath(__file__)
        flag = '--fido2-only' if self._fido2_only_var.get() else ''
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {flag}', os.path.dirname(script), 1
        )
        if result > 32:
            self.root.quit()

    def _on_restore_from_tray(self, event=None):
        if hasattr(self, '_tray_var') and self._tray_var.get():
            self._tray_destroy()
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()

    def _tray_create(self):
        if getattr(self, '_tray_thread', None) and self._tray_thread.is_alive():
            return
        import uuid
        self._tray_stop_event = threading.Event()
        cls_name = f"PicoTrayMsgWindow_{uuid.uuid4().hex[:8]}"
        WM_APP = 0x8000
        NIM_ADD = 0
        NIM_DELETE = 2
        NIF_MESSAGE = 1
        NIF_TIP = 4
        NIF_ICON = 2
        class NIDW(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.wintypes.DWORD),
                ("hWnd", ctypes.wintypes.HWND),
                ("uID", ctypes.wintypes.UINT),
                ("uFlags", ctypes.wintypes.UINT),
                ("uCallbackMessage", ctypes.wintypes.UINT),
                ("hIcon", ctypes.wintypes.HICON),
                ("szTip", ctypes.wintypes.WCHAR * 128),
                ("dwState", ctypes.wintypes.DWORD),
                ("dwStateMask", ctypes.wintypes.DWORD),
                ("szInfo", ctypes.wintypes.WCHAR * 256),
                ("uVersion", ctypes.wintypes.UINT),
                ("szInfoTitle", ctypes.wintypes.WCHAR * 64),
                ("dwInfoFlags", ctypes.wintypes.DWORD),
                ("guidItem", ctypes.c_byte * 16),
                ("hBalloonIcon", ctypes.wintypes.HICON),
            ]
        def tray_thread():
            WNDPROCTYPE = ctypes.WINFUNCTYPE(ctypes.c_int64, ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.c_int64, ctypes.c_int64)
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            hinstance = kernel32.GetModuleHandleW(None)
            WM_LBUTTONDBLCLK = 0x203
            WM_RBUTTONUP = 0x205
            WM_DESTROY = 0x0002
            def wnd_proc(hwnd, msg, wparam, lparam):
                if msg == WM_APP:
                    if lparam == WM_LBUTTONDBLCLK:
                        self.root.after(0, self._on_restore_from_tray)
                    elif lparam == WM_RBUTTONUP:
                        self.root.after(0, self._tray_show_menu)
                elif msg == WM_DESTROY:
                    user32.PostQuitMessage(0)
                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
            WPF = ctypes.WINFUNCTYPE(ctypes.c_int64, ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.c_int64, ctypes.c_int64)
            proc = WPF(wnd_proc)
            user32.DefWindowProcW.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.c_int64, ctypes.c_int64]
            user32.DefWindowProcW.restype = ctypes.c_int64
            reg_cls = user32.RegisterClassExW
            reg_cls.argtypes = [ctypes.c_void_p]
            reg_cls.restype = ctypes.c_ushort
            class WNDCLASSEXW(ctypes.Structure):
                _fields_ = [
                    ("cbSize", ctypes.wintypes.UINT),
                    ("style", ctypes.wintypes.UINT),
                    ("lpfnWndProc", WPF),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", ctypes.wintypes.HINSTANCE),
                    ("hIcon", ctypes.wintypes.HICON),
                    ("hCursor", ctypes.wintypes.HCURSOR),
                    ("hbrBackground", ctypes.wintypes.HBRUSH),
                    ("lpszMenuName", ctypes.wintypes.LPCWSTR),
                    ("lpszClassName", ctypes.wintypes.LPCWSTR),
                    ("hIconSm", ctypes.wintypes.HICON),
                ]
            wc = WNDCLASSEXW()
            wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
            wc.lpfnWndProc = proc
            wc.hInstance = hinstance
            wc.lpszClassName = cls_name
            atom = reg_cls(ctypes.byref(wc))
            if not atom:
                return
            hwnd = user32.CreateWindowExW(0, cls_name, "PicoTrayMsgWindow", 0, 0, 0, 0, 0, 0, 0, hinstance, None)
            if not hwnd:
                return
            nid = NIDW()
            nid.cbSize = ctypes.sizeof(NIDW)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON
            nid.uCallbackMessage = WM_APP
            nid.szTip = "Pico HSM/FIDO2 Manager"
            nid.hIcon = user32.LoadIconW(None, 32512)  # IDI_APPLICATION
            if ctypes.windll.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
                self._tray_nid_data = nid
                self._tray_hwnd = hwnd
                while not self._tray_stop_event.is_set():
                    msg = ctypes.wintypes.MSG()
                    ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                    if ret <= 0:
                        break
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
            user32.DestroyWindow(hwnd)
        self._tray_thread = threading.Thread(target=tray_thread, daemon=True)
        self._tray_thread.start()

    def _tray_destroy(self):
        if hasattr(self, '_tray_stop_event'):
            self._tray_stop_event.set()
        if hasattr(self, '_tray_nid_data'):
            try:
                NIM_DELETE = 2
                class NIDW(ctypes.Structure):
                    _fields_ = [
                        ("cbSize", ctypes.wintypes.DWORD),
                        ("hWnd", ctypes.wintypes.HWND),
                        ("uID", ctypes.wintypes.UINT),
                        ("uFlags", ctypes.wintypes.UINT),
                        ("uCallbackMessage", ctypes.wintypes.UINT),
                        ("hIcon", ctypes.wintypes.HICON),
                        ("szTip", ctypes.wintypes.WCHAR * 128),
                        ("dwState", ctypes.wintypes.DWORD),
                        ("dwStateMask", ctypes.wintypes.DWORD),
                        ("szInfo", ctypes.wintypes.WCHAR * 256),
                        ("uVersion", ctypes.wintypes.UINT),
                        ("szInfoTitle", ctypes.wintypes.WCHAR * 64),
                        ("dwInfoFlags", ctypes.wintypes.DWORD),
                        ("guidItem", ctypes.c_byte * 16),
                        ("hBalloonIcon", ctypes.wintypes.HICON),
                    ]
                nid = NIDW()
                nid.cbSize = ctypes.sizeof(NIDW)
                nid.hWnd = self._tray_nid_data.hWnd
                nid.uID = 1
                ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            except Exception:
                pass

    def _tray_show_menu(self):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=T("Show"), command=self._on_restore_from_tray)
        menu.add_separator()
        menu.add_command(label=T("Exit"), command=self._on_close_real)
        try:
            menu.tk_popup(self.root.winfo_pointerx(), self.root.winfo_pointery())
        finally:
            menu.grab_release()

    def _on_close_real(self):
        self._save_geometry()
        if self._agent_running:
            self._agent_stop()
        self._tray_destroy()
        self.root.destroy()

    def connect(self):
        from smartcard import listReaders
        all_readers = listReaders()
        # detect which readers are HSM by trying PicoKey (no login needed)
        pico_readers = []
        for i, r in enumerate(all_readers):
            if 'Pico' not in r:
                continue
            try:
                from picokey import PicoKey, Product
                pk = PicoKey(slot=i)
                if pk.product == Product.HSM:
                    pico_readers.append((i, r))
                pk.close()
            except:
                pass
        if not pico_readers:
            messagebox.showerror(T("Error"), T("No Pico HSM device found"))
            return
        d = tk.Toplevel(self.root)
        d.title(T("Connect"))
        d.geometry("400x200")
        d.transient(self.root)
        d.attributes('-topmost', True); d.lift()
        self.root.deiconify(); self.root.lift(); self.root.update_idletasks()
        d.attributes('-topmost', False)
        self._center_dialog(d)
        f = ttk.Frame(d, padding=12)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=T("Device:")).pack(anchor=tk.W)
        dev_names = [r for _, r in pico_readers]
        dev_var = tk.StringVar(value=dev_names[0] if dev_names else "")
        dev_combo = ttk.Combobox(f, textvariable=dev_var, values=dev_names, state="readonly", width=50)
        dev_combo.pack(fill=tk.X, pady=(0,8))
        ttk.Label(f, text=T("PIN:")).pack(anchor=tk.W)
        e = ttk.Entry(f, show="*", width=30)
        e.pack(fill=tk.X, pady=(0,8))
        e.focus_set()
        e.bind('<Return>', lambda event: do_connect())
        d.bind('<Escape>', lambda event: d.destroy())
        err = ttk.Label(f, text="", foreground="red")
        err.pack(fill=tk.X)
        bf = ttk.Frame(f)
        bf.pack(fill=tk.X)
        def do_connect():
            pin = e.get().strip()
            if not pin:
                err.config(text=T("Enter PIN"))
                return
            sel_name = dev_var.get()
            sel_slot = None
            for i, r in pico_readers:
                if r == sel_name:
                    sel_slot = i
                    break
            if sel_slot is None:
                err.config(text=T("Select a device"))
                return
            d.destroy()
            self.connect_btn.config(text=T("Connecting..."))
            self.connect_btn.state(["disabled"])
            self.root.update_idletasks()
            def _do():
                try:
                    hsm = PicoHSM(pin=pin, slot=sel_slot)
                    if not hsm.is_logged():
                        hsm.login(pin=pin)
                    self.root.after(0, self._connect_ok, hsm, pin, sel_name)
                except Exception as ex:
                    self.root.after(0, self._connect_fail, str(ex))
            threading.Thread(target=_do, daemon=True).start()
        ttk.Button(bf, text=T("Connect"), command=do_connect).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text=T("Cancel"), command=d.destroy).pack(side=tk.RIGHT, padx=4)

    def _toggle_menu(self, state):
        for mn, idx in self._menu_cmds:
            mn.entryconfig(idx, state=state)

    def disconnect(self):
        self._stop_periodic_refresh()
        if self.hsm:
            try:
                self.hsm.logout()
            except:
                pass
            self.hsm = None
        self._hsm_dev_name = ""
        self._retries_var.set("")
        self.log(T("Disconnected from Pico HSM."))
        self.status_var.set(T("Disconnected"))
        self.connect_btn.state(["!disabled"])
        self.disconnect_btn.state(["disabled"])
        self.device_lbl.config(text="")
        for b in (self.btn_gen, self.btn_view, self.btn_ssh, self.btn_label, self.btn_cert, self.btn_encrypt, self.btn_decrypt, self.btn_refresh, self.btn_export_all_hsm):
            b.state(["disabled"])
        self._toggle_menu("disabled")

    def _connect_ok(self, hsm, pin, dev_name=""):
        self._inc_stat('hsm_connects')
        self._save_stats()
        self.hsm = hsm
        self._pin = pin
        self._hsm_dev_name = dev_name
        label = T("Connected (PIN: ") + pin + ")"
        if dev_name:
            label += f" [{dev_name}]"
        self.status_var.set(label)
        self.status_lbl.configure(style="Success.TLabel")
        self.connect_btn.config(text=T("Connect"))
        self.connect_btn.state(["disabled"])
        self.disconnect_btn.state(["!disabled"])
        for b in (self.btn_gen, self.btn_refresh):
            b.state(["!disabled"])
        for b in (self.btn_view, self.btn_ssh, self.btn_label, self.btn_cert):
            b.state(["disabled"])
        self._toggle_menu("normal")
        self.device_lbl.config(text=f"ID: {hsm.device_id}" if hsm.device_id else "")
        self._update_retries()
        self.log(T("Connection to Pico-HSM established."))
        try:
            ver = hsm.get_version()
            self.log(f'  Version: {ver}')
        except:
            pass
        try:
            sinfo = hsm.get_serial_info()
            self.log(f'  Serial: {sinfo}')
        except:
            pass
        self.refresh_keys()
        self._start_periodic_refresh()
        self._agent_try_auto_start()

    def _connect_fail(self, err):
        self.status_var.set(T("Error: ") + err)
        self.status_lbl.configure(style="Error.TLabel")
        self.connect_btn.config(text=T("Connect"))
        self.connect_btn.state(["!disabled"])
        self.disconnect_btn.state(["disabled"])
        self.device_lbl.config(text="")
        self.log(T("Connection error: ") + err)

    def refresh_keys(self):
        self.log(T("Scanning keys..."))
        self.keys_tree.delete(*self.keys_tree.get_children())
        self.keys = {}

        def _do():
            keys = self._get_all_keys()
            self.root.after(0, self._show_keys, keys)

        threading.Thread(target=_do, daemon=True).start()

    def _get_all_keys(self):
        hsm = self.hsm
        keys = {}
        internal_ids = []
        for kid in range(0, 256):
            try:
                data = hsm.get_contents(p1=DOPrefixes.PRKD_PREFIX, p2=kid)
                if data:
                    internal_ids.append(kid)
            except:
                pass

        pkcs11_objects = self._pkcs11_get_objects()

        for kid in internal_ids:
            if kid in SKIP_IDS:
                continue
            try:
                cert = bytearray(hsm.get_contents(p1=DOPrefixes.EE_CERTIFICATE_PREFIX, p2=kid))
                if cert:
                    cvc = CVC().decode(cert)
                    oid = bytes(cvc.pubkey().oid())

                    if oid == OID_RI_ECDH:
                        pub = hsm.public_key(kid)
                        # Если библиотека уже распознала тип — доверяем ей
                        if isinstance(pub, ed25519.Ed25519PublicKey):
                            keys[kid] = ('Ed25519 (ECDH)', pub)
                        elif isinstance(pub, ed448.Ed448PublicKey):
                            keys[kid] = ('Ed448 (ECDH)', pub)
                        elif isinstance(pub, x448.X448PublicKey):
                            keys[kid] = ('X448 (ECDH)', pub)
                        elif isinstance(pub, x25519.X25519PublicKey):
                            keys[kid] = ('X25519 (ECDH)', pub)
                        else:
                            name = type(pub).__name__.replace('EllipticCurvePublicKey', 'EC').replace('PublicKey', '')
                            keys[kid] = (f'{name} (ECDH)', pub)
                        continue

                    elif oid == OID_TA_ECDSA:
                        Y = bytes(cvc.pubkey().find(0x86).data())
                        P = bytes(cvc.pubkey().find(0x81).data())
                        if not (Y and P):
                            raise ValueError("no EC params")
                        curve_obj = EcCurve.from_P(P)
                        crypto = curve_obj.to_crypto()
                        if Y[0] != 0x04:
                            Y = b"\x04" + Y
                        pub = ec.EllipticCurvePublicKey.from_encoded_point(crypto, Y)
                        curve_name = type(curve_obj).__name__
                        pkcs11_id = kid + 0x30
                        if pkcs11_id in pkcs11_objects:
                            curve_name = pkcs11_objects[pkcs11_id][0]
                        has_ecdh = False
                        ainfo = self._key_algos.get(kid)
                        if ainfo and ainfo['type'] == KeyType.ECC:
                            has_ecdh = Algorithm.ALGO_EC_ECDH in ainfo['algos']
                        else:
                            # key created before this session — assume all ops allowed
                            has_ecdh = True
                        suffix = " (ECDSA+ECDH)" if has_ecdh else " (ECDSA)"
                        keys[kid] = (f'{curve_name}{suffix}', pub)
                        continue

                    elif oid == OID_TA_RSA:
                        pub = hsm.public_key(kid)
                        if pub:
                            has_decrypt = False
                            ainfo = self._key_algos.get(kid)
                            if ainfo and ainfo['type'] == KeyType.RSA:
                                has_decrypt = any(a in ainfo['algos'] for a in (Algorithm.ALGO_RSA_DECRYPT, Algorithm.ALGO_RSA_DECRYPT_PKCS1, Algorithm.ALGO_RSA_DECRYPT_OEP))
                            else:
                                has_decrypt = True  # old key — assume all ops allowed
                            suffix = " (decrypt)" if has_decrypt else ""
                            keys[kid] = (f'RSA ({pub.key_size} bit){suffix}', pub)
                        continue
            except:
                pass

            try:
                info = hsm.keyinfo(kid)
                if info:
                    t = {1: "RSA", 2: "EC", 3: "AES"}.get(info.get("type"), "?")
                    pub = None
                    if t == "RSA":
                        try:
                            pub = hsm.public_key(kid)
                        except:
                            pass
                    suffix = ""
                    if t in ("RSA", "EC"):
                        ainfo = self._key_algos.get(kid)
                        if ainfo and ainfo.get('type') in (KeyType.RSA, KeyType.ECC):
                            if t == "RSA":
                                if any(a in ainfo.get('algos', []) for a in (Algorithm.ALGO_RSA_DECRYPT, Algorithm.ALGO_RSA_DECRYPT_PKCS1, Algorithm.ALGO_RSA_DECRYPT_OEP)):
                                    suffix = " (decrypt)"
                            elif t == "EC":
                                if Algorithm.ALGO_EC_ECDH in ainfo.get('algos', []):
                                    suffix = " (ECDSA+ECDH)"
                                else:
                                    suffix = " (ECDSA)"
                        else:
                            if t == "RSA":
                                suffix = " (decrypt)"  # old key, assume all ops allowed
                            elif t == "EC":
                                suffix = " (ECDSA+ECDH)"
                    keys[kid] = (f"{t} {info.get('key_size','?')}b{suffix}", pub)
            except:
                keys[kid] = ("Unknown", None)

        return dict(sorted(keys.items()))

    def _pkcs11_get_objects(self):
        result = {}
        try:
            out = subprocess.run(
                [PKCS11_TOOL, '--login', '--pin', self._pin, '-O'],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            ).stdout
        except:
            return result

        current = {}
        for line in out.splitlines():
            line = line.strip()
            if 'Public Key Object' in line:
                current = {'is_pub': True}
                if 'EC' in line:
                    current['ktype'] = 'EC'
                    m = re.search(r'(\d+)\s+bits', line)
                    current['bits'] = int(m.group(1)) if m else None
                elif 'RSA' in line:
                    current['ktype'] = 'RSA'
                    m = re.search(r'(\d+)\s+bits', line)
                    current['bits'] = int(m.group(1)) if m else None
            elif current.get('is_pub'):
                if line.startswith('ID:'):
                    m = re.search(r'ID:\s+(\d+)', line)
                    if m:
                        current['id'] = int(m.group(1))
                elif line.startswith('EC Params:'):
                    curve = 'unknown'
                    if '2b:81:04:00:23' in line: curve = 'secp521r1'
                    elif '2b:81:04:00:22' in line: curve = 'secp384r1'
                    elif '2a:86:48:ce:3d:03:01:07' in line: curve = 'secp256r1'
                    elif '2b:81:04:00:0a' in line: curve = 'secp256k1'
                    current['curve'] = curve
                    if 'id' in current:
                        bits = current.get('bits', '')
                        name = f'EC {curve} ({bits} bit)' if bits else f'EC {curve}'
                        result[current['id']] = (name, None)
                elif line.startswith('Modulus:') and 'id' in current:
                    bits = current.get('bits', '')
                    name = f'RSA ({bits} bit)' if bits else 'RSA'
                    result[current['id']] = (name, None)
        return result

    def _show_keys(self, keys):
        self.keys = keys
        self.keys_tree.delete(*self.keys_tree.get_children())
        for kid, (name, _) in keys.items():
            label = ""
            try:
                info = self.hsm.keyinfo(kid)
                if info and info.get('label'):
                    label = info['label']
            except:
                pass
            self.keys_tree.insert("", tk.END, iid=str(kid), text=str(kid), values=(name, label))
        self.log(T("Keys found: ") + str(len(keys)))
        if keys:
            self.btn_export_all_hsm.state(["!disabled"])
            self._m_keys.entryconfig(3, state="normal")
        else:
            self.btn_export_all_hsm.state(["disabled"])
            self._m_keys.entryconfig(3, state="disabled")
        self._agent_keys()

    def _on_key_select(self, event):
        sel = self.keys_tree.selection()
        if sel:
            kid = int(sel[0])
            name, pub = self.keys.get(kid, ("?", None))
            self.status_var.set(T("Selected key ID ") + str(kid) + ": " + name)
            self._m_keys.entryconfig(0, state="normal")
            for b in (self.btn_view, self.btn_ssh, self.btn_label, self.btn_cert):
                b.state(["!disabled"])
            can_encrypt = "AES" in name or pub is not None and (isinstance(pub, rsa.RSAPublicKey) or "ECDH" in name)
            can_decrypt = "AES" in name or pub is not None and ("ECDH" in name or "(decrypt)" in name)
            if can_encrypt:
                self.btn_encrypt.state(["!disabled"])
            else:
                self.btn_encrypt.state(["disabled"])
            if can_decrypt:
                self.btn_decrypt.state(["!disabled"])
            else:
                self.btn_decrypt.state(["disabled"])
        else:
            self._m_keys.entryconfig(0, state="disabled")
            for b in (self.btn_view, self.btn_ssh, self.btn_label, self.btn_cert, self.btn_encrypt, self.btn_decrypt):
                b.state(["disabled"])

    def _on_f2_tree_select(self, event):
        sel = self._f2_tree.selection()
        if sel:
            self._f2_verify_btn.state(['!disabled'])
            self._f2_edit_btn.state(['!disabled'])
            self._f2_ssh_btn.state(['!disabled'])
        else:
            self._f2_verify_btn.state(['disabled'])
            self._f2_edit_btn.state(['disabled'])
            self._f2_ssh_btn.state(['disabled'])

    def _on_agent_key_select(self, event):
        sel = self._agent_tree.selection()
        if not sel:
            self._agent_key_info.config(text="")
            return
        sid = sel[0]
        text = ""
        if sid.isdigit():
            kid = int(sid)
            name, pub = self.keys.get(kid, ("?", None))
            text = f"{T('ID: ')}{kid}  {T('Type: ')}{name}"
            if pub is not None:
                ssh = self._to_ssh(pub, comment=f"pico-hsm-key-{kid}")
                if ssh:
                    text += f"  SSH: {ssh}"
        elif sid.startswith('f2:') and sid in self._f2_agent_creds:
            ci = self._f2_agent_creds[sid]
            text = f"FIDO2 {ci['rp_id']} ({ci['user_name']})  {ci['algo']}"
        self._agent_key_info.config(text=text)

    def _selected_kid(self):
        sel = self.keys_tree.selection()
        if not sel:
            self._info(T("Warning"), T("Select a key from the list."))
            return None
        return int(sel[0])

    def view_pubkey(self):
        kid = self._selected_kid()
        if kid is None:
            return
        name, pub = self.keys.get(kid, ("?", None))
        self.log_clear()
        self.log(f"{T('Key ID: ')}{kid}  {T('Type: ')}{name}")
        self.log("-" * 60)
        if pub is None:
            self.log(T("Public key unavailable (AES or read error)."))
            return
        try:
            pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
            self.log(T("PEM:"))
            for line in pem.strip().split("\n"):
                self.log(f"  {line}")
        except Exception as e:
            self.log(T("PEM unavailable: ") + str(e))
        ssh = self._to_ssh(pub, comment=f"pico-hsm-key-{kid}")
        if ssh:
            self.log("")
            self.log(T("SSH (authorized_keys):"))
            self.log(f"  {ssh}")
        else:
            self.log(T("SSH not supported for this key type."))

    def export_ssh(self):
        sel = self.keys_tree.selection()
        if not sel:
            self._info(T("Warning"), T("Select a key from the list."))
            return
        lines = []
        for sid in sel:
            kid = int(sid)
            name, pub = self.keys.get(kid, ("?", None))
            if pub is None:
                continue
            ssh = self._to_ssh(pub, comment=f"pico-hsm-key-{kid}")
            if not ssh:
                continue
            lines.append(ssh)
        if not lines:
            self._info(T("Error"), T("SSH format not supported for these key types."))
            return
        text = "\n".join(lines)
        self.log_clear()
        for line in lines:
            self.log(f"  {line}")
        self.log("")
        r = self._confirm(T("Export SSH key"), text + "\n\n" + T("Copy to clipboard?"))
        if r:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.log(T("Copied to clipboard."))
        r2 = self._confirm(T("Export SSH key"), T("Save to file?"))
        if r2:
            fp = "hsm_keys.pub"
            try:
                with open(fp, "w", encoding="utf-8") as f:
                    f.write(text + "\n")
                self.log(T("Saved: ") + os.path.abspath(fp))
            except Exception as e:
                self.log(T("Save error: ") + str(e))

    def _hsm_export_all_ssh(self):
        if not self.keys:
            self._info(T("Info"), T("No keys to export."))
            return
        ssh_dir = os.path.expanduser("~/.ssh")
        try:
            os.makedirs(ssh_dir, exist_ok=True)
        except Exception as e:
            self.log(f"{T('Error:')} {ssh_dir}: {e}")
            return
        count = 0
        for kid, (name, pub) in self.keys.items():
            if pub is None:
                continue
            try:
                ssh = self._to_ssh(pub, comment=f"pico-hsm-key-{kid}")
                if not ssh:
                    continue
                fname = f"id_hsm_{kid}.pub"
                fpath = os.path.join(ssh_dir, fname)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(ssh + "\n")
                self.log(f"{T('Saved:')} {fpath}")
                count += 1
            except Exception as e:
                self.log(f"{T('Error:')} {kid}: {e}")
        self.log(T("total") + f" {count} -> {ssh_dir}")

    def _hsm_delete_all(self):
        if not self.keys:
            self._info(T("Info"), T("No keys to delete."))
            return
        msg = T("Delete ALL HSM keys?") + f"\n({len(self.keys)} keys)"
        if not self._confirm(T("Confirm"), msg):
            return
        if not self._confirm(T("Confirm"), T("This cannot be undone. Continue?")):
            return
        self.log(T("Deleting all keys..."))
        self._m_keys.entryconfig(3, state="disabled")
        kids = list(self.keys.keys())
        def _do():
            ok = 0
            for kid in kids:
                try:
                    self.hsm.delete_key(kid)
                    self._key_algos.pop(kid, None)
                    ok += 1
                except Exception as e:
                    self.log(f"{T('Error deleting')} {kid}: {e}")
            self.root.after(0, self._hsm_delete_all_done, ok, len(kids))
        threading.Thread(target=_do, daemon=True).start()

    def _hsm_delete_all_done(self, ok, total):
        self._inc_stat('keys_deleted', ok)
        self._save_stats()
        self._save_key_algos()
        self._m_keys.entryconfig(3, state="normal")
        self.log(T("Deleted") + f" {ok}/{total} " + T("keys."))
        self.refresh_keys()

    def view_cert(self):
        kid = self._selected_kid()
        if kid is None:
            return
        self.cert_text.delete("1.0", tk.END)
        try:
            data = self.hsm.get_contents(p1=DOPrefixes.EE_CERTIFICATE_PREFIX, p2=kid)
            if not data:
                self.cert_text.insert(tk.END, f"{T('EE certificate for ID ')}{kid} {T('not found.')}\n")
                return
            cvc = CVC().decode(data)
            self.cert_text.insert(tk.END, f"CAR: {cvc.car().decode()}\n")
            self.cert_text.insert(tk.END, f"CHR: {cvc.chr().decode()}\n")
            try:
                self.cert_text.insert(tk.END, f"CPI: {cvc.cpi()}\n")
            except:
                pass
            try:
                oid = cvc.oid()
                if oid:
                    self.cert_text.insert(tk.END, f"OID: {bytes(oid).hex()}\n")
            except:
                pass
            try:
                exp = cvc.expires()
                if exp:
                    self.cert_text.insert(tk.END, f"Expires: {exp}\n")
            except:
                pass
            try:
                self.cert_text.insert(tk.END, f"Role: {cvc.role()}\n")
            except:
                pass
            pk = cvc.pubkey()
            if pk:
                self.cert_text.insert(tk.END, "\n-- Public Key Tags --\n")
                for t, d in pk.all():
                    b = bytes(d)
                    desc = {0x81: "P", 0x82: "E/e", 0x83: "G", 0x84: "Y/Q",
                            0x86: "Y", 0x02: "A", 0x03: "B"}.get(t, f"0x{t:02X}")
                    self.cert_text.insert(tk.END, f"  Tag 0x{t:02X} ({desc}): {len(b)} {T('bytes')}\n")
                    self.cert_text.insert(tk.END, f"    {b.hex()[:80]}{'...' if len(b) > 40 else ''}\n")
            try:
                sig = cvc.signature()
                if sig:
                    self.cert_text.insert(tk.END, f"\nSignature: {sig.hex()[:80]}...\n")
            except:
                pass
            self.cert_text.insert(tk.END, f"\nRaw ({len(data)} {T('bytes')}):\n")
            for i in range(0, len(data), 32):
                chunk = data[i:i+32]
                h = " ".join(f"{b:02x}" for b in chunk)
                a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                self.cert_text.insert(tk.END, f"  {i:04x}: {h:<96s} {a}\n")
        except Exception as e:
            self.cert_text.insert(tk.END, f"{T('Error:')} {e}\n")

    def _encrypt_file(self):
        kid = self._selected_kid()
        if kid is None:
            return
        name, pub = self.keys.get(kid, (None, None))
        if pub is not None and isinstance(pub, rsa.RSAPublicKey) and "(decrypt)" not in name:
            if not messagebox.askyesno(T("Warning"), T("This RSA key cannot decrypt. Encrypted file will NOT be recoverable. Continue?")):
                return
        from tkinter import filedialog
        src = filedialog.askopenfilename(title=T("Select file to encrypt"))
        if not src:
            return
        dst = src + ".enc"
        self.log(T("Encrypting..."))
        def _do_encrypt():
            try:
                iv = os.urandom(12)
                if "AES" in name:
                    salt = os.urandom(16)
                    aes_key = bytes(self.hsm.hkdf(hashes.SHA256, kid, list(b"file-enc"), list(salt), out_len=32))
                else:
                    aes_key = os.urandom(32)
                with open(src, "rb") as f:
                    pt = f.read()
                ct = AESGCM(aes_key).encrypt(iv, pt, None)
                if "AES" in name:
                    with open(dst, "wb") as f:
                        f.write(b"AES" + salt + iv + ct)
                elif isinstance(pub, rsa.RSAPublicKey):
                    wrapped = pub.encrypt(
                        aes_key,
                        padding.PKCS1v15())
                    with open(dst, "wb") as f:
                        f.write(b"RSA" + len(wrapped).to_bytes(4, "big") + wrapped + iv + ct)
                else:
                    eph_priv = ec.generate_private_key(ec.SECP256R1())
                    eph_pub = eph_priv.public_key()
                    ss = bytes(self.hsm.exchange(kid, eph_pub))
                    derived = hashlib.sha256(ss).digest()
                    wrapped = bytes(a ^ b for a, b in zip(aes_key, derived))
                    eph_pub_bytes = eph_pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                    with open(dst, "wb") as f:
                        f.write(b"ECH" + len(eph_pub_bytes).to_bytes(2, "big") + eph_pub_bytes + wrapped + iv + ct)
                self.root.after(0, lambda: self.log(f"{T('Saved:')} {dst}"))
                self._inc_stat('file_encrypts')
                self._save_stats()
            except Exception as e:
                msg = str(e)
                if "6985" in msg:
                    if pub is not None and isinstance(pub, rsa.RSAPublicKey):
                        msg = T("RSA key does not have decrypt permission. Create a new RSA key with the fix.")
                    else:
                        msg = T("Key does not support ECDH. Use an RSA key or create an ECDH key.")
                self.root.after(0, lambda m=msg: self.log(f"{T('Error:')} {m}"))
        threading.Thread(target=_do_encrypt, daemon=True).start()

    def _decrypt_file(self):
        kid = self._selected_kid()
        if kid is None:
            return
        name, pub = self.keys.get(kid, (None, None))
        from tkinter import filedialog
        src = filedialog.askopenfilename(title=T("Select file to decrypt"), filetypes=[("Encrypted", "*.enc"), ("All", "*.*")])
        if not src:
            return
        dst = src[:-4] if src.lower().endswith(".enc") else src + ".dec"
        self.log(T("Decrypting..."))
        def _do_decrypt():
            try:
                with open(src, "rb") as f:
                    data = f.read()
                magic = data[:3]
                rest = data[3:]
                if magic == b"AES":
                    salt = rest[:16]
                    iv = rest[16:28]
                    ct = rest[28:]
                    aes_key = bytes(self.hsm.hkdf(hashes.SHA256, kid, list(b"file-enc"), list(salt), out_len=32))
                    pt = AESGCM(aes_key).decrypt(iv, ct, None)
                elif magic == b"RSA":
                    wlen = int.from_bytes(rest[:4], "big")
                    wrapped = rest[4:4+wlen]
                    iv = rest[4+wlen:4+wlen+12]
                    ct = rest[4+wlen+12:]
                    raw_key = bytes(self.hsm.decrypt(kid, list(wrapped), Padding.RAW))
                    # Strip PKCS#1 v1.5 padding: 00 02 <random non-zero> 00 <data>
                    if len(raw_key) < 11:
                        raise ValueError("Decrypted data too short")
                    if raw_key[:2] != b'\x00\x02':
                        raise ValueError("Bad PKCS1 padding header")
                    sep = raw_key.find(b'\x00', 2)
                    if sep < 10:
                        raise ValueError("PKCS1 padding separator not found or too short")
                    aes_key = raw_key[sep+1:]
                    pt = AESGCM(aes_key).decrypt(iv, ct, None)
                elif magic == b"ECH":
                    elen = int.from_bytes(rest[:2], "big")
                    eph_pub_bytes = rest[2:2+elen]
                    wrapped = rest[2+elen:2+elen+32]
                    iv = rest[2+elen+32:2+elen+44]
                    ct = rest[2+elen+44:]
                    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_pub_bytes)
                    ss = bytes(self.hsm.exchange(kid, eph_pub))
                    derived = hashlib.sha256(ss).digest()
                    aes_key = bytes(a ^ b for a, b in zip(wrapped, derived))
                    pt = AESGCM(aes_key).decrypt(iv, ct, None)
                else:
                    self.root.after(0, lambda: self.log(T("Unknown file format")))
                    return
                with open(dst, "wb") as f:
                    f.write(pt)
                self.root.after(0, lambda: self.log(f"{T('Saved:')} {dst} ({len(pt)} {T('bytes')})"))
                self._inc_stat('file_decrypts')
                self._save_stats()
            except Exception as e:
                msg = str(e) or type(e).__name__
                if "6985" in msg:
                    if pub is not None and isinstance(pub, rsa.RSAPublicKey):
                        msg = T("RSA key does not have decrypt permission. Create a new RSA key with the fix.") + f" (SW:6985)"
                    else:
                        msg = T("Key does not support ECDH. Use an RSA key or create an ECDH key.")
                self.root.after(0, lambda m=msg: self.log(f"{T('Error:')} {m}"))
        threading.Thread(target=_do_decrypt, daemon=True).start()

    def write_ca_cert(self):
        from tkinter import filedialog
        d = tk.Toplevel(self.root)
        d.title(T("Write CA cert"))
        d.geometry("500x200")
        d.transient(self.root)
        self._center_dialog(d)
        d.grab_set()

        f = ttk.Frame(d, padding=10)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text=T("ID (CA slot number):")).pack(anchor=tk.W)
        pairs = self.hsm.list_keys()
        ca_ids = sorted([k for p, k in pairs if p == DOPrefixes.CA_CERTIFICATE_PREFIX])
        free_id = 0
        for c in ca_ids:
            if c <= free_id:
                free_id = c + 1
        id_entry = ttk.Entry(f, font=("Consolas", 10), width=10)
        id_entry.insert(0, str(free_id))
        id_entry.pack(anchor=tk.W, pady=(0,6))
        if ca_ids:
            ttk.Label(f, text=f"{T('Occupied IDs:')} {ca_ids}", foreground="#888").pack(anchor=tk.W)

        file_path = tk.StringVar()
        ttk.Label(f, text=T("CVC certificate file:")).pack(anchor=tk.W)
        ff = ttk.Frame(f)
        ff.pack(fill=tk.X)
        fp_entry = ttk.Entry(ff, textvariable=file_path, font=("Consolas", 9))
        fp_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        def browse():
            path = filedialog.askopenfilename(
                title=T("Select CVC certificate"),
                filetypes=[("DER/CVC files", "*.der *.cvc *.bin"), ("All files", "*.*")],
                parent=d
            )
            if path:
                file_path.set(path)

        ttk.Button(ff, text=T("Browse..."), command=browse).pack(side=tk.RIGHT, padx=4)

        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=10)

        def do_write():
            kid_str = id_entry.get().strip()
            if not kid_str.isdigit():
                messagebox.showerror(T("Error"), T("ID must be a number"), parent=d)
                return
            kid = int(kid_str)
            path = file_path.get().strip()
            if not path:
                messagebox.showerror(T("Error"), T("Select a file"), parent=d)
                return
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except Exception as e:
                messagebox.showerror(T("Error"), T("Could not read file: ") + str(e), parent=d)
                return
            self.log(T("Writing CA certificate ID ") + str(kid) + f" ({len(data)} {T('bytes')})...")
            d.destroy()

            def _do():
                try:
                    self.hsm.put_contents(DOPrefixes.CA_CERTIFICATE_PREFIX, kid, list(data))
                    self.root.after(0, self._ca_done, kid)
                except Exception as e:
                    self.root.after(0, self._ca_fail, str(e))

            threading.Thread(target=_do, daemon=True).start()

        ttk.Button(bf, text=T("Write"), command=do_write).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text=T("Cancel"), command=d.destroy).pack(side=tk.RIGHT, padx=4)

    def _ca_done(self, kid):
        self.log(T("CA certificate ID ") + str(kid) + " " + T("written."))

    def _ca_fail(self, err):
        self.log(T("CA certificate write error: ") + str(err))
        self._info(T("Error"), T("Could not write CA certificate: ") + str(err))

    def set_label(self):
        kid = self._selected_kid()
        if kid is None:
            return
        name, _ = self.keys.get(kid, ("?", None))
        old_label = ""
        try:
            info = self.hsm.keyinfo(kid)
            if info and info.get('label'):
                old_label = info['label']
        except:
            pass

        d = tk.Toplevel(self.root)
        d.title(T("Key label ID ") + str(kid))
        d.geometry("400x150")
        d.transient(self.root)
        self._center_dialog(d)
        d.grab_set()

        f = ttk.Frame(d, padding=10)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text=T("Key: ") + name).pack(anchor=tk.W)
        ttk.Label(f, text=T("Label:")).pack(anchor=tk.W, pady=(6,2))
        entry = ttk.Entry(f, font=("Consolas", 10), width=50)
        entry.insert(0, old_label)
        entry.pack(fill=tk.X)
        entry.focus_set()

        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=8)

        def do_set():
            new_label = entry.get().strip()
            if new_label == old_label:
                d.destroy()
                return
            self.log(T("Setting label for ID ") + str(kid) + f": \"{new_label}\"...")
            d.destroy()

            def _do():
                try:
                    self._write_label_raw(kid, new_label)
                    self.root.after(0, self._label_done, kid, new_label)
                except Exception as e:
                    self.root.after(0, self._label_fail, str(e))

            threading.Thread(target=_do, daemon=True).start()

        ttk.Button(bf, text=T("Save"), command=do_set).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text=T("Cancel"), command=d.destroy).pack(side=tk.RIGHT, padx=4)

    def _write_label_raw(self, kid, new_label):
        prkd = bytearray(self.hsm.get_contents(DOPrefixes.PRKD_PREFIX, kid))
        label_bytes = new_label.encode('utf-8')

        def der_length(length):
            if length <= 0x7F:
                return bytearray([length])
            b = length.to_bytes((length.bit_length() + 7) // 8, 'big')
            return bytearray([0x80 | len(b)]) + b

        def read_der(buf, pos):
            tag = buf[pos]; pos += 1
            if buf[pos] & 0x80:
                nlen = buf[pos] & 0x7F
                length = int.from_bytes(buf[pos+1:pos+1+nlen], 'big')
                pos += 1 + nlen
            else:
                length = buf[pos]; pos += 1
            return tag, length, pos, pos + length

        # Walk outer → 0x30 → find 0x0C
        _, _, outer_data_start, outer_end = read_der(prkd, 0)
        pos = outer_data_start
        while pos < outer_end:
            tag, length, content_start, content_end = read_der(prkd, pos)
            if tag == 0x30:
                seq_tag_pos = pos
                seq_len_field_start = pos + 1
                seq_len_field_end = content_start
                old_seq_len = length

                pos2 = content_start
                while pos2 < content_end:
                    itag, ilen, icontent_start, icontent_end = read_der(prkd, pos2)
                    if itag == 0x0C:
                        old_label_der = prkd[pos2:icontent_end]
                        new_label_der = bytearray([0x0C]) + der_length(len(label_bytes)) + label_bytes
                        delta = len(new_label_der) - len(old_label_der)

                        # 1) Replace label DER
                        prkd2 = bytearray()
                        prkd2 += prkd[:pos2]
                        prkd2 += new_label_der
                        prkd2 += prkd[icontent_end:]

                        # 2) Fix 0x30 length
                        new_seq_len = old_seq_len + delta
                        prkd3 = bytearray()
                        prkd3 += prkd2[:seq_len_field_start]
                        prkd3 += der_length(new_seq_len)
                        prkd3 += prkd2[seq_len_field_end:]

                        # 3) Fix outer length
                        _, old_outer_len, old_outer_data_start, _ = read_der(prkd, 0)
                        new_outer_len = old_outer_len + delta
                        prkd4 = bytearray()
                        prkd4 += prkd3[:1]
                        prkd4 += der_length(new_outer_len)
                        prkd4 += prkd3[old_outer_data_start:]

                        self.hsm.put_contents(DOPrefixes.PRKD_PREFIX, kid, list(prkd4))
                        return
                    pos2 = icontent_end
            pos = content_end
        raise ValueError("0x0C label tag not found in PRKD")

    def _label_done(self, kid, new_label):
        self.log(T("Label for ID ") + str(kid) + " " + T("set:") + f" \"{new_label}\"")
        self.refresh_keys()

    def _label_fail(self, err):
        self.log(T("Label set error: ") + str(err))
        self._info(T("Error"), T("Could not set label: ") + str(err))

    def show_generate(self):
        d = tk.Toplevel(self.root)
        d.title(T("Create key"))
        d.geometry("620x500")
        d.transient(self.root)
        self._center_dialog(d)
        d.grab_set()

        f = ttk.Frame(d, padding=10)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text=T("Key type:"), font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)

        # build flattened items: (selectable?, text, (name,ktype,param)|None)
        flat_items = []
        for cat_name, items in KEY_CATEGORIES:
            flat_items.append((False, f"── {T(cat_name)} ──", None))
            for item in items:
                flat_items.append((True, f"    {item[0]}", item))
            flat_items.append((False, "", None))  # spacing

        lb = tk.Listbox(f, font=("Consolas", 10), height=12)
        lb.pack(fill=tk.BOTH, expand=True)
        for sel, text, _ in flat_items:
            lb.insert(tk.END, text)
            if not sel:
                lb.itemconfig(tk.END, foreground="#888", selectbackground=lb.cget("bg"),
                              selectforeground="#888")

        pf = ttk.LabelFrame(f, text=T("Purpose"), padding=6)
        pf.pack(fill=tk.X, pady=4)
        sign_var = tk.BooleanVar(value=True)
        enc_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(pf, text=T("Sign"), variable=sign_var).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(pf, text=T("Encrypt"), variable=enc_var).pack(side=tk.LEFT, padx=10)

        def on_select(*_):
            sel = lb.curselection()
            if not sel:
                return
            idx = sel[0]
            is_sel, text, item_data = flat_items[idx]
            if not is_sel or item_data is None:
                return
            name, ktype, param = item_data
            if ktype == KeyType.RSA:
                sign_var.set(True); enc_var.set(True)
                sign_entry.config(state=tk.NORMAL); enc_entry.config(state=tk.NORMAL)
            elif ktype == KeyType.AES:
                sign_var.set(False); enc_var.set(False)
                sign_entry.config(state=tk.DISABLED); enc_entry.config(state=tk.DISABLED)
            elif param in ('ed25519', 'ed448'):
                sign_var.set(True); enc_var.set(False)
                sign_entry.config(state=tk.NORMAL); enc_entry.config(state=tk.DISABLED)
            elif param in ('curve25519', 'curve448'):
                sign_var.set(False); enc_var.set(True)
                sign_entry.config(state=tk.DISABLED); enc_entry.config(state=tk.NORMAL)
            else:
                sign_var.set(True); enc_var.set(True)
                sign_entry.config(state=tk.NORMAL); enc_entry.config(state=tk.NORMAL)
        lb.bind("<<ListboxSelect>>", on_select)
        sign_entry = None
        enc_entry = None
        for child in pf.winfo_children():
            if child.winfo_class() == "TCheckbutton":
                txt = child.cget("text")
                if txt == T("Sign"):
                    sign_entry = child
                elif txt == T("Encrypt"):
                    enc_entry = child

        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=6)

        def do_gen():
            sel = lb.curselection()
            if not sel:
                messagebox.showwarning(T("Warning"), T("Select a key type."), parent=d)
                return
            idx = sel[0]
            is_sel, text, item_data = flat_items[idx]
            if not is_sel or item_data is None:
                messagebox.showwarning(T("Warning"), T("Select a key type from the list."), parent=d)
                return
            name, ktype, param = item_data
            if ktype != KeyType.AES and not sign_var.get() and not enc_var.get():
                messagebox.showwarning(T("Warning"), T("Select at least Sign or Encrypt."), parent=d)
                return
            if not messagebox.askyesno(T("Confirm"), f"{T('Create')} {name}?", parent=d):
                return
            self.log(f"{T('Generate')} {name}...")
            d.destroy()

            def _do():
                try:
                    algos = []
                    if ktype == KeyType.RSA:
                        if sign_var.get():
                            algos += [Algorithm.ALGO_RSA_PKCS1, Algorithm.ALGO_RSA_RAW,
                                      Algorithm.ALGO_RSA_PKCS1_SHA256, Algorithm.ALGO_RSA_PSS_SHA256]
                        if enc_var.get():
                            algos += [Algorithm.ALGO_RSA_DECRYPT, Algorithm.ALGO_RSA_DECRYPT_PKCS1, Algorithm.ALGO_RSA_DECRYPT_OEP]
                        # If only sign: still allow raw decrypt
                        if not enc_var.get() and sign_var.get():
                            algos += [Algorithm.ALGO_RSA_DECRYPT]
                        kid = self.hsm.key_generation(ktype, param, algorithms=algos)
                        self._key_algos[kid] = {'type': ktype, 'algos': algos}
                    elif ktype == KeyType.AES:
                        kid = self.hsm.key_generation(ktype, param)
                    else:
                        if sign_var.get():
                            algos += [Algorithm.ALGO_EC_SHA256, Algorithm.ALGO_EC_RAW]
                        if enc_var.get():
                            algos.append(Algorithm.ALGO_EC_ECDH)
                        kid = self.hsm.key_generation(ktype, param, algorithms=algos)
                        self._key_algos[kid] = {'type': ktype, 'algos': algos}
                    self.root.after(0, self._gen_done, kid, name)
                except Exception as e:
                    self.root.after(0, self._gen_fail, str(e))

            threading.Thread(target=_do, daemon=True).start()

        ttk.Button(bf, text=T("Create"), command=do_gen).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text=T("Cancel"), command=d.destroy).pack(side=tk.RIGHT, padx=4)

    def _gen_done(self, kid, name):
        self.log(f"{T('Key created! ID =')} {kid}  {T('Type =')} {name}")
        self._inc_stat('keys_created')
        self._save_stats()
        self._save_key_algos()
        self.refresh_keys()

    def _gen_fail(self, err):
        self.log(T("Generation error: ") + str(err))
        self._info(T("Error"), T("Generation error: ") + str(err))

    def delete_selected_keys(self):
        if self._device_mode.get() == 'Pico FIDO2':
            self._f2_delete()
            return
        sel = self.keys_tree.selection()
        if not sel:
            self._info(T("Warning"), T("Select at least one key from the list."))
            return
        kids = [int(sid) for sid in sel]
        names = [self.keys.get(k, ("?", None))[0] for k in kids]
        msg = T("Delete selected keys?") + "\n" + "\n".join(f"  {k} ({n})" for k, n in zip(kids, names))
        if not self._confirm(T("Confirm"), msg):
            return
        self.log(T("Deleting selected keys..."))
        def _do():
            ok = 0
            for kid in kids:
                try:
                    self.hsm.delete_key(kid)
                    self._key_algos.pop(kid, None)
                    ok += 1
                    self.root.after(0, self.log, T("Key ID ") + str(kid) + " " + T("deleted."))
                except Exception as e:
                    self.root.after(0, self.log, f"{T('Error deleting')} {kid}: {e}")
            self.root.after(0, self._del_selected_done, ok, len(kids))
        threading.Thread(target=_do, daemon=True).start()

    def _del_selected_done(self, ok, total):
        self._inc_stat('keys_deleted', ok)
        self._save_stats()
        self._save_key_algos()
        self._m_keys.entryconfig(0, state="disabled")
        self.log(T("Deleted") + f" {ok}/{total} " + T("keys."))
        self.refresh_keys()

    def _load_key_algos(self):
        try:
            with open(KEY_ALGOS_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._key_algos = {int(k): v for k, v in data.items()}
        except:
            self._key_algos = {}

    def _save_key_algos(self):
        try:
            with open(KEY_ALGOS_PATH, 'w', encoding='utf-8') as f:
                json.dump(self._key_algos, f, ensure_ascii=False)
        except:
            pass

    def _to_ssh(self, pub, comment="pico-hsm"):
        try:
            def ssh_str(s):
                return struct.pack(">I", len(s)) + s
            if isinstance(pub, ec.EllipticCurvePublicKey):
                curve = pub.curve
                if isinstance(curve, ec.SECP256R1):
                    key_type, curve_name = b"ecdsa-sha2-nistp256", b"nistp256"
                elif isinstance(curve, ec.SECP384R1):
                    key_type, curve_name = b"ecdsa-sha2-nistp384", b"nistp384"
                elif isinstance(curve, ec.SECP521R1):
                    key_type, curve_name = b"ecdsa-sha2-nistp521", b"nistp521"
                elif isinstance(curve, ec.SECP256K1):
                    key_type, curve_name = b"ecdsa-sha2-nistp256", b"nistp256"
                else:
                    return None
                point = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                blob = ssh_str(key_type) + ssh_str(curve_name) + ssh_str(point)
                return f"{key_type.decode()} {base64.b64encode(blob).decode()} {comment}"
            elif isinstance(pub, ed25519.Ed25519PublicKey):
                key_type = b"ssh-ed25519"
                raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
                blob = ssh_str(key_type) + ssh_str(raw)
                return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"
            elif isinstance(pub, rsa.RSAPublicKey):
                ssh_bytes = pub.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                return ssh_bytes.decode() + f" {comment}"
        except:
            pass
        return None

    def change_pin(self):
        if self._device_mode.get() == 'Pico FIDO2':
            self._f2_factory_reset()
            return
        if not self._confirm(T("Factory Reset"),
            T("All keys and certificates will be deleted.") + "\n\n"
            + T("Continue?")):
            return
        d = tk.Toplevel(self.root)
        d.title(T("Factory Reset"))
        d.geometry("360x250")
        d.transient(self.root)
        self._center_dialog(d)
        d.grab_set()

        f = ttk.Frame(d, padding=12)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text=T("New PIN:")).pack(anchor=tk.W)
        e_new = ttk.Entry(f, show="*", width=30)
        e_new.pack(fill=tk.X, pady=(0,4))
        e_new.focus_set()

        ttk.Label(f, text=T("Confirm PIN:")).pack(anchor=tk.W)
        e_cfm = ttk.Entry(f, show="*", width=30)
        e_cfm.pack(fill=tk.X, pady=(0,4))

        v_same = tk.BooleanVar(value=True)
        def toggle_sopin():
            st = "disabled" if v_same.get() else "normal"
            e_so_cfm.config(state=st)

        ttk.Checkbutton(f, text=T("SO PIN = User PIN (default)"), variable=v_same,
            command=toggle_sopin).pack(anchor=tk.W, pady=(4,4))

        ttk.Label(f, text=T("New SO PIN:")).pack(anchor=tk.W)
        e_so_new = ttk.Entry(f, show="*", width=30)
        e_so_new.pack(fill=tk.X, pady=(0,4))
        e_so_new.insert(0, "57621880")

        ttk.Label(f, text=T("Confirm SO PIN:")).pack(anchor=tk.W)
        e_so_cfm = ttk.Entry(f, show="*", width=30)
        e_so_cfm.pack(fill=tk.X, pady=(0,4))
        e_so_cfm.insert(0, "57621880")
        e_so_cfm.config(state="disabled")

        err = ttk.Label(f, text="", foreground="red")
        err.pack(fill=tk.X)

        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=(8,0))

        def do_reset():
            new = e_new.get().strip()
            cfm = e_cfm.get().strip()
            if v_same.get():
                sopin = new
            else:
                sopin = e_so_new.get().strip()
                so_cfm = e_so_cfm.get().strip()
                if not sopin:
                    err.config(text=T("SO PIN cannot be empty"))
                    return
                if sopin != so_cfm:
                    err.config(text=T("SO PINs do not match"))
                    return
                if len(sopin) < 4 or len(sopin) > 16:
                    err.config(text=T("SO PIN length must be 4-16 characters"))
                    return
            if not new:
                err.config(text=T("PIN cannot be empty"))
                return
            if new != cfm:
                err.config(text=T("PINs do not match"))
                return
            if len(new) < 4 or len(new) > 16:
                err.config(text=T("PIN length must be 4-16 characters"))
                return
            d.destroy()
            self.log(T("Resetting device..."))
            def _do():
                try:
                    self.hsm.initialize(pin=new, sopin=sopin)
                    self.pin.set(new)
                    self.root.after(0, self.refresh_keys)
                    self.root.after(0, lambda: self.log(T("Device reset. New PIN: ") + new))
                except Exception as e:
                    err_msg = str(e)
                    self.root.after(0, lambda m=err_msg: self.log(T("Reset error: ") + m))
            threading.Thread(target=_do, daemon=True).start()

        ttk.Button(bf, text=T("Reset"), command=do_reset).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bf, text=T("Cancel"), command=d.destroy).pack(side=tk.RIGHT, padx=4)

    def change_pin_only(self):
        if self._device_mode.get() == 'Pico FIDO2':
            self._f2_change_pin()
            return
        d = tk.Toplevel(self.root)
        d.title(T("Change PIN"))
        d.geometry("360x450")
        d.transient(self.root)
        self._center_dialog(d)
        d.grab_set()

        f = ttk.Frame(d, padding=14)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text=T("Old PIN:")).pack(anchor=tk.W)
        e_old = ttk.Entry(f, show="*", width=30)
        e_old.pack(fill=tk.X, pady=(0,6))
        e_old.focus_set()
        e_old.insert(0, self._pin)

        ttk.Label(f, text=T("New PIN:")).pack(anchor=tk.W)
        e_new = ttk.Entry(f, show="*", width=30)
        e_new.pack(fill=tk.X, pady=(0,6))

        ttk.Label(f, text=T("Confirm PIN:")).pack(anchor=tk.W)
        e_cfm = ttk.Entry(f, show="*", width=30)
        e_cfm.pack(fill=tk.X, pady=(0,6))

        ttk.Separator(f, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=6)

        v_change_so = tk.BooleanVar(value=False)
        def toggle_sopin():
            st = "normal" if v_change_so.get() else "disabled"
            e_so_old.config(state=st)
            e_so_new.config(state=st)
            e_so_cfm.config(state=st)

        ttk.Checkbutton(f, text=T("Also change SO PIN"), variable=v_change_so,
            command=toggle_sopin).pack(anchor=tk.W)

        ttk.Label(f, text=T("Old SO PIN:")).pack(anchor=tk.W, pady=(4,0))
        e_so_old = ttk.Entry(f, show="*", width=30)
        e_so_old.pack(fill=tk.X, pady=(0,4))
        e_so_old.insert(0, "00000000")
        e_so_old.config(state="disabled")

        ttk.Label(f, text=T("New SO PIN:")).pack(anchor=tk.W)
        e_so_new = ttk.Entry(f, show="*", width=30)
        e_so_new.pack(fill=tk.X, pady=(0,4))
        e_so_new.insert(0, "00000000")
        e_so_new.config(state="disabled")

        ttk.Label(f, text=T("Confirm SO PIN:")).pack(anchor=tk.W)
        e_so_cfm = ttk.Entry(f, show="*", width=30)
        e_so_cfm.pack(fill=tk.X, pady=(0,4))
        e_so_cfm.insert(0, "00000000")
        e_so_cfm.config(state="disabled")

        err = ttk.Label(f, text="", foreground="red")
        err.pack(fill=tk.X)

        bf = ttk.Frame(f)
        bf.pack(fill=tk.X, pady=(10,0))

        def do_change():
            old = e_old.get().strip()
            new = e_new.get().strip()
            cfm = e_cfm.get().strip()
            if not old:
                err.config(text=T("Enter PIN"))
                return
            if not new:
                err.config(text=T("PIN cannot be empty"))
                return
            if new != cfm:
                err.config(text=T("PINs do not match"))
                return
            if len(new) < 4 or len(new) > 16:
                err.config(text=T("PIN length must be 4-16 characters"))
                return
            if v_change_so.get():
                so_old = e_so_old.get().strip()
                sopin = e_so_new.get().strip()
                so_cfm = e_so_cfm.get().strip()
                if not so_old:
                    err.config(text=T("Enter SO PIN"))
                    return
                if not sopin:
                    err.config(text=T("SO PIN cannot be empty"))
                    return
                if sopin != so_cfm:
                    err.config(text=T("SO PINs do not match"))
                    return
                if len(sopin) < 4 or len(sopin) > 16:
                    err.config(text=T("SO PIN length must be 4-16 characters"))
                    return
            d.destroy()
            self.log(T("Changing PIN..."))
            def _do():
                if old != new:
                    try:
                        self.hsm.send(command=0x24, p2=0x81, data=old.encode() + new.encode())
                        self._pin = new
                        self.pin.set(new)
                        self.root.after(0, lambda: self.log(T("User PIN changed.")))
                    except Exception as e:
                        self.root.after(0, lambda m=str(e): self.log(T("PIN change error: ") + m))
                if v_change_so.get():
                    try:
                        self.hsm.send(command=0x24, p2=0x88, data=so_old.encode() + sopin.encode())
                        self.root.after(0, lambda: self.log(T("SO PIN changed.")))
                    except Exception as e:
                        self.root.after(0, lambda m=str(e): self.log(T("SO PIN change error: ") + m))
                self.root.after(0, self.refresh_keys)
                self.root.after(0, self.refresh_keys)
            threading.Thread(target=_do, daemon=True).start()

        ttk.Button(bf, text=T("Change"), command=do_change).pack(side=tk.RIGHT, padx=6)
        ttk.Button(bf, text=T("Cancel"), command=d.destroy).pack(side=tk.RIGHT, padx=6)

    def device_info(self):
        if self._device_mode.get() == 'Pico FIDO2':
            self._f2_device_info()
            return
        d = tk.Toplevel(self.root)
        d.title(T("Device info"))
        d.geometry("380x280")
        d.transient(self.root)
        self._center_dialog(d)
        d.grab_set()

        f = ttk.Frame(d, padding=14)
        f.pack(fill=tk.BOTH, expand=True)

        info = tk.StringVar(value=T("Loading device info..."))
        lbl = ttk.Label(f, textvariable=info, font=("Consolas", 10),
                        background="white", relief=tk.SUNKEN, padding=8)
        lbl.pack(fill=tk.BOTH, expand=True)

        ptc_var = tk.BooleanVar(value=False)

        def refresh():
            info.set(T("Loading device info..."))
            results = {}
            def fetch(name, fn):
                def _do():
                    try:
                        results[name] = fn()
                    except Exception as e:
                        results[name] = str(e)
                    lines = ""
                    if "memory" in results:
                        m = results["memory"]
                        if isinstance(m, dict):
                            def fmt(v):
                                if v >= 1024:
                                    return f"{v/1024:.1f} KB"
                                return f"{v} B"
                            lines += f"{T('Memory:')} {fmt(m['free'])} {T('free')} / {fmt(m['used'])} {T('used')} / {fmt(m['total'])} {T('total')}\n"
                            lines += f"{T('Files:')} {m['files']} ({fmt(m['size'])})\n"
                        elif isinstance(m, str):
                            lines += f"Memory: {m}\n"
                    if "version" in results:
                        v = results["version"]
                        if isinstance(v, (int, float)):
                            lines += f"{T('Firmware version:')} {v:.1f}\n"
                    if "retries" in results:
                        r = results["retries"]
                        if isinstance(r, int):
                            lines += f"{T('PIN retries:')} {r if r >= 0 else 'N/A'}\n"
                    self.root.after(0, lambda l=lines: info.set(l))
                threading.Thread(target=_do, daemon=True).start()
            fetch("memory", self.hsm.memory)
            fetch("version", self.hsm.get_version)
            fetch("retries", self.hsm.get_login_retries)

        refresh()

        ttk.Separator(f, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)

        ctrl = ttk.Frame(f)
        ctrl.pack(fill=tk.X)

        def toggle_ptc():
            def _do():
                try:
                    val = bytes([0x01 if ptc_var.get() else 0x00])
                    self.hsm.send(cla=0x80, command=0x64, p1=0x06, p2=0x00, data=val)
                    self.root.after(0, lambda: self.log(
                        T("Press-to-confirm enabled.") if ptc_var.get() else T("Press-to-confirm disabled.")))
                except Exception as e:
                    self.root.after(0, lambda: self.log(f"{T('Error:')} {e}"))
            threading.Thread(target=_do, daemon=True).start()

        ttk.Checkbutton(ctrl, text=T("Press-to-confirm"), variable=ptc_var,
                        command=toggle_ptc).pack(side=tk.LEFT)
        ttk.Button(ctrl, text=T("Refresh"), command=refresh).pack(side=tk.RIGHT)
        ttk.Button(ctrl, text=T("Close"), command=d.destroy).pack(side=tk.RIGHT, padx=(0,6))

    def _build_agent_tab(self, nb):
        f = ttk.Frame(nb)
        f.pack(fill=tk.BOTH, expand=True)
        nb.add(f, text=T("SSH Agent"), padding=6)

        self._agent_running = False
        self._agent_engine = None
        self._agent_thread = None

        pw = ttk.PanedWindow(f, orient=tk.HORIZONTAL)
        pw.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(pw)
        pw.add(left, weight=2)

        self._lbl_agent_title = ttk.Label(left, text=T("Keys for agent:"), style="Header.TLabel")
        self._lbl_agent_title.pack(anchor=tk.W)

        self._agent_tree = ttk.Treeview(left, columns=("type", "label"), show="tree headings", height=4, selectmode="extended")
        self._agent_tree.heading("#0", text=T("ID"))
        self._agent_tree.heading("type", text=T("Type"))
        self._agent_tree.heading("label", text=T("Label"))
        self._agent_tree.column("#0", width=40, minwidth=30, stretch=False)
        self._agent_tree.column("type", width=120, minwidth=60, stretch=True)
        self._agent_tree.column("label", width=100, minwidth=40, stretch=True)
        self._agent_tree.pack(fill=tk.BOTH, expand=True)
        self._agent_tree.bind("<<TreeviewSelect>>", self._on_agent_key_select)
        self._agent_tree.bind("<<TreeviewSelect>>", self._on_agent_keys_changed, add="+")

        self._agent_key_info = ttk.Label(left, text="", style="Muted.TLabel")
        self._agent_key_info.pack(anchor=tk.W, pady=(2,0))
        self._agent_empty_lbl = ttk.Label(left, text=T("No keys with public part (Ed25519/EC/RSA)."), style="Muted.TLabel")
        self._agent_hint_lbl = ttk.Label(left, text="(Ctrl+click / Shift+click to select multiple keys for agent)", style="Muted.TLabel", font=("Segoe UI", 8))
        self._agent_hint_lbl.pack(anchor=tk.W, pady=(0,2))

        right = ttk.Frame(pw)
        pw.add(right, weight=1)

        self._lbl_agent_log = ttk.Label(right, text=T("Agent log"), style="Header.TLabel")
        self._lbl_agent_log.pack(anchor=tk.W)
        self._agent_log = scrolledtext.ScrolledText(right, font=("Consolas", 9), wrap=tk.WORD, height=5)
        self._add_copy_menu(self._agent_log)
        self._agent_log.pack(fill=tk.BOTH, expand=True)

        sf = ttk.LabelFrame(f, text=T("Control"), padding=6)
        sf.pack(fill=tk.X, pady=(6, 0))

        self._agent_status = tk.StringVar(value=T("Stopped"))
        ttk.Label(sf, textvariable=self._agent_status, style="Muted.TLabel").pack(side=tk.LEFT, padx=4)
        self._agent_confirm_var = tk.BooleanVar(value=True)
        self._agent_confirm_cb = ttk.Checkbutton(sf, text=T("Confirm signing"), variable=self._agent_confirm_var)
        self._agent_confirm_cb.pack(side=tk.LEFT, padx=8)
        self._agent_auto_start_cb = ttk.Checkbutton(sf, text=T("Auto-start on connect"), variable=self._agent_auto_start_var)
        self._agent_auto_start_cb.pack(side=tk.LEFT, padx=8)

        self._btn_agent_start = ttk.Button(sf, text=T("Start"), width=14)
        self._btn_agent_start.pack(side=tk.RIGHT, padx=2)

        self._btn_agent_stop = ttk.Button(sf, text=T("Stop"), width=14, state=["disabled"])
        self._btn_agent_stop.pack(side=tk.RIGHT, padx=2)

        self._btn_agent_test = ttk.Button(sf, text=T("Test"), width=8, state=["disabled"])
        self._btn_agent_test.pack(side=tk.RIGHT, padx=2)

        self._btn_agent_export = ttk.Button(sf, text=T("Export authorized_keys"), width=20, state=["disabled"])
        self._btn_agent_export.pack(side=tk.RIGHT, padx=4)

        self._btn_agent_start.config(command=self._agent_start)
        self._btn_agent_stop.config(command=self._agent_stop)
        self._btn_agent_test.config(command=self._agent_test)
        self._btn_agent_export.config(command=self._agent_export_authkeys)

    def _agent_keys(self):
        prev = set(self._agent_tree.selection())
        self._agent_tree.delete(*self._agent_tree.get_children())
        all_iids = []
        # HSM keys
        for kid, (name, pub) in self.keys.items():
            if pub is not None and not isinstance(pub, (x25519.X25519PublicKey, x448.X448PublicKey)):
                lbl = ""
                try:
                    info = self.hsm.keyinfo(kid)
                    if info and info.get('label'):
                        lbl = info['label']
                except:
                    pass
                iid = str(kid)
                self._agent_tree.insert("", tk.END, iid=iid, text=iid, values=(name, lbl))
                all_iids.append(iid)
        # FIDO2 credentials
        for cid, ci in self._f2_agent_creds.items():
            uname = ci['user_name']
            rp_id = ci['rp_id']
            lbl = f"{rp_id} ({uname})"
            ptype = 'FIDO2'
            self._agent_tree.insert("", tk.END, iid=cid, text=cid, values=(ptype, lbl))
            all_iids.append(cid)
        sel = [i for i in prev if self._agent_tree.exists(i)]
        if sel:
            self._agent_tree.selection_set(sel)
        if all_iids:
            self._agent_empty_lbl.pack_forget()
            self._btn_agent_export.state(['!disabled'])
        else:
            self._agent_empty_lbl.pack(anchor=tk.W, pady=4)
            self._btn_agent_export.state(['disabled'])

    def _agent_log_msg(self, msg):
        self._agent_log.insert(tk.END, msg + "\n")
        self._agent_log.see(tk.END)

    def _agent_try_auto_start(self):
        if self._agent_auto_start_var.get() and not self._agent_running:
            sel = self._agent_tree.selection()
            if not sel:
                all_ids = self._agent_tree.get_children()
                if all_ids:
                    self._agent_tree.selection_set(all_ids)
                    sel = all_ids
            if sel:
                self._agent_start()

    def _agent_export_authkeys(self):
        sel = self._agent_tree.selection()
        if not sel:
            sel = self._agent_tree.get_children()
        if not sel:
            self._agent_log_msg(T("No keys for agent."))
            return
        ssh_dir = os.path.expanduser("~/.ssh")
        try:
            os.makedirs(ssh_dir, exist_ok=True)
        except Exception as e:
            self._agent_log_msg(f"{T('Error:')} {ssh_dir}: {e}")
            return
        fpath = os.path.join(ssh_dir, "authorized_keys")
        lines = []
        for sid in sel:
            try:
                if sid.isdigit():
                    kid = int(sid)
                    if kid in self.keys:
                        name, pub = self.keys[kid]
                        if pub is None:
                            continue
                        ssh = self._to_ssh(pub, comment=f"pico-hsm-key-{kid}")
                        if ssh:
                            lines.append(ssh)
                elif sid.startswith('f2:') and sid in self._f2_agent_creds:
                    ci = self._f2_agent_creds[sid]
                    blob = ci.get('ssh_blob')
                    if blob:
                        b64 = base64.b64encode(blob).decode()
                        ssh_line = f"{ci['algo']} {b64} FIDO2_{ci['rp_id']}_{ci['user_name']}"
                        lines.append(ssh_line)
            except Exception as e:
                self._agent_log_msg(f"{T('Error:')} {sid}: {e}")
        if not lines:
            self._agent_log_msg(T("No keys to export."))
            return
        try:
            existing = []
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    existing = [l.rstrip("\n") for l in f if l.strip()]
            new_lines = [l for l in lines if l not in existing]
            if not new_lines:
                self._agent_log_msg(T("All keys already in ") + fpath)
                return
            with open(fpath, "a", encoding="utf-8") as f:
                for line in new_lines:
                    f.write(line + "\n")
            self._agent_log_msg(f"{T('Saved:')} {len(new_lines)} {T('keys')} → {fpath}")
        except Exception as e:
            self._agent_log_msg(f"{T('Save error:')} {e}")

    def _agent_start(self):
        if self._agent_running:
            return
        sel = self._agent_tree.selection()
        agent_keys = {}
        for sid in sel:
            # HSM key
            if sid.isdigit():
                kid = int(sid)
                if kid in self.keys:
                    name, pub = self.keys[kid]
                    if pub is not None and not isinstance(pub, (x25519.X25519PublicKey, x448.X448PublicKey)):
                        agent_keys[kid] = {'type': 'hsm', 'kid': kid, 'name': name, 'pub': pub}
            # FIDO2 key
            elif sid.startswith('f2:') and sid in self._f2_agent_creds:
                ci = self._f2_agent_creds[sid]
                agent_keys[sid] = {'type': 'fido2', 'name': ci['user_name'],
                    'ssh_blob': ci['ssh_blob'], 'rp_id': ci['rp_id'],
                    'algo': ci['algo'], 'cose_key': ci['cose_key'],
                    'cred_id': ci.get('cred_id')}
        if not agent_keys:
            self._agent_log_msg(T("No keys for agent."))
            return

        # Подтверждение при старте, если включена галочка
        if self._agent_confirm_var.get():
            lines = []
            for k in sorted(agent_keys, key=str):
                entry = agent_keys[k]
                if entry['type'] == 'hsm':
                    lbl = ""
                    try:
                        info = self.hsm.keyinfo(entry['kid'])
                        if info and info.get('label'):
                            lbl = info['label']
                    except:
                        pass
                    line = f"  HSM ID {entry['kid']}: {entry['name']}"
                    if lbl:
                        line += f" — \"{lbl}\""
                else:
                    line = f"  FIDO2 {entry['rp_id']}: {entry['name']}"
                lines.append(line)
            if not self._confirm(
                T("Confirm"),
                T("Allow these keys for SSH authentication?") + "\n\n" + "\n".join(lines)):
                self._agent_log_msg(T("Agent keys not confirmed."))
                return

        self._agent_log_msg(T("Starting SSH agent..."))

        self._agent_engine = _SshAgentEngine(self, self.hsm, agent_keys,
            approve_fn=self._agent_approve_sign,
            identities_fn=self._agent_pick_keys)
        self._agent_thread = threading.Thread(target=self._agent_engine.run, daemon=True)
        self._agent_thread.start()

        self._agent_running = True
        self._agent_status.set(T("Running (Pageant)"))
        self._btn_agent_start.state(["disabled"])
        self._btn_agent_stop.state(["!disabled"])
        self._btn_agent_test.state(["!disabled"])
        self._agent_log_msg(T("Agent started. Running as Pageant (WM_COPYDATA) + named pipe (OpenSSH)."))
        self._agent_log_msg(T("Open for PuTTY/Kitty/NetBox/WinSCP via Pageant/OpenSSH agent."))
        self._agent_log_msg(T("Close real Pageant: taskkill /f /im pageant.exe"))
        self._agent_log_msg(T("Agent log: ") + AGENT_LOG)

    def _agent_stop(self):
        if not self._agent_running:
            return
        self._agent_log_msg(T("Stopping agent..."))
        if self._agent_engine:
            self._agent_engine.stop()
        self._agent_running = False
        self._agent_status.set(T("Stopped"))
        self._btn_agent_start.state(["!disabled"])
        self._btn_agent_stop.state(["disabled"])
        self._btn_agent_test.state(["disabled"])
        self._agent_log_msg(T("Agent stopped."))

    def _agent_test(self):
        self._agent_log_msg(T("Running test (background thread)..."))

        sel = self._agent_tree.selection()
        target_blobs = []
        if sel and self._agent_engine:
            for sid in sel:
                key = int(sid) if sid.isdigit() else sid
                blob = self._agent_engine._get_pubkey_blob(key)
                if blob:
                    target_blobs.append((sid, blob))
            if target_blobs:
                self._agent_log_msg(f"Testing {len(target_blobs)} selected key(s): {', '.join(str(s) for s, _ in target_blobs)}")

        def _run_test():

            def tlog(msg):
                self.root.after(0, lambda m=msg: self._agent_log_msg(m))

            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            class COPYDATASTRUCT(ctypes.Structure):
                _fields_ = [("dwData", ctypes.c_void_p), ("cbData", ctypes.wintypes.DWORD), ("lpData", ctypes.c_void_p)]

            WNDPROCTYPE = ctypes.WINFUNCTYPE(LRESULT, ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM)
            WM_COPYDATA = 0x004A

            FindWindowW = user32.FindWindowW
            FindWindowW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR]
            FindWindowW.restype = ctypes.wintypes.HWND
            hwnd = FindWindowW("Pageant", "Pageant")
            if not hwnd:
                tlog("✗ " + T("Pageant window not found. Agent not running."))
                return
            tlog("✓ " + T("Pageant window found: HWND 0x") + f"{hwnd:08x}")

            PAGEANT_MAPSIZE = 8192
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

            CreateFileMappingA = kernel32.CreateFileMappingA
            CreateFileMappingA.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_char_p]
            CreateFileMappingA.restype = ctypes.wintypes.HANDLE

            MapViewOfFile = kernel32.MapViewOfFile
            MapViewOfFile.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_size_t]
            MapViewOfFile.restype = ctypes.c_void_p

            UnmapViewOfFile = kernel32.UnmapViewOfFile
            UnmapViewOfFile.argtypes = [ctypes.c_void_p]
            UnmapViewOfFile.restype = ctypes.wintypes.BOOL

            CloseHandle = kernel32.CloseHandle
            CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
            CloseHandle.restype = ctypes.wintypes.BOOL

            PAGE_READWRITE = 0x04
            FILE_MAP_ALL_ACCESS = 0x000F001F

            SendMessageW = user32.SendMessageW
            SendMessageW.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM]
            SendMessageW.restype = LRESULT

            def send(pkt):
                map_name = f"PicoHSMTest-{os.getpid()}-{threading.get_ident()}"
                hmap = CreateFileMappingA(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, PAGEANT_MAPSIZE, map_name.encode())
                if not hmap:
                    tlog("✗ " + T("CreateFileMapping failed (err=") + f"{kernel32.GetLastError()})")
                    return None
                ptr = MapViewOfFile(hmap, FILE_MAP_ALL_ACCESS, 0, 0, 0)
                if not ptr:
                    tlog("✗ " + T("MapViewOfFile failed (err=") + f"{kernel32.GetLastError()})")
                    CloseHandle(hmap)
                    return None
                ctypes.memmove(ptr, pkt, len(pkt))
                name_bytes = map_name.encode() + b'\x00'
                name_buf = ctypes.create_string_buffer(name_bytes)
                cds = COPYDATASTRUCT()
                cds.dwData = 0x80420001
                cds.cbData = ctypes.sizeof(name_buf)
                cds.lpData = ctypes.addressof(name_buf)
                SendMessageW(hwnd, WM_COPYDATA, 0, ctypes.addressof(cds))
                resp_len = struct.unpack(">I", bytes((ctypes.c_ubyte * 4).from_address(ptr)))[0]
                resp_len = min(resp_len, PAGEANT_MAPSIZE - 4)
                resp = bytes((ctypes.c_ubyte * (4 + resp_len)).from_address(ptr))
                UnmapViewOfFile(ptr)
                CloseHandle(hmap)
                return resp

            tlog("\n1. " + T("Requesting key list...") + " (SSH2_AGENTC_REQUEST_IDENTITIES)...")
            pkt = b"\x00\x00\x00\x01\x0b"
            resp = send(pkt)
            if not resp:
                tlog("✗ " + T("No response - agent did not process request"))
            else:
                tlen = struct.unpack(">I", resp[:4])[0]
                mtype = resp[4]
                tlog("   " + T("Response: length=") + f"{tlen}, " + T("message_type=") + f"{mtype}")
                if mtype == 12:
                    nkeys = struct.unpack(">I", resp[5:9])[0]
                    tlog("   " + T("Keys on device: ") + f"{nkeys}")
                    if nkeys > 0:
                        pos = 9
                        first_blob = None
                        for i in range(nkeys):
                            blen = struct.unpack(">I", resp[pos:pos+4])[0]; pos += 4
                            blob = resp[pos:pos+blen]; pos += blen
                            if i == 0:
                                first_blob = blob
                            clen = struct.unpack(">I", resp[pos:pos+4])[0]; pos += 4 + clen
                            alen = struct.unpack(">I", blob[:4])[0]
                            key_type = blob[4:4+alen].decode()
                            fp = base64.b64encode(blob).decode()[:44]
                            tlog(f"   [{i}] {key_type}  {fp}")
                    else:
                        tlog("   " + T("No keys with public part for SSH"))
                else:
                    tlog("   ✗ " + T("Unexpected type: ") + f"{mtype}")

            blobs_to_test = target_blobs or ([("agent", first_blob)] if first_blob else [])
            if resp and mtype == 12 and nkeys > 0 and blobs_to_test:
                for idx, (sid, test_blob) in enumerate(blobs_to_test):
                    tlog(f"\n2.{idx} " + T("Signature test") + f" [{sid}]...")
                    challenge = b"pico-hsm-test-" + os.urandom(4)
                    req = bytes([13])
                    req += struct.pack(">I", len(test_blob)) + test_blob
                    req += struct.pack(">I", 0)
                    req += struct.pack(">I", len(challenge)) + challenge
                    pkt2 = struct.pack(">I", len(req)) + req
                    resp2 = send(pkt2)
                    if resp2:
                        tlen2 = struct.unpack(">I", resp2[:4])[0]
                        mtype2 = resp2[4]
                        tlog("   " + T("Response: length=") + f"{tlen2}, " + T("message_type=") + f"{mtype2}")
                        if mtype2 == 14:
                            pos2 = 5
                            sig_len = struct.unpack(">I", resp2[pos2:pos2+4])[0]; pos2 += 4
                            sig_blob = resp2[pos2:pos2+sig_len]
                            salen = struct.unpack(">I", sig_blob[:4])[0]
                            signame = sig_blob[4:4+salen].decode()
                            rest = sig_blob[4+salen:]
                            if signame.startswith('sk-'):
                                f2_flags = rest[0]
                                f2_counter = struct.unpack(">I", rest[1:5])[0]
                                slen = struct.unpack(">I", rest[5:9])[0]
                                sdat = rest[9:9+slen]
                                tlog(f"   {T('Algorithm: ')} {signame} flags=0x{f2_flags:02x} counter={f2_counter} signature: {len(sdat)} {T('bytes')}")
                            else:
                                slen = struct.unpack(">I", rest[:4])[0]
                                sdat = rest[4:4+slen]
                                tlog(f"   {T('Algorithm: ')} {signame} signature: {len(sdat)} {T('bytes')}")
                            tlog(f"   Sig hex: {sdat.hex()[:48]}...")
                            tlog("   ✓ " + T("Signature successful!"))
                        else:
                            tlog("   ✗ " + T("Unexpected response type: ") + f"{mtype2}")
                    else:
                        tlog("   ✗ " + T("No response to sign request"))

            tlog("\n--- " + T("Test completed") + " ---")

        threading.Thread(target=_run_test, daemon=True).start()
    def _agent_approve_sign(self, kid, name):
        """Ask user to approve a signature request (non-blocking with timeout)."""
        result = [False]
        event = threading.Event()

        def ask():
            entry_line = str(kid)
            if isinstance(kid, int):
                lbl = ""
                try:
                    info = self.hsm.keyinfo(kid)
                    if info and info.get('label'):
                        lbl = info['label']
                except:
                    pass
                entry_line = f"HSM ID {kid} ({name})"
                if lbl:
                    entry_line += f" — \"{lbl}\""
            else:
                entry_line = f"FIDO2 {kid} ({name})"
            r = self._confirm(
                "SSH Agent — Approve Signature",
                f"Sign with key:\n  {entry_line}\n\n"
                "Approve this signature request?",
                btn_yes="Allow", btn_no="Deny")
            result[0] = r
            event.set()

        self.root.after(0, ask)
        while not event.is_set():
            if not self._agent_running:
                return False
            event.wait(timeout=0.5)
        return result[0]

    def _agent_get_pin_dialog(self):
        """Show PIN dialog from agent thread (blocking). Returns PIN or None."""
        result = [None]
        event = threading.Event()
        def ask():
            d = tk.Toplevel(self.root)
            d.title(T("Enter PIN"))
            d.geometry("300x120")
            d.transient(self.root)
            d.attributes('-topmost', True)
            d.lift()
            self.root.deiconify()
            self.root.lift()
            self.root.update_idletasks()
            d.attributes('-topmost', False)
            self._center_dialog(d)
            f = ttk.Frame(d, padding=12)
            f.pack(fill=tk.BOTH, expand=True)
            ttk.Label(f, text=T('PIN:')).pack(anchor=tk.W)
            pin_e = ttk.Entry(f, show='*', width=30)
            pin_e.pack(fill=tk.X, pady=(0,8))
            pin_e.focus()
            pin_e.bind('<Return>', lambda ev: do_ok())
            d.bind('<Escape>', lambda ev: (d.destroy(), event.set()))
            bf = ttk.Frame(f)
            bf.pack(fill=tk.X)
            def do_ok():
                pin = pin_e.get().strip()
                if not pin:
                    return
                result[0] = pin
                d.destroy()
                event.set()
            ttk.Button(bf, text=T("Connect"), command=do_ok).pack(side=tk.RIGHT, padx=4)
            ttk.Button(bf, text=T("Cancel"), command=lambda: (d.destroy(), event.set())).pack(side=tk.RIGHT, padx=4)
            d.protocol("WM_DELETE_WINDOW", lambda: (d.destroy(), event.set()))
        self.root.after(0, ask)
        while not event.is_set():
            if not self._agent_running:
                return None
            event.wait(timeout=0.5)
        return result[0]

    def _agent_pick_keys(self, available):
        """Return all keys (pre-selected in agent tab before start)."""
        return set(available.keys())

    def _on_agent_keys_changed(self, event=None):
        """Called when agent tree selection changes — updates engine keys live."""
        if not self._agent_running or not self._agent_engine:
            return
        sel = self._agent_tree.selection()
        agent_keys = {}
        for sid in sel:
            if sid.isdigit():
                kid = int(sid)
                if kid in self.keys:
                    name, pub = self.keys[kid]
                    if pub is not None and not isinstance(pub, (x25519.X25519PublicKey, x448.X448PublicKey)):
                        agent_keys[kid] = {'type': 'hsm', 'kid': kid, 'name': name, 'pub': pub}
            elif sid.startswith('f2:') and sid in self._f2_agent_creds:
                ci = self._f2_agent_creds[sid]
                agent_keys[sid] = {'type': 'fido2', 'name': ci['user_name'],
                    'ssh_blob': ci['ssh_blob'], 'rp_id': ci['rp_id'],
                    'algo': ci['algo'], 'cose_key': ci['cose_key'],
                    'cred_id': ci.get('cred_id')}
        self._agent_engine.set_active_keys(agent_keys)
        self._agent_log_msg(f"Agent keys updated: {len(agent_keys)} key(s) active")


class _SshAgentEngine:
    def __init__(self, app, hsm, keys, approve_fn=None, identities_fn=None):
        self.app = app
        self.hsm = hsm
        self._active_keys = dict(keys)  # id -> dict with type, name, pub/ssh_blob; replaceable at runtime
        self._approve_fn = approve_fn
        self._identities_fn = identities_fn
        self._running = False
        self._hwnd = 0
        self._pageant_msg_id = 0
        self._user32 = ctypes.windll.user32
        self._kernel32 = ctypes.windll.kernel32
        self._np_stop = threading.Event()
        self._np_thread = None

    def set_active_keys(self, keys):
        self._active_keys = dict(keys)

    def stop(self):
        self._running = False
        self._np_stop.set()
        # Открываем pipe, чтобы разблокировать ConnectNamedPipe
        try:
            kernel32 = self._kernel32
            CreateFileW = kernel32.CreateFileW
            CreateFileW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_void_p]
            CreateFileW.restype = ctypes.wintypes.HANDLE
            GENERIC_READ_WRITE = 0x80000000 | 0x40000000
            OPEN_EXISTING = 3
            h = CreateFileW(r"\\.\pipe\openssh-ssh-agent", GENERIC_READ_WRITE, 0, None, OPEN_EXISTING, 0, None)
            if h and h != ctypes.c_void_p(-1).value:
                kernel32.CloseHandle(h)
        except:
            pass
        if self._hwnd:
            self._user32.DestroyWindow(self._hwnd)
            self._hwnd = 0
        if getattr(self, '_hinstance', None):
            self._user32.UnregisterClassW("Pageant", self._hinstance)
        if self._np_thread and self._np_thread.is_alive():
            self._np_thread.join(timeout=3)

    def run(self):
        self._running = True
        alog(f"[agent] Starting SSH agent, keys={list(self._active_keys.keys())}")
        # Pageant (WM_COPYDATA) window
        self._create_pageant_window()
        if not self._hwnd:
            alog("[agent] FAIL: could not create Pageant window", 'error')
            return
        alog(f"[agent] Pageant window created hwnd=0x{self._hwnd:08x}")
        # OpenSSH named pipe (\\.\pipe\openssh-ssh-agent)
        self._np_stop.clear()
        self._np_thread = threading.Thread(target=self._named_pipe_loop, daemon=True)
        self._np_thread.start()
        alog("[agent] Named pipe thread started: \\\\.\\pipe\\openssh-ssh-agent")
        self._message_loop()
        alog("[agent] Message loop exited")

    def _get_pubkey_blob(self, kid):
        entry = self._active_keys.get(kid)
        if entry is None:
            return None
        if entry['type'] == 'fido2':
            return entry.get('ssh_blob')
        pub = entry.get('pub')
        if pub is None:
            return None
        try:
            import struct
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            def ssh_str(s):
                return struct.pack(">I", len(s)) + s

            if isinstance(pub, ed25519.Ed25519PublicKey):
                raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
                return ssh_str(b"ssh-ed25519") + ssh_str(raw)
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                curve = pub.curve
                if isinstance(curve, ec.SECP256R1):
                    ct = b"nistp256"
                elif isinstance(curve, ec.SECP384R1):
                    ct = b"nistp384"
                elif isinstance(curve, ec.SECP521R1):
                    ct = b"nistp521"
                else:
                    return None
                encoded = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                blob = ssh_str(b"ecdsa-sha2-" + ct) + ssh_str(ct) + ssh_str(encoded)
                return blob
            elif isinstance(pub, rsa.RSAPublicKey):
                nums = pub.public_numbers()
                n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
                if n_bytes[0] & 0x80:
                    n_bytes = b'\x00' + n_bytes
                e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
                if e_bytes[0] & 0x80:
                    e_bytes = b'\x00' + e_bytes
                return ssh_str(b"ssh-rsa") + ssh_str(e_bytes) + ssh_str(n_bytes)
        except:
            pass
        return None

    def _parse_der_sig(self, sig_bytes):
        if not sig_bytes or sig_bytes[0] != 0x30:
            return None
        pos = 2
        if sig_bytes[1] & 0x80:
            pos = 2 + (sig_bytes[1] & 0x7F)
        def read_int(data, start):
            if data[start] != 0x02:
                return None, start
            ilen = data[start+1]
            if ilen & 0x80:
                return None, start
            ival = int.from_bytes(data[start+2:start+2+ilen], "big")
            return ival, start + 2 + ilen
        r, pos = read_int(sig_bytes, pos)
        if r is None:
            return None
        s, _ = read_int(sig_bytes, pos)
        if s is None:
            return None
        return r, s

    def _sign(self, kid, challenge, flags=0):
        entry = self._active_keys.get(kid)
        if entry is None:
            return None
        if entry['type'] == 'fido2':
            return self._fido2_sign(entry, challenge)  # returns (raw_sig, flags_byte, counter) or None
        try:
            from picohsm import Algorithm
            pub = entry.get('pub')
            if pub is None:
                return None

            if isinstance(pub, ed25519.Ed25519PublicKey):
                alog(f"[sign] Ed25519 kid={kid} challenge_len={len(challenge)}")
                schemes = [Algorithm.ALGO_EC_RAW, Algorithm.ALGO_EC_SHA512, Algorithm.ALGO_EC_SHA256]
                sig = None
                for scheme in schemes:
                    try:
                        sig = bytes(self.hsm.sign(kid, challenge, scheme=scheme))
                        alog(f"[sign] Ed25519 scheme={scheme} response: len={len(sig)} hex={sig[:8].hex()}...")
                        if len(sig) > 0:
                            break
                    except Exception as e:
                        alog(f"[sign] Ed25519 scheme={scheme} failed: {e}")
                        sig = None
                if sig is None:
                    alog("[sign] Ed25519 FAIL: all schemes failed", 'error')
                    return None
                if len(sig) == 64:
                    alog("[sign] Ed25519 OK: raw 64 bytes")
                    self._inc_stat('ssh_signs')
                    return sig
                if len(sig) > 64 and sig[0] == 0x30:
                    alog("[sign] Ed25519: DER-wrapped, trying to unpack")
                    parsed = self._parse_der_sig(sig)
                    if parsed:
                        r, s = parsed
                        r_bytes = r.to_bytes(32, 'big')
                        s_bytes = s.to_bytes(32, 'big')
                        result = r_bytes + s_bytes
                        if len(result) == 64:
                            alog("[sign] Ed25519 OK: DER unpacked to 64 bytes")
                            self._inc_stat('ssh_signs')
                            return result
                alog(f"[sign] Ed25519 FAIL: unexpected sig format len={len(sig)} first_byte={sig[0]:02x}", 'error')
                return None
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                alog(f"[sign] ECDSA kid={kid} curve={type(pub.curve).__name__} challenge_len={len(challenge)}")
                sig = self.hsm.sign(kid, challenge, scheme=Algorithm.ALGO_EC_SHA256)
                parsed = self._parse_der_sig(sig)
                if parsed:
                    r, s = parsed
                    curve = pub.curve
                    size = curve.key_size
                    pad = (size + 7) // 8
                    r_bytes = r.to_bytes(pad, "big")
                    s_bytes = s.to_bytes(pad, "big")
                    alog(f"[sign] ECDSA OK: {pad*2} bytes")
                    self._inc_stat('ssh_signs')
                    return r_bytes + s_bytes
                alog(f"[sign] ECDSA FAIL: DER parse failed", 'error')
                return None
            elif isinstance(pub, rsa.RSAPublicKey):
                alog(f"[sign] RSA kid={kid} data_len={len(challenge)} flags={flags}")
                import hashlib
                if flags & 4:
                    hash_bytes = hashlib.sha512(challenge).digest()
                    di = bytes([
                        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                        0x00, 0x04, 0x40
                    ]) + hash_bytes
                elif flags & 2:
                    hash_bytes = hashlib.sha256(challenge).digest()
                    di = bytes([
                        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                        0x00, 0x04, 0x20
                    ]) + hash_bytes
                else:
                    hash_bytes = hashlib.sha1(challenge).digest()
                    di = bytes([
                        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
                    ]) + hash_bytes
                k = (pub.key_size + 7) // 8
                pad_len = k - len(di) - 3
                if pad_len < 8:
                    alog(f"[sign] RSA FAIL: padding too short ({pad_len})", 'error')
                    return None
                padded = b'\x00\x01' + b'\xff' * pad_len + b'\x00' + di
                alog(f"[sign] RSA k={k} di_len={len(di)} pad_len={pad_len} padded_len={len(padded)}")
                result = bytes(self.hsm.sign(kid, padded, scheme=Algorithm.ALGO_RSA_RAW))
                alog(f"[sign] RSA OK: {len(result)} bytes sig_prefix={result[:8].hex()}")
                self._inc_stat('ssh_signs')
                return result
        except Exception as e:
            import traceback
            alog(f"[sign] EXCEPTION kid={kid}: {e}", 'error')
            traceback.print_exc()
        return None

    def _fido2_sign(self, entry, challenge):
        try:
            rp_id = entry['rp_id']
            algo = entry['algo']
            app = self.app
            ctap2 = app._fido2_ctap2 if app else None
            if not ctap2:
                alog("[fido2_sign] no ctap2", 'error')
                return None
            pin = app._fido2_pin_cache if app else None
            if not pin:
                alog("[fido2_sign] no cached pin, prompting user")
                pin = app._agent_get_pin_dialog() if app else None
                if pin:
                    app._fido2_pin_cache = pin
                else:
                    alog("[fido2_sign] pin cancelled", 'error')
                    return None
            from fido2.ctap2.pin import ClientPin
            import hashlib, json, base64, struct
            client_pin = ClientPin(ctap2)
            token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.GET_ASSERTION)
            protocol = client_pin.protocol
            cd = json.dumps({
                'type': 'webauthn.get',
                'challenge': base64.b64encode(challenge).decode(),
                'origin': 'ssh:',
            }).encode()
            cd_hash = hashlib.sha256(cd).digest()
            pin_auth = protocol.authenticate(token, cd_hash)
            alog(f"[fido2_sign] signing for rp_id={rp_id} challenge_len={len(challenge)}")
            # Try with allow_list first; fallback if Pico firmware rejects it
            cred_id_obj = entry.get('cred_id')
            allow = None
            if cred_id_obj:
                if hasattr(cred_id_obj, 'id'):
                    allow = [{'id': bytes(cred_id_obj.id), 'type': 'public-key'}]
                elif isinstance(cred_id_obj, dict):
                    cid = cred_id_obj.get('id', b'')
                    if cid:
                        allow = [{'id': bytes(cid), 'type': 'public-key'}]
            results = None
            if allow:
                try:
                    results = ctap2.get_assertion(
                        rp_id, cd_hash,
                        allow_list=allow,
                        options={'up': True},
                        pin_uv_param=pin_auth,
                        pin_uv_protocol=protocol.VERSION,
                    )
                    alog(f"[fido2_sign] allow_list OK")
                except Exception as al_e:
                    alog(f"[fido2_sign] allow_list failed ({al_e}), retrying without")
                    results = None
            if not results:
                results = ctap2.get_assertion(
                    rp_id, cd_hash,
                    options={'up': True},
                    pin_uv_param=pin_auth,
                    pin_uv_protocol=protocol.VERSION,
                )
            if not results:
                alog("[fido2_sign] no assertion results", 'error')
                return None
            assertion = results[0] if isinstance(results, (list, tuple)) else results
            raw_sig = bytes(assertion.signature)
            # Parse authenticatorData for flags and counter
            auth_data = bytes(assertion.auth_data) if hasattr(assertion, 'auth_data') else b''
            flags_byte = auth_data[32] if len(auth_data) >= 37 else 0x01
            counter = struct.unpack(">I", auth_data[33:37])[0] if len(auth_data) >= 37 else 0
            # Normalize ECDSA DER sig -> raw r||s
            if algo.startswith('sk-ecdsa'):
                parsed = self._parse_der_sig(raw_sig)
                if parsed:
                    r, s = parsed
                    size = 256 if 'nistp256' in algo else 384 if 'nistp384' in algo else 521
                    pad = (size + 7) // 8
                    raw_sig = r.to_bytes(pad, "big") + s.to_bytes(pad, "big")
                    alog(f"[fido2_sign] ECDSA (DER->raw) OK: {pad*2} bytes")
                elif len(raw_sig) == 64:
                    alog(f"[fido2_sign] ECDSA raw sig OK: 64 bytes")
                else:
                    alog(f"[fido2_sign] ECDSA bad sig format len={len(raw_sig)}", 'error')
                    return None
            elif algo.startswith('sk-ed25519') and len(raw_sig) != 64:
                alog(f"[fido2_sign] Ed25519 bad sig len={len(raw_sig)}", 'error')
                return None
            alog(f"[fido2_sign] OK: algo={algo} flags=0x{flags_byte:02x} counter={counter}")
            return (raw_sig, flags_byte, counter)
        except Exception as e:
            import traceback
            alog(f"[fido2_sign] EXCEPTION: {e}", 'error')
            traceback.print_exc()
        return None

    def _handle_message(self, data):
        try:
            return self._handle_message_inner(data)
        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            alog(f"[hmsg] EXCEPTION: {exc}", "error")
            for line in tb.strip().split("\n"):
                alog(f"[hmsg]   {line}", "error")
            try:
                with open(ERROR_LOG, "a", encoding="utf-8") as f:
                    f.write(f"=== _handle_message error ===\n{exc}\n{tb}\n")
            except:
                pass
            return struct.pack(">IBB", 5, 5, 0)

    def _handle_message_inner(self, data):
        if len(data) < 5:
            return None
        msg_type = data[4]
        _MSG_NAMES = {11: 'REQUEST_IDENTITIES', 13: 'SIGN_REQUEST', 1: 'REQUEST_VERSION'}
        alog(f"[msg] << {_MSG_NAMES.get(msg_type, f'UNKNOWN({msg_type})')} data_len={len(data)}")

        if msg_type == 11:
            if self._identities_fn:
                allowed = self._identities_fn(self._active_keys)
                if allowed is None:
                    allowed = set()
                keys_iter = ((k, v) for k, v in self._active_keys.items() if k in allowed)
            else:
                keys_iter = self._active_keys.items()
            entries = b""
            num_keys = 0
            for kid, entry in keys_iter:
                blob = self._get_pubkey_blob(kid)
                if blob:
                    comment = b"FIDO2" if entry.get('type') == 'fido2' else b"pico-hsm"
                    entries += struct.pack(">I", len(blob)) + blob + struct.pack(">I", len(comment)) + comment
                    num_keys += 1
                    alog(f"[ident] kid={kid} type={entry.get('type')} blob_len={len(blob)}")
            resp_data = bytes([12]) + struct.pack(">I", num_keys) + entries
            return struct.pack(">I", len(resp_data)) + resp_data

        elif msg_type == 13:
            pos = 5
            blob_len = struct.unpack(">I", data[pos:pos+4])[0]; pos += 4
            blob = data[pos:pos+blob_len]; pos += blob_len
            data_len = struct.unpack(">I", data[pos:pos+4])[0]; pos += 4
            challenge = data[pos:pos+data_len]; pos += data_len
            flags = struct.unpack(">I", data[pos:pos+4])[0]; pos += 4
            alog(f"[sign] blob_len={blob_len} blob_prefix={blob[:8].hex()} data_len={data_len} flags={flags}")

            # Match blob to our key
            target_kid = None
            for kid in self._active_keys.keys():
                my_blob = self._get_pubkey_blob(kid)
                if my_blob and my_blob == blob:
                    target_kid = kid
                    break
            if target_kid is None:
                alog(f"[sign] no match for blob_len={blob_len}", 'error')
                for kid in self._active_keys.keys():
                    my_blob = self._get_pubkey_blob(kid)
                    if my_blob:
                        alog(f"[sign]   kid={kid} my_blob_len={len(my_blob)} my_prefix={my_blob[:8].hex()}")
                return struct.pack(">IBB", 5, 5, 0)

            if self._approve_fn:
                entry = self._active_keys[target_kid]
                kid_name = entry.get('name', str(target_kid))
                if not self._approve_fn(target_kid, kid_name):
                    alog(f"[sign] kid={target_kid} denied by user")
                    return struct.pack(">IBB", 5, 5, 0)

            alog(f"[sign] calling _sign kid={target_kid} flags={flags}")
            sig = self._sign(target_kid, challenge, flags)
            alog(f"[sign] _sign returned sig_len={len(sig) if sig else 0}")
            if sig is None:
                return struct.pack(">IBB", 5, 5, 0)

            entry = self._active_keys[target_kid]
            if entry['type'] == 'fido2':
                raw_sig, f2_flags, f2_counter = sig
                algo_name = entry['algo'].encode()
                sig_blob = struct.pack(">I", len(algo_name)) + algo_name
                sig_blob += struct.pack("B", f2_flags)
                sig_blob += struct.pack(">I", f2_counter)
                sig_blob += struct.pack(">I", len(raw_sig)) + raw_sig
                alog(f"[msg] >> SK-SIGN_RESPONSE algo={algo_name.decode()} flags=0x{f2_flags:02x} counter={f2_counter} sig_len={len(raw_sig)}")
            else:
                pub = entry.get('pub')
                from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
                if isinstance(pub, ec.EllipticCurvePublicKey):
                    curve = pub.curve
                    if isinstance(curve, ec.SECP256R1):
                        algo_name = b"ecdsa-sha2-nistp256"
                    elif isinstance(curve, ec.SECP384R1):
                        algo_name = b"ecdsa-sha2-nistp384"
                    elif isinstance(curve, ec.SECP521R1):
                        algo_name = b"ecdsa-sha2-nistp521"
                    else:
                        algo_name = b"ecdsa-sha2-nistp256"
                elif isinstance(pub, ed25519.Ed25519PublicKey):
                    algo_name = b"ssh-ed25519"
                    if len(sig) != 64:
                        return struct.pack(">IBB", 5, 5, 0)
                elif isinstance(pub, rsa.RSAPublicKey):
                    if flags & 4:
                        algo_name = b"rsa-sha2-512"
                    elif flags & 2:
                        algo_name = b"rsa-sha2-256"
                    else:
                        algo_name = b"ssh-rsa"
                else:
                    return struct.pack(">IBB", 5, 5, 0)
                sig_blob = struct.pack(">I", len(algo_name)) + algo_name
                sig_blob += struct.pack(">I", len(sig)) + sig
                alog(f"[msg] >> SIGN_RESPONSE algo={algo_name.decode()} sig_len={len(sig)}")
            resp_data = bytes([14]) + struct.pack(">I", len(sig_blob)) + sig_blob
            return struct.pack(">I", len(resp_data)) + resp_data

        elif msg_type == 1:
            return struct.pack(">IBB", 5, 2, 0)

        alog(f"[msg] >> FAILURE (unhandled msg_type={msg_type})")
        return struct.pack(">IBB", 5, 5, 0)

    def _create_pageant_window(self):
        import sys
        def global_exc_hook(exctype, value, tb):
            try:
                with open(ERROR_LOG, "a") as f:
                    f.write("=== global exception hook ===\n")
                    traceback.print_exception(exctype, value, tb, file=f)
            except:
                pass
        sys.excepthook = global_exc_hook

        user32 = self._user32
        kernel32 = self._kernel32

        class COPYDATASTRUCT(ctypes.Structure):
            _fields_ = [("dwData", ctypes.c_void_p), ("cbData", ctypes.wintypes.DWORD), ("lpData", ctypes.c_void_p)]

        WM_COPYDATA = 0x004A
        WNDPROCTYPE = ctypes.WINFUNCTYPE(LRESULT, ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM)

        GetLastError = kernel32.GetLastError
        GetLastError.argtypes = []
        GetLastError.restype = ctypes.wintypes.DWORD
        SendMessageW = user32.SendMessageW
        SendMessageW.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM]
        SendMessageW.restype = LRESULT
        DefWindowProcW = user32.DefWindowProcW
        DefWindowProcW.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM]
        DefWindowProcW.restype = LRESULT

        UnregisterClassW = user32.UnregisterClassW
        UnregisterClassW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.HINSTANCE]
        UnregisterClassW.restype = ctypes.wintypes.BOOL

        engine = self
        self._wndproc_refs = []  # keep GC from collecting ctypes callbacks

        # Настоящий Pageant-протокол использует shared memory.
        # WM_COPYDATA.lpData = имя маппинга (например b"quest00001234\x00")
        # SSH-пакет лежит в shared memory, туда же пишется ответ.
        PAGEANT_MAPSIZE = 8192

        OpenFileMappingA   = kernel32.OpenFileMappingA
        OpenFileMappingA.argtypes  = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.c_char_p]
        OpenFileMappingA.restype   = ctypes.wintypes.HANDLE

        MapViewOfFile      = kernel32.MapViewOfFile
        MapViewOfFile.argtypes     = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
                                      ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_size_t]
        MapViewOfFile.restype      = ctypes.c_void_p

        UnmapViewOfFile    = kernel32.UnmapViewOfFile
        UnmapViewOfFile.argtypes   = [ctypes.c_void_p]
        UnmapViewOfFile.restype    = ctypes.wintypes.BOOL

        CloseHandle        = kernel32.CloseHandle
        CloseHandle.argtypes       = [ctypes.wintypes.HANDLE]
        CloseHandle.restype        = ctypes.wintypes.BOOL

        FILE_MAP_ALL_ACCESS = 0x000F001F

        PostQuitMessage = user32.PostQuitMessage
        PostQuitMessage.argtypes = [ctypes.c_int]
        PostQuitMessage.restype = None

        @WNDPROCTYPE
        def wndproc(hwnd, msg, wparam, lparam):
            try:
                if msg == 0x0002:  # WM_DESTROY
                    PostQuitMessage(0)
                    return 0
                if msg == WM_COPYDATA and lparam:
                    cds = ctypes.cast(lparam, ctypes.POINTER(COPYDATASTRUCT)).contents
                    # lpData — имя shared memory маппинга (ANSI-строка с нулём)
                    map_name_ptr = ctypes.cast(cds.lpData, ctypes.c_char_p)
                    map_name = map_name_ptr.value  # bytes до null-terminator
                    alog(f"[shm] WM_COPYDATA map_name={map_name!r}")

                    hmap = OpenFileMappingA(FILE_MAP_ALL_ACCESS, False, map_name)
                    if not hmap:
                        err = GetLastError()
                        alog(f"[shm] OpenFileMapping FAILED for {map_name!r}, err={err}", "error")
                        return 1

                    ptr = MapViewOfFile(hmap, FILE_MAP_ALL_ACCESS, 0, 0, 0)
                    if not ptr:
                        alog(f"[shm] MapViewOfFile FAILED", "error")
                        CloseHandle(hmap)
                        return 1

                    try:
                        # Читаем SSH-пакет из shared memory
                        shm = (ctypes.c_ubyte * PAGEANT_MAPSIZE).from_address(ptr)
                        raw = bytes(shm)
                        pkt_len = struct.unpack(">I", raw[:4])[0]
                        pkt_len = min(pkt_len, PAGEANT_MAPSIZE - 4)
                        ssh_data = raw[:4 + pkt_len]
                        alog(f"[shm] Read {4 + pkt_len} bytes from shm, msg_type={raw[4] if pkt_len>0 else -1}")

                        # Обрабатываем SSH-пакет
                        result = engine._handle_message(ssh_data)

                        # Пишем ответ обратно в shared memory
                        if result and len(result) <= PAGEANT_MAPSIZE:
                            ctypes.memmove(ptr, result, len(result))
                            alog(f"[shm] Wrote {len(result)} bytes response to shm")
                        else:
                            # Пишем FAILURE
                            fail = struct.pack(">IBB", 5, 5, 0)
                            ctypes.memmove(ptr, fail, len(fail))
                    finally:
                        UnmapViewOfFile(ptr)
                        CloseHandle(hmap)

                    return 1
                return DefWindowProcW(hwnd, msg, wparam, lparam)
            except Exception:
                try:
                    with open(ERROR_LOG, "a") as f:
                        f.write("=== wndproc error ===\n")
                        traceback.print_exc(file=f)
                except:
                    pass
                return 1
        self._wndproc_refs.append(wndproc)

        GetModuleHandleW = kernel32.GetModuleHandleW
        GetModuleHandleW.argtypes = [ctypes.wintypes.LPCWSTR]
        GetModuleHandleW.restype = ctypes.wintypes.HINSTANCE
        hinstance = GetModuleHandleW(None)
        self._hinstance = hinstance

        class WNDCLASS(ctypes.Structure):
            _fields_ = [
                ("style", ctypes.wintypes.UINT),
                ("lpfnWndProc", ctypes.c_void_p),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", ctypes.wintypes.HINSTANCE),
                ("hIcon", ctypes.wintypes.HICON),
                ("hCursor", ctypes.wintypes.HCURSOR),
                ("hbrBackground", ctypes.wintypes.HBRUSH),
                ("lpszMenuName", ctypes.wintypes.LPCWSTR),
                ("lpszClassName", ctypes.wintypes.LPCWSTR),
            ]

        wc = WNDCLASS()
        wc.style = 0
        wc.lpfnWndProc = ctypes.cast(wndproc, ctypes.c_void_p)
        wc.cbClsExtra = 0
        wc.cbWndExtra = 0
        wc.hInstance = hinstance
        wc.hIcon = 0
        wc.hCursor = 0
        wc.hbrBackground = 0
        wc.lpszMenuName = None
        wc.lpszClassName = "Pageant"

        atom = user32.RegisterClassW(ctypes.byref(wc))
        if not atom:
            err1 = GetLastError()
            alog(f"[shm] RegisterClassW failed, err={err1}, unregistering old class and retrying...", "warning")
            if user32.UnregisterClassW("Pageant", hinstance):
                atom = user32.RegisterClassW(ctypes.byref(wc))
                if not atom:
                    err2 = GetLastError()
                    alog(f"[shm] RegisterClassW failed twice, err={err2}", "error")
                    return
            else:
                err2 = GetLastError()
                alog(f"[shm] UnregisterClassW failed, err={err2}, cannot create window", "error")
                return

        CreateWindowExW = user32.CreateWindowExW
        CreateWindowExW.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.INT, ctypes.wintypes.INT, ctypes.wintypes.INT, ctypes.wintypes.INT, ctypes.wintypes.HWND, ctypes.wintypes.HMENU, ctypes.wintypes.HINSTANCE, ctypes.wintypes.LPVOID]
        CreateWindowExW.restype = ctypes.wintypes.HWND

        self._hwnd = CreateWindowExW(
            0, "Pageant", "Pageant", 0x00CF0000,
            -2147483648, -2147483648, -2147483648, -2147483648,
            0, 0, hinstance, 0
        )
        if self._hwnd:
            user32.ShowWindow(self._hwnd, 0)
            # Пропускаем WM_COPYDATA от процессов с низким уровнем целостности (UIPI)
            ChangeWindowMessageFilterEx = user32.ChangeWindowMessageFilterEx
            ChangeWindowMessageFilterEx.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.wintypes.DWORD, ctypes.c_void_p]
            ChangeWindowMessageFilterEx.restype = ctypes.wintypes.BOOL
            ChangeWindowMessageFilterEx(self._hwnd, WM_COPYDATA, 1, None)
            self._pageant_msg_id = user32.RegisterWindowMessageW("PageantMessage")

    def _message_loop(self):
        user32 = self._user32
        msg = ctypes.wintypes.MSG()
        while self._running:
            ret = user32.GetMessageW(ctypes.byref(msg), 0, 0, 0)
            if ret == 0:
                break
            if ret == -1:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def _named_pipe_loop(self):
        kernel32 = self._kernel32
        PIPE_NAME = r"\\.\pipe\openssh-ssh-agent"
        PIPE_ACCESS_DUPLEX = 0x00000003
        PIPE_TYPE_MESSAGE = 0x00000004
        PIPE_READMODE_MESSAGE = 0x00000002
        PIPE_WAIT = 0x00000000
        PIPE_UNLIMITED_INSTANCES = 255
        BUFSIZE = 65536
        NMPWAIT_USE_DEFAULT_WAIT = 0
        INVALID_HANDLE = ctypes.c_void_p(-1).value

        CreateNamedPipeW = kernel32.CreateNamedPipeW
        CreateNamedPipeW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_void_p]
        CreateNamedPipeW.restype = ctypes.wintypes.HANDLE

        ConnectNamedPipe = kernel32.ConnectNamedPipe
        ConnectNamedPipe.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
        ConnectNamedPipe.restype = ctypes.wintypes.BOOL

        DisconnectNamedPipe = kernel32.DisconnectNamedPipe
        DisconnectNamedPipe.argtypes = [ctypes.wintypes.HANDLE]
        DisconnectNamedPipe.restype = ctypes.wintypes.BOOL

        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        CloseHandle.restype = ctypes.wintypes.BOOL

        ReadFile = kernel32.ReadFile
        ReadFile.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p]
        ReadFile.restype = ctypes.wintypes.BOOL

        WriteFile = kernel32.WriteFile
        WriteFile.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p]
        WriteFile.restype = ctypes.wintypes.BOOL

        while not self._np_stop.is_set():
            hpipe = CreateNamedPipeW(
                PIPE_NAME,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUFSIZE, BUFSIZE,
                NMPWAIT_USE_DEFAULT_WAIT,
                None
            )
            if hpipe == INVALID_HANDLE:
                err = ctypes.windll.kernel32.GetLastError()
                alog(f"[pipe] CreateNamedPipeW failed: {err}", 'error')
                break

            alog("[pipe] Waiting for client...")
            ok = ConnectNamedPipe(hpipe, None)
            if not ok:
                err = ctypes.windll.kernel32.GetLastError()
                if err != 535:  # ERROR_PIPE_CONNECTED (client already connected)
                    alog(f"[pipe] ConnectNamedPipe failed: {err}", 'error')
                    CloseHandle(hpipe)
                    continue

            # Read request
            read_buf = (ctypes.c_ubyte * BUFSIZE)()
            nread = ctypes.wintypes.DWORD(0)
            ok = ReadFile(hpipe, read_buf, BUFSIZE, ctypes.byref(nread), None)
            if not ok or nread.value < 4:
                err = ctypes.windll.kernel32.GetLastError()
                alog(f"[pipe] ReadFile failed: {err} nread={nread.value}", 'error')
                DisconnectNamedPipe(hpipe)
                CloseHandle(hpipe)
                continue

            raw = bytes(read_buf[:nread.value])
            pkt_len_buf = raw[:4]
            pkt_len = struct.unpack(">I", pkt_len_buf)[0]
            ssh_data = raw[:4 + pkt_len]
            alog(f"[pipe] << Request len={len(ssh_data)}")

            result = self._handle_message(ssh_data)
            if result:
                resp_len = min(len(result), BUFSIZE)
                nwritten = ctypes.wintypes.DWORD(0)
                ok = WriteFile(hpipe, bytes(result), resp_len, ctypes.byref(nwritten), None)
                alog(f"[pipe] >> Response len={nwritten.value}")
                if not ok:
                    err = ctypes.windll.kernel32.GetLastError()
                    alog(f"[pipe] WriteFile failed: {err}", 'error')
            else:
                alog("[pipe] >> No response", 'error')

            DisconnectNamedPipe(hpipe)
            CloseHandle(hpipe)

        alog("[pipe] Named pipe loop exited")



def _ssh_str(data):
    if isinstance(data, str):
        data = data.encode()
    return struct.pack(">I", len(data)) + data


def _fido2_build_pubkey_blob(algo, raw_bytes):
    parts = [_ssh_str(algo), _ssh_str(raw_bytes)]
    return b"".join(parts)



if __name__ == "__main__":
    fido2_only = '--fido2-only' in sys.argv
    if not fido2_only:
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
                fido2_only = cfg.get('fido2_only', False)
        except:
            pass
    if not ctypes.windll.shell32.IsUserAnAdmin():
        script = os.path.abspath(__file__)
        params = f'"{script}" --fido2-only' if fido2_only else f'"{script}"'
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, os.path.dirname(script), 1
        )
        if result > 32:
            sys.exit(0)
    root = tk.Tk()
    PicoHSMGUI(root, fido2_only=fido2_only)
    root.mainloop()
