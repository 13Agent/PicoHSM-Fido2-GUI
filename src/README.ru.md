<p align="right">
  <a href="README-source.md">English</a> ·
  <a href="README-source.ru.md">Русский</a> ·
  <a href="README-source.he.md">עברית</a>
</p>

# Pico HSM Manager (hsm_guir.py)

Универсальный графический интерфейс для управления устройствами **Pico HSM** и **Pico FIDO2** на Windows.

## Возможности

### Pico HSM
- Подключение по PIN-коду
- Создание ключей: RSA (2048/3072/4096), EC (secp256r1/384r1/521r1/256k1, brainpoolP256r1/384r1/512r1, Ed25519, Ed448), ECDH (X25519, X448), AES (128/192/256)
- Просмотр публичных ключей (PEM, SSH-формат)
- Экспорт SSH-ключей (копирование в буфер / сохранение в файл)
- Установка меток (label) ключей
- Просмотр EE-сертификатов (CVC)
- Запись CA-сертификатов (CVC)
- Удаление ключей
- Сброс устройства (Factory Reset) со сменой PIN/SO PIN
- Смена PIN / SO PIN
- Информация об устройстве (версия прошивки, память, попытки PIN)
- Управление Press-to-Confirm

### Pico FIDO2
- Подключение через HID
- Регистрация WebAuthn credential'ов
- Проверка (get assertion)
- Управление резидентными ключами
- Экспорт SSH-ключей (sk-ecdsa-sha2-nistp256@openssh.com / sk-ed25519@openssh.com)
- Смена PIN FIDO2
- Сброс устройства

### SSH-агент
- Встроенный SSH-агент, совместимый с **Pageant** (WM_COPYDATA) и **OpenSSH** (named pipe `\\.\pipe\openssh-ssh-agent`)
- Поддержка ключей как с Pico HSM, так и с Pico FIDO2
- Выбор множества ключей для агента
- Запрос подтверждения на каждую операцию подписи (опционально)
- Автостарт при подключении
- GUI-тест агента (список ключей, тестовая подпись)

### Интерфейс
- Двуязычный интерфейс: Русский / English / עברית
- Тёмная и светлая темы
- Сохранение геометрии окна и настроек

## Зависимости

- Python 3.7+
- `picohsm` — библиотека для работы с Pico HSM
- `cryptography` — криптографические операции
- `cvc` — работа с CVC-сертификатами
- `tkinter` — входит в состав Python (Windows)
- `fido2` (опционально) — поддержка Pico FIDO2
- `cbor2` или `cbor` (опционально, для fido2)

Установка зависимостей:

```bash
pip install picohsm cryptography cvc fido2 cbor2
```

## Использование

### Готовая сборка (EXE)

Скачайте `PicoHSMManager.exe` из [releases](../../releases) — запускайте напрямую (без Python).

### Из исходного кода

```bash
pip install picohsm cryptography cvc fido2 cbor2
python hsm_guir.py
```

При запуске без прав администратора скрипт запросит повышение привилегий (требуется для HID-доступа к FIDO2 и для работы SSH-агента).

### Режимы

Переключение между режимами **Pico HSM** и **Pico FIDO2** — через выпадающий список в верхней панели. Приложение автоматически определяет подключённое устройство.

### SSH-агент

1. Подключитесь к устройству.
2. Перейдите на вкладку **SSH Agent**.
3. Выберите ключи из списка (Ctrl+Click / Shift+Click для множественного выбора).
4. Нажмите **Start**.

Агент будет доступен:
- PuTTY / Kitty / NetBox / WinSCP — через Pageant (WM_COPYDATA)
- OpenSSH (ssh.exe) — через named pipe `\\.\pipe\openssh-ssh-agent`

Если у вас запущен настоящий Pageant, его нужно остановить:
```
taskkill /f /im pageant.exe
```

## Конфигурация

Файл настроек: `hsm_guir.json` (создаётся автоматически в директории скрипта).

Параметры:
- `geometry` — положение и размер окна
- `theme` — "light" или "dark"
- `lang` — "en", "ru", "he"

Логи:
- `%TEMP%\hsm_agent.log` — основной лог
- `%TEMP%\hsm_agent_crash.log` — лог ошибок SSH-агента

## Сборка EXE

```bash
pip install pyinstaller
python -m PyInstaller --clean --onefile --uac-admin --windowed --name "PicoHSMManager" hsm_guir.py
```

Готовый `.exe` появится в `dist/`.

## Зависимости (периферийные)

- **pkcs11-tool.exe** (из [OpenSC](https://github.com/OpenSC/OpenSC/wiki)) — опционально, используется для уточнения названий кривых у EC-ключей. Путь по умолчанию: `C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe`. Если отсутствует, типы ключей определяются из CVC-сертификатов.

## Примечания

- FIDO2 HID-доступ требует прав администратора.
- Для работы SSH-агента через named pipe OpenSSH требуется Windows 10 1809+ с установленным компонентом OpenSSH Client.
- При одновременном использовании с настоящим Pageant возможны конфликты — используйте только один экземпляр.

## Лицензия

MIT
