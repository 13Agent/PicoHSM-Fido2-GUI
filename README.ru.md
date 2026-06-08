<p align="right">
  <a href="README.md">English</a> ·
  <a href="README.ru.md">Русский</a> ·
  <a href="README.he.md">עברית</a>
</p>

# Pico HSM Manager

Графическое приложение для Windows для управления устройствами **Pico HSM** и **Pico FIDO2** — ключами, сертификатами и встроенным SSH-агентом.

## Быстрый старт

1. Скачайте `PicoHSMManager.exe` из [Releases](../../releases)
2. Запустите (требуются права администратора для FIDO2 и SSH-агента)
3. Подключите устройство, введите PIN
4. Управляйте ключами, сертификатами и SSH-агентом

## Возможности

### Pico HSM
- **Создание ключей**: RSA (2048–4096), EC (secp256r1/384r1/521r1/256k1, brainpoolP256r1/384r1/512r1, Ed25519, Ed448), ECDH (X25519, X448), AES (128–256)
- Просмотр и экспорт публичных ключей (PEM, SSH authorized_keys)
- Установка меток ключей
- Просмотр EE-сертификатов (CVC), запись CA-сертификатов (CVC)
- Сброс устройства (Factory Reset) с установкой нового PIN/SO PIN
- Смена PIN и SO PIN
- Информация об устройстве (версия прошивки, память, попытки PIN)
- Включение/отключение Press-to-Confirm

### Pico FIDO2
- Регистрация и проверка WebAuthn учётных записей
- Управление резидентными (discoverable) credential'ами
- Экспорт SSH-ключей (`sk-ecdsa-sha2-nistp256@openssh.com` / `sk-ed25519@openssh.com`)
- Смена PIN FIDO2, сброс устройства
- Информация об устройстве

### Встроенный SSH-агент
- Совместим с **Pageant** (WM_COPYDATA) — PuTTY, KiTTY, NetBox, WinSCP
- Совместим с **OpenSSH** (named pipe `\\.\pipe\openssh-ssh-agent`) — `ssh.exe`
- Поддерживает ключи как Pico HSM, так и Pico FIDO2
- Выбор нескольких ключей, запрос подтверждения каждой подписи
- Автостарт при подключении устройства
- Встроенный тест агента

### Интерфейс
- Языки: русский, English, עברית
- Тёмная и светлая темы
- Сохранение положения и размера окна

## Системные требования
- Windows 10 / 11 (x64)
- OpenSSH Client (встроен в Windows 10 1809+) — требуется только для интеграции с `ssh.exe`
- Права администратора (для HID-доступа к FIDO2 и работы SSH-агента через named pipe)

## Примечания
- Если запущен настоящий Pageant, закройте его: `taskkill /f /im pageant.exe`
- Логи: `%TEMP%\hsm_agent.log` и `%TEMP%\hsm_agent_crash.log`
- Настройки: `hsm_guir.json` (создаётся рядом с исполняемым файлом)

## Лицензия
MIT
