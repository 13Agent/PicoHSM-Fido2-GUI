<p align="right">
  <a href="README.md">English</a> ·
  <a href="README.ru.md">Русский</a> ·
  <a href="README.he.md">עברית</a>
</p>

# Pico HSM Manager

A Windows GUI application for managing **Pico HSM** and **Pico FIDO2** devices — keys, certificates, and built-in SSH agent.

## Quick Start

1. Download `PicoHSMManager.exe` from [Releases](../../releases)
2. Run it (administrator privileges required for FIDO2 and SSH agent)
3. Connect your device, enter PIN
4. Manage keys, certificates, and the SSH agent

## Features

### Pico HSM
- **Key generation**: RSA (2048–4096), EC (secp256r1/384r1/521r1/256k1, brainpoolP256r1/384r1/512r1, Ed25519, Ed448), ECDH (X25519, X448), AES (128–256)
- View & export public keys (PEM, SSH authorized_keys format)
- Set key labels (tags)
- View EE certificates (CVC), write CA certificates (CVC)
- Factory reset with new PIN/SO PIN
- Change PIN / SO PIN
- Device info (firmware version, memory, PIN retries)
- Press-to-Confirm toggle

### Pico FIDO2
- Register and verify WebAuthn credentials
- Manage resident (discoverable) credentials
- Export SSH public keys (`sk-ecdsa-sha2-nistp256@openssh.com` / `sk-ed25519@openssh.com`)
- Change FIDO2 PIN, factory reset
- Device info

### Built-in SSH Agent
- Compatible with **Pageant** (WM_COPYDATA) — PuTTY, KiTTY, NetBox, WinSCP
- Compatible with **OpenSSH** (named pipe `\\.\pipe\openssh-ssh-agent`) — `ssh.exe`
- Supports both Pico HSM and Pico FIDO2 keys
- Multi-key selection, per-signature approval prompt
- Auto-start on device connect
- Built-in agent test tool

### Interface
- Languages: English, Russian, Hebrew
- Dark & light themes
- Window geometry and settings persistence

## System Requirements
- Windows 10 / 11 (x64)
- OpenSSH Client (built-in on Windows 10 1809+) — only needed for `ssh.exe` integration
- Administrator privileges (for FIDO2 HID access and named pipe SSH agent)

## Notes
- If you have the real Pageant running, close it first: `taskkill /f /im pageant.exe`
- Logs: `%TEMP%\hsm_agent.log` and `%TEMP%\hsm_agent_crash.log`
- Config: `hsm_guir.json` (created next to the executable)

## License
MIT
