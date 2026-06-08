<p align="right">
  <a href="README.md">English</a> ·
  <a href="README.ru.md">Русский</a> ·
  <a href="README.he.md">עברית</a>
</p>

# Pico HSM Manager (hsm_guir.py)

A universal Windows GUI for managing **Pico HSM** and **Pico FIDO2** devices.

## Features

### Pico HSM
- PIN-based connection
- Key generation: RSA (2048/3072/4096), EC (secp256r1/384r1/521r1/256k1, brainpoolP256r1/384r1/512r1, Ed25519, Ed448), ECDH (X25519, X448), AES (128/192/256)
- View public keys (PEM, SSH format)
- Export SSH keys (clipboard / file)
- Set key labels
- View EE certificates (CVC)
- Write CA certificates (CVC)
- Delete keys
- Factory reset with PIN/SO PIN change
- Change PIN / SO PIN
- Device info (firmware version, memory, PIN retries)
- Press-to-Confirm control

### Pico FIDO2
- HID connection
- Register WebAuthn credentials
- Verify (get assertion)
- Manage resident keys
- Export SSH keys (sk-ecdsa-sha2-nistp256@openssh.com / sk-ed25519@openssh.com)
- Change FIDO2 PIN
- Factory reset

### SSH Agent
- Built-in SSH agent compatible with **Pageant** (WM_COPYDATA) and **OpenSSH** (named pipe `\\.\pipe\openssh-ssh-agent`)
- Supports both Pico HSM and Pico FIDO2 keys
- Multi-key selection for the agent
- Optional signature approval prompt
- Auto-start on connect
- GUI agent test (key list, test signature)

### Interface
- Languages: English, Russian, Hebrew
- Dark and light themes
- Window geometry and settings persistence

## Dependencies

- Python 3.7+
- `picohsm` — Pico HSM library
- `cryptography` — cryptographic operations
- `cvc` — CVC certificate handling
- `tkinter` — included with Python (Windows)
- `fido2` (optional) — Pico FIDO2 support
- `cbor2` or `cbor` (optional, for fido2)

Install dependencies:

```bash
pip install picohsm cryptography cvc fido2 cbor2
```

## Usage

### Pre-built EXE

Download `PicoHSMManager.exe` from [releases](../../releases) — run directly (no Python required).

### From source

```bash
pip install picohsm cryptography cvc fido2 cbor2
python hsm_guir.py
```

When launched without administrator privileges, the script auto-elevates (required for FIDO2 HID access and SSH agent).

### Modes

Switch between **Pico HSM** and **Pico FIDO2** modes via the dropdown in the top panel. The application auto-detects the connected device.

### SSH Agent

1. Connect to your device.
2. Switch to the **SSH Agent** tab.
3. Select keys from the list (Ctrl+Click / Shift+Click for multi-select).
4. Click **Start**.

The agent is accessible from:
- PuTTY / Kitty / NetBox / WinSCP — via Pageant (WM_COPYDATA)
- OpenSSH (ssh.exe) — via named pipe `\\.\pipe\openssh-ssh-agent`

If you have the real Pageant running, stop it first:
```
taskkill /f /im pageant.exe
```

## Configuration

Config file: `hsm_guir.json` (auto-created in the script directory).

Parameters:
- `geometry` — window position and size
- `theme` — "light" or "dark"
- `lang` — "en", "ru", "he"

Logs:
- `%TEMP%\hsm_agent.log` — main log
- `%TEMP%\hsm_agent_crash.log` — SSH agent error log

## Building EXE

```bash
pip install pyinstaller
python -m PyInstaller --clean --onefile --uac-admin --windowed --name "PicoHSMManager" hsm_guir.py
```

The executable will be in `dist/`.

## Peripheral dependencies

- **pkcs11-tool.exe** (from [OpenSC](https://github.com/OpenSC/OpenSC/wiki)) — optional, used for refining EC curve names. Default path: `C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe`. If missing, key types are determined from CVC certificates.

## Notes

- FIDO2 HID access requires administrator privileges.
- SSH agent via OpenSSH named pipe requires Windows 10 1809+ with the OpenSSH Client component installed.
- Conflicts may occur when used alongside the real Pageant — run only one instance.

## License

MIT
