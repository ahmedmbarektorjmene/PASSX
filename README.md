<p align="center">
  <img src="assets/logo.png" alt="PassX Logo" width="128" height="128">
</p>

<h1 align="center">PassX</h1>

<p align="center">
  <strong>A secure, zero-knowledge password manager with TPM integration</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#security">Security</a> •
  <a href="#installation">Installation</a> •
  <a href="#building-from-source">Build</a> •
  <a href="#license">License</a>
</p>

---

## Overview

**PassX** is an open-source, offline-first password manager built entirely in Rust. It uses hardware-backed encryption via TPM 2.0 (when available), a native Slint GUI, and strong cryptographic primitives to keep your credentials safe — with zero reliance on cloud services or third-party servers.

## Features

- 🔐 **Zero-Knowledge Architecture** — Your master password never leaves your device. All encryption and decryption happens locally.
- 🛡️ **TPM 2.0 Integration** — Optionally seal vault keys to your device's Trusted Platform Module for hardware-backed security.
- 🔑 **Strong Cryptography** — ChaCha20-Poly1305 authenticated encryption, Argon2id key derivation, HKDF key expansion, and Ed25519 signing.
- 🕐 **TOTP Authenticator** — Built-in two-factor authentication code generator with QR code scanning support.
- 🖥️ **Native Desktop UI** — Built with [Slint](https://slint.dev/), a pure-Rust GUI framework. No Electron, no web views.
- 🌙 **Dark & Light Themes** — Automatically follows your system appearance.
- 📋 **Secure Clipboard** — Copies credentials to your clipboard with automatic clearing.
- 🔄 **Import / Export** — Supports CSV and JSON formats for easy migration.
- 📦 **Portable Mode** — Run directly from a USB drive with no installation required.
- 🔄 **Auto-Updates** — Built-in self-update mechanism.
- 🗑️ **Trash & Recovery** — Deleted entries go to trash before permanent removal.
- 🔒 **Password Generator** — Generate strong, customizable passwords on the fly.

## Security

PassX employs multiple layers of defense:

| Layer | Details |
|---|---|
| **Encryption** | ChaCha20-Poly1305 (AEAD) with unique nonces per entry |
| **Key Derivation** | Argon2id with configurable memory/time cost |
| **Key Expansion** | HKDF-SHA256 for deriving sub-keys |
| **Memory Protection** | Secrets are zeroized on drop via the `zeroize` crate; locked memory pages on Windows |
| **TPM Sealing** | Vault keys can be sealed to TPM 2.0 via Windows NCrypt APIs |
| **Anti-Debug** | Detects attached debuggers and terminates on detection |
| **Process Hardening** | DACL restrictions, process mitigation policies, single-instance enforcement, and thread hardening |
| **Antivirus Check** | Verifies antivirus software is active at launch |
| **Signing** | Ed25519 signatures for vault integrity verification |

## Installation

### Pre-built Installer (Windows)

Download the latest `.msi` installer from the [Releases](https://github.com/AhmedMBarek/PASSX/releases) page and run it.

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/) (stable, 2021 edition)
- Windows 10/11 (PassX uses native Windows APIs)

### Build

```bash
# Clone the repository
git clone https://github.com/AhmedMBarek/PASSX.git
cd PASSX

# Build in release mode
cargo build --release
```

The compiled binary will be at `target/release/passx.exe`.

### Run Tests

```bash
cargo test
```

## Project Structure

```
PASSX/
├── src/
│   ├── main.rs            # Entry point — security checks, TPM init, UI launch
│   ├── lib.rs             # Module declarations
│   ├── crypto/            # Encryption, key derivation, signing
│   ├── memory/            # Secure memory handling & zeroization
│   ├── security/          # Process hardening, anti-debug, DACL
│   ├── tpm/               # TPM 2.0 key sealing via NCrypt
│   ├── vault/             # Vault storage, entries, CRUD operations
│   ├── session/           # Session management & locking
│   ├── io/                # Import/export (CSV, JSON)
│   ├── runtime/           # Runtime integrity & monitoring
│   └── ui/                # Slint GUI — screens, components, bridge logic
├── assets/                # Icons, logos, SVG assets
├── tests/                 # Integration, crypto, memory, and adversarial tests
├── wix/                   # WiX installer configuration
├── scripts/               # Code signing utilities
├── Cargo.toml             # Dependencies & project metadata
└── LICENSE                # GNU GPLv3
```

## Tech Stack

| Category | Technology |
|---|---|
| Language | Rust (2021 edition) |
| GUI | [Slint](https://slint.dev/) |
| Encryption | ChaCha20-Poly1305, Argon2id, HKDF, Ed25519 |
| Platform APIs | Windows crate (NCrypt, DACL, Mitigation Policies) |
| TOTP | totp-rs with QR code support |
| Serialization | serde, bincode, serde_json, CSV |
| Async | Tokio |
| Testing | proptest, tempfile |

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

PassX is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

```
PassX - A secure open-source password manager
Copyright (C) 2026  Ahmed Mbarek
```

---

<p align="center">
  Made with 🦀 Rust and ❤️ by <a href="https://github.com/AhmedMBarek">Ahmed Mbarek</a>
</p>
