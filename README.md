# Lightweight File Encryption Tool
[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.com/paypalme/GUNPANICHTUNSKUL)

A simple, offline-first file and folder encryption tool.  
Designed to protect your data **locally before upload or sharing**.

No accounts. No cloud. No telemetry.

---

## Features

- AES-256-GCM authenticated encryption
- Password-based key derivation using Scrypt
- Random salt and nonce per file
- Tamper detection (authenticated encryption)
- Works fully offline
- Simple GUI (PyQt6)

---

## How It Works

Files are encrypted locally on your machine.  
Your password is never stored or transmitted anywhere.

If the password is lost, the data **cannot be recovered**.

---

## Usage

### Encrypt
1. Select file or folder
2. Enter password
3. Click **Encrypt**

### Decrypt
1. Select encrypted file
2. Enter password
3. Click **Decrypt**

---

## Build From Source

### Install Dependencies

```bash
pip install -r package.txt
