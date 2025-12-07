#!/usr/bin/env python3
"""
Folder Encryptor GUI
- Cross-platform desktop app using PyQt6
- Encrypts an entire folder into a single .fenc file (zip + AES-256-GCM)
- Decrypts a .fenc file back to a folder

Security notes:
- Uses scrypt KDF (N=2**15, r=8, p=1) with 16-byte salt -> 32-byte key
- AES-256-GCM with 12-byte nonce and 16-byte auth tag
- Authenticated encryption (detects wrong password / tampering)

File format:
MAGIC(5) | VERSION(1) | SALT(16) | NONCE(12) | CIPHERTEXT(...) | TAG(16)

Dependencies:
  pip install PyQt6 cryptography

Run:
  python folder_encryptor_gui.py
"""
from __future__ import annotations
import os
import sys
import zipfile
import tempfile
from pathlib import Path

from PyQt6 import QtGui, QtWidgets
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

MAGIC = b"FENC1"  # 5 bytes
VERSION = b"\x01"  # 1 byte
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN

CHUNK_SIZE = 1024 * 1024  # 1 MiB

class Encryptor:
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1, backend=default_backend())
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def _zip_folder(folder_path: Path, temp_zip_path: Path) -> None:
        with zipfile.ZipFile(temp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            base = folder_path.resolve()
            for root, _, files in os.walk(base):
                for f in files:
                    full = Path(root) / f
                    rel = full.resolve().relative_to(base)
                    zf.write(full, arcname=str(rel))

    @staticmethod
    def encrypt_folder(folder_path: Path, password: str, output_file: Path, progress_cb=None) -> None:
        folder_path = folder_path.resolve()
        if not folder_path.is_dir():
            raise ValueError("Input must be a folder")
        output_file = output_file.resolve()

        # Create temp zip
        with tempfile.TemporaryDirectory() as td:
            temp_zip = Path(td) / "archive.zip"
            Encryptor._zip_folder(folder_path, temp_zip)

            salt = secrets.token_bytes(SALT_LEN)
            nonce = secrets.token_bytes(NONCE_LEN)
            key = Encryptor._derive_key(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()

            total = temp_zip.stat().st_size
            processed = 0

            with open(output_file, "wb") as fout:
                # Write header sans TAG
                fout.write(MAGIC)
                fout.write(VERSION)
                fout.write(salt)
                fout.write(nonce)

                with open(temp_zip, "rb") as fin:
                    while True:
                        chunk = fin.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        enc = encryptor.update(chunk)
                        if enc:
                            fout.write(enc)
                        processed += len(chunk)
                        if progress_cb:
                            progress_cb(int(processed * 100 / max(total, 1)))
                # finalize and write TAG
                encryptor.finalize()
                fout.write(encryptor.tag)

    @staticmethod
    def decrypt_file(input_file: Path, password: str, output_folder: Path, progress_cb=None) -> None:
        input_file = input_file.resolve()
        output_folder = output_folder.resolve()
        if not input_file.is_file():
            raise ValueError("Input must be a file")

        size = input_file.stat().st_size
        if size < HEADER_LEN + TAG_LEN:
            raise ValueError("File too small or corrupted")

        with open(input_file, "rb") as fin:
            header = fin.read(HEADER_LEN)
            magic = header[: len(MAGIC)]
            version = header[len(MAGIC) : len(MAGIC) + len(VERSION)]
            if magic != MAGIC or version != VERSION:
                raise ValueError("Unsupported or corrupted file format")
            offset = len(MAGIC) + len(VERSION)
            salt = header[offset : offset + SALT_LEN]
            nonce = header[offset + SALT_LEN : offset + SALT_LEN + NONCE_LEN]

            key = Encryptor._derive_key(password, salt)

            # Read TAG from end
            fin.seek(-TAG_LEN, os.SEEK_END)
            tag = fin.read(TAG_LEN)
            ciphertext_len = size - HEADER_LEN - TAG_LEN

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            fin.seek(HEADER_LEN, os.SEEK_SET)

            with tempfile.TemporaryDirectory() as td:
                temp_zip = Path(td) / "archive.zip"
                with open(temp_zip, "wb") as zout:
                    processed = 0
                    remaining = ciphertext_len
                    while remaining > 0:
                        to_read = min(CHUNK_SIZE, remaining)
                        chunk = fin.read(to_read)
                        if not chunk:
                            break
                        dec = decryptor.update(chunk)
                        if dec:
                            zout.write(dec)
                        processed += len(chunk)
                        remaining -= len(chunk)
                        if progress_cb and ciphertext_len:
                            progress_cb(int(processed * 100 / ciphertext_len))
                # finalize to verify tag
                decryptor.finalize()

                # Extract zip
                output_folder.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(temp_zip, "r") as zf:
                    zf.extractall(output_folder)

class DropLineEdit(QtWidgets.QLineEdit):
    def __init__(self, placeholder: str = "", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: QtGui.QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event: QtGui.QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.setText(path)
        else:
            super().dropEvent(event)

class EncryptTab(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        self.input_path = DropLineEdit("Drop a folder here or Browse…")
        browse_btn = QtWidgets.QPushButton("Browse Folder…")
        browse_btn.clicked.connect(self.browse_folder)

        pass_layout = QtWidgets.QHBoxLayout()
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Password")
        self.show_pass = QtWidgets.QCheckBox("Show")
        self.show_pass.toggled.connect(self.toggle_password)
        pass_layout.addWidget(self.password)
        pass_layout.addWidget(self.show_pass)

        self.output_path = QtWidgets.QLineEdit()
        self.output_path.setPlaceholderText("Output file (.fenc)")
        out_btn = QtWidgets.QPushButton("Choose Output…")
        out_btn.clicked.connect(self.choose_output)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)

        run_btn = QtWidgets.QPushButton("Encrypt")
        run_btn.setDefault(True)
        run_btn.clicked.connect(self.run_encrypt)

        layout.addWidget(QtWidgets.QLabel("Folder to encrypt:"))
        layout.addWidget(self.input_path)
        layout.addWidget(browse_btn)
        layout.addSpacing(8)
        layout.addWidget(QtWidgets.QLabel("Password:"))
        layout.addLayout(pass_layout)
        layout.addSpacing(8)
        layout.addWidget(QtWidgets.QLabel("Output encrypted file:"))
        hl = QtWidgets.QHBoxLayout()
        hl.addWidget(self.output_path)
        hl.addWidget(out_btn)
        layout.addLayout(hl)
        layout.addWidget(self.progress)
        layout.addWidget(run_btn)
        layout.addStretch(1)

    def toggle_password(self, checked: bool):
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal if checked else QtWidgets.QLineEdit.EchoMode.Password)

    def browse_folder(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "Choose folder to encrypt")
        if d:
            self.input_path.setText(d)
            # Suggest output name
            base = Path(d).name or "encrypted"
            self.output_path.setText(str(Path.home() / f"{base}.fenc"))

    def choose_output(self):
        f, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save encrypted file", filter="Folder Archive (*.fenc)")
        if f:
            if not f.endswith(".fenc"):
                f += ".fenc"
            self.output_path.setText(f)

    def run_encrypt(self):
        folder = Path(self.input_path.text().strip())
        password = self.password.text()
        out = Path(self.output_path.text().strip())
        try:
            if not folder or not folder.exists() or not folder.is_dir():
                raise ValueError("Please choose a valid folder")
            if not password:
                raise ValueError("Password required")
            if not out:
                raise ValueError("Please choose an output file")
            out.parent.mkdir(parents=True, exist_ok=True)

            def update_prog(p):
                self.progress.setValue(p)
                QtWidgets.QApplication.processEvents()

            Encryptor.encrypt_folder(folder, password, out, progress_cb=update_prog)
            self.progress.setValue(100)
            QtWidgets.QMessageBox.information(self, "Done", f"Encrypted to:\n{out}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))

class DecryptTab(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        self.input_file = DropLineEdit("Drop a .fenc file here or Browse…")
        browse_btn = QtWidgets.QPushButton("Browse File…")
        browse_btn.clicked.connect(self.browse_file)

        pass_layout = QtWidgets.QHBoxLayout()
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Password")
        self.show_pass = QtWidgets.QCheckBox("Show")
        self.show_pass.toggled.connect(self.toggle_password)
        pass_layout.addWidget(self.password)
        pass_layout.addWidget(self.show_pass)

        self.output_folder = QtWidgets.QLineEdit()
        self.output_folder.setPlaceholderText("Destination folder for decrypted files")
        out_btn = QtWidgets.QPushButton("Choose Folder…")
        out_btn.clicked.connect(self.choose_output_folder)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)

        run_btn = QtWidgets.QPushButton("Decrypt")
        run_btn.setDefault(True)
        run_btn.clicked.connect(self.run_decrypt)

        layout.addWidget(QtWidgets.QLabel("Encrypted file (.fenc):"))
        layout.addWidget(self.input_file)
        layout.addWidget(browse_btn)
        layout.addSpacing(8)
        layout.addWidget(QtWidgets.QLabel("Password:"))
        layout.addLayout(pass_layout)
        layout.addSpacing(8)
        layout.addWidget(QtWidgets.QLabel("Output folder:"))
        hl = QtWidgets.QHBoxLayout()
        hl.addWidget(self.output_folder)
        hl.addWidget(out_btn)
        layout.addLayout(hl)
        layout.addWidget(self.progress)
        layout.addWidget(run_btn)
        layout.addStretch(1)

    def toggle_password(self, checked: bool):
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal if checked else QtWidgets.QLineEdit.EchoMode.Password)

    def browse_file(self):
        f, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose .fenc file", filter="Folder Archive (*.fenc)")
        if f:
            self.input_file.setText(f)
            # Suggest output folder next to file
            self.output_folder.setText(str(Path(f).with_suffix("").with_name(Path(f).stem + "_decrypted")))

    def choose_output_folder(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "Choose output folder")
        if d:
            self.output_folder.setText(d)

    def run_decrypt(self):
        infile = Path(self.input_file.text().strip())
        password = self.password.text()
        outdir = Path(self.output_folder.text().strip())
        try:
            if not infile or not infile.exists() or not infile.is_file():
                raise ValueError("Please choose a valid .fenc file")
            if not password:
                raise ValueError("Password required")
            if not outdir:
                raise ValueError("Please choose an output folder")

            def update_prog(p):
                self.progress.setValue(p)
                QtWidgets.QApplication.processEvents()

            Encryptor.decrypt_file(infile, password, outdir, progress_cb=update_prog)
            self.progress.setValue(100)
            QtWidgets.QMessageBox.information(self, "Done", f"Decrypted to:\n{outdir}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Folder Encryptor (AES-256-GCM)")
        self.resize(700, 420)

        tabs = QtWidgets.QTabWidget()
        tabs.addTab(EncryptTab(), "Encrypt")
        tabs.addTab(DecryptTab(), "Decrypt")
        self.setCentralWidget(tabs)

        # Minimal styling
        self.setStyleSheet(
            """
            QLineEdit { padding: 8px; }
            QPushButton { padding: 8px 12px; }
            QProgressBar { height: 18px; }
            """
        )

    def closeEvent(self, event: QtGui.QCloseEvent):
        event.accept()


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
