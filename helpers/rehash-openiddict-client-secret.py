#!/usr/bin/env python3
"""Rehydrate a migrated OpenIddict client secret using OpenIddict's format.

The legacy Duende store contains Base64(SHA-256(secret)). OpenIddict 7 stores
client secrets as a versioned PBKDF2 representation. This helper intentionally
requires the raw secret through a protected file and is a dry-run by default.
It only updates a confidential client whose current value is NULL or the
legacy SHA-256 representation of the supplied secret.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import re
import struct
import subprocess
import sys
from pathlib import Path


OPENIDDICT_VERSION = 1
OPENIDDICT_SHA256 = 1
OPENIDDICT_ITERATIONS = 10_000
OPENIDDICT_SALT_BYTES = 128
OPENIDDICT_KEY_BYTES = 32
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]+$")
DATABASE = re.compile(r"^[A-Za-z0-9_]+$")


def fail(message: str) -> "NoReturn":
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rehash one migrated OpenIddict client secret. "
            "The default mode is read-only."
        )
    )
    parser.add_argument("--defaults-extra-file", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--secret-file", required=True)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def read_secret(path: Path) -> str:
    if not path.is_file():
        fail("--secret-file must point to an existing protected file")
    try:
        value = path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read --secret-file: {exc}")
    value = value.rstrip("\r\n")
    if not value or "\r" in value or "\n" in value:
        fail("secret file must contain exactly one non-empty line")
    return value


def run_db(defaults_file: str, database: str, sql: str) -> str:
    command = [
        "mariadb",
        f"--defaults-extra-file={defaults_file}",
        f"--database={database}",
        "--batch",
        "--skip-column-names",
        "--raw",
    ]
    try:
        result = subprocess.run(
            command,
            input=sql,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        fail("mariadb client was not found")
    if result.returncode != 0:
        detail = result.stderr.strip() or "database command failed"
        fail(detail)
    return result.stdout.rstrip("\r\n")


def legacy_hash(secret: str) -> str:
    return base64.b64encode(hashlib.sha256(secret.encode()).digest()).decode()


def make_hash(secret: str) -> str:
    salt = os.urandom(OPENIDDICT_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode(),
        salt,
        OPENIDDICT_ITERATIONS,
        OPENIDDICT_KEY_BYTES,
    )
    payload = bytes([OPENIDDICT_VERSION]) + struct.pack(
        ">III",
        OPENIDDICT_SHA256,
        OPENIDDICT_ITERATIONS,
        len(salt),
    ) + salt + derived
    return base64.b64encode(payload).decode()


def verify_hash(secret: str, value: str) -> bool:
    try:
        payload = base64.b64decode(value, validate=True)
        if len(payload) < 13 or payload[0] != OPENIDDICT_VERSION:
            return False
        algorithm, iterations, salt_length = struct.unpack(">III", payload[1:13])
        if algorithm != OPENIDDICT_SHA256 or iterations <= 0:
            return False
        if salt_length < 16 or len(payload) <= 13 + salt_length:
            return False
        salt = payload[13 : 13 + salt_length]
        expected = payload[13 + salt_length :]
        actual = hashlib.pbkdf2_hmac(
            "sha256", secret.encode(), salt, iterations, len(expected)
        )
        return hmac.compare_digest(expected, actual)
    except (ValueError, struct.error):
        return False


def main() -> int:
    args = parse_args()
    if not Path(args.defaults_extra_file).is_file():
        fail("--defaults-extra-file must point to an existing protected file")
    if not DATABASE.fullmatch(args.database):
        fail("invalid --database identifier")
    if not IDENTIFIER.fullmatch(args.client_id):
        fail("invalid --client-id identifier")

    secret = read_secret(Path(args.secret_file))
    old = run_db(
        args.defaults_extra_file,
        args.database,
        "SELECT client_type, COALESCE(client_secret, '') "
        f"FROM applications WHERE client_id = '{args.client_id}';",
    )
    rows = old.splitlines()
    if len(rows) != 1 or "\t" not in rows[0]:
        fail(f"client '{args.client_id}' was not found or is ambiguous")
    client_type, current = rows[0].split("\t", 1)
    if client_type != "confidential":
        fail(f"client '{args.client_id}' is not confidential")

    old_hash = legacy_hash(secret)
    if current and verify_hash(secret, current):
        print(
            f"client={args.client_id} status=already-valid "
            f"stored_length={len(current)}"
        )
        return 0
    if current and current != old_hash:
        fail(
            "current secret is neither NULL nor the expected legacy SHA-256 "
            "value; refusing to overwrite it"
        )

    replacement = make_hash(secret)
    print(
        f"client={args.client_id} status=ready "
        f"current={'legacy-sha256' if current else 'missing'} "
        f"replacement_length={len(replacement)} apply={args.apply}"
    )
    if not args.apply:
        print("dry-run only; rerun with --apply after validating the secret source")
        return 0

    # The client ID and both values are constrained/derived above. Feed SQL
    # through stdin so the protected secret never appears in process arguments.
    sql = (
        "START TRANSACTION;\n"
        "UPDATE applications SET client_secret = "
        f"'{replacement}' WHERE client_id = '{args.client_id}' "
        "AND client_type = 'confidential' AND (client_secret IS NULL OR "
        f"client_secret = '{old_hash}');\n"
        "SELECT ROW_COUNT();\n"
        "COMMIT;\n"
    )
    result = run_db(args.defaults_extra_file, args.database, sql)
    if result.splitlines()[-1:] != ["1"]:
        fail("precondition changed or update affected an unexpected number of rows")
    print("applied=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
