#!/usr/bin/env python3
"""Re-wrap existing key files using a local MASTER_KEY (AES-GCM).

Usage:
  python scripts/rewrap_keys_with_master.py --keys-folder keys --backup-dir keys_backup --dry-run
  python scripts/rewrap_keys_with_master.py --keys-folder keys --backup-dir keys_backup --yes --save-master

If MASTER_KEY is not provided via --master-key, a secure random 32-byte passphrase will be generated and
(optionally) written to `.env.local` when --save-master is used. The script will set MASTER_KEY in the
process environment while performing the wrapping so `app.protect_key` uses AES-GCM.

This script is intended for offline/local migrations and avoids calling AWS KMS.
"""

import argparse
import os
import json
import shutil
import logging
from pathlib import Path
from base64 import b64encode

from app import unprotect_key, protect_key
from Crypto.Random import get_random_bytes

logger = logging.getLogger('rewrap_keys')
logging.basicConfig(level=logging.INFO)


def generate_master_passphrase():
    return b64encode(get_random_bytes(32)).decode('utf-8')


def write_env_file(path: Path, master_value: str):
    content = f"MASTER_KEY={master_value}\n"
    path.write_text(content)
    logger.info('Wrote master key to %s (ensure file is ignored by git)', path)


def rewrap_keys(keys_folder: str, backup_dir: str | None = None, master_key: str | None = None, dry_run: bool = True, save_master: bool = False, env_file: str = '.env.local'):
    p = Path(keys_folder)
    if not p.exists() or not p.is_dir():
        raise SystemExit(f"keys folder not found: {p}")

    if backup_dir:
        backup_path = Path(backup_dir)
        backup_path.mkdir(parents=True, exist_ok=True)
        logger.info('Backups will be stored in %s', backup_path)
    else:
        backup_path = None

    if not master_key:
        master_key = generate_master_passphrase()
        logger.info('Generated a new MASTER_KEY (not saved). Use --save-master to persist to %s', env_file)

    changed = []

    # Set MASTER_KEY in process env so protect_key will use it
    os.environ['MASTER_KEY'] = master_key

    for jf in p.glob('*.json'):
        try:
            data = json.loads(jf.read_text())
        except Exception as e:
            logger.warning('Skipping %s: cannot parse JSON: %s', jf, e)
            continue

        enc = data.get('enc_key') or data.get('key')
        # If already GCM (method='gcm') or KMS, skip
        if isinstance(enc, dict) and enc.get('method') in ('gcm', 'kms'):
            logger.info('%s already protected (method=%s)', jf.name, enc.get('method'))
            continue

        # Try to get plaintext
        try:
            key_bytes = unprotect_key(enc)
        except Exception as e:
            logger.warning('Failed to unprotect key for %s: %s', jf.name, e)
            continue

        logger.info('Prepared to rewrap %s (will wrap key with local MASTER_KEY)', jf.name)
        if dry_run:
            changed.append(jf.name)
            continue

        # Backup
        if backup_path:
            shutil.copy2(jf, backup_path / jf.name)

        # Protect locally (AES-GCM via protect_key which respects MASTER_KEY env)
        try:
            new_wrapped = protect_key(key_bytes)
        except Exception as e:
            logger.exception('Local protect failed for %s: %s', jf.name, e)
            continue

        data['enc_key'] = new_wrapped
        if 'key' in data:
            del data['key']

        jf.write_text(json.dumps(data, indent=2))
        logger.info('Rewrapped %s -> method=%s', jf.name, new_wrapped.get('method'))
        changed.append(jf.name)

    # Persist master key if requested and not a dry run
    if save_master and not dry_run:
        env_path = Path(env_file)
        write_env_file(env_path, master_key)

    return changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keys-folder', default=os.environ.get('KEYS_FOLDER', 'keys'))
    ap.add_argument('--backup-dir', default=None)
    ap.add_argument('--master-key', default=None)
    ap.add_argument('--env-file', default='.env.local')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--yes', action='store_true', help='Perform rewrap (requires --yes)')
    ap.add_argument('--save-master', action='store_true', help='Write generated/provided MASTER_KEY to --env-file')
    args = ap.parse_args()

    if args.dry_run:
        logger.info('Running rewrap in dry-run mode')
    if not args.dry_run and not args.yes:
        raise SystemExit('Not performing rewrap; re-run with --yes to apply changes')

    changed = rewrap_keys(args.keys_folder, args.backup_dir, args.master_key, dry_run=args.dry_run, save_master=args.save_master, env_file=args.env_file)
    logger.info('Files to be changed / changed: %s', changed)


if __name__ == '__main__':
    main()
