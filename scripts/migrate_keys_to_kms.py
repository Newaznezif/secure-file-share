#!/usr/bin/env python3
"""Migration script to re-wrap existing key mappings with AWS KMS.

Usage:
  python scripts/migrate_keys_to_kms.py --keys-folder keys --backup-dir keys_backup --yes
  python scripts/migrate_keys_to_kms.py --dry-run

The script will:
- For each JSON file in keys folder, skip if already method 'kms'
- Attempt to retrieve plaintext key bytes using app.unprotect_key
- Call KMS Encrypt to wrap the key
- Backup original file and write updated `enc_key` with method 'kms'

Run with --dry-run first to see what would change.
"""

import argparse
import os
import json
import shutil
import logging
from pathlib import Path

from app import unprotect_key, kms_encrypt_key

logger = logging.getLogger('migrate_keys')
logging.basicConfig(level=logging.INFO)


def migrate_keys(keys_folder: str, backup_dir: str | None = None, dry_run: bool = True):
    p = Path(keys_folder)
    if not p.exists() or not p.is_dir():
        raise SystemExit(f"keys folder not found: {p}")

    if backup_dir:
        backup_path = Path(backup_dir)
        backup_path.mkdir(parents=True, exist_ok=True)
        logger.info('Backups will be stored in %s', backup_path)
    else:
        backup_path = None

    changed = []

    for jf in p.glob('*.json'):
        try:
            data = json.loads(jf.read_text())
        except Exception as e:
            logger.warning('Skipping %s: cannot parse JSON: %s', jf, e)
            continue

        enc = data.get('enc_key') or data.get('key')
        if isinstance(enc, dict) and enc.get('method') == 'kms':
            logger.info('%s already migrated (kms)', jf.name)
            continue

        # Try to get plaintext
        try:
            key_bytes = unprotect_key(enc)
        except Exception as e:
            logger.warning('Failed to unprotect key for %s: %s', jf.name, e)
            continue

        logger.info('Prepared to migrate %s (will wrap key with KMS)', jf.name)
        if dry_run:
            changed.append(jf.name)
            continue

        # Backup
        if backup_path:
            shutil.copy2(jf, backup_path / jf.name)

        # Encrypt with KMS
        try:
            new_cipher_b64 = kms_encrypt_key(key_bytes)
        except Exception as e:
            logger.exception('KMS encrypt failed for %s: %s', jf.name, e)
            continue

        data['enc_key'] = {'method': 'kms', 'data': new_cipher_b64}
        # Remove legacy 'key' if present
        if 'key' in data:
            del data['key']

        jf.write_text(json.dumps(data, indent=2))
        logger.info('Migrated %s -> kms', jf.name)
        changed.append(jf.name)

    return changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keys-folder', default=os.environ.get('KEYS_FOLDER', 'keys'))
    ap.add_argument('--backup-dir', default=None)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--yes', action='store_true', help='Perform migration (requires --yes)')
    args = ap.parse_args()

    if args.dry_run:
        logger.info('Running migration in dry-run mode')
    if not args.dry_run and not args.yes:
        raise SystemExit('Not performing migration; re-run with --yes to apply changes')

    changed = migrate_keys(args.keys_folder, args.backup_dir, dry_run=args.dry_run)
    logger.info('Files to be changed / changed: %s', changed)


if __name__ == '__main__':
    main()
