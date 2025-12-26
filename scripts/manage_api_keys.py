#!/usr/bin/env python
"""Admin CLI to manage API keys (create, list, revoke).

Usage:
  python -m scripts.manage_api_keys create --show
  python -m scripts.manage_api_keys list
  python -m scripts.manage_api_keys revoke <key_id>
"""
import json
import secrets
import uuid
from datetime import datetime
import click
import os

# Import helpers from the application
from app import _hash_key, _load_persisted_keys, _save_persisted_keys, ensure_data_dir


@click.group()
def main():
    """Manage API keys for the Secure File Share app."""
    pass


@main.command()
@click.option('--show', is_flag=True, help='Print the plaintext API key to stdout.')
@click.option('--name', default=None, help='Optional human-readable name for the key')
def create(show, name):
    """Create a new API key and persist its hash."""
    ensure_data_dir()
    # Generate a URL-safe random secret
    plaintext = secrets.token_urlsafe(32)
    hashed = _hash_key(plaintext)
    rec = {
        'id': uuid.uuid4().hex,
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'hash': hashed,
        'revoked': False,
    }
    if name:
        rec['name'] = name

    data = _load_persisted_keys()
    data.append(rec)
    _save_persisted_keys(data)

    click.echo('Created API key id: %s' % rec['id'])
    if show:
        click.echo('API key (save this now): %s' % plaintext)
    else:
        click.echo('Run with --show to print the plaintext key.')


@main.command()
def list():
    """List persisted API keys (IDs and metadata)."""
    data = _load_persisted_keys()
    if not data:
        click.echo('No persisted API keys found.')
        return
    for rec in data:
        status = 'revoked' if rec.get('revoked') else 'active'
        name = rec.get('name', '')
        click.echo('%s  %s  %s %s' % (rec['id'], rec['created_at'], status, name))


@main.command()
@click.argument('key_id')
def revoke(key_id):
    """Revoke an existing API key by id."""
    data = _load_persisted_keys()
    changed = False
    for rec in data:
        if rec.get('id') == key_id:
            if rec.get('revoked'):
                click.echo('Key %s is already revoked.' % key_id)
                return
            rec['revoked'] = True
            rec['revoked_at'] = datetime.utcnow().isoformat() + 'Z'
            changed = True
            break
    if not changed:
        click.echo('Key id %s not found.' % key_id)
        return
    _save_persisted_keys(data)
    click.echo('Key %s revoked.' % key_id)


if __name__ == '__main__':
    main()
