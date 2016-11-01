import gnupg
import os
import common

gpg = gnupg.GPG(use_agent=True)


def list_keys():
    keys = gpg.list_keys(True)
    if not keys:
        raise common.DeltaException("No PGP keys available.")
    keys.sort(key=lambda x: x["fingerprint"])
    return keys


def has_key(key_id):
    return gpg.export_keys(key_id) is not None


def encrypt(file, key, output=None, overwrite=None):
    assert output is None or not os.path.exists(output) or overwrite
    assert key is not None
    if type(file) in (str, bytes):
        out = gpg.encrypt(file, [key], sign=key, armor=False, always_trust=True, output=output)
    else:
        out = gpg.encrypt_file(file, [key], sign=key, armor=False, always_trust=True, output=output)
    if output is None:
        return out.data


def decrypt(file, key, output=None):
    assert output is None or not os.path.exists(output)
    assert key is not None
    if type(file) in (str, bytes):
        decrypted = gpg.decrypt(file, always_trust=True, output=output)
    else:
        decrypted = gpg.decrypt_file(file, always_trust=True, output=output)
    assert decrypted.fingerprint == key, "key mismatch: unexpected %s instead of %s" % (decrypted.fingerprint, key)
    if output is None:
        return decrypted.data
