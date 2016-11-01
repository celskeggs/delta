import gnupg
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


def encrypt(file, key, output=None):
    out = gpg.encrypt_file(file, [key], sign=key, armor=False, always_trust=True, output=output)
    if output is None:
        return out.data


def decrypt(file, key, output=None):
    assert not os.path.exists(tempfile)
    if type(file) is str:
        decrypted = gpg.decrypt(file, always_trust=True, output=output)
    else:
        decrypted = gpg.decrypt_file(file, always_trust=True, output=output)
    assert decrypted.fingerprint == key, "key mismatch: unexpected %s" % decrypted.fingerprint
    if output is None:
        return decrypted.data
