import crypto
import remote
import tempfile
import os


def list_upstream():
    return remote.list_upstream()


def upload_object(object, fin, key, overwrite=False):
    assert key is not None
    with tempfile.NamedTemporaryFile() as f:
        crypto.encrypt(fin, key, output=f.name, overwrite=True)
        remote.upload_object(object, f, overwrite)


def exists_object(object):
    return remote.exists_object(object)


def download_object(object, key, fname_out=None):
    assert key is not None
    with tempfile.TemporaryFile() as fdown:
        remote.download_object(object, fdown)
        fdown.seek(0, os.SEEK_SET)
        if fname_out is None:
            return crypto.decrypt(fdown, key)
        else:
            crypto.decrypt(fdown, key, output=fname_out)
