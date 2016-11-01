from google.cloud import storage
import tree

paradox = None


def get_ref():
    global paradox
    if paradox is None:
        paradox = storage.Client(project="backups-cela").get_bucket("paradox_backup")
    return paradox


def list_upstream():
    out = []
    for blob in get_ref().list_blobs():
        name = blob.name
        if len(name) == tree.SHA_LEN and tree.is_hex(name):
            out.append(name)
    return out


def upload_object(object, f, overwrite=False):
    blob = get_ref().blob(object)
    assert not blob.exists() or overwrite  # TODO: fix race condition
    if type(f) in (str, bytes):
        blob.upload_from_string(f)
    else:
        blob.upload_from_file(f)


def exists_object(object):
    return get_ref().blob(object).exists()


def download_object(object, f):
    blob = get_ref().blob(object)
    assert blob.exists()
    if f is not None:
        return blob.download_to_file(f)
    else:
        return blob.download_as_string()
