from google.cloud import storage
import google.cloud.storage.blob
import google.cloud.streaming.transfer
import tree

paradox = None


def get_ref():
    global paradox
    if paradox is None:
        paradox = storage.Client(project="backups-cela").get_bucket("paradox_backup")
    return paradox


# NOTE: THIS IS SOME HACKY MONKEYPATCHING
def vUpload(stream, *args, **kwargs):
    print("UPLOAD", stream, args, kwargs)
    inst = google.cloud.streaming.transfer.Upload(stream, *args, **kwargs)
    if hasattr(stream, "__upload_cb"):
        inst.__progress = inst._progress

        def fget():
            return inst.__progress

        def fset(x):
            inst.__progress = x
            stream.__upload_cb(x)

        inst._progress = property(fget, fset)
    return inst


oldconf = google.cloud.storage.blob.Upload.configure_request
def newconf(upload, *args, **kwargs):
    out = oldconf(upload, *args, **kwargs)
    print("STRATEGY", upload.strategy, upload.total_size)
    return out
google.cloud.storage.blob.Upload.configure_request = newconf
google.cloud.storage.blob.Upload = vUpload


def get_blob(object):
    return storage.Blob(name=object, bucket=get_ref())


def list_upstream():
    out = []
    for blob in get_ref().list_blobs():
        name = blob.name
        if len(name) == tree.SHA_LEN and tree.is_hex(name):
            out.append(name)
    return out


def upload_object(object, f, overwrite=False):
    blob = get_blob(object)
    assert not blob.exists() or overwrite  # TODO: fix race condition
    if type(f) in (str, bytes):
        blob.upload_from_string(f)
    else:
        def uploadcb(x):
            print("status", x)
        f.__upload_cb = uploadcb
        blob.upload_from_file(f)
        del f.__upload_cb


def exists_object(object):
    return get_blob(object).exists()


def download_object(object, f):
    blob = get_blob(object)
    assert blob.exists()
    if f is not None:
        return blob.download_to_file(f)
    else:
        return blob.download_as_string()
