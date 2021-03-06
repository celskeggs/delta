import os
import common
import time
import json
import crypto
import hashlib

DDIR = ".delta"
KEYFILE = "key"
LTREEFILE = "ltree"
DATADIR = "data"
STAGEDIR = "stage"


def ddir_for(x):
    return os.path.join(x, DDIR)


def find_ctx(fail=True):
    cur_dir = os.getcwd()
    while os.path.dirname(cur_dir) != cur_dir:
        if os.path.exists(ddir_for(cur_dir)):
            if os.listdir(os.path.join(ddir_for(cur_dir), STAGEDIR)):
                raise common.DeltaException("Inconsistent state. Manual rescue required.")
            with open(os.path.join(ddir_for(cur_dir), KEYFILE), "r") as f:
                key_id = f.readline().strip()
            if not crypto.has_key(key_id):
                raise common.DeltaException("Key not found in keyring: %s" % key_id)
            return cur_dir, ddir_for(cur_dir), key_id
        cur_dir = os.path.dirname(cur_dir)
    if fail:
        raise common.DeltaException("Cannot find delta root.")
    else:
        return None


def fail(err):
    raise err


def tree_walk(root):
    for dirpath, dirnames, filenames in os.walk(root, onerror=fail):
        if DDIR in dirnames:
            if dirpath != root:
                raise common.DeltaException("Encountered %s file in subdirectory." % DDIR)
            dirnames.remove(DDIR)
        for filename in filenames:
            yield os.path.join(dirpath, filename)


def tree_status(root):
    link_count = 0
    unsaved = []
    for filepath in tree_walk(root):
        if os.path.islink(filepath):
            link_count += 1
        else:
            assert os.path.exists(filepath), "failed: %s" % filepath
            unsaved.append(filepath)
    unsaved.sort()
    return link_count, unsaved


def is_hex(x):
    return all(c in "0123456789abcdef" for c in x)


def cache_status(root):
    cache = []
    for object in os.listdir(os.path.join(ddir_for(root), DATADIR)):
        assert not os.path.isdir(object) and not os.path.islink(object)
        assert len(object) == SHA_LEN and is_hex(object)
        cache.append(object)
    return cache


SHA_LEN = 64  # hex digits


def sha256_file(file):
    sha = hashlib.sha256()
    with open(file, "rb") as f:
        while True:
            chunk = f.read(64 * 1024)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def stash_file(root, file):
    assert os.path.exists(file) and not os.path.isdir(file) and not os.path.islink(file)
    print("Stashing %s" % file)
    hashname = sha256_file(file)
    goalfile = os.path.join(ddir_for(root), DATADIR, hashname)
    if os.path.exists(goalfile):
        assert hashname == sha256_file(goalfile)
    tempfile = os.path.join(ddir_for(root), STAGEDIR, os.path.basename(file))
    os.rename(file, tempfile)
    os.chmod(tempfile, os.stat(tempfile).st_mode & ~0o222)
    assert not os.path.exists(file)
    os.symlink(os.path.relpath(goalfile, os.path.dirname(os.path.abspath(file))), file)
    os.utime(file, ns=(os.path.getatime(tempfile), os.path.getmtime(tempfile)), follow_symlinks=False)
    if os.path.exists(goalfile):
        os.remove(tempfile)
    else:
        os.chmod(os.path.join(ddir_for(root), DATADIR), 0o755)
        os.rename(tempfile, goalfile)
        os.chmod(os.path.join(ddir_for(root), DATADIR), 0o555)


def export_object(root, object):
    source = os.path.join(ddir_for(root), DATADIR, object)
    assert os.path.exists(source)
    return open(source, "rb")


def import_object_path(root, object):
    target = os.path.join(ddir_for(root), DATADIR, object)
    assert not os.path.exists(target)
    return target


def init_folder(root, key):
    ddir = ddir_for(root)
    os.mkdir(ddir)
    with open(os.path.join(ddir, KEYFILE), "w") as f:
        f.write(key + "\n")
    os.mkdir(os.path.join(ddir, DATADIR))
    os.mkdir(os.path.join(ddir, STAGEDIR))
    assert (root, ddir, key) == find_ctx()


def get_tree(root):
    tf = os.path.join(ddir_for(root), LTREEFILE)
    if not os.path.exists(tf):
        return {}
    with open(tf, "r") as f:
        return json.load(f)


def set_tree(root, tree):
    with open(os.path.join(ddir_for(root), LTREEFILE), "w") as f:
        json.dump(tree, f)


def flatten(tree):
    return json.dumps(tree)


def unflatten(tree):
    return json.loads(tree if type(tree) == str else tree.decode())


def get_tree_flat(root):
    tf = os.path.join(ddir_for(root), LTREEFILE)
    if not os.path.exists(tf):
        return "{}"
    with open(tf, "rb") as f:
        return f.read()


def set_tree_flat(root, tree):
    with open(os.path.join(ddir_for(root), LTREEFILE), "wb") as f:
        f.write(tree)


def dump_tree(root):
    out = {}
    for filename in tree_walk(root):
        if not os.path.islink(filename):
            continue
        mtime = None
        try:
            mtime = os.stat(filename).st_mtime
        except FileNotFoundError:
            pass
        out[os.path.relpath(filename, root)] = [os.readlink(filename), mtime]
    return out


def load_tree(root, tree):
    count = {"blocked": 0, "insert": 0, "replace": 0, "delete": 0}
    for change in list_changes(root, tree):
        count[change[0]] += 1
        if change[0] == "blocked":
            print("Cannot load file due to existing data: %s %s %s" % change[1:])
        else:
            apply_change(root, change)
    return count


def list_changes(root, tree):
    tree2 = dump_tree(root)
    for key, (link, mtime) in tree.items():
        if key not in tree2:
            if os.path.exists(os.path.join(root, key)):
                yield "blocked", key, link, mtime
            else:
                yield "insert", key, link, mtime
        elif tuple(tree2[key]) != (link, mtime):
            yield "replace", key, link, mtime
    for key, (link, mtime) in tree2.items():
        if key not in tree:
            yield "delete", key, link, mtime


def apply_change(root, change):
    cmd, key, link, mtime = change
    path = os.path.join(root, key)
    if cmd == "insert":
        assert not os.path.exists(path)
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        os.symlink(link, path)
        os.utime(path, (time.time(), mtime))
    elif cmd == "replace":
        assert os.path.islink(path)
        os.remove(path)
        os.symlink(link, path)
        os.utime(path, (time.time(), mtime))
        leaf = os.path.dirname(os.path.abspath(path))
        if not os.listdir(leaf):
            os.removedirs(leaf)
    elif cmd == "delete":
        assert os.path.islink(path)
        os.remove(path)
        leaf = os.path.dirname(os.path.abspath(path))
        if not os.listdir(leaf):
            os.removedirs(leaf)
    else:
        assert False
