import os
import gnupg
import hashlib

class DeltaException(Exception):
	pass

DDIR = ".delta"
KEYFILE = "key"
DATADIR = "data"
STAGEDIR = "stage"
CRYPTDIR = "crypt"

gpg = gnupg.GPG(use_agent=True)

list_keys = gpg.list_keys

def ddir_for(x):
	return os.path.join(x, DDIR)

def find_ctx(fail=True):
	cur_dir = os.getcwd()
	while os.path.dirname(cur_dir) != cur_dir:
		if os.path.exists(ddir_for(cur_dir)):
			if os.listdir(os.path.join(ddir_for(cur_dir), STAGEDIR)):
				raise DeltaException("Inconsistent state. Manual rescue required.")
			with open(os.path.join(ddir_for(cur_dir), KEYFILE), "r") as f:
				key_id = f.readline().strip()
			if key_id not in [key["fingerprint"] for key in gpg.list_keys(True)]:
				raise DeltaException("Key not found in keyring: %s" % key_id)
			return cur_dir, ddir_for(cur_dir), key_id
		cur_dir = os.path.dirname(cur_dir)
	if fail:
		raise DeltaException("Cannot find delta root.")
	else:
		return None

def fail(err):
	raise err

def tree_status(root):
	link_count = 0
	unsaved = []
	for dirpath, dirnames, filenames in os.walk(root, onerror=fail):
		if DDIR in dirnames:
			if dirpath != root:
				raise DeltaException("Encountered %s file in subdirectory." % DDIR)
			dirnames.remove(DDIR)
		for filename in filenames:
			filepath = os.path.join(dirpath, filename)
			if os.path.islink(filepath):
				link_count += 1
			else:
				assert os.path.exists(filepath), "failed: %s" % filepath
				unsaved.append(filepath)
	unsaved.sort()
	return link_count, unsaved

def is_hex(x):
	return all(c in "0123456789abcdefABCDEF" for c in x)

def cache_status(root):
	cache_decrypt, cache_encrypt = [], []
	for object in os.listdir(os.path.join(ddir_for(root), DATADIR)):
		assert not os.path.isdir(object) and not os.path.islink(object)
		assert len(object) == SHA_LEN and is_hex(object)
		cache_decrypt.append(object)
	for object in os.listdir(os.path.join(ddir_for(root), CRYPTDIR)):
		assert not os.path.isdir(object) and not os.path.islink(object)
		assert len(object) == SHA_LEN and is_hex(object)
		cache_encrypt.append(object)
	return cache_decrypt, cache_encrypt

SHA_LEN = 64 # hex digits
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
	os.utime(file, times=(os.path.getatime(tempfile), os.path.getmtime(tempfile)), follow_symlinks=False)
	if os.path.exists(goalfile):
		os.remove(tempfile)
	else:
		os.rename(tempfile, goalfile)

def encrypt_file(root, key, object):
	source = os.path.join(ddir_for(root), DATADIR, object)
	target = os.path.join(ddir_for(root), CRYPTDIR, object)
	tempfile = os.path.join(ddir_for(root), STAGEDIR, object)
	assert os.path.exists(source) and not os.path.exists(target)
	print("Encrypting %s" % object)
	assert object == sha256_file(source)
	with open(source, "rb") as fin:
		assert not os.path.exists(tempfile)
		gpg.encrypt_file(fin, [key], sign=key, armor=False, always_trust=True, output=tempfile)
	os.rename(tempfile, target)

def decrypt_file(root, key, object):
	source = os.path.join(ddir_for(root), CRYPTDIR, object)
	target = os.path.join(ddir_for(root), DATADIR, object)
	tempfile = os.path.join(ddir_for(root), STAGEDIR, object)
	assert os.path.exists(source) and not os.path.exists(target)
	print("Decrypting %s" % object)
	with open(source, "rb") as fin:
		assert not os.path.exists(tempfile)
		decrypted = gpg.decrypt_file(fin, always_trust=True, output=tempfile)
	assert decrypted.fingerprint == key, "key mismatch: unexpected %s" % decrypted.fingerprint
	assert object == sha256_file(tempfile)
	os.rename(tempfile, target)

def init_folder(root, key):
	ddir = ddir_for(root)
	os.mkdir(ddir)
	with open(os.path.join(ddir, KEYFILE), "w") as f:
		f.write(key + "\n")
	os.mkdir(os.path.join(ddir, DATADIR))
	os.mkdir(os.path.join(ddir, STAGEDIR))
	os.mkdir(os.path.join(ddir, CRYPTDIR))
	assert (root, ddir, key) == find_ctx()
