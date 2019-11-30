from shutil import which
from os import makedirs, chmod, path
import subprocess

if __name__ == "__main__":
    pass


def find_openssl():
    openssl_path = which("openssl")
    retval = subprocess.run([openssl_path, "version"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not retval.returncode == 0:
        exit("Unable to find OpenSSL")
    return openssl_path


def make_folders(dirs=[]):
    for dir in dirs:
        makedirs(dir, exist_ok=True)


def gen_key(openssl, key_path):
    retval = subprocess.run(
        [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key_path])
    if not retval.returncode == 0:
        exit("Failed!")
    chmod(key_path, 0o400)


def check_conf(file):
    if not path.isfile(file):
        exit("Unable to find '{}'".format(file))


def gen_signing_request(openssl, key_path, csr_path, subject):
    retval = subprocess.run(
        [openssl, "req", "-config", "intermediate-openssl.cnf", "-new", "-sha256",
         "-key", key_path, "-out", csr_path, "-subj", subject])
    if not retval.returncode == 0:
        exit("Failed!")
