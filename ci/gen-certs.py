from shutil import which
from os import makedirs
from os import chmod
import subprocess


def find_openssl():
    openssl_path = which("openssl")
    # print(openssl_path)

    retval = subprocess.run([openssl_path, "version"])
    if not retval.returncode == 0:
        exit("Unable to find OpenSSL")

    return openssl_path


def make_root_folders():
    makedirs("ca/certs", exist_ok=True)
    makedirs("ca/newcerts", exist_ok=True)
    makedirs("ca/private", mode=0o700, exist_ok=True)

    open("ca/index.txt", "w+")
    with open("ca/serial", "w+") as f:
        f.write("1000")


def gen_root_key(openssl):
    print("Generating ca.key.pem")
    key_path = "ca/private/ca.key.pem"
    retval = subprocess.run(
        [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key_path])
    if not retval.returncode == 0:
        exit("Failed!")
    chmod(key_path, 0o400)


openssl = find_openssl()
make_root_folders()
gen_root_key(openssl)
