from shutil import which
from os import makedirs
import subprocess


def find_openssl():
    openssl_path = which("openssl")

    # print(openssl_path)

    retval = subprocess.run([openssl_path, "--version"])
    if not retval.check_returncode() == 0:
        exit()


makedirs("ca/certs", exist_ok=True)
makedirs("ca/newcerts", exist_ok=True)
makedirs("ca/private", mode=0o700, exist_ok=True)

open("ca/index.txt", "w+")
with open("ca/serial", "w+") as f:
    f.write("1000")
