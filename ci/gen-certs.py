from shutil import which
from os import makedirs
from os import chmod
from os import path
import subprocess


DOMAIN = "testserver.lan"
CA_FQDN = "ca.{}".format(DOMAIN)
INT_FQDN = "i{}".format(CA_FQDN)


def find_openssl():
    openssl_path = which("openssl")
    # print(openssl_path)

    retval = subprocess.run([openssl_path, "version"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not retval.returncode == 0:
        exit("Unable to find OpenSSL")

    return openssl_path


def make_folders(dirs=[]):
    for dir in dirs:
        makedirs(dir, exist_ok=True)


def make_root_folders():
    make_folders(["ca/certs", "ca/newcerts", "ca/private"])
    chmod("ca/private", mode=0o700)

    open("ca/index.txt", "w+")
    with open("ca/serial", "w+") as f:
        f.write("1000")


def gen_key(openssl, key_path):
    retval = subprocess.run(
        [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key_path])
    if not retval.returncode == 0:
        exit("Failed!")
    chmod(key_path, 0o400)


def gen_root_key(openssl):
    print("Generating ca.key.pem")
    key_path = "ca/private/ca.key.pem"
    gen_key(openssl, key_path)


def check_openssl_conf():
    if not path.isfile("openssl.cnf"):
        exit("Unable to find 'openssl.cnf'")


def gen_root_cert(openssl):
    print("Generating ca.cert.pem")
    key_path = "ca/private/ca.key.pem"
    cert_path = "ca/certs/ca.cert.pem"
    retval = subprocess.run(
        [openssl, "req", "-config", "openssl.cnf",
         "-key",  key_path, "-new", "-x509", "-days", "18250",
         "-sha256", "-extensions", "v3_ca",    "-out",  cert_path,
         "-subj", "/C=CA/ST=Quebec/O=prince-chrismc/OU=Hello-Boost-Beast/CN={}".format(
             CA_FQDN)])
    chmod(cert_path, 0o444)


def make_intermidate_folders():
    make_folders(["ca/intermediate/certs", "ca/intermediate/crl", "ca/intermediate/csr",
                  "ca/intermediate/newcerts", "ca/intermediate/private"])
    chmod("ca/intermediate/private", mode=0o700)

    open("ca/intermediate/index.txt", "w+")
    with open("ca/intermediate/serial", "w+") as f:
        f.write("1000")
    with open("ca/intermediate/crlnumber", "w+") as f:
        f.write("1000")


def gen_intermidate_key(openssl):
    print("Generating intermediate.key.pem")
    key_path = "ca/intermediate/private/intermediate.key.pem"
    gen_key(openssl, key_path)


openssl = find_openssl()

make_root_folders()
gen_root_key(openssl)
check_openssl_conf()
gen_root_cert(openssl)


make_intermidate_folders()
gen_intermidate_key(openssl)
