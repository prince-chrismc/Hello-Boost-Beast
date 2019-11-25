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


def check_conf(file):
    if not path.isfile(file):
        exit("Unable to find '{}'".format(file))


def check_openssl_conf():
    check_conf("openssl.cnf")


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


def check_intermidate_openssl_conf():
    check_conf("intermediate-openssl.cnf")


def gen_intermidate_signing_request(openssl):
    print("Generating intermediate.crs.pem")
    key_path = "ca/intermediate/private/intermediate.key.pem"
    crs_path = "ca/intermediate/csr/intermediate.csr.pem"
    retval = subprocess.run(
        [openssl, "req", "-config", "intermediate-openssl.cnf", "-new", "-sha256",
         "-key", key_path, "-out", crs_path, "-subj",
         "/C=CA/ST=Quebec/O=prince-chrismc/OU=Hello-Boost-Beast/CN={}".format(INT_FQDN)])
    if not retval.returncode == 0:
        exit("Failed!")


def gen_intermidate_cert(openssl):
    print("Generating intermediate.cert.pem")
    crs_path = "ca/intermediate/csr/intermediate.csr.pem"
    cert_path = "ca/intermediate/certs/intermediate.cert.pem"
    retval = subprocess.run(
        [openssl, "ca", "-batch", "-config", "openssl.cnf", "-extensions", "v3_intermediate_ca",
         "-days", "18250", "-notext", "-md", "sha256", "-in", crs_path,
         "-out", cert_path, "-subj", "/C=CA/ST=Quebec/O=prince-chrismc/OU=Hello-Boost-Beast/CN={}".format(INT_FQDN)],
        stderr=subprocess.DEVNULL)
    if not retval.returncode == 0:
        exit("Failed!")
    chmod(cert_path, 0o444)


def verify_intermidate_cert_with_root(openssl):
    root_path = "ca/certs/ca.cert.pem"
    cert_path = "ca/intermediate/certs/intermediate.cert.pem"
    retval = subprocess.run(
        [openssl, "verify", "-CAfile", root_path, cert_path])
    if not retval.returncode == 0:
        exit("Failed!")


openssl = find_openssl()

make_root_folders()
gen_root_key(openssl)
check_openssl_conf()
gen_root_cert(openssl)


make_intermidate_folders()
gen_intermidate_key(openssl)
check_intermidate_openssl_conf()
gen_intermidate_signing_request(openssl)
gen_intermidate_cert(openssl)
verify_intermidate_cert_with_root(openssl)
