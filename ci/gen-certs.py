from shutil import which
from os import makedirs, chmod, path
from sys import argv
import subprocess

from . import find_openssl, make_folders, gen_key, check_conf, gen_signing_request

DOMAIN = "testserver.lan"
CA_FQDN = "ca.{}".format(DOMAIN)
INT_FQDN = "i{}".format(CA_FQDN)


def make_root_folders():
    make_folders(["ca/certs", "ca/newcerts", "ca/private"])
    chmod("ca/private", mode=0o700)

    open("ca/index.txt", "w+")
    with open("ca/serial", "w+") as f:
        f.write("1000")


def gen_root_key(openssl):
    print("Generating ca.key.pem")
    key_path = "ca/private/ca.key.pem"
    gen_key(openssl, key_path)


def check_openssl_conf():
    check_conf("openssl.cnf")


def gen_root_cert(openssl):
    print("Generating ca.cert.pem")
    key_path = "ca/private/ca.key.pem"
    cert_path = "ca/certs/ca.cert.pem"
    retval = subprocess.run(
        [openssl, "req", "-config", "openssl.cnf", "-key", key_path, "-new", "-x509",
         "-days", "18250", "-sha256", "-extensions", "v3_ca", "-out", cert_path,
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
    csr_path = "ca/intermediate/csr/intermediate.csr.pem"
    gen_signing_request(openssl, key_path, csr_path,
                        "/C=CA/ST=Quebec/O=prince-chrismc/OU=Hello-Boost-Beast/CN={}".format(INT_FQDN))


def gen_intermidate_cert(openssl):
    print("Generating intermediate.cert.pem")
    csr_path = "ca/intermediate/csr/intermediate.csr.pem"
    cert_path = "ca/intermediate/certs/intermediate.cert.pem"
    retval = subprocess.run(
        [openssl, "ca", "-batch", "-config", "openssl.cnf", "-extensions", "v3_intermediate_ca",
         "-days", "18250", "-notext", "-md", "sha256", "-in", csr_path,
         "-out", cert_path, "-subj",
         "/C=CA/ST=Quebec/O=prince-chrismc/OU=Hello-Boost-Beast/CN={}".format(INT_FQDN)],
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


def gen_intermidate_crl(openssl):
    print("Generating intermediate.crl.pem")
    crl_path = "ca/intermediate/certs/intermediate.crl.pem"
    retval = subprocess.run(
        [openssl, "ca", "-batch", "-config", "intermediate-openssl.cnf", "-gencrl",
         "-out", crl_path], stderr=subprocess.DEVNULL)
    if not retval.returncode == 0:
        exit("Failed!")


def gen_ocsp_pair(openssl):
    print("Generating ocsp.cert.pem")
    key_path = "ca/intermediate/private/ocsp.{}.key.pem".format(DOMAIN)
    gen_key(openssl, key_path)

    csr_path = "ca/intermediate/csr/ocsp.{}.crs.pem".format(DOMAIN)
    gen_signing_request(openssl, key_path, csr_path,
                        "/C=CA/ST=Quebec/O=prince-chrismc/OU=Hello-Boost-Beast/CN=ocsp.{}".format(DOMAIN))

    cert_path = "ca/intermediate/csr/ocsp.{}.cert.pem".format(DOMAIN)
    retval = subprocess.run(
        [openssl, "ca", "-batch", "-config", "intermediate-openssl.cnf", "-extensions", "ocsp",
         "-days", "18250", "-notext", "-md", "sha256", "-in", csr_path, "-out", cert_path],
        stderr=subprocess.DEVNULL)
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
gen_intermidate_crl(openssl)
gen_ocsp_pair(openssl)


def gen_dhparam(openssl, fast=True):
    print("Generating dhparam.pem")
    key_path = "ca/intermediate/private/dhparam.pem"
    if fast:
        args = [openssl, "dhparam", "-dsaparam", "-out", key_path, "2048"]
    else:
        args = [openssl, "dhparam", "-out", key_path, "4096"]

    retval = subprocess.run(args)
    if not retval.returncode == 0:
        exit("Failed!")


gen_dhparam(openssl, len(argv) > 1)

# Create ECDSA key
FQDN = "https.{}".format(DOMAIN)


def gen_host_key(openssl):
    print("Generating ecdsa.{}.key.pem".format(FQDN))
    key_path = "ca/intermediate/private/ecdsa.{}.key.pem".format(FQDN)
    gen_key(openssl, key_path)


def gen_host_csr(openssl):
    print("Generating ecdsa.{}.csr.pem".format(FQDN))
    key_path = "ca/intermediate/private/ecdsa.{}.key.pem".format(FQDN)
    csr_path = "ca/intermediate/csr/ecdsa.{}.csr.pem".format(FQDN)
    gen_signing_request(openssl, key_path, csr_path,
                        "/C=CA/ST=Quebec/O=prince-chrismc/OU=Hello-Boost-Beast/CN=ocsp.{}".format(FQDN))


def gen_host_cert(openssl):
    print("Generating ecdsa.{}.cert.pem".format(FQDN))
    csr_path = "ca/intermediate/csr/ecdsa.{}.csr.pem".format(FQDN)
    cert_path = "ca/intermediate/certs/ecdsa.{}.certs.pem".format(FQDN)
    retval = subprocess.run(
        [openssl, "ca", "-batch", "-config", "intermediate-openssl.cnf",
         "-extensions", "server_cert", "-days", "18250", "-notext", "-md", "sha256",
         "-in", csr_path, "-out", cert_path], stderr=subprocess.DEVNULL)
    if not retval.returncode == 0:
        exit("Failed!")


# Create end-entity cert chain
def gen_host_cert_chain(openssl):
    print("Generating ecdsa.{}.cert.chain.pem".format(FQDN))
    with open("ca/intermediate/certs/ecdsa.{}.cert.chain.pem".format(FQDN), "w+") as f:
        host_cert_path = "ca/intermediate/certs/ecdsa.{}.certs.pem".format(
            FQDN)
        intermediate_cert_path = "ca/intermediate/certs/intermediate.cert.pem"
        retval = subprocess.run(
            ["cat", host_cert_path, intermediate_cert_path], stdout=f)
        if not retval.returncode == 0:
            exit("Failed!")


def verify_host_against_root(openssl):
    verification_path = "ca/intermediate/certs/verification-ca-chain.cert.pem"
    entity_cert_path = "ca/intermediate/certs/ecdsa.{}.cert.chain.pem".format(
        FQDN)
    with open(verification_path, "w+") as f:
        retval = subprocess.run(
            ["cat",
             "ca/intermediate/certs/intermediate.cert.pem",
             "ca/certs/ca.cert.pem",
             ],
            stdout=f
        )
        if not retval.returncode == 0:
            exit("Failed!")

    # Check end-entity
    retval = subprocess.run(
        [openssl, "verify", "-CAfile", verification_path, entity_cert_path])


gen_host_key(openssl)
gen_host_csr(openssl)
gen_host_cert(openssl)
gen_host_cert_chain(openssl)
verify_host_against_root(openssl)
