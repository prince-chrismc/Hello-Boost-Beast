import sys
import ssl
import requests
import OpenSSL

if len(sys.argv) != 2:
    print("Args: '{0}' was not valid.".format(sys.argv), file=sys.stderr)
    print("Usage: {0} <host>".format(sys.argv[0]))
    exit(127)

host = sys.argv[1]
if not host.startswith("https://"):
    host = "https://" + host

print("Targert: '{0}'".format(host))

unsecure = host
unsecure.replace("https://", "http://")
print("Sending unsecure HTTP to {}...".format(unsecure))
r1 = requests.get(unsecure + "/", verify=False)
if not r1.status_code == 404:
    print("FAILED: Obtained a ({}) from server".format(r1.status_code))
    exit(1)

fqdn = host
fqdn = fqdn.replace("https://", "")
print("Trying to obtain certificate from {}...".format(fqdn))
index = fqdn.find(":")
if index == -1:
    port = 443
else:
    port = int(fqdn.split(":")[1])
    fqdn = fqdn.split(":")[0]

cert = ssl.get_server_certificate((fqdn, port))
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
subject = x509.get_subject().get_components()
if b'CN' in subject:
    if not subject[b'CN'] == fqdn:
        print("FAILED: certificate CN '{0}' did not match {1}."
              .format(x509.get_subject().get_components()['CN'], fqdn))

print("Sending basic un-verified request...")
r2 = requests.get(host + "/", verify=False)

print("Sending verified request...")
r3 = requests.get(host + "/", verify=False)
