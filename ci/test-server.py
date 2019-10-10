import sys
import ssl
import requests
import OpenSSL

if 2 <= len(sys.argv) <= 3:
    print("Args: '{0}' was not valid.".format(sys.argv), file=sys.stderr)
    print("Usage: {0} <host> <port>\n   host: Fully Qualifed Domain Name (FQDN)\n   port: optional. default 443\n".format(sys.argv[0]))
    exit(127)

host = sys.argv[1]
port = 443
if len(sys.argv) == 3:
    port = sys.argv[2]
print("Targert: '{0}:{1}'".format(host, port))

unsecure = "http://{0}:{1}".format(host, port)
print("Sending unsecure HTTP to {}...".format(unsecure))
r1 = requests.get(unsecure + "/", verify=False)
if not r1.status_code == 404:
    print("FAILED: Obtained a ({}) from server".format(r1.status_code))
    exit(1)

print("Trying to obtain certificate from {}:{}...".format(host, port))
cert = ssl.get_server_certificate((host, port))
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
subject = x509.get_subject().get_components()
if b'CN' in subject:
    if not subject[b'CN'] == host:
        print("FAILED: certificate CN '{0}' did not match {1}."
              .format(x509.get_subject().get_components()['CN'], host))
        exit(2)
else:
    print("FAILED: certificate did not contain a common name (CN)")
    exit(2)
