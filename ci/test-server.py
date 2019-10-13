import sys
import ssl
import requests
import OpenSSL
import urllib3
import http.client
import argparse
from os import path

parser = argparse.ArgumentParser(
    description="A small test suite that validates a secure webserver's HTTP/1.0 and HTTP/1.1 behavoirs, and tries to verify the SSL certificate that it exposes")
parser.add_argument("host",
                    help="Fully Qualifed Domain Name (FQDN) of the targetted host"
                    "(local or remote) to test and verify")
parser.add_argument("-p", "--port", type=int, default=443,
                    help="Port of the targetted webserver")
parser.add_argument("--ca_cert", default="ca/certs/ca.cert.pem",
                    help="Path to a root certificate that will be used when verifying targets certificate")
args = parser.parse_args()

host = args.host.replace("host=", "")
port = args.port
ca_cert = args.ca_cert

if not path.isfile(ca_cert):
    print("ca_cert '{}' is not a file".format(ca_cert), file=sys.stderr)
    parser.print_help()
    exit(127)

print("   -----\n"
      "   Targert: '{0}:{1}'\n"
      "   Verifying with: {2}\n"
      "   -----\n"
      .format(host, port, ca_cert))

urllib3.disable_warnings()  # Unverified are for test purposes

# test_01
try:
    unsecure = "http://{0}:{1}/".format(host, port)
    print("Sending unsecure HTTP to {}...".format(unsecure))
    requests.get(unsecure)
except requests.ConnectionError:
    pass
else:
    print("FAILED: Obtained a response or unexpected error from server")
    exit(1)

# test_02
unverified = "https://{0}:{1}".format(host, port)
print("Sending HTTPS to {} without checking certificate...".format(unverified))
r1 = requests.get(unverified, verify=False)
if not r1.status_code == 404:
    print("FAILED: Obtained a ({}) from server".format(r1.status_code))
    exit(2)

# test_03
print("Trying to obtain certificate from...")
cert = ssl.get_server_certificate(
    (host, port), ca_certs=ca_cert)
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
subject = x509.get_subject().get_components()
if not (b'CN', host.encode()) in subject:
    print("FAILED: certificate CN did not match {}.".format(host))
    exit(3)

# test_04
print("Attempting to verify certificate...")
r4 = requests.get(unverified, verify=ca_cert)
if not r4.status_code == 404:
    print("FAILED: Obtained a ({}) from server".format(r4.status_code))
    exit(4)

# test_05
print("Testing HTTP/1.0 response headers {}:{}...".format(host, port))
http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
for page in {"/", "/README.md", "/LICENSE"}:
    r5 = requests.get(unverified, verify=ca_cert)
    if not r5.close:
        print("FAILED: Expected underlying connection to be closed")
        exit(5)
    if not 'Connection' in r5.headers:
        print("FAILED: Missing 'Connection' header. Obtained headers {} from server".format(
            r5.headers))
        exit(5)
    if not r5.headers['Connection'] == 'closed':
        print("FAILED: 'Connection' header did not indicate 'closed'. Obtained '{}' from server".format(
            r5.headers['Connection']))
        exit(5)
