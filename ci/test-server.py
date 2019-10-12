import sys
import ssl
import requests
import OpenSSL
import urllib3
import http.client

if not 2 <= len(sys.argv) <= 3:
    print("Args: '{0}' was not valid.".format(sys.argv), file=sys.stderr)
    print("Usage: {0} <host> <port>\n   host: Fully Qualifed Domain Name (FQDN)\n   port: optional. default 443\n".format(
        sys.argv[0]))
    exit(127)

host = sys.argv[1]
port = 443
if len(sys.argv) == 3:
    port = sys.argv[2]
print("Targert: '{0}:{1}'".format(host, port))

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

urllib3.disable_warnings()

# test_02
unverified = "https://{0}:{1}".format(host, port)
print("Sending HTTPS to {} without checking certificate...".format(unverified))
r1 = requests.get(unverified, verify=False)
if not r1.status_code == 404:
    print("FAILED: Obtained a ({}) from server".format(r1.status_code))
    exit(2)

# test_03
print("Trying to obtain certificate from {}:{}...".format(host, port))
cert = ssl.get_server_certificate((host, port))
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
subject = x509.get_subject().get_components()
if not (b'CN', host.encode()) in subject:
    print("FAILED: certificate CN did not match {}.".format(host))
    exit(3)

# test_04
print("Testing HTTP/1.0 response headers {}:{}...".format(host, port))
http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
http = urllib3.PoolManager(cert_reqs='NONE')
for page in {"/", "/README.md", "/LICENSE"}:
    r2 = http.request("GET", unverified + page)
    if not 'Connection' in r2.headers:
        print("FAILED: Missing 'Connection' header. Obtained headers {} from server".format(
            r2.headers))
        exit(4)
    if not r2.headers['Connection'] == 'closed':
        print("FAILED: 'Connection' header did not indicate 'closed'. Obtained '{}' from server".format(
            r2.headers['Connection']))
        exit(4)
