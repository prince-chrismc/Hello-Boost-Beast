import sys
import requests

if len(sys.argv) != 2:
    print("Args: '{}' was not valid.".format(sys.argv), file=sys.stderr)
    print("{0} <host>".format(sys.argv[0]))
    exit(127)

host = sys.argv[1]
if not host.startswith("https://"):
    host = "https://" + host

print("Sending basic un-verified request...")
r = requests.get(host + "/", verify=False)
data = r.content  # Content of response
print(r.status_code)  # Status code of response
# print(data)

print("Sending verified request...")
rv = requests.get(
    host + "/",
    #  verify=False,
    #  verify="ca/intermediate/certs/ca-chain.cert.pem")
    # verify="ca/intermediate/certs/"
)
print(rv.status_code)  # Status code of response
