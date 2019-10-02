import fileinput

SERVER_CERT = "./ca/intermediate/certs/ecdsa.https.testserver.lan.cert.cahin.pem"
SERVER_KEY = "./ca/intermediate/private/ecdsa.https.testserver.lan.key.pem"
DH_PARAM = "./ca/intermediate/private/dhparam.pem"

output = open('../src/server_certificate.hpp', 'w')

with open(SERVER_CERT, 'r') as file:
    cert = file.read()

with open(SERVER_KEY, 'r') as file:
    key = file.read()

with open(DH_PARAM, 'r') as file:
    param = file.read()

with fileinput.FileInput("server_certificate.template") as file:
    for line in file:
        line = line.replace("%%SERVER_CERT%%", cert)
        line = line.replace("%%SERVER_KEY%%", key)
        line = line.replace("%%DH_PARAM%%", param)
        output.write(line)
