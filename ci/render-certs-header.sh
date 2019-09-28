#!/bin/sh

SERVER_CERT="./ca/intermediate/certs/ecdsa.https.testserver.lan.cert.pem"
SERVER_KEY="./ca/intermediate/private/ecdsa.https.testserver.lan.key.pem"
DH_PARAM="./ca/intermediate/private/dhparam.pem"

cert="s!%%SERVER_CERT%%!$(cat "$SERVER_CERT")!g;"
key="s/%%SERVER_KEY%%/$(cat "$SERVER_KEY")/g;"
param="s/%%DH_PARAM%%/$(cat "$DH_PARAM")/g;"

echo $cert

sed -r "$cert" server_certificate.template |
   sed -r "$key" |
   sed -r "$param" >../src/server_certificate.hpp
