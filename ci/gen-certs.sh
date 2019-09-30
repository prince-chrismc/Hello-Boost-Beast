#!/bin/sh

# This script started life as a copy paste from https://jamielinux.com/docs/openssl-certificate-authority/index.html
# The modifications are to the algorithm is ecdsa

rm -rf ca/

echo "$0: Starting in: $(pwd)"
mkdir ca ca/certs ca/newcerts ca/private
chmod 700 ca/private
touch ca/index.txt
echo 1000 >ca/serial

DOMAIN="testserver.lan"
CA_FQDN="ca.$DOMAIN"
INT_FQDN="i$CA_FQDN"

# Create ECDSA key
echo "Generating ca.key.pem"
openssl ecparam -name prime256v1 -genkey -noout -out ca/private/ca.key.pem
chmod 400 ca/private/ca.key.pem

echo "Generating ca.cert.pem"
openssl req -config openssl.cnf \
   -key ca/private/ca.key.pem \
   -new -x509 -days 18250 -sha256 -extensions v3_ca \
   -out ca/certs/ca.cert.pem \
   -subj "/C=CA/ST=Quebec/O=prince-chrismc/CN=$CA_FQDN"
chmod 444 ca/certs/ca.cert.pem

# openssl x509 -noout -text -in certs/ca.cert.pem # verification
mkdir ca/intermediate ca/intermediate/certs ca/intermediate/crl ca/intermediate/csr \
   ca/intermediate/newcerts ca/intermediate/private
chmod 700 ca/intermediate/private
touch ca/intermediate/index.txt
echo 1000 >ca/intermediate/serial
echo 1000 >ca/intermediate/crlnumber

echo "Generating intermediate.key.pem"
openssl ecparam -name prime256v1 -genkey -noout \
   -out ca/intermediate/private/intermediate.key.pem

chmod 400 ca/intermediate/private/intermediate.key.pem

echo "Generating intermediate.crs.pem"
openssl req -config intermediate-openssl.cnf -new -sha256 \
   -key ca/intermediate/private/intermediate.key.pem \
   -out ca/intermediate/csr/intermediate.csr.pem \
   -subj "/C=CA/ST=Quebec/O=prince-chrismc/CN=$INT_FQDN"

echo "Generating intermediate.cert.pem"
openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
   -days 18250 -notext -md sha256 \
   -in ca/intermediate/csr/intermediate.csr.pem \
   -out ca/intermediate/certs/intermediate.cert.pem \
   -subj "/C=CA/ST=Quebec/O=prince-chrismc/CN=$INT_FQDN"

chmod 444 ca/intermediate/certs/intermediate.cert.pem

# openssl x509 -noout -text \
#    -in ca/intermediate/certs/intermediate.cert.pem

# openssl verify -CAfile ca/certs/ca.cert.pem ca/intermediate/certs/intermediate.cert.pem

cp ca/certs/ca.cert.pem ca/intermediate/certs/ca-chain.cert.pem
chmod 444 ca/intermediate/certs/ca-chain.cert.pem

# Create DH parameters
openssl dhparam -out ca/intermediate/private/dhparam.pem 4096

# Create CRL
openssl ca -config intermediate-openssl.cnf -gencrl \
   -out ca/intermediate/crl/intermediate.crl.pem

# Create OCSP pair
openssl genrsa -out ca/intermediate/private/ocsp.$DOMAIN.key.pem 4096
openssl req -config intermediate-openssl.cnf -new -sha256 \
   -key ca/intermediate/private/ocsp.$DOMAIN.key.pem \
   -out ca/intermediate/csr/ocsp.$DOMAIN.csr.pem \
   -subj "/C=CA/ST=Quebec/O=prince-chrismc/CN=ocsp.$DOMAIN"
openssl ca -batch -config intermediate-openssl.cnf -extensions ocsp \
   -days 18250 -notext -md sha256 \
   -in ca/intermediate/csr/ocsp.$DOMAIN.csr.pem \
   -out ca/intermediate/certs/ocsp.$DOMAIN.cert.pem

# Create ECDSA key
FQDN="https.$DOMAIN"
echo "Generating ecdsa.$FQDN.key.pem"
openssl ecparam -name prime256v1 -genkey -noout -out ca/intermediate/private/ecdsa.$FQDN.key.pem
chmod 400 ca/intermediate/private/ecdsa.$FQDN.key.pem

openssl req -config intermediate-openssl.cnf \
   -key ca/intermediate/private/ecdsa.$FQDN.key.pem \
   -new -sha256 -out ca/intermediate/csr/ecdsa.$FQDN.csr.pem \
   -subj "/C=CA/ST=Quebec/O=prince-chrismc/CN=$FQDN"

# Sign ECDSA CSR
openssl ca -batch -config intermediate-openssl.cnf -extensions server_cert \
   -days 18250 -notext -md sha256 -in ca/intermediate/csr/ecdsa.$FQDN.csr.pem \
   -out ca/intermediate/certs/ecdsa.$FQDN.cert.pem
cat ca/intermediate/certs/ecdsa.$FQDN.cert.pem \
   ca/intermediate/certs/ca-chain.cert.pem \
   >ca/intermediate/certs/ecdsa.$FQDN.cert.chain.pem
# openssl pkcs12 -passout pass: -export \
#    -out ca/intermediate/certs/ecdsa.$FQDN.cert.pfx \
#    -inkey ca/intermediate/private/ecdsa.$FQDN.key.pem \
#    -in ca/intermediate/certs/ecdsa.$FQDN.cert.pem