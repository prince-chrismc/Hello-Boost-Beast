#!/bin/sh

# This script started life as a copy paste from https://jamielinux.com/docs/openssl-certificate-authority/index.html
# The modifications are to the algorithm is ecdsa

mkdir -p /root/ca
cd /root/ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 >serial

# Create ECDSA key
openssl ecparam -name secp256r1 -genkey -noout -out private/ca.key.pem
chmod 400 private/ca.key.pem

openssl req -config openssl.cnf \
   -key private/ca.key.pem \
   -new -x509 -days 7300 -sha256 -extensions v3_ca \
   -out certs/ca.cert.pem
chmod 444 certs/ca.cert.pem

openssl x509 -noout -text -in certs/ca.cert.pem # verification

mkdir /root/ca/intermediate
cd /root/ca/intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 >serial
echo 1000 >/root/ca/intermediate/crlnumber

openssl ecparam -name secp256r1 -genkey -noout \
   -out intermediate/private/intermediate.key.pem

chmod 400 intermediate/private/intermediate.key.pem

openssl req -config intermediate/openssl.cnf -new -sha256 \
   -key intermediate/private/intermediate.key.pem \
   -out intermediate/csr/intermediate.csr.pem

openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
   -days 3650 -notext -md sha256 \
   -in intermediate/csr/intermediate.csr.pem \
   -out intermediate/certs/intermediate.cert.pem

chmod 444 intermediate/certs/intermediate.cert.pem

openssl x509 -noout -text \
   -in intermediate/certs/intermediate.cert.pem

openssl verify -CAfile certs/ca.cert.pem \
   intermediate/certs/intermediate.cert.pem

certs/ca.cert.pem >intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem
