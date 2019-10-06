#!/bin/sh
# Shell script leverging curl and wget to verify basic HTTP/1.0 and HTTP/1.1
# behavoir such as connection and keep alive headers and HTTPS criterias

alias curl-insecure="curl -k -i -s"
alias wget-insecure="wget --no-check-certificate -q --save-headers -O -"

BASE_HREF="https://https.testserver.lan:8443"
README_HREF="${BASE_HREF}/README.md"
LICENSE_HREF="${BASE_HREF}/LICENSE"

# HTTP does not answer
curl --http1.1 http://https.testserver.lan:8443 # I expect a "curl: (52) Empty reply from server"
[ $? -eq 0 ] || (echo "Failed: HTTP" && exit 1)

# HTTPS reports correct hostname
[ $(wget --no-check-certificate --output-file=- "${BASE_HREF}" |
   grep -c ".testserver.lan") -ge 1 ] || (echo "Failed: Certificate Hostname" && exit 1)

# HTTPS verification with CA passes
curl -v --http1.1 --cacert "$(pwd)/ca/certs/ca.cert.pem" "${BASE_HREF}"
openssl s_client -showcerts -servername server -connect 127.0.0.1:8443

###
mkdir /usr/local/share/ca-certificates
cp ca.cert.pem /usr/local/share/ca-certificates
sudo cp ca.cert.pem /usr/local/share/ca-certificates
cd /usr/local/share/ca-certificates/
openssl x509 -outform der -in ca.cert.pem -out testerver.lan.crt
sudo openssl x509 -outform der -in ca.cert.pem -out testerver.lan.crt
sudo update-ca-certificates
sudo cp testerver.lan.crt /etc/ssl/certs/

# HTTPS does not answer from incorrect name

# Basic HTTP/1.0 response indicated connection closed
[ $(curl-insecure --http1.0 "${BASE_HREF}" "${README_HREF}" "${LICENSE_HREF}" |
   grep -o "Connection: closed" | wc -l) -eq 3 ] || (echo "Failed: HTTP/1.0" && exit 1)

# Basic HTTP/1.1 response keep alive limit decrements
HTTP_ONE_DOT_ONE_MULTIPLE_REQUESTS=$(curl-insecure --http1.1 "${README_HREF}" "${LICENSE_HREF}")
[ $(echo "${HTTP_ONE_DOT_ONE_MULTIPLE_REQUESTS}" | grep -o "Keep-Alive: timeout=60, max=49" |
   wc -l) -eq 1 ] || (echo "Failed: HTTP/1.1 - Limit" && exit 1)
[ $(echo "${HTTP_ONE_DOT_ONE_MULTIPLE_REQUESTS}" | grep -o "Keep-Alive: timeout=60, max=48" |
   wc -l) -eq 1 ] || (echo "Failed: HTTP/1.1 - Decrement" && exit 1)

# Basic HTTP/1.1 response limit loops around

# Basic HTTP/1.1 response keep alive timeout reset connection
[ $(wget-insecure -w 65 "${README_HREF}" "${LICENSE_HREF}" | grep -o "Keep-Alive: timeout=60, max=49" |
   wc -l) -eq 2 ] || (echo "Failed: HTTP/1.1 - Timeout" && exit 1)
