#!/bin/sh
# Shell script leverging curl and wget to verify basic HTTP/1.0 and HTTP/1.1
# behavoir such as connection and keep alive headers and HTTPS criterias

alias curl-insecure="curl -k -i -s"
alias wget-insecure="wget --no-check-certificate -q --save-headers -O -"

BASE_HREF="https://https.testserver.lan:8443"
README_HREF="${BASE_HREF}/README.md"
LICENSE_HREF="${BASE_HREF}/LICENSE"

# HTTPS does not answer from incorrect name

# Basic HTTP/1.1 response limit loops around

# Basic HTTP/1.1 response keep alive timeout reset connection
[ $(wget-insecure -w 65 "${README_HREF}" "${LICENSE_HREF}" | grep -o "Keep-Alive: timeout=60, max=49" |
   wc -l) -eq 2 ] || (echo "Failed: HTTP/1.1 - Timeout" && exit 1)
