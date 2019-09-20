#!/bin/sh
# Shell script leverging curl and wget to verify basic HTTP/1.0 and HTTP/1.1
# connection and keep alive headers

alias curl-insecure="curl -k -i -s"
alias wget-insecure="wget --no-check-certificate -q --save-headers -O -"

BASE_HREF="https://https.testserver.lan:8443"
README_HREF="${BASE_HREF}/README.md"
LICENSE_HREF="${BASE_HREF}/LICENSE"

# Basic HTTP/1.0 response indicated connection closed
[ $(curl-insecure --http1.0 "${BASE_HREF}" "${README_HREF}" "${LICENSE_HREF}" |
   grep -o "Connection: closed" | wc -l) -eq 3 ] || (echo "Failed: HTTP/1.0" && exit 1)

# Basic HTTP/1.1 response keep alive limit decrements
HTTP_ONE_DOT_ONE_MULTIPLE_REQUESTS=$(curl-insecure --http1.1 "${README_HREF}" "${LICENSE_HREF}")
[ $(echo "${HTTP_ONE_DOT_ONE_MULTIPLE_REQUESTS}" | grep -o "Keep-Alive: timeout=60, max=49" |
   wc -l) -eq 1 ] || (echo "Failed: HTTP/1.1 - Limit" && exit 1)
[ $(echo "${HTTP_ONE_DOT_ONE_MULTIPLE_REQUESTS}" | grep -o "Keep-Alive: timeout=60, max=48" |
   wc -l) -eq 1 ] || (echo "Failed: HTTP/1.1 - Decrement" && exit 1)

# Basic HTTP/1.1 response keep alive timeout reset connection
[ $(wget-insecure -w 65 "${README_HREF}" "${LICENSE_HREF}" | grep -o "Keep-Alive: timeout=60, max=49" |
   wc -l) -eq 2 ] || (echo "Failed: HTTP/1.1 - Timeout" && exit 1)
