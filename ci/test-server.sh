!#/bin/sh

[ $(curl -k --http1.1 -i -s https://localhost:8443/README.md https://localhost:8443/LICENSE | grep -o "Keep-Alive: timeout=60, max=49" | wc -l) -eq 1 ] || (echo false && exit 1)
[ $(curl -k --http1.1 -i -s https://localhost:8443/README.md https://localhost:8443/LICENSE | grep -o "Keep-Alive: timeout=60, max=48" | wc -l) -eq 1 ] || (echo false && exit 1)

[ $(wget --no-check-certificate -q -w 65 --save-headers -O - https://localhost:8443/README.md https://localhost:8443/LICENSE | grep -o "Keep-Alive: timeout=60, max=49" | wc -l) -eq 2 ] && echo true
