#!/bin/sh
if [ ! -d "$1" ]; then
   echo "usage: $0 <PATH>"
fi

(cd ~/vcpkg && git reset --hard 8a44d47f76e01b787ebb1fc71dfe36909fdd1793 && git fetch && git pull) || (
   cd ~/ &&
   git clone https://github.com/Microsoft/vcpkg.git &&
   cd vcpkg &&
   ./bootstrap-vcpkg.sh &&
   sudo ./vcpkg integrate install &&
   git apply -v --ignore-whitespace "$1"/vcpkg.patch
)
