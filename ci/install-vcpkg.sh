#!/bin/sh
if [ ! -d "$1" ]; then
   echo "usage: $0 <PATH>"
fi

(cd ~/vcpkg && git fetch && git pull) || (
   cd ~/ &&
   git clone https://github.com/Microsoft/vcpkg.git &&
   cd vcpkg &&
   ./bootstrap-vcpkg.sh &&
   sudo ./vcpkg integrate install &&
   git apply -v --ignore-whitespace "$1"/vcpkg.patch
)
