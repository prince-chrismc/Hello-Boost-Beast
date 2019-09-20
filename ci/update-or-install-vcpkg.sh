#!/bin/sh
if [ ! -d "$1" ]; then
   echo "usage: $0 <PATH>"
fi

VCPKG_REPO_EXISTS=[ (cd ~/vcpkg && git fetch) ]

if [ VCPKG_REPO_EXISTS ]; then
   git pull --rebase
else
   cd ~/
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg
   ./bootstrap-vcpkg.sh
   sudo ./vcpkg integrate install
   git apply -v --ignore-whitespace "$1"/vcpkg.patch
   git commit -a -m "patching asio and beast version"
fi
