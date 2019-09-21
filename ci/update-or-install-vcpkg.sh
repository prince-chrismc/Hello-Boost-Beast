#!/bin/sh
if [ ! -d "$1" ]; then
   echo "usage: $0 <PATH>"
fi

$(cd ~/vcpkg && git fetch)
VCPKG_REPO_EXISTS=$?

if [ $VCPKG_REPO_EXISTS ]; then
   cd ~/vcpkg || exit 1
   git pull --rebase
   ./vcpkg upgrade --no-dry-run
else
   cd ~/ || exit 1
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg || exit 1
   ./bootstrap-vcpkg.sh
   sudo ./vcpkg integrate install
   git apply -v --ignore-whitespace "$1"/vcpkg.patch
   git commit -a -m "patching asio and beast version"
   export VCPKG_CXX_FLAGS="-std=c++11 -D _GLIBCXX_USE_CXX11_ABI=0"
   ./vcpkg install beast:x64-linux openssl:x64-linux
fi
