#!/bin/sh
if [ ! -d "$1" ]; then
   echo "usage: $0 <PATH>"
fi

VCPKG_REPO_EXISTS="FALSE"
PKGS="boost-beast openssl fmt"

if [ -d "$HOME/vcpkg/.git/" ]; then
   VCPKG_REPO_EXISTS="TRUE"
fi

if [ $VCPKG_REPO_EXISTS = "TRUE" ]; then
   cd ~/vcpkg || exit 1
   git fetch
   git pull --rebase
   ./vcpkg upgrade --no-dry-run
else
   cd ~/ || exit 1
   if [ -d "$HOME/vcpkg/" ]; then
      rm -rf "$HOME/vcpkg/"
   fi

   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg || exit 1
   ./bootstrap-vcpkg.sh
   ./vcpkg integrate install
   git apply -v --ignore-whitespace "$1"/vcpkg.patch
   git commit -a -m "patching asio and beast version"
   export VCPKG_CXX_FLAGS="-std=c++11 -D _GLIBCXX_USE_CXX11_ABI=0"
fi

./vcpkg install ${PKGS}
