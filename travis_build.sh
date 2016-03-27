#!/bin/bash

# Build a custom version of GN
git clone git://github.com/mikezackles/gn-git
cd gn-git
makepkg -sr --noconfirm
sudo pacman -U gn-git*pkg.tar.xz --noconfirm
cd ..
gn gen out/release --args="is_debug=false"
ninja -C out/release
