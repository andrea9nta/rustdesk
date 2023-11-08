#!/bin/sh

mkdir $HOME/Downloads/rustdesk-build


brew install flutter cocoapods
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
brew install llvm create-dmg nasm yasm cmake gcc wget ninja pkg-config



FLUTTER_RUST_BRIDGE_VERSION="1.75.3"



cd $HOME/Downloads/rustdesk-build
git clone https://github.com/microsoft/vcpkg
cd vcpkg
git checkout 2023.04.15
./bootstrap-vcpkg.sh
brew install nasm yasm
./vcpkg install libvpx libyuv opus aom
git clone https://github.com/rustdesk/rustdesk
cd rustdesk


# Change this
export VCPKG_ROOT=$HOME/Downloads/rustdesk-build/vcpkg


wget https://github.com/c-smile/sciter-sdk/raw/master/bin.osx/libsciter.dylib


# This maybe has to be put before  ./vcpkg install libvpx libyuv opus aom
cargo install flutter_rust_bridge_codegen --version $FLUTTER_RUST_BRIDGE_VERSION --features "uuid"
pushd flutter && flutter pub get && popd
~/.cargo/bin/flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs --dart-output ./flutter/lib/generated_bridge.dart --c-output ./flutter/macos/Runner/bridge_generated.h



./build.py --flutter


# The file is $HOME/flutter/rustdesk.dmg
