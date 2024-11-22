#!/bin/bash

set -e

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ENV_FOLDER="wasm-unpack-env"
LIBS_FOLDER="libs"
WASM_LIB="lib"

if [ -d "$ENV_FOLDER" ]; then
    echo "Folder '$ENV_FOLDER' already exists."
else
    echo "Folder '$ENV_FOLDER' does not exist. Creating it now..."
    mkdir "$ENV_FOLDER"
    echo "Folder '$ENV_FOLDER' created."
fi

if [ -d "$LIBS_FOLDER" ]; then
    echo "Folder '$LIBS_FOLDER' already exists."
else
    echo "Folder '$LIBS_FOLDER' does not exist. Creating it now..."
    mkdir "$LIBS_FOLDER"
    echo "Folder '$LIBS_FOLDER' created."
fi

PREFIX_DIR=$THIS_DIR/wasm-unpack-env
EMSDK_DIR=$THIS_DIR/libs/emsdk
PREFIX=$PREFIX_DIR

if [ -z "$MAMBA_EXE" ]; then
    echo "Error: MAMBA_EXE environment variable is not set."
    exit 1
fi

cd $THIS_DIR

rm -rf $PREFIX_DIR

echo "Start of compiling emscripten-forge"

if [ ! -d "$EMSDK_DIR" ]; then
    echo "Cloning emsdk repository..."
    cd $LIBS_FOLDER
    git clone https://github.com/emscripten-core/emsdk.git
    cd $EMSDK_DIR
    ./emsdk install "3.1.45"
    ./emsdk activate "3.1.45"
    cd ..
else
    echo "$EMSDK_DIR directory already exists. Skipping clone."
fi

source $EMSDK_DIR/emsdk_env.sh
echo "Finish of compiling emscripten-forge"

if true; then
    echo "Creating wasm env at $PREFIX_DIR"
    $MAMBA_EXE create -p $PREFIX_DIR \
            --platform=emscripten-wasm32 \
            -c https://repo.mamba.pm/emscripten-forge \
            -c https://repo.mamba.pm/conda-forge \
            --yes \
            zlib bzip2 zstd libiconv libarchive "emscripten-abi=3.1.45"
fi
   
export PREFIX=$PREFIX_DIR
export CPPFLAGS="-I$PREFIX/include"
export LDFLAGS="-L$PREFIX/lib"
export LDLIBS="-lbz2 -lz -lzstd"

cd $THIS_DIR

echo "Start of compiling unpack.c"

if [ -d "$WASM_LIB" ]; then
    echo "Folder '$WASM_LIB' already exists."
else
    echo "Folder '$WASM_LIB' does not exist. Creating it now..."
    mkdir "$WASM_LIB"
    echo "Folder '$WASM_LIB' created."
fi

emcc unpack.c -o $WASM_LIB/unpack.js \
    $CPPFLAGS $LDFLAGS \
    ${PREFIX}/lib/libarchive.a \
    ${PREFIX}/lib/libz.a ${PREFIX}/lib/libbz2.a ${PREFIX}/lib/libzstd.a ${PREFIX}/lib/libiconv.a\
    -s MODULARIZE=1 -s WASM=1 -O3 -s ALLOW_MEMORY_GROWTH=1 -fsanitize=address \
    -s INITIAL_MEMORY=128MB \
    -s ENVIRONMENT=web \
    -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap", "getValue", "UTF8ToString", "wasmMemory"]' \
    -s EXPORTED_FUNCTIONS="['_extract_archive', '_free_extracted_archive', '_malloc', '_free']"

echo "Build completed successfully!"