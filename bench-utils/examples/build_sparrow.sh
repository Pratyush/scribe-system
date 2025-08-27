#!/usr/bin/env bash
set -e

# 1. Check that libgmp is installed using pkg-config
if ! pkg-config --exists gmp; then
    echo "Error: libgmp not found. Please install libgmp on your system." >&2
    exit 1
fi

SPARROW_DIR="../../target/sparrow"
mkdir -p "$SPARROW_DIR"

# 2. Download the library archive
ARCHIVE_URL="https://github.com/anonymousg3bz6q2/Sparrow/archive/refs/heads/main.zip"
ARCHIVE_PATH="$OUT_DIR/sparrow.zip"

echo "Downloading library from $ARCHIVE_URL..."
# Using curl to download the file
curl -L "$ARCHIVE_URL" -o "$ARCHIVE_PATH"

echo "Extracting archive to $UNZIP_DIR..."
unzip -q "$ARCHIVE_PATH" -d "$UNZIP_DIR"

# 4. Use CMake to build the library
echo "Configuring and building the library with CMake..."
# Create a separate build directory for CMake
BUILD_DIR="$OUT_DIR/"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure the project. Add additional -D options if needed.
cmake "$UNZIP_DIR"

# Build the library (default: use all available cores)
cmake --build . -- -j"$(nproc)"