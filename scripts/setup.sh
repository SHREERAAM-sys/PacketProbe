#!/bin/bash
set -e

echo "[INFO] Checking and installing dependencies..."

# Update package list
sudo apt update -y

# Install core tools
sudo apt install -y build-essential cmake pkg-config

# Install GTest (for unit testing)
if ! dpkg -s libgtest-dev >/dev/null 2>&1; then
    echo "[INFO] Installing GoogleTest sources..."
    sudo apt install -y libgtest-dev
    echo "[INFO] Building GoogleTest..."
    cd /usr/src/gtest
    sudo cmake .
    sudo make
    sudo cp lib/*.a /usr/lib
    cd -
else
    echo "[INFO] GoogleTest already installed."
fi

echo "[INFO] All dependencies installed successfully."
