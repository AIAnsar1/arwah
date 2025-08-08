#!/bin/bash

echo "=== Arwah Unified Tool Test ==="

# Проверяем компиляцию
echo "1. Building Arwah..."
cargo build --release --bin arwah

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi

# Проверяем help
echo "2. Testing help command..."
./target/release/arwah --help

echo "3. Testing scan subcommand help..."
./target/release/arwah scan --help

echo "4. Testing sniff subcommand help..."
./target/release/arwah sniff --help

echo "=== Test completed ==="