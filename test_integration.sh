#!/bin/bash

echo "=== Testing Arwah Integration ==="

# Сборка проекта
echo "Building project..."
cargo build --release

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    
    # Тестируем help
    echo -e "\n=== Testing help ==="
    ./target/release/arwah --help
    
    # Тестируем scan help
    echo -e "\n=== Testing scan help ==="
    ./target/release/arwah scan --help
    
    # Тестируем sniff help
    echo -e "\n=== Testing sniff help ==="
    ./target/release/arwah sniff --help
    
    echo -e "\n✅ All tests completed!"
else
    echo "❌ Build failed!"
    exit 1
fi