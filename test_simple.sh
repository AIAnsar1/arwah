#!/bin/bash

echo "Testing Arwah CLI..."

# Test 1: Help
echo "Test 1: Help"
timeout 5 ./target/debug/arwah --help 2>&1 | head -3

# Test 2: Simple scan
echo "Test 2: Simple scan"
timeout 5 ./target/debug/arwah -a 127.0.0.1 2>&1 | head -3

# Test 3: Both mode
echo "Test 3: Both mode"
timeout 5 ./target/debug/arwah --both 2>&1 | head -3

echo "Tests completed"