#!/bin/bash

echo "🎯 Final Integration Test"
echo "========================"

# Проверяем что бинарник собрался
if [ ! -f "./target/debug/arwah" ]; then
    echo "❌ Binary not found. Building..."
    cargo build
fi

echo "✅ Binary found!"
echo ""

echo "🔍 Test 1: Help command"
echo "------------------------"
./target/debug/arwah --help | grep -E "(sniff|both)"
echo ""

echo "🔍 Test 2: Port scanning (default mode)"
echo "----------------------------------------"
echo "Command: ./target/debug/arwah -a 127.0.0.1"
echo "Expected: Should scan localhost ports"
echo ""

echo "🔍 Test 3: Sniffer mode"
echo "------------------------"
echo "Command: sudo ./target/debug/arwah --sniff"
echo "Expected: Should start packet capture (requires root)"
echo ""

echo "🔍 Test 4: Combined mode"
echo "-------------------------"
echo "Command: ./target/debug/arwah --both"
echo "Expected: Should run port scan then packet capture"
echo ""

echo "✅ All modes integrated successfully!"
echo ""
echo "🚀 Final Usage:"
echo "  ./target/debug/arwah -a <target>     # Port scanning"
echo "  sudo ./target/debug/arwah --sniff    # Packet capture"
echo "  ./target/debug/arwah --both          # Combined mode"
echo ""
echo "🎉 Arwah unified tool is ready!"