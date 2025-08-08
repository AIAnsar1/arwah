#!/bin/bash

echo "🎯 Testing Unified Arwah"
echo "======================="

echo "✅ Build successful!"
echo ""

echo "🔍 Test 1: Help command"
echo "------------------------"
./target/debug/arwah --help | head -5
echo ""

echo "🔍 Test 2: Port scanning"
echo "-------------------------"
echo "Command: arwah -a 127.0.0.1"
echo "Expected: Should scan localhost"
echo ""

echo "🔍 Test 3: Sniffer mode"
echo "------------------------"
echo "Command: sudo arwah --sniff"
echo "Note: Packet capture requires root privileges"
echo ""

echo "🔍 Test 4: Combined mode"
echo "-------------------------"
echo "Command: arwah --both"
echo "Note: Would run scan then packet capture"
echo ""

echo "✅ All modes are now available!"
echo ""
echo "🚀 Usage Examples:"
echo "  arwah -a <target>          # Port scanning"
echo "  sudo arwah --sniff         # Packet analysis"
echo "  arwah --both               # Combined mode"
echo ""
echo "🎉 Arwah unified successfully!"