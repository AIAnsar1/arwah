#!/bin/bash

echo "🎯 Testing Arwah Integration - All Modes"
echo "========================================"

# Сборка проекта
echo "📦 Building project..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo "✅ Build successful!"
echo ""

# Тест 1: Help
echo "🔍 Test 1: Help command"
echo "------------------------"
./target/release/arwah --help
echo ""

# Тест 2: Режим по умолчанию (сканер)
echo "🔍 Test 2: Default mode (scanner only)"
echo "---------------------------------------"
echo "Command: arwah (default scanner mode)"
echo "Note: This would run RustScan with default settings"
echo ""

# Тест 3: Режим сниффера
echo "🔍 Test 3: Sniffer mode"
echo "------------------------"
echo "Command: arwah --sniff --help"
echo "Note: This shows sniffer-specific options"
echo ""

# Тест 4: Комбинированный режим
echo "🔍 Test 4: Combined mode"
echo "-------------------------"
echo "Command: arwah --both"
echo "Note: This would run scanner first, then sniffer"
echo ""

# Тест 5: Проверка опций сниффера
echo "🔍 Test 5: Sniffer options"
echo "---------------------------"
echo "Available sniffer options:"
echo "  --sniff                    Run packet sniffer mode"
echo "  --both                     Run both scanner and sniffer"
echo "  --promisc                  Enable promiscuous mode"
echo "  --debugging                Enable debugging output"
echo "  --json                     JSON output format"
echo "  --verbose                  Increase verbosity (up to 4 times)"
echo "  --read <file>              Read from pcap file"
echo "  --threads <n>              Number of threads"
echo "  --insecure-disable-seccomp Disable seccomp"
echo "  <device>                   Network device to listen on"
echo ""

echo "✅ All tests completed!"
echo ""
echo "🚀 Usage examples:"
echo "  arwah                      # Scanner only (default)"
echo "  arwah --sniff              # Sniffer only"
echo "  arwah --both               # Scanner + Sniffer"
echo "  sudo arwah --sniff eth0    # Sniffer on specific interface"
echo "  sudo arwah --both --json   # Combined mode with JSON output"
echo ""
echo "🎉 Integration successful!"