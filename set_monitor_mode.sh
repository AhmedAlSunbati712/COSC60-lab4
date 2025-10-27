#!/bin/bash
# Usage: sudo ./set_monitor_mode.sh <interface> <channel>
# Example: sudo ./set_monitor_mode.sh wlan0 6

if [ "$#" -ne 2 ]; then
    echo "Usage: sudo $0 <interface> <channel>"
    exit 1
fi

IFACE=$1
CHANNEL=$2

echo "[+] Setting $IFACE to monitor mode on channel $CHANNEL..."

# Bring down interface
sudo ip link set $IFACE down || { echo "[-] Failed to bring down $IFACE"; exit 1; }

# Set type to monitor
sudo iw dev $IFACE set type monitor || { echo "[-] Failed to set monitor mode"; exit 1; }

# Set channel
sudo iw dev $IFACE set channel $CHANNEL || { echo "[-] Failed to set channel"; exit 1; }

# Bring interface back up
sudo ip link set $IFACE up || { echo "[-] Failed to bring up $IFACE"; exit 1; }

# Confirm
echo "[+] Verifying monitor mode..."
iw dev $IFACE info | grep -E "Interface|type|channel"

echo "[✓] $IFACE successfully set to monitor mode on channel $CHANNEL"
