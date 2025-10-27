"""
survivor_transmitter.py
Transmits IEEE 802.11 beacon frames with a custom vendor-specific element
to signal a survivor's presence. It automatically finds the MAC address
for the specified interface.

Usage:
  sudo ./survivor_transmitter.py <iface> [rate]
"""

import sys
import time
import uuid
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp, get_if_hwaddr

# OUI to distinguish survivor packets from other packets
OUI = b'\xAA\xBB\xCC'
DEFAULT_RATE = 1.0


def format_info(oui, uuid_bytes):
    """Vendor info = OUI (3) + UUID (16)."""
    return oui + uuid_bytes


def build_frame(iface_mac, uuid_bytes, ssid):
    """Constructs the full 802.11 beacon frame."""
    # 802.11 layer
    dot11 = Dot11(
        type=0,  # management frame
        subtype=8,  # beacon
        addr1='ff:ff:ff:ff:ff:ff',  # broadcast destination
        addr2=iface_mac,  # transmitter address
        addr3=iface_mac   # BSSID (network ID)
    )
    # Beacon layer
    beacon = Dot11Beacon()
    # SSID information element
    ssid_elt = Dot11Elt(ID='SSID', info=ssid.encode())
    # Custom vendor-specific information element
    vendor_data = format_info(OUI, uuid_bytes)
    vendor_elt = Dot11Elt(ID=221, info=vendor_data) # 221 is for Vendor Specific

    # Stack all layers together, starting with the RadioTap header
    return RadioTap() / dot11 / beacon / ssid_elt / vendor_elt


def print_usage_and_exit():
    """Prints usage information and exits the script."""
    print("Usage: sudo ./survivor_transmitter.py <iface> [rate_seconds]")
    sys.exit(1)


def main():
    # --- MODIFIED: Updated argument parsing ---
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print_usage_and_exit()

    iface = sys.argv[1]

    # --- NEW: Automatically get the MAC address for the interface ---
    try:
        iface_mac = get_if_hwaddr(iface)
    except Exception as e:
        print(f"[-] Error: Could not get MAC address for interface '{iface}'.")
        print(f"[-] Please ensure the interface name is correct and is up.")
        print(f"[-] Details: {e}")
        sys.exit(1)

    # --- MODIFIED: Rate argument is now the second argument ---
    rate = float(sys.argv[2]) if len(sys.argv) == 3 else DEFAULT_RATE

    survivor_uuid = uuid.uuid4()
    survivor_uuid_bytes = survivor_uuid.bytes
    survivor_ssid = f"Survivor-{survivor_uuid}"

    frame = build_frame(iface_mac=iface_mac, uuid_bytes=survivor_uuid_bytes, ssid=survivor_ssid)

    print(f"[+] Interface: {iface}")
    print(f"[+] Transmitter MAC: {iface_mac} (auto-detected)")
    print(f"[+] Device UUID: {survivor_uuid}")
    print(f"[+] SSID: {survivor_ssid}")
    print(f"[+] Beacon rate: {rate:.2f}s")
    print("\n[+] Make sure interface is in monitor mode (e.g., 'sudo airmon-ng start wlan0').")
    print("[+] Press Ctrl-C to stop.")

    try:
        while True:
            # Send the frame on layer 2
            sendp(frame, iface=iface, verbose=False)
            time.sleep(rate)
    except KeyboardInterrupt:
        print("\n[+] Stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] An error occurred during transmission: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
