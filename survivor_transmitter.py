"""
survivor_transmitter.py

Usage:
  sudo ./survivor_transmitter.py <iface> <MAC_address> [rate]
"""

import sys
import time
import struct
import uuid
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp

# OUI to distinguish survivor packets from other packets
OUI = b'\xAA\xBB\xCC'
DEFAULT_RATE = 1.0


def format_info(oui, uuid_bytes):
    """Vendor info = OUI (3) + packed UUID (16)."""
    return oui + struct.pack('!16s', uuid_bytes)


def build_frame(iface_mac, uuid_bytes, ssid):
    """Construct RadioTap / Dot11 / Dot11Beacon / SSID IE / Vendor IE."""
    dot11 = Dot11(
        type=0,  # management frame
        subtype=8,  # beacon
        addr1='ff:ff:ff:ff:ff:ff',  # broadcast
        addr2=iface_mac,  # transmitter
        addr3=iface_mac   # BSSID (network ID)
    )
    beacon = Dot11Beacon()
    ssid_elt = Dot11Elt(ID='SSID', info=ssid.encode())
    vendor_data = format_info(OUI, uuid_bytes)
    vendor_elt = Dot11Elt(ID=221, info=vendor_data)
    return RadioTap() / dot11 / beacon / ssid_elt / vendor_elt


def print_usage_and_exit():
    print("Usage: sudo ./survivor_transmitter.py <iface> <MAC_address> [rate_seconds]")
    sys.exit(1)


def main():
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print_usage_and_exit()

    iface = sys.argv[1]
    iface_mac = sys.argv[2]
    rate = float(sys.argv[3]) if len(sys.argv) == 4 else DEFAULT_RATE

    survivor_uuid = uuid.uuid4()
    survivor_uuid_bytes = survivor_uuid.bytes
    survivor_ssid = f"Survivor-{survivor_uuid}"

    frame = build_frame(iface_mac=iface_mac, uuid_bytes=survivor_uuid_bytes, ssid=survivor_ssid)

    print(f"[+] Interface: {iface}")
    print(f"[+] Transmitter MAC: {iface_mac}")
    print(f"[+] Device UUID: {survivor_uuid}")
    print(f"[+] SSID: {survivor_ssid}")
    print(f"[+] Beacon rate: {rate:.2f}s")
    print("[+] Make sure interface is in monitor mode and run as root (sudo).")
    print("[+] Press Ctrl-C to stop.")

    try:
        while True:
            sendp(frame, iface=iface, verbose=False)
            time.sleep(rate)
    except KeyboardInterrupt:
        print("\n[+] Stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
