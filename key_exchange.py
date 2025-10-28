#!/usr/bin/env python3

"""
This script performs a key exchange between two devices in Wi-Fi monitor mode
by measuring the Received Signal Strength Indication (RSSI) of a series of
packet exchanges.

Usage:
On both devices:
    sudo python3 rssi_key_exchange_no_threads.py <interface_name>

citation: Google Gemini for explanation on probe requests for Dot11 instead of default Data frame
          and help on how Dot11 elements are stacked
citation: https://scapy.readthedocs.io/en/latest/build_dissect.html for custom layer info
"""

import sys
import hashlib
import numpy as np
import time
import struct
from scapy.all import *

# --- Configuration ---
# Global variables that will be set by discovery
IFACE = None
MY_MAC = None
PEER_MAC = None
role = None

# Discovery parameters
OUI = b'\xAA\xBB\xC5'
MSG_TYPE_READY = 0x01
MSG_TYPE_ACK = 0x02
DISCOVERY_LISTEN_TIME = 3
INITIATOR_LISTEN_TIMEOUT = 1 # to listen for an ACK after sending READY

# Exchange parameters
TOTAL_PACKETS = 300
MAX_RETRIES_PER_PACKET = 20
RESPONSE_TIMEOUT = 0.5
RESPONDER_SNIFF_TIMEOUT = TOTAL_PACKETS * (RESPONSE_TIMEOUT * MAX_RETRIES_PER_PACKET) * 1.2 + 30.0

# Message types for the key exchange payload
MSG_TYPES = {
    0: "RSSI_INIT_TO_RESP",
    1: "RSSI_RESP_TO_INIT",
    2: "INDICES_INIT_TO_RESP", # Initiator sends used indices
    3: "VERIFY_INIT_TO_RESP",  # Initiator sends key hash
    4: "VERIFY_RESP_TO_INIT"   # Responder replies with "OK" or "FAIL"
}

# --- Data Packing/Unpacking Functions ---

def pack_ke_data(msg_type, index=0, retry_num=0, payload=b''):
    """
    Packs key exchange data into a bytes object.
    Format: !HBBH (Network byte order)
    - index (2 bytes)
    - retry_num (1 byte)
    - msg_type (1 byte)
    - payload_len (2 bytes)
    - payload (variable)
    """
    payload_len = len(payload)
    header = struct.pack('!HBBH', index, retry_num, msg_type, payload_len)
    return header + payload

def unpack_ke_data(data):
    """
    Unpacks key exchange data from a bytes object.
    Returns a dictionary with the data or None if unpacking fails.
    """
    header_format = '!HBBH'
    header_size = struct.calcsize(header_format)
    if len(data) < header_size:
        return None

    index, retry_num, msg_type, payload_len = struct.unpack(header_format, data[:header_size])

    if len(data) < header_size + payload_len:
        return None

    payload = data[header_size : header_size + payload_len]

    return {
        "index": index,
        "retry_num": retry_num,
        "msg_type": msg_type,
        "payload_len": payload_len,
        "payload": payload
    }


# --- Discovery Functions ---

def create_vendor_elt(msg_type):
    """
    Constructs a vendor-specific information element (Dot11Elt ID=221)
    containing our OUI, message type, and MAC address.
    """
    global MY_MAC, IFACE
    mac_bytes = bytes.fromhex(MY_MAC.replace(':', ''))
    return Dot11Elt(ID=221, info=OUI + bytes([msg_type]) + mac_bytes)



def perform_discovery():
    """
    Listens to determine role. If no initiator is found, becomes initiator
    and broadcasts READY beacons in a send->listen loop until an ACK is heard.
    """
    # These globals are set by this function for the rest of the script
    global role, PEER_MAC

    # This flag is now a local variable, private to perform_discovery
    discovery_complete_flag = False

    def discovery_packet_handler(pkt):
        """
        Callback function for sniffing during the discovery phase.
        Looks for READY or ACK packets from a peer.
        """
        nonlocal discovery_complete_flag
        global PEER_MAC, role

        # We only care about vendor-specific elements
        if not pkt.haslayer(Dot11Elt):
            return

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            # Check for our specific element: ID 221, length 10 (3 OUI + 1 type + 6 MAC), and matching OUI
            if elt.ID == 221 and len(elt.info) == 10 and elt.info[:3] == OUI:
                # If we've already completed discovery, do nothing
                if discovery_complete_flag:
                    return

                msg_type = elt.info[3]
                peer_mac_bytes = elt.info[4:]
                peer_mac_str = ':'.join(f'{b:02x}' for b in peer_mac_bytes)
                # Ignore our own packets
                if peer_mac_str.lower() == MY_MAC.lower():
                    elt = elt.payload.getlayer(Dot11Elt)
                    continue

                if msg_type == MSG_TYPE_READY:
                    # We found an initiator. We are the responder.
                    print(f"Heard READY from {peer_mac_str}")
                    role = 'responder'
                    PEER_MAC = peer_mac_str

                    # Send ACK to confirm
                    print(f"Sending ACK to {PEER_MAC}...")
                    ack_elt = create_vendor_elt(MSG_TYPE_ACK)
                    if ack_elt:
                        # Send a probe request frame (type 0, subtype 4) as our ACK
                        ack_pkt = RadioTap() / \
                                  Dot11(addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC, type=0, subtype=4) / \
                                  ack_elt
                        sendp(ack_pkt, iface=IFACE, verbose=0, count=10, inter=0.15)

                    discovery_complete_flag = True
                    return

                elif msg_type == MSG_TYPE_ACK and role == 'initiator':
                    # We are the initiator and a responder has ACK'd us
                    print(f"Heard ACK from {peer_mac_str}")
                    PEER_MAC = peer_mac_str
                    discovery_complete_flag = True
                    return

            # Move to the next element
            elt = elt.payload.getlayer(Dot11Elt)

    print(f"Starting discovery on {IFACE} (My MAC: {MY_MAC})")
    print(f"Listening for {DISCOVERY_LISTEN_TIME}s to find an initiator...")

    # Block and listen for DISCOVERY_LISTEN_TIME.
    # discovery_packet_handler will set role/PEER_MAC/flag if it hears a READY.
    sniff(
        iface=IFACE,
        prn=discovery_packet_handler,
        timeout=DISCOVERY_LISTEN_TIME,
        stop_filter=lambda p: discovery_complete_flag
    )

    if role == 'responder':
        # Handler found a READY, sent an ACK, and set the flag. We are done.
        print("Role set to RESPONDER. Waiting for key exchange.")
        return role

    # If we're here, we heard no READY packets. We become the initiator.
    print("No initiator found. Becoming INITIATOR.")
    role = 'initiator'

    # Initiator's Send/Listen Loop
    # We broadcast READY beacons and listen for an ACK.
    print("Broadcasting READY beacons...")
    ready_elt = create_vendor_elt(MSG_TYPE_READY)
    if not ready_elt:
        print("Error: Could not create READY beacon.")
        return None

    # Create a beacon frame (type 0, subtype 8)
    ready_pkt = RadioTap() / \
                Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=MY_MAC, addr3='ff:ff:ff:ff:ff:ff', type=0, subtype=8) / \
                Dot11Beacon() / \
                ready_elt

    # Loop until the discovery_packet_handler finds an ACK
    while not discovery_complete_flag:
        print("Sending beacon burst...")
        sendp(ready_pkt, iface=IFACE, verbose=0, count=5, inter=0.2)

        print(f"Listening for ACK for {INITIATOR_LISTEN_TIMEOUT}s...")
        sniff(
            iface=IFACE,
            prn=discovery_packet_handler,
            timeout=INITIATOR_LISTEN_TIMEOUT,
            stop_filter=lambda p: discovery_complete_flag
        )

    print(f"Discovery complete. Peer found: {PEER_MAC}")
    return role


# --- Argument Parsing ---

def parse_args():
    """Parses sys.argv to get the interface."""
    global IFACE, MY_MAC
    if len(sys.argv) != 2:
        print(f"Error: Please specify an interface.")
        print(f"Usage: sudo python3 {sys.argv[0]} <interface>")
        sys.exit(1)

    IFACE = sys.argv[1]

    try:
        # Get the MAC address for the specified interface
        MY_MAC = get_if_hwaddr(IFACE)
        if not MY_MAC:
            raise Exception("Could not get MAC address.")
    except Exception as e:
        print(f"Error: Could not get MAC address for interface '{IFACE}'.")
        print(e)
        sys.exit(1)

# --- Key Exchange Functions ---

def get_rssi(pkt):
    """Extracts the RSSI value from a RadioTap header."""
    return pkt[RadioTap].dbm_antsignal if RadioTap in pkt else None

def perform_exchange(role):
    """
    Performs the main packet exchange to gather RSSI measurements.
    Returns a dictionary of {index: rssi_value}
    """
    rssi_measurements = {}

    if role == 'initiator':
        print(f"Initiator starting {TOTAL_PACKETS} packet exchanges with {PEER_MAC}...")
        index = 0
        while index < TOTAL_PACKETS:
            retries = 0
            success = False

            while retries < MAX_RETRIES_PER_PACKET and not success:
                print(f"  Attempting index {index} (try {retries + 1}/{MAX_RETRIES_PER_PACKET})...", end='', flush=True)

                # Pack the data into bytes
                ke_bytes = pack_ke_data(msg_type=MSG_TYPES.get("RSSI_INIT_TO_RESP"), index=index, retry_num=retries)

                # Build the packet to send using a vendor-specific element
                pkt = RadioTap() / \
                      Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
                      Dot11Elt(ID=221, info=ke_bytes)

                # Send the packet and wait for a single response
                ans = srp1(pkt, iface=IFACE, timeout=RESPONSE_TIMEOUT, verbose=0)

                if ans:
                    # Check if the response contains our data and is the correct type
                    if ans.haslayer(Dot11Elt) and ans[Dot11Elt].ID == 221:
                        response_data = unpack_ke_data(ans[Dot11Elt].info)
                        if response_data and response_data['msg_type'] == MSG_TYPES.get("RSSI_RESP_TO_INIT") and response_data['index'] == index:
                            rssi = get_rssi(ans)
                            if rssi is not None:
                                print(f" -> Success! RSSI: {rssi}")
                                rssi_measurements[index] = rssi
                                success = True
                            else:
                                print(" -> Reply received, but no RSSI. Retrying...")
                        else:
                            print(" -> Received wrong response type. Retrying...")
                    else:
                        print(" -> Received non-protocol response. Retrying...")
                else:
                    print(" -> Timeout. Retrying...")

                if not success:
                    retries += 1

            if not success:
                print(f"Failed to get response for index {index} after {MAX_RETRIES_PER_PACKET} retries.")

            index += 1
        print("Initiator finished sending key exchange packets.")

    elif role == 'responder':
        print(f"Responder sniffing for {RESPONDER_SNIFF_TIMEOUT}s for packets from {PEER_MAC}...")
        last_seen_retry = {}

        def reply_packet(pkt):
            """Processes sniffed packets and replies."""
            # Check if it's our vendor packet from the peer (initiator)
            if pkt.haslayer(Dot11Elt) and pkt.addr2.lower() == PEER_MAC.lower() and pkt[Dot11Elt].ID == 221:
                ke_data = unpack_ke_data(pkt[Dot11Elt].info)

                if not ke_data:
                    return

                # Ensure it's the correct message type
                if ke_data['msg_type'] == MSG_TYPES.get("RSSI_INIT_TO_RESP"):
                    index = ke_data['index']
                    retry_num = ke_data['retry_num']
                    last_retry = last_seen_retry.get(index, -1)

                    if retry_num >= last_retry:
                        rssi = get_rssi(pkt)
                        if rssi is not None:
                            rssi_measurements[index] = rssi
                            last_seen_retry[index] = retry_num
                            print(f"  Accepted index {index} on retry {retry_num} with RSSI: {rssi}")

                            # Pack the reply data
                            reply_bytes = pack_ke_data(msg_type=MSG_TYPES.get("RSSI_RESP_TO_INIT"), index=index)

                            # Build and send the reply
                            reply_pkt = RadioTap() / \
                                        Dot11(addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
                                        Dot11Elt(ID=221, info=reply_bytes)
                            sendp(reply_pkt, iface=IFACE, verbose=0)

        # This is a single blocking call that processes packets with reply_packet
        sniff(iface=IFACE, prn=reply_packet, timeout=RESPONDER_SNIFF_TIMEOUT)
        print("Responder finished sniffing.")

    return rssi_measurements

def generate_key(rssi_dict, z=1):
    """
    Generates a temporary key (dict) from the RSSI measurements (dict).
    """
    if not rssi_dict:
        print("No RSSI values to generate key from.")
        return {}

    rssi_values = list(rssi_dict.values())
    mean = np.mean(rssi_values)
    std_dev = np.std(rssi_values)

    print(f"Generating key from {len(rssi_values)} values")

    temp_key = {}
    for index, rssi in rssi_dict.items():
        if rssi > mean + z * std_dev:
            temp_key[index] = '1'
        elif rssi < mean - z * std_dev:
            temp_key[index] = '0'
    print(f"  Generated {len(temp_key)} bits for temporary key.")
    return temp_key

def get_common_indices(role, temp_key):
    """
    Exchanges the used indices to find the common set.
    """
    initial_indices = set(temp_key.keys())

    if role == 'initiator':
        print("Initiator sending its index list...")
        indices_str = ",".join(map(str, sorted(list(initial_indices))))

        # Pack data and send
        payload_bytes = indices_str.encode('utf-8')
        ke_bytes = pack_ke_data(msg_type=MSG_TYPES.get("INDICES_INIT_TO_RESP"), payload=payload_bytes)

        pkt = RadioTap() / \
              Dot11(addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
              Dot11Elt(ID=221, info=ke_bytes)

        sendp(pkt, iface=IFACE, count=3, inter=0.2, verbose=0)
        print(f"Sent {len(initial_indices)} indices.")
        return sorted(list(initial_indices))

    elif role == 'responder':
        print("Responder waiting for index list...")
        received_pkt_payload = None

        def get_indices_pkt(pkt):
            nonlocal received_pkt_payload
            if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 221 and pkt.addr2.lower() == PEER_MAC.lower():
                ke_data = unpack_ke_data(pkt[Dot11Elt].info)
                if ke_data and ke_data['msg_type'] == MSG_TYPES.get("INDICES_INIT_TO_RESP"):
                    received_pkt_payload = ke_data['payload']
                    return True  # Stop sniffing
            return False

        sniff(iface=IFACE, stop_filter=get_indices_pkt, timeout=30)

        if not received_pkt_payload:
            print("Error: Did not receive index list from initiator.")
            return None

        received_indices_str = received_pkt_payload.decode('utf-8')
        received_indices = set(map(int, received_indices_str.split(',')))

        common_indices = sorted(list(initial_indices.intersection(received_indices)))
        print(f"  Received {len(received_indices)} indices. Common set: {len(common_indices)} indices.")
        return common_indices

def perform_verification(role, key_hash):
    """
    Exchanges the final key hash to verify a match.
    """
    if role == 'initiator':
        print("Initiator sending key hash for verification.")
        payload_bytes = key_hash.encode('utf-8')
        ke_bytes = pack_ke_data(msg_type=MSG_TYPES.get("VERIFY_INIT_TO_RESP"), payload=payload_bytes)

        pkt = RadioTap() / \
              Dot11(addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
              Dot11Elt(ID=221, info=ke_bytes)

        ans = srp1(pkt, iface=IFACE, timeout=10.0, retry=3, verbose=0)

        if ans and ans.haslayer(Dot11Elt) and ans[Dot11Elt].ID == 221:
            ke_data = unpack_ke_data(ans[Dot11Elt].info)
            if ke_data and ke_data['msg_type'] == MSG_TYPES.get("VERIFY_RESP_TO_INIT"):
                result = ke_data['payload'].decode('utf-8')
                if result == "OK":
                    print("SUCCESS: Responder confirmed keys match!")
                elif result == "FAIL":
                    print("FAILURE: Responder reports keys DO NOT match.")
                else:
                    print(f"Error: Do not recognize responder's message: {result}")
                return

        print("Error: Did not receive valid verification result from responder.")

    elif role == 'responder':
        print("Responder waiting for key hash...")
        received_pkt_payload = None

        def get_verify_pkt(pkt):
            nonlocal received_pkt_payload
            if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 221 and pkt.addr2.lower() == PEER_MAC.lower():
                ke_data = unpack_ke_data(pkt[Dot11Elt].info)
                if ke_data and ke_data['msg_type'] == MSG_TYPES.get("VERIFY_INIT_TO_RESP"):
                    received_pkt_payload = ke_data['payload']
                    return True
            return False

        sniff(iface=IFACE, stop_filter=get_verify_pkt, timeout=30)

        if not received_pkt_payload:
            print("Error: Did not receive key hash from initiator.")
            return

        received_hash = received_pkt_payload.decode('utf-8')
        reply_payload_str = ""

        if received_hash == key_hash:
            print("SUCCESS: Hashes match!")
            reply_payload_str = "OK"
        else:
            print(f"FAILURE: Hashes DO NOT match.")
            print(f"  My Hash:     {key_hash}")
            print(f"  Peer's Hash: {received_hash}")
            reply_payload_str = "FAIL"

        reply_payload_bytes = reply_payload_str.encode('utf-8')
        reply_bytes = pack_ke_data(msg_type=MSG_TYPES.get("VERIFY_RESP_TO_INIT"), payload=reply_payload_bytes)

        reply_pkt = RadioTap() / \
                    Dot11(addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
                    Dot11Elt(ID=221, info=reply_bytes)
        sendp(reply_pkt, iface=IFACE, verbose=0, count=3, inter=0.2)

def main():
    global role, PEER_MAC

    parse_args()

    role = perform_discovery()
    if not role or not PEER_MAC:
        print("Error: Discovery failed. Could not determine role or find peer.")
        return

    print(f"=== Starting RSSI Key Exchange as: {role.upper()} ===")
    print(f"Interface: {IFACE}")
    print(f"My MAC:    {MY_MAC}")
    print(f"Peer MAC:  {PEER_MAC}")

    rssi_measurements = perform_exchange(role)
    if not rssi_measurements:
        print("Error: No RSSI measurements were gathered.")
        return

    temp_key = generate_key(rssi_measurements, z=1)
    if not temp_key:
        print("Error: Failed to generate temporary key.")
        return

    common_indices = get_common_indices(role, temp_key)
    if common_indices is None:
        print("Error: Failed to get common indices.")
        return

    final_key = ""
    for index in common_indices:
        if index in temp_key:
            final_key += temp_key[index]
        else:
            print(f"Warning: Common index {index} not in my temp_key. Skipping.")

    if not final_key:
        print("Error: Could not generate the final key.")
        return

    print(f"Built final key with {len(final_key)} bits.")
    if len(final_key) < 65:
        print(f"  Final Key: {final_key}")
    else:
        print(f"  Final Key: {final_key[:32]}...{final_key[-32:]}")

    # Hash key and perform verification
    key_hash = hashlib.sha256(final_key.encode()).hexdigest()
    perform_verification(role, key_hash)

    print(f"=== {role.upper()} FINISHED ===")


if __name__ == "__main__":
    main()
