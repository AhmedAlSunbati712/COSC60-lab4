#!/usr/bin/env python3

"""
This script performs a key exchange between two devices in Wi-Fi monitor mode
by measuring the Received Signal Strength Indication (RSSI) of a series of
packet exchanges.

This version is updated to use only sendp and sniff for packet transmission
and reception, avoiding srp/srp1 which can be unreliable in monitor mode.

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
TOTAL_PACKETS = 255
MAX_RETRIES_PER_PACKET = 20
RESPONSE_TIMEOUT = 0.5
RESPONDER_SNIFF_TIMEOUT = TOTAL_PACKETS * (RESPONSE_TIMEOUT * MAX_RETRIES_PER_PACKET) * 1.2 + 30.0

# Message types for the key exchange payload
MSG_TYPES = {
    "RSSI_INIT_TO_RESP" : 0,
    "RSSI_RESP_TO_INIT" : 1,
    "INDICES_INIT_TO_RESP" : 2, # Initiator sends used indices
    "VERIFY_INIT_TO_RESP" : 3,  # Initiator sends key hash
    "VERIFY_RESP_TO_INIT" : 4,  # Responder replies with "OK" or "FAIL"
    "EXCHANGE_COMPLETE": 5,
    "EXCHANGE_ACK": 6,
    "READY_FOR_INDICES": 7,
    "INDICES_RESP_TO_INIT": 8,
}

# --- Data Packing/Unpacking Functions ---

def pack_ke_data(msg_type, index=0, retry_num=0, payload=b''):
    """
    Packs key exchange data into a bytes object.
    Format: !HBBH (Network byte order)
    - OUI (3 bytes)
    - index (2 bytes)
    - retry_num (1 byte)
    - msg_type (1 byte)
    - payload_len (2 bytes)
    - payload (variable)
    """
    payload_len = len(payload)
    header = OUI + struct.pack('!HBBH', index, retry_num, msg_type, payload_len)
    return header + payload

def unpack_ke_data(data):
    """
    Unpacks key exchange data from a bytes object.
    Returns a dictionary with the data or None if unpacking fails.
    """
    header_format = '!HBBH'
    header_size = struct.calcsize(header_format)
    oui_size = len(OUI)

    if len(data) < oui_size + header_size:
        return None

    try:
        index, retry_num, msg_type, payload_len = struct.unpack(header_format, data[oui_size : oui_size + header_size])
    except struct.error:
        return None

    if len(data) < oui_size + header_size + payload_len:
        return None

    payload = data[oui_size + header_size : oui_size + header_size + payload_len]

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
    global MY_MAC
    mac_bytes = bytes.fromhex(MY_MAC.replace(':', ''))
    return Dot11Elt(ID=221, info=OUI + bytes([msg_type]) + mac_bytes)



def perform_discovery():
    """
    Listens to determine role. If no initiator is found, becomes initiator
    and broadcasts READY beacons in a send->listen loop until an ACK is heard.
    """
    global role, PEER_MAC
    discovery_complete_flag = False

    def discovery_packet_handler(pkt):
        """
        Callback function for sniffing during the discovery phase.
        Looks for READY or ACK packets from a peer.
        """
        nonlocal discovery_complete_flag
        global PEER_MAC, role

        if discovery_complete_flag:
            return

        if not pkt.haslayer(Dot11Elt):
            return

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            # Check for our specific element: ID 221, length 10 (3 OUI + 1 type + 6 MAC), and matching OUI
            if elt.ID == 221 and len(elt.info) == 10 and elt.info[:3] == OUI:
                msg_type = elt.info[3]
                peer_mac_bytes = elt.info[4:]
                peer_mac_str = ':'.join(f'{b:02x}' for b in peer_mac_bytes)

                if peer_mac_str.lower() == MY_MAC.lower():
                    elt = elt.payload.getlayer(Dot11Elt)
                    continue

                if msg_type == MSG_TYPE_READY:
                    print(f"Heard READY from {peer_mac_str}")
                    role = 'responder'
                    PEER_MAC = peer_mac_str

                    print(f"Sending ACK to {PEER_MAC}...")
                    ack_elt = create_vendor_elt(MSG_TYPE_ACK)
                    ack_pkt = RadioTap() / \
                              Dot11(addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC, type=0, subtype=4) / \
                              ack_elt
                    sendp(ack_pkt, iface=IFACE, verbose=0, count=10, inter=0.15)
                    discovery_complete_flag = True
                    return

                elif msg_type == MSG_TYPE_ACK and role == 'initiator':
                    print(f"Heard ACK from {peer_mac_str}")
                    PEER_MAC = peer_mac_str
                    discovery_complete_flag = True
                    return

            elt = elt.payload.getlayer(Dot11Elt)

    print(f"Starting discovery on {IFACE} (My MAC: {MY_MAC})")
    print(f"Listening for {DISCOVERY_LISTEN_TIME}s to find an initiator...")

    sniff(
        iface=IFACE,
        prn=discovery_packet_handler,
        timeout=DISCOVERY_LISTEN_TIME,
        stop_filter=lambda p: discovery_complete_flag
    )

    if role == 'responder':
        print("Role set to RESPONDER. Waiting for key exchange.")
        return role

    print("No initiator found. Becoming INITIATOR.")
    role = 'initiator'

    print("Broadcasting READY beacons...")
    ready_elt = create_vendor_elt(MSG_TYPE_READY)
    ready_pkt = RadioTap() / \
                Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=MY_MAC, addr3='ff:ff:ff:ff:ff:ff', type=0, subtype=8) / \
                Dot11Beacon() / \
                ready_elt

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
    return pkt[RadioTap].dBm_AntSignal if RadioTap in pkt else None
def perform_exchange(role):
    """
    Performs the main packet exchange to gather RSSI measurements.
    Includes a handshake to ensure both parties finish before proceeding.
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

                ke_bytes = pack_ke_data(msg_type=MSG_TYPES.get("RSSI_INIT_TO_RESP"), index=index, retry_num=retries)
                pkt = RadioTap() / \
                      Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
                      Dot11Elt(ID=221, info=ke_bytes)
                sendp(pkt, iface=IFACE, verbose=0)

                def response_filter(p):
                    if not (p.haslayer(Dot11Elt) and p.addr2 and p.addr2.lower() == PEER_MAC.lower() and p[Dot11Elt].ID == 221):
                        return False
                    response_data = unpack_ke_data(p[Dot11Elt].info)
                    return response_data and response_data.get('msg_type') == MSG_TYPES.get("RSSI_RESP_TO_INIT") and response_data.get('index') == index

                ans_list = sniff(iface=IFACE, timeout=RESPONSE_TIMEOUT, stop_filter=response_filter, count=1)

                if ans_list:
                    rssi = get_rssi(ans_list[0])
                    if rssi is not None:
                        print(f" -> Success! RSSI: {rssi}")
                        rssi_measurements[index] = rssi
                        success = True
                    else:
                        print(" -> Reply received, but no RSSI. Retrying...")
                else:
                    print(" -> Timeout. Retrying...")

                if not success: retries += 1
            if not success: print(f"\nFailed to get response for index {index} after {MAX_RETRIES_PER_PACKET} retries.")
            index += 1

        print("Initiator finished sending RSSI packets.")
        
        # --- NEW HANDSHAKE LOGIC ---
        print("Signaling end of exchange and waiting for ACK...")
        ack_received = False
        ack_retries = 0
        MAX_ACK_RETRIES = 15

        def ack_filter(p):
            if not (p.haslayer(Dot11Elt) and p.addr2 and p.addr2.lower() == PEER_MAC.lower() and p[Dot11Elt].ID == 221):
                return False
            ack_data = unpack_ke_data(p[Dot11Elt].info)
            return ack_data and ack_data.get('msg_type') == MSG_TYPES.get("EXCHANGE_ACK")

        while not ack_received and ack_retries < MAX_ACK_RETRIES:
            complete_bytes = pack_ke_data(msg_type=MSG_TYPES.get("EXCHANGE_COMPLETE"))
            complete_pkt = RadioTap() / \
                           Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
                           Dot11Elt(ID=221, info=complete_bytes)
            sendp(complete_pkt, iface=IFACE, count=3, inter=0.1, verbose=0)

            # Wait for the ACK from the responder
            ans_list = sniff(iface=IFACE, stop_filter=ack_filter, timeout=1.0, count=1)
            if ans_list:
                print(" -> Exchange ACK received. Proceeding.")
                ack_received = True
            else:
                print(f" -> Timeout waiting for ACK (try {ack_retries + 1}/{MAX_ACK_RETRIES}).")
                ack_retries += 1
        
        if not ack_received:
            print("Error: Did not receive exchange completion ACK from responder. Aborting.")
            return {} # Return empty dict to signal failure
        # --- END HANDSHAKE LOGIC ---

    elif role == 'responder':
        print(f"Responder sniffing for packets from {PEER_MAC}...")
        last_seen_retry = {}
        exchange_is_complete = False

        def process_and_reply(pkt):
            nonlocal exchange_is_complete
            try:
                if not (pkt.haslayer(Dot11Elt) and pkt.addr2.lower() == PEER_MAC.lower() and pkt[Dot11Elt].ID == 221):
                    return

                ke_data = unpack_ke_data(pkt[Dot11Elt].info)
                if not ke_data: return

                msg_type = ke_data.get('msg_type')

                # --- MODIFIED: Respond to completion signal ---
                if msg_type == MSG_TYPES.get("EXCHANGE_COMPLETE"):
                    print("Received exchange complete signal. Sending ACK and stopping sniff.")
                    # Send ACK back immediately
                    ack_bytes = pack_ke_data(msg_type=MSG_TYPES.get("EXCHANGE_ACK"))
                    ack_pkt = RadioTap() / \
                              Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
                              Dot11Elt(ID=221, info=ack_bytes)
                    sendp(ack_pkt, iface=IFACE, count=3, inter=0.1, verbose=0)
                    exchange_is_complete = True # This will stop the sniff
                    return
                # --- END MODIFICATION ---

                if msg_type == MSG_TYPES.get("RSSI_INIT_TO_RESP"):
                    index, retry_num = ke_data['index'], ke_data['retry_num']
                    if retry_num > last_seen_retry.get(index, -1):
                        rssi = get_rssi(pkt)
                        if rssi is not None:
                            rssi_measurements[index] = rssi
                            last_seen_retry[index] = retry_num
                            print(f"  Accepted index {index} on retry {retry_num} with RSSI: {rssi}")
                            reply_bytes = pack_ke_data(msg_type=MSG_TYPES.get("RSSI_RESP_TO_INIT"), index=index)
                            reply_pkt = RadioTap() / \
                                        Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
                                        Dot11Elt(ID=221, info=reply_bytes)
                            sendp(reply_pkt, iface=IFACE, verbose=0)
            except Exception: return

        sniff(
            iface=IFACE,
            prn=process_and_reply,
            timeout=RESPONDER_SNIFF_TIMEOUT,
            stop_filter=lambda p: exchange_is_complete
        )
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
    Performs a two-way exchange to determine the common set of indices,
    including fragmentation for lists larger than the Dot11Elt limit.
    """
    initial_indices = set(temp_key.keys())

    if role == 'initiator':
        # Step 1: Wait for responder to be ready
        print("Waiting for responder to signal readiness for index list...")
        def ready_filter(p):
            if not (p.haslayer(Dot11Elt) and p.addr2 and p.addr2.lower() == PEER_MAC.lower() and p[Dot11Elt].ID == 221):
                return False
            ready_data = unpack_ke_data(p[Dot11Elt].info)
            return ready_data and ready_data.get('msg_type') == MSG_TYPES.get("READY_FOR_INDICES")
        
        if not sniff(iface=IFACE, stop_filter=ready_filter, timeout=10.0, count=1):
            print("Error: Did not receive 'ready for indices' signal. Aborting.")
            return None
        
        print(" -> Responder is ready. Pausing before sending index list...")
        time.sleep(0.2) # Prevent race condition

        # Step 2: Send our own index list
        indices_str = ",".join(map(str, sorted(list(initial_indices))))
        payload_bytes = indices_str.encode('utf-8')
        CHUNK_SIZE = 240
        payload_chunks = [payload_bytes[i:i + CHUNK_SIZE] for i in range(0, len(payload_bytes), CHUNK_SIZE)]
        
        print(f"Sending my index list ({len(payload_bytes)} bytes in {len(payload_chunks)} chunks).")
        pkt = RadioTap() / Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC)
        for chunk in payload_chunks:
            ke_bytes = pack_ke_data(msg_type=MSG_TYPES.get("INDICES_INIT_TO_RESP"), payload=chunk)
            pkt /= Dot11Elt(ID=221, info=ke_bytes)
        sendp(pkt, iface=IFACE, count=5, inter=0.2, verbose=0)

        # Step 3: Wait for the responder to send back the final common list
        print("Waiting for responder to send back the common index list...")
        received_common_payload = None
        def get_common_list_pkt(p):
            nonlocal received_common_payload
            if not (p.haslayer(Dot11Elt) and p.addr2.lower() == PEER_MAC.lower()): return False
            payload_parts = []
            elt = p.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 221:
                    ke_data = unpack_ke_data(elt.info)
                    if ke_data and ke_data['msg_type'] == MSG_TYPES.get("INDICES_RESP_TO_INIT"):
                        payload_parts.append(ke_data['payload'])
                elt = elt.payload.getlayer(Dot11Elt)
            if payload_parts:
                received_common_payload = b''.join(payload_parts)
                return True
            return False
        
        sniff(iface=IFACE, stop_filter=get_common_list_pkt, timeout=15)
        
        if not received_common_payload:
            print("Error: Did not receive common index list from responder.")
            return None
            
        common_indices_str = received_common_payload.decode('utf-8')
        # Handle case of empty list
        if not common_indices_str: return []
        
        final_common_indices = sorted(list(map(int, common_indices_str.split(','))))
        print(f"  Received final list with {len(final_common_indices)} common indices.")
        return final_common_indices

    elif role == 'responder':
        # Step 1: Signal readiness
        print("Signaling readiness for index list...")
        ready_bytes = pack_ke_data(msg_type=MSG_TYPES.get("READY_FOR_INDICES"))
        ready_pkt = RadioTap() / Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / Dot11Elt(ID=221, info=ready_bytes)
        sendp(ready_pkt, iface=IFACE, count=5, inter=0.2, verbose=0)

        # Step 2: Wait for the initiator's index list
        print("Waiting for initiator's index list...")
        received_initiator_payload = None
        def get_initiator_list_pkt(p):
            nonlocal received_initiator_payload
            if not (p.haslayer(Dot11Elt) and p.addr2.lower() == PEER_MAC.lower()): return False
            payload_parts = []
            elt = p.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 221:
                    ke_data = unpack_ke_data(elt.info)
                    if ke_data and ke_data['msg_type'] == MSG_TYPES.get("INDICES_INIT_TO_RESP"):
                        payload_parts.append(ke_data['payload'])
                elt = elt.payload.getlayer(Dot11Elt)
            if payload_parts:
                received_initiator_payload = b''.join(payload_parts)
                return True
            return False
            
        sniff(iface=IFACE, stop_filter=get_initiator_list_pkt, timeout=15)
        
        if not received_initiator_payload:
            print("Error: Did not receive index list from initiator.")
            return None

        # Step 3: Calculate intersection and send it back
        received_indices_str = received_initiator_payload.decode('utf-8')
        received_indices = set(map(int, received_indices_str.split(',')))
        
        common_indices = sorted(list(initial_indices.intersection(received_indices)))
        print(f"  Calculated {len(common_indices)} common indices. Sending list back...")

        common_indices_str = ",".join(map(str, common_indices))
        payload_bytes = common_indices_str.encode('utf-8')
        CHUNK_SIZE = 240
        payload_chunks = [payload_bytes[i:i + CHUNK_SIZE] for i in range(0, len(payload_bytes), CHUNK_SIZE)]

        pkt = RadioTap() / Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC)
        for chunk in payload_chunks:
            ke_bytes = pack_ke_data(msg_type=MSG_TYPES.get("INDICES_RESP_TO_INIT"), payload=chunk)
            pkt /= Dot11Elt(ID=221, info=ke_bytes)
        sendp(pkt, iface=IFACE, count=5, inter=0.2, verbose=0)
        
        return common_indices

def perform_verification(role, key_hash):
    """
    Exchanges the final key hash to verify a match using sendp/sniff.
    """
    if role == 'initiator':
        print("Initiator sending key hash for verification.")
        payload_bytes = key_hash.encode('utf-8')
        ke_bytes = pack_ke_data(msg_type=MSG_TYPES.get("VERIFY_INIT_TO_RESP"), payload=payload_bytes)

        pkt = RadioTap() / \
              Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
              Dot11Elt(ID=221, info=ke_bytes)

        # Send a burst of packets to increase chance of reception
        sendp(pkt, iface=IFACE, count=5, inter=0.2, verbose=0)
        print("Waiting for verification response...")

        def verification_filter(p):
            if not (p.haslayer(Dot11Elt) and p.addr2 and p.addr2.lower() == PEER_MAC.lower() and p[Dot11Elt].ID == 221):
                return False
            ke_data = unpack_ke_data(p[Dot11Elt].info)
            if ke_data and ke_data.get('msg_type') == MSG_TYPES.get("VERIFY_RESP_TO_INIT"):
                return True
            return False

        # Sniff for the response
        ans_list = sniff(iface=IFACE, stop_filter=verification_filter, timeout=15.0, count=1)

        if ans_list:
            ans = ans_list[0]
            ke_data = unpack_ke_data(ans[Dot11Elt].info)
            if ke_data:
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
                    Dot11(type=0, subtype=4, addr1=PEER_MAC, addr2=MY_MAC, addr3=PEER_MAC) / \
                    Dot11Elt(ID=221, info=reply_bytes)
        sendp(reply_pkt, iface=IFACE, verbose=0, count=5, inter=0.2)

def main():
    global role, PEER_MAC
    parse_args()
    role = perform_discovery()
    if not role or not PEER_MAC:
        print("Error: Discovery failed. Could not determine role or find peer.")
        return

    print(f"\n=== Starting RSSI Key Exchange as: {role.upper()} ===")
    print(f"Interface: {IFACE}")
    print(f"My MAC:    {MY_MAC}")
    print(f"Peer MAC:  {PEER_MAC}\n")

    rssi_measurements = perform_exchange(role)
    if not rssi_measurements:
        print("Error: No RSSI measurements were gathered.")
        return

    temp_key = generate_key(rssi_measurements, z=1.8)
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

    key_hash = hashlib.sha256(final_key.encode()).hexdigest()
    perform_verification(role, key_hash)

    print(f"\n=== {role.upper()} FINISHED ===")


if __name__ == "__main__":
    main()