import time
from scapy.all import sniff, Dot11, Dot11Elt, RadioTap

"""
Right now what im thinking of is to have three types of messages to differentiate the messages that
are getting exchanged between devices in this part of the lab.

1. 0x01: If the device doesn't find any initator, it starts transmitting beacon frames with vendor info
         that is OUI + 0x01. Any other device that is listening will find this message, extract the type (the 4th
         byte in the info in the packet), will find it's 0x01 and discover that there's an initiator.
2. 0x02: If an initiator hears back this message type (it extracts the message type in the same way described above),
         it will start exchanging data frames (message type = 0x03) with the responder who sent it.
3. 0x03: Attach it to the frames being exchanged after the devices discover each other.

"""
# Make sure to define define these global variables in your file!
found_initiator = False
OUI = b'\xAA\xBB\xCC'
iface = None # parse it through the command line sys.argv
MSG_TYPE_READY = 0x01
MSG_TYPE_ACK = 0x02
MSG_TYPE_DATA = 0x03


def create_vendor_info_secret_key(OUI, msg_type):
    """
    Description: Constructs a vendor-specific information element (Dot11Elt with ID=221) containing the 
                 device's custom OUI and a one-byte message type. 
    """
    return Dot11Elt(ID=221, info = OUI + bytes([msg_type]))

def find_vendor_info(pkt):
    """
    Description: Traverses all Dot11Elt layers within a received 802.11 packet to locate the 
                 vendor-specific element (ID=221). Returns the raw bytes of its info field if found, 
                 or None if no vendor-specific element is present.
    """
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 221:
            return bytes(elt.info)
        elt = elt.payload.getlayer(elt)
    return None

def packet_handler_determine_role(pkt):
    """
    Description: Callback function for packet sniffing. Processes incoming 802.11 packets to detect 
                 custom frames with the matching OUI. Determines the message type (READY, ACK or DATA) 
                 and updates global state
    """
    global found_initiator
    if not pkt.haslayer(Dot11):
        return
    # Extracting vendor-specific info if existant
    info = find_vendor_info(pkt)
    if len(info) < 4:
        return
    if not info or info[:3] != OUI:
        return
    
    # Extracting message type
    msg_type = info[3]
    if msg_type == MSG_TYPE_READY:
        print("[+] Detected READY frame from another device.")
        found_initiator = True
    
def determine_role(iface, packet_handler, timeout=3):
    """
    Description: Listens on the specified wireless interface for a limited time to determine 
                 whether another device is already transmitting READY frames.
    """
    global found_initiator
    start = time.time()
    while (time.time() - start) < timeout:
        sniff(iface=iface, prn=packet_handler)
        if found_initiator:
            print("[+] This device is the responder")
            return "responder"
    print("This device is the initiator")
    return "initiator"


    
