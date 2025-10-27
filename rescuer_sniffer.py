"""
rescuer_sniffer.py

Usage:
  sudo ./rescuer_sniffer.py <iface>
"""

import sys
import time
import threading
import queue
import struct
from collections import deque, defaultdict
import curses
import math
import signal
from uuid import UUID

from scapy.all import sniff, Dot11, Dot11Elt, RadioTap


OUI = b'\xAA\xBB\xCC'   # OUI to identify survivor packets
HISTORY_LEN = 10        # number of samples to keep per survivor
UI_REFRESH = 0.5        # seconds between UI refreshes
TREND_THRESHOLD_DB_PER_S = 0.4  # Minimum rate of change to determine whether we are getting closer or further

# Nice synchronized queue class. Prevents race-conditions (mainly producer-consumer problem in this case)
pkt_q = queue.Queue()

# I added a deque here to treat the incoming readings in a
# first-in-first-out fashion. Can also think of it as a sliding window for readings
survivors = defaultdict(lambda: {
    'samples': deque(maxlen=HISTORY_LEN),
    'last_seen': 0.0, # Keeping track of the last tick when we received a packet from that survivor
    'last_rssi': None, # Last seen signal value
    'avg': None # The average of signals in the window we currently have
})

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

def extract_uuid_from_vendor(info_bytes):
    """
    Description: Vendor info expected to be: OUI (which we set to three bytes) + payload
                 The payload is 16 bytes of uuid
    """
    if not info_bytes or len(info_bytes) < 3 + 16:
        return None
    if info_bytes[:3] != OUI:
        return None

    payload = info_bytes[3:] # Removing the OUI
    uuid_bytes = payload[:16] # Extracting only 16 bytes from the payload
    uid = UUID(bytes=uuid_bytes)
    return str(uid)

def extract_rssi(pkt):
    """
    Description: Extract RSSI in dBm from Radiotap header if available.
    Returns float or None.
    """
    rt = pkt.getlayer(RadioTap)
    rssi = rt.dBm_AntSignal
    return float(rssi) if rssi else None

def add_sample(uuid_str, rssi):
    """
    Description: Given a survior with a unique identifier uuid_str, add this resistance reading
                 to its entry in the survirors dictionary, update last_seen, last_rssi and avg signals.
    """
    t = time.time()
    entry = survivors[uuid_str]
    entry['last_seen'] = t
    # Add new sample reading and compute new avearge only if we received a new reading
    if rssi:
        entry['samples'].append((t, float(rssi)))
        entry['last_rssi'] = float(rssi)

        # Average the readings in samples
        vals = [v for (_, v) in entry['samples']]
        entry['avg'] = sum(vals)/len(vals) if vals else None

def compute_slope(samples):
    """
    Description: Linear regression slope (dB/sec) for samples list of (t, rssi).
                 Returns slope in dB/sec or 0 if insufficient data.
    """
    if not samples or len(samples) < 2:
        return 0.0
    n = len(samples)
    xs = [s[0] for s in samples]
    ys = [s[1] for s in samples]
    x_mean = sum(xs)/n
    y_mean = sum(ys)/n
    num = sum((xs[i]-x_mean)*(ys[i]-y_mean) for i in range(n))
    den = sum((xs[i]-x_mean)**2 for i in range(n))
    if den == 0:
        return 0.0
    slope = num/den
    return slope

def packet_handler(pkt):
    """
    Description: Called in sniffing thread for each packet.
    """
    try:
        # only consider management beacons (type=0 subtype=8) to match what transmitter sends
        if not pkt.haslayer(Dot11):
            return
        if pkt.type != 0 or pkt.subtype != 8:
            return

        # Extract the vendor info from the packet (should be OUI + survivor_uuid)
        vendor_info = find_vendor_info(pkt)
        if not vendor_info or vendor_info[:3] != OUI:
            return
        uuid_survivor = extract_uuid_from_vendor(vendor_info)
        if not uuid_survivor:
            return

        # Extract resistance reading from radio tap layer
        if not pkt.haslayer(RadioTap):
            return
        rssi = extract_rssi(pkt) # Extract signal strength

        pkt_q.put((uuid_str, rssi, time.time())) # push to queue
    except Exception:
        pass
    

def sniff_thread_func(iface):
    """
    Description: Runs scapy.sniff() in a loop, handling sniffed packets with packet_handler
    """
    # sniff will call packet_handler for each pkt
    sniff(iface=iface, prn=packet_handler)

def draw_ui(stdscr, iface):
    """
    Description: Continuously update the curses-based UI with live survivor RSSI data.
    """

    # curses init
    curses.use_default_colors()
    stdscr.nodelay(True)
    stdscr.clear()

    last_refresh = 0
    while True:
        updated = False # To keep track of whether there are new samples in the queue or not
        try:
            while True:
                item = pkt_q.get_nowait()

                uuid_str, rssi, ts = item
                add_sample(uuid_str, rssi)
                updated = True
        except queue.Empty:
            pass

        # only refresh UI at UI_REFRESH intervals or if we have new samples (updated set to true)
        now = time.time()
        if (now - last_refresh) >= UI_REFRESH or updated:
            stdscr.erase()
            stdscr.addstr(0, 0, "Rescuer RSSI Monitor (OUI: %s) - iface: %s" % (OUI.hex(), iface))
            stdscr.addstr(1, 0, "-" * 72)
            header = "{:<38} {:>7} {:>8} {:>7} {:>7}".format("UUID", "Last(dBm)", "Average", "Trend", "Age(s)")
            stdscr.addstr(2, 0, header)
            stdscr.addstr(3, 0, "-" * 72)

            # prepare list sorted by recency or strongest avg
            items = []
            for uid, entry in survivors.items():
                last_seen = entry['last_seen']
                age = now - last_seen if last_seen else float('inf')
                last_rssi = entry['last_rssi']
                avg = entry['avg']
                slope = compute_slope(list(entry['samples']))
                items.append((uid, entry, age, last_rssi, avg, slope))

            # Sort by age ascendingly or if two survivors are of the same age, the one with the bigger
            # rssi will come first
            items_sorted = sorted([it for it in items], key=lambda it: (it[2], -it[4]))

            row = 4
            for it in items_sorted:
                uid, entry, age, last_rssi, avg, slope = it
                age_s = int(age)
                last_str = f"{last_rssi:.1f}" if last_rssi is not None else "N/A"
                avg_str = f"{avg:.1f}" if avg is not None else "N/A"
                # trend arrow
                if slope > TREND_THRESHOLD_DB_PER_S:
                    trend = "▲"
                elif slope < -TREND_THRESHOLD_DB_PER_S:
                    trend = "▼"
                else:
                    trend = "→"

                line = "{:<38} {:>7} {:>8} {:>7} {:>7}".format(uid, last_str, avg_str, trend, age_s)
                stdscr.addstr(row, 0, line)
                row += 1
                if row >= curses.LINES - 2:
                    break

            stdscr.addstr(curses.LINES-1, 0, "Press Ctrl-C to quit.")
            stdscr.refresh()
            last_refresh = now

        time.sleep(0.05)


def main():
    iface = sys.argv[1] if len(sys.argv) >= 2 else "wlan0"

    # Start sniff thread
    t = threading.Thread(target=sniff_thread_func, args=(iface,), daemon=True)
    t.start()

    try:
        curses.wrapper(lambda scr: draw_ui(scr, iface))
    except KeyboardInterrupt:
        print("\nExiting...")


if __name__ == "__main__":
    main()
