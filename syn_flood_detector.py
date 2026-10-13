import time
from scapy.layers.inet import IP,TCP
from scapy.sendrecv import sniff

syn_tracker = {}

WINDOW=10
SYN_THRESHOLD=100

def packet_callback(packet):
    if IP not in packet or TCP not in packet:
        return
    #Detect intial SYN packets only
    if packet[TCP].flags != "S":
        return
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    current_time = time.time()

    #track each source and destination pair
    key=(source_ip,destination_ip)

    if key not in syn_tracker:
        syn_tracker[key] = []

    syn_tracker[key].append(current_time)

    # remove timestamps outside the time window
    cutoff_time =  current_time - WINDOW

    syn_tracker[key] = [
        timestamp
        for timestamp in syn_tracker[key]
        if timestamp >= cutoff_time
    ]

    syn_count = len(syn_tracker[key])

    print(
        f"{source_ip} -> {destination_ip} |"
        f"SYN packets in last {WINDOW}s: {syn_count}"
    )
    if syn_count >= SYN_THRESHOLD:
        print("!!! POSSIBLE SYN FLOOD !!!")

sniff(prn=packet_callback)