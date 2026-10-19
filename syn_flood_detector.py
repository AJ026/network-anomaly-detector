import time
from scapy.layers.inet import IP,TCP
from scapy.sendrecv import sniff
from database import initialize_database, save_alert
from telegram_notifier import send_telegram_alert

syn_tracker = {}
alerted_pairs =set()

WINDOW=10
SYN_THRESHOLD=100

def packet_callback(packet,current_time=None):
    if IP not in packet or TCP not in packet:
        return
    #Detect intial SYN packets only ,not SYN-ACK responses.
    if packet[TCP].flags != "S":
        return
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    if current_time is None:
        current_time = time.monotonic()

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
    if syn_count >= SYN_THRESHOLD and key not in alerted_pairs:
        print("!!! POSSIBLE SYN FLOOD !!!")

        attack_type = "Possible SYN FLOOD"
        severity = "High"

        save_alert(source_ip, destination_ip, attack_type, severity)

        send_telegram_alert(
            source_ip,
            destination_ip,
            attack_type,
            severity,
        )

        alerted_pairs.add(key)
    if syn_count < SYN_THRESHOLD:
        alerted_pairs.discard(key)

if __name__ == "__main__":
    initialize_database()
    sniff(prn=packet_callback)
