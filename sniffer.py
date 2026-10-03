from scapy.all import sniff
from scapy.layers.inet import IP,TCP,UDP
import time

port_tracker={}

WINDOW=10
PORT_THRESHOLD=10

def packet_callback(packet):
    if IP not in packet:
        return
    if TCP not in packet:
        return
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    destination_port = packet[TCP].dport
    current_time= time.time()

    key = (source_ip,destination_ip)
    if key not in port_tracker:
        port_tracker[key]=[]

    port_tracker[key].append((current_time,destination_port))

    cutoff_time=current_time - WINDOW

    port_tracker[key] =[
        (timestamp, port)
        for timestamp, port in port_tracker[key]
        if timestamp >= cutoff_time
    ]
    recent_ports={
        port for timestamp,port in port_tracker[key]
    }
    print(
        f"{source_ip}->{destination_ip}"
        f"  ports:{recent_ports}"
    )
    if len(recent_ports)>= PORT_THRESHOLD:
        print("!!! POSSIBLE PORT SCAN !!!")

sniff(prn=packet_callback)