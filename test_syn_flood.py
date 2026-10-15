from scapy.layers.inet import IP,TCP
from syn_flood_detector import (
	packet_callback,
	syn_tracker,
	alerted_pairs,
)

#start with clean test state.
syn_tracker.clear()
alerted_pairs.clear()

#create 100 synthetic initial-SYN packets.
for i in range(100):
	packet=(
		IP(src="192.0.2.10",dst="192.0.2.20")
		/ TCP(sport=40000 + i,dport=80,flags="S")
	)
	

	#Simulate 100 packets arriving over 5 seconds.
	packet_callback(packet,current_time=100+i * 0.05)

print("\nTest complete.")

#Test that a SYN-ACK packet is ignored.
count_before = len(syn_tracker.get(
	("192.0.2.10", "192.0.2.20"), []
))

response = (
	IP(src="192.0.2.20", dst="192.0.2.10")
	/ TCP(sport=80, dport=40000, flags="SA")
)

packet_callback(response,current_time=105.1)

count_after =len(syn_tracker.get(
	("192.0.2.10", "192.0.2.20"),[]
))

print("SYN-ACK ignored:", count_before ==count_after)

#Test whether old SYN observation expire

syn_tracker.clear()
alerted_pairs.clear()

packet = (
    IP(src="192.0.2.10", dst="192.0.2.20")
    / TCP(sport=45000, dport=80, flags="S")
)

# Record one SYN at simulated time 100.
packet_callback(packet, current_time=100)

# At time 111, the observation at time 100 is older
# than the 10-second window and should be removed.
packet_callback(packet, current_time=111)

key = ("192.0.2.10", "192.0.2.20")
print("Current SYN count:", len(syn_tracker[key]))
print("Old timestamp expired:", len(syn_tracker[key]) == 1)
