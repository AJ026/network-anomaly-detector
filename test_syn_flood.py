from scapy.layers.inet import IP,TCP
from syn_flood_detector import (
	packet_callback,
	syn_tracker,
	alerted_pairs,
)

from database  import initialize_database, get_alerts

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


# Test that SYN-flood detection saves an alert to SQLite.
initialize_database()
syn_tracker.clear()
alerted_pairs.clear()

source_ip = "192.0.2.30"
destination_ip = "192.0.2.40"

def count_matching_alerts():
    alerts = get_alerts()
    return sum(
        1 for alert in alerts
        if alert[2] == source_ip
        and alert[3] == destination_ip
        and alert[4].lower() == "possible syn flood"
    )

# Count matching records already in the database.
alerts_before = count_matching_alerts()

# Generate 100 synthetic initial-SYN packets.
for i in range(100):
    packet = (
        IP(src=source_ip, dst=destination_ip)
        / TCP(sport=41000 + i, dport=80, flags="S")
    )
    packet_callback(packet, current_time=200 + i * 0.05)

alerts_after = count_matching_alerts()
new_alerts = alerts_after - alerts_before

print("Matching alerts before test:", alerts_before)
print("Matching alerts after test:", alerts_after)
print("New alerts saved by this test:", new_alerts)

assert new_alerts == 1, (
    f"Expected 1 new alert, but found {new_alerts}"
)

print("Detection-to-database integration test passed!")
