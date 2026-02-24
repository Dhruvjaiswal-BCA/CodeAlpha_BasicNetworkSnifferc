from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        print("========== Packet ==========")
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

        # Protocol detection
        if packet.haslayer(TCP):
            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        elif packet.haslayer(ICMP):
            print("Protocol: ICMP")

        # Display Payload
        print("Payload:", bytes(packet.payload))
        print("============================\n")

print("Starting Network Sniffer...\n")

sniff(filter="tcp port 443",prn=packet_callback, timeout=30)

print("Sniffing Completed.")