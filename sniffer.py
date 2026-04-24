from scapy.all import sniff, IP, TCP, UDP
def process_packet(packet):
    if packet.haslayer(IP):
       src_ip = packet[IP].src
       dst_ip = packet[IP].dst
       proto = "Other"
       if packet.haslayer(TCP):
           proto = "TCP"
       elif packet.haslayer(UDP):
           proto = "UDP"
    print(f"[{proto}]{src_ip}--->{dst_ip}")
print("---Network Sniffer Active---")
print("To see the traffic open any website")
sniff(prn=process_packet, store=0)