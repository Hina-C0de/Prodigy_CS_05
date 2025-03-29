from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

def packet_callback(packet):
    """Processes captured packets and extracts relevant information."""
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = dst_port = None
        else:
            src_port = dst_port = None
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"[{timestamp}] {protocol} Packet: {src_ip}:{src_port} → {dst_ip}:{dst_port}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            print(f"  Payload:\n{payload}\n")

def start_sniffing(interface="eth0"):
    """Starts sniffing packets on the given network interface."""
    
    print(f"[*] Starting packet sniffing on {interface}...")
    
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopping packet sniffer.")

if __name__ == "__main__":
    start_sniffing()
