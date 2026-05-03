from scapy.all import sniff, TCP, IP, ICMP, UDP
import time

def start_sniffing(callback_function, stop_check=None):
    """
    Captures TCP, ICMP, and UDP packets and extracts relevant fields.
    Passes extracted fields to callback.
    """
    def packet_handler(packet):
        if IP in packet:
            packet_data = {
                "source_ip": packet[IP].src,
                "destination_ip": packet[IP].dst,
                "timestamp": time.time()
            }
            
            if TCP in packet:
                packet_data["protocol"] = "TCP"
                packet_data["destination_port"] = packet[TCP].dport
                packet_data["tcp_flags"] = packet[TCP].flags
                callback_function(packet_data)
            elif ICMP in packet:
                packet_data["protocol"] = "ICMP"
                callback_function(packet_data)
            elif UDP in packet:
                packet_data["protocol"] = "UDP"
                packet_data["destination_port"] = packet[UDP].dport
                callback_function(packet_data)

    print("[*] Starting packet capture...")
    # Updated filter to include 'udp'
    sniff(filter="tcp or icmp or udp", prn=packet_handler, store=False, stop_filter=stop_check)
