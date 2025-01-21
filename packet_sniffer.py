from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
import os

# Define log file to save captured packets
LOG_FILE = "packet_logs.txt"

# Ensure log file is created or cleared initially
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as file:
        file.write("Packet Sniffer Log\n")
        file.write("=" * 50 + "\n\n")

# Function to decode payload
def decode_payload(payload):
    try:
        # Attempt to decode as UTF-8
        return payload.decode("utf-8", errors="replace")
    except Exception:
        # Fallback to hex representation
        return payload.hex()

# Packet handler function
def packet_handler(packet):
    try:
        # Extract basic packet details
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Prepare a log entry
        log_entry = f"[{timestamp}] Source: {src_ip} --> Destination: {dst_ip}"

        # Add protocol-specific details
        if protocol == 6:  # TCP Protocol
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            log_entry += f" | Protocol: {protocol_name} | Src Port: {src_port}, Dst Port: {dst_port}"
        elif protocol == 17:  # UDP Protocol
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            log_entry += f" | Protocol: {protocol_name} | Src Port: {src_port}, Dst Port: {dst_port}"
        elif protocol == 1:  # ICMP Protocol
            protocol_name = "ICMP"
            log_entry += f" | Protocol: {protocol_name}"
        else:
            protocol_name = "Other"
            log_entry += f" | Protocol: {protocol_name}"

        # Decode payload (if available)
        if packet[IP].payload:
            raw_payload = bytes(packet[IP].payload)
            readable_payload = decode_payload(raw_payload)
            log_entry += f" | Payload: {readable_payload[:100]}"  # Limit to first 100 chars for readability

        # Print the log entry to the console
        print(log_entry)

        # Save the log entry to the file
        with open(LOG_FILE, "a") as log_file:
            log_file.write(log_entry + "\n")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Main function to start the packet sniffer
def start_sniffer():
    print("Starting packet capture. Press Ctrl+C to stop.")
    try:
        # Use the filter for IP packets
        sniff(filter="ip", prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\nStopping packet capture.")
        print(f"Logs saved to {LOG_FILE}")

# Run the packet sniffer
if __name__ == "__main__":
    start_sniffer()
