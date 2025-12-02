from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


def get_protocol(packet) -> str:
    """Return a simple protocol name based on layers present."""
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    elif IP in packet:
        return "IP"
    else:
        return "OTHER"


def packet_callback(packet):
    """Called for each captured packet."""
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = get_protocol(packet)
        length = len(packet)
        timestamp = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")

        # Small payload preview (if available)
        payload_preview = ""
        if Raw in packet:
            raw_bytes = bytes(packet[Raw])[:40]  # first 40 bytes
            try:
                payload_preview = raw_bytes.decode(errors="ignore")
                payload_preview = payload_preview.replace("\n", "\\n")
            except Exception:
                payload_preview = str(raw_bytes)

        print("=" * 80)
        print(f"Time      : {timestamp}")
        print(f"Source    : {src_ip}")
        print(f"Destination: {dst_ip}")
        print(f"Protocol  : {protocol}")
        print(f"Length    : {length} bytes")
        if payload_preview:
            print(f"Payload   : {payload_preview}")
        else:
            print("Payload   : <no printable payload>")


def main():
    print("=== Packet Sniffer (Educational Use Only) ===")
    print("Capturing packets on the default network interface.\n")
    print("⚠️  Use this tool ONLY on networks you own or have explicit permission to analyze.")
    print("Press Ctrl+C to stop.\n")

    try:
        # You can add a filter like 'ip' or 'tcp' if needed:
        # sniff(filter='ip', prn=packet_callback, store=False)
        sniff(prn=packet_callback, store=False)
    except PermissionError:
        print("\n[ERROR] Permission denied.")
        print("Run this script with administrator/root privileges.")
    except KeyboardInterrupt:
        print("\nSniffing stopped by user.")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
