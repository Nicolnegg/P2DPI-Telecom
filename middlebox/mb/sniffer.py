# middlebox/mb/sniffer.py
# Passive sniffer for inspecting HTTP traffic in real time using PyShark

import pyshark

def start_sniff(interface="lo", bpf_filter="tcp port 8080"):
    """
    Start a passive sniffer that captures live HTTP packets.

    Args:
        interface (str): Network interface to sniff on (e.g., 'lo', 'eth0').
        bpf_filter (str): Berkeley Packet Filter expression to filter captured traffic.
                          Example: 'tcp port 8080' captures only TCP packets on port 8080.

    Behavior:
        - Captures packets continuously.
        - Extracts HTTP method, host and URI from each HTTP request.
        - Prints the extracted info to the terminal (simulating the MB inspection).
    """
    print(f"[MB] Starting sniffer on interface: {interface} with filter: {bpf_filter}")
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)

    for packet in capture.sniff_continuously():
        try:
            if 'HTTP' in packet:
                # Extract basic HTTP info
                method = packet.http.get_field_by_showname("Request Method")
                uri = packet.http.get_field_by_showname("Request URI")
                host = packet.http.get_field_by_showname("Host")
                if method and uri and host:
                    print(f"[MB] HTTP   {method} request to {host}{uri}")
                    
                # TODO: Send 'host + uri' to the sender module to compute T_j
                # TODO: Compare with rules I_i from RG

        except AttributeError:
            # Some packets may not contain expected fields
            continue

if __name__ == "__main__":
    # Run the sniffer directly for testing on localhost
    start_sniff()
