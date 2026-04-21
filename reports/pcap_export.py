"""
PCAP export — save captured packets to .pcap file
for analysis in Wireshark.
"""

import os
from datetime import datetime
from scapy.all import wrpcap


class PCAPExport:

    def __init__(self, output_dir="reports/pcaps"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._packets = []

    def add_packet(self, packet):
        self._packets.append(packet)

    def export(self, session_id=None):
        if not self._packets:
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{session_id}_{timestamp}.pcap" if session_id else f"capture_{timestamp}.pcap"
        filepath = os.path.join(self.output_dir, filename)

        try:
            wrpcap(filepath, self._packets)
            return filepath
        except Exception:
            return None

    def get_packet_count(self):
        return len(self._packets)

    def clear(self):
        self._packets = []

