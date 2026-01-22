"""
PCAP file parser.
Corresponds to pcap_parser.cpp/hpp in the C++ implementation.
"""

import time
from typing import List, Optional
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
from tqdm import tqdm

from .packet_info import (
    PacketType, set_pkt_type_code, test_pkt_type_code, TYPE_NAMES
)
from .packet_basic import BasicPacket, BasicPacket4, BasicPacket6, BasicPacketBad


class PcapParser:
    """PCAP file parser using scapy."""
    
    def __init__(self, file_path: str):
        """
        Initialize parser with file path.
        
        Args:
            file_path: Path to the PCAP file.
        """
        self.file_path = file_path
        self.raw_packets = None
        self.parse_result: Optional[List[BasicPacket]] = None
    
    def parse_raw_packet(self, num_to_parse: int = -1) -> list:
        """
        Parse raw packets from PCAP file.
        
        Args:
            num_to_parse: Number of packets to parse (-1 for all).
            
        Returns:
            List of raw scapy packets.
        """
        start_time = time.time()
        
        print(f"[LOG] Reading packets from {self.file_path}")
        
        if num_to_parse > 0:
            self.raw_packets = rdpcap(self.file_path, count=num_to_parse)
        else:
            self.raw_packets = rdpcap(self.file_path)
        
        print(f"[LOG] Read {len(self.raw_packets)} raw packets from {self.file_path}")
        print(f"[TIMER] parse_raw_packet: {time.time() - start_time:.6f}s")
        
        return self.raw_packets
    
    def parse_basic_packet_fast(self) -> List[BasicPacket]:
        """
        Parse raw packets to basic packet representation.
        
        Returns:
            List of BasicPacket objects.
        """
        start_time = time.time()
        
        if self.raw_packets is None:
            raise RuntimeError("Raw packets not parsed yet. Call parse_raw_packet first.")
        
        self.parse_result = []
        bad_packet_count = 0
        
        for raw_pkt in tqdm(self.raw_packets, desc="Parsing packets"):
            packet_code = 0
            packet_time = float(raw_pkt.time)
            packet_length = len(raw_pkt)
            
            # Parse IP layer
            if IP in raw_pkt:
                ip_layer = raw_pkt[IP]
                packet_code = set_pkt_type_code(packet_code, PacketType.IPv4)
                
                src_ip = int.from_bytes(bytes(map(int, ip_layer.src.split('.'))), 'big')
                dst_ip = int.from_bytes(bytes(map(int, ip_layer.dst.split('.'))), 'big')
                src_port = 0
                dst_port = 0
                packet_length = ip_layer.len if hasattr(ip_layer, 'len') and ip_layer.len else len(raw_pkt)
                
                # Parse transport layer
                if TCP in raw_pkt:
                    tcp_layer = raw_pkt[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    
                    flags = tcp_layer.flags
                    if flags.S:  # SYN
                        packet_code = set_pkt_type_code(packet_code, PacketType.TCP_SYN)
                    if flags.A:  # ACK
                        packet_code = set_pkt_type_code(packet_code, PacketType.TCP_ACK)
                    if flags.F:  # FIN
                        packet_code = set_pkt_type_code(packet_code, PacketType.TCP_FIN)
                    if flags.R:  # RST
                        packet_code = set_pkt_type_code(packet_code, PacketType.TCP_RST)
                        
                elif UDP in raw_pkt:
                    udp_layer = raw_pkt[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    packet_code = set_pkt_type_code(packet_code, PacketType.UDP)
                    
                elif ICMP in raw_pkt:
                    packet_code = set_pkt_type_code(packet_code, PacketType.ICMP)
                else:
                    packet_code = set_pkt_type_code(packet_code, PacketType.UNKNOWN)
                
                pkt = BasicPacket4(src_ip, dst_ip, src_port, dst_port, packet_time, packet_code, packet_length)
                self.parse_result.append(pkt)
                
            elif IPv6 in raw_pkt:
                ip6_layer = raw_pkt[IPv6]
                packet_code = set_pkt_type_code(packet_code, PacketType.IPv6)
                
                import ipaddress
                src_ip = int(ipaddress.IPv6Address(ip6_layer.src))
                dst_ip = int(ipaddress.IPv6Address(ip6_layer.dst))
                src_port = 0
                dst_port = 0
                packet_length = ip6_layer.plen if hasattr(ip6_layer, 'plen') and ip6_layer.plen else len(raw_pkt)
                
                # Parse transport layer
                if TCP in raw_pkt:
                    tcp_layer = raw_pkt[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    
                    flags = tcp_layer.flags
                    if flags.S:
                        packet_code = set_pkt_type_code(packet_code, PacketType.TCP_SYN)
                    if flags.A:
                        packet_code = set_pkt_type_code(packet_code, PacketType.TCP_ACK)
                    if flags.F:
                        packet_code = set_pkt_type_code(packet_code, PacketType.TCP_FIN)
                    if flags.R:
                        packet_code = set_pkt_type_code(packet_code, PacketType.TCP_RST)
                        
                elif UDP in raw_pkt:
                    udp_layer = raw_pkt[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    packet_code = set_pkt_type_code(packet_code, PacketType.UDP)
                    
                elif ICMP in raw_pkt:
                    packet_code = set_pkt_type_code(packet_code, PacketType.ICMP)
                else:
                    packet_code = set_pkt_type_code(packet_code, PacketType.UNKNOWN)
                
                pkt = BasicPacket6(src_ip, dst_ip, src_port, dst_port, packet_time, packet_code, packet_length)
                self.parse_result.append(pkt)
            else:
                # Bad packet
                bad_packet_count += 1
                self.parse_result.append(BasicPacketBad(packet_time))
        
        print(f"[LOG] {len(self.parse_result)} packets parsed, {bad_packet_count} bad packets")
        print(f"[TIMER] parse_basic_packet_fast: {time.time() - start_time:.6f}s")
        
        return self.parse_result
    
    def type_statistic(self) -> None:
        """Print packet type statistics."""
        if self.parse_result is None:
            raise RuntimeError("Packets not parsed yet.")
        
        start_time = time.time()
        
        stats = {i: 0 for i in range(len(TYPE_NAMES))}
        bad_count = 0
        
        for pkt in self.parse_result:
            if isinstance(pkt, BasicPacketBad):
                bad_count += 1
            else:
                for i in range(len(TYPE_NAMES)):
                    if test_pkt_type_code(pkt.tp, PacketType(i)):
                        stats[i] += 1
        
        print("[LOG] Packet type statistics:")
        for i, name in enumerate(TYPE_NAMES):
            print(f"[{name:8s}]: {stats[i]}")
        
        total = stats[PacketType.IPv4] + stats[PacketType.IPv6] + bad_count
        print(f"[{'ALL':8s}]: {total}")
        print(f"[{'BAD':8s}]: {bad_count}")
        
        print(f"[TIMER] type_statistic: {time.time() - start_time:.6f}s")
    
    def get_basic_packet_rep(self) -> Optional[List[BasicPacket]]:
        """Get parsed packet representations."""
        return self.parse_result
