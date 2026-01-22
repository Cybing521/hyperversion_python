"""
Basic packet structures.
Corresponds to packet_basic.hpp in the C++ implementation.
"""

from dataclasses import dataclass, field
from typing import Optional
from .packet_info import Tuple4Conn4, Tuple4Conn6, ip_to_str, str_to_ip4, str_to_ip6


@dataclass
class BasicPacket:
    """Base packet class."""
    ts: float  # timestamp in seconds
    tp: int    # packet type code
    length: int  # packet length
    
    def __post_init__(self):
        pass


@dataclass
class BasicPacketBad(BasicPacket):
    """Bad/invalid packet."""
    def __init__(self, ts: float = 0.0):
        super().__init__(ts=ts, tp=0, length=0)


@dataclass
class BasicPacket4(BasicPacket):
    """IPv4 packet with 4-tuple flow ID."""
    flow_id: Tuple4Conn4 = None
    
    def __init__(self, src_ip: int, dst_ip: int, src_port: int, dst_port: int,
                 ts: float, tp: int, length: int):
        super().__init__(ts=ts, tp=tp, length=length)
        self.flow_id = Tuple4Conn4(src_ip, dst_ip, src_port, dst_port)
    
    @classmethod
    def from_string(cls, s: str) -> 'BasicPacket4':
        """Create packet from string representation."""
        parts = s.split()
        assert parts[0] == '4', "Not an IPv4 packet string"
        src_ip = int(parts[1])
        dst_ip = int(parts[2])
        src_port = int(parts[3])
        dst_port = int(parts[4])
        ts = float(parts[5]) / 1e6
        tp = int(parts[6])
        length = int(parts[7])
        return cls(src_ip, dst_ip, src_port, dst_port, ts, tp, length)
    
    def to_string(self, align_time: int = 0) -> str:
        """Convert packet to string representation."""
        ts_us = int(self.ts * 1e6) - align_time
        return f"4 {self.flow_id.src_ip} {self.flow_id.dst_ip} {self.flow_id.src_port} {self.flow_id.dst_port} {ts_us} {self.tp} {self.length}\n"
    
    def get_src_str(self) -> str:
        """Get source IP as string."""
        return ip_to_str(self.flow_id.src_ip, is_ipv6=False)
    
    def get_dst_str(self) -> str:
        """Get destination IP as string."""
        return ip_to_str(self.flow_id.dst_ip, is_ipv6=False)


@dataclass
class BasicPacket6(BasicPacket):
    """IPv6 packet with 4-tuple flow ID."""
    flow_id: Tuple4Conn6 = None
    
    def __init__(self, src_ip: int, dst_ip: int, src_port: int, dst_port: int,
                 ts: float, tp: int, length: int):
        super().__init__(ts=ts, tp=tp, length=length)
        self.flow_id = Tuple4Conn6(src_ip, dst_ip, src_port, dst_port)
    
    @classmethod
    def from_string(cls, s: str) -> 'BasicPacket6':
        """Create packet from string representation."""
        parts = s.split()
        assert parts[0] == '6', "Not an IPv6 packet string"
        src_ip = int(parts[1])
        dst_ip = int(parts[2])
        src_port = int(parts[3])
        dst_port = int(parts[4])
        ts = float(parts[5]) / 1e6
        tp = int(parts[6])
        length = int(parts[7])
        return cls(src_ip, dst_ip, src_port, dst_port, ts, tp, length)
    
    def to_string(self, align_time: int = 0) -> str:
        """Convert packet to string representation."""
        ts_us = int(self.ts * 1e6) - align_time
        return f"6 {self.flow_id.src_ip} {self.flow_id.dst_ip} {self.flow_id.src_port} {self.flow_id.dst_port} {ts_us} {self.tp} {self.length}\n"
    
    def get_src_str(self) -> str:
        """Get source IP as string."""
        return ip_to_str(self.flow_id.src_ip, is_ipv6=True)
    
    def get_dst_str(self) -> str:
        """Get destination IP as string."""
        return ip_to_str(self.flow_id.dst_ip, is_ipv6=True)
