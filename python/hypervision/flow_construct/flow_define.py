"""
Flow definitions.
Corresponds to flow_define.hpp in the C++ implementation.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import sys

from ..packet_parse.packet_basic import BasicPacket, BasicPacketBad
from ..packet_parse.packet_info import Tuple5Conn4, Tuple5Conn6


@dataclass
class BasicFlow:
    """Basic flow class containing a sequence of packets."""
    
    start_time: float = field(default=float('inf'))
    end_time: float = field(default=float('-inf'))
    code: int = 0
    packet_seq: List[BasicPacket] = field(default_factory=list)
    reverse_index: List[int] = field(default_factory=list)
    
    def emplace_packet(self, pkt: BasicPacket, reverse_id: int) -> bool:
        """
        Add a packet to the flow.
        
        Args:
            pkt: The packet to add.
            reverse_id: The reverse index of the packet.
            
        Returns:
            True if packet was added, False if it was a bad packet.
        """
        if isinstance(pkt, BasicPacketBad):
            return False
        
        ts = pkt.ts
        self.start_time = min(self.start_time, ts)
        self.end_time = max(self.end_time, ts)
        self.code |= pkt.tp
        self.packet_seq.append(pkt)
        self.reverse_index.append(reverse_id)
        return True
    
    def get_str_time(self) -> float:
        """Get flow start time."""
        return self.start_time
    
    def get_end_time(self) -> float:
        """Get flow end time."""
        return self.end_time
    
    def get_fct(self) -> float:
        """Get flow completion time (duration)."""
        return self.end_time - self.start_time
    
    def get_pkt_code(self) -> int:
        """Get combined packet type code."""
        return self.code
    
    def get_p_reverse_id(self) -> List[int]:
        """Get reverse index list."""
        return self.reverse_index
    
    def get_p_packet_p_seq(self) -> List[BasicPacket]:
        """Get packet sequence."""
        return self.packet_seq


@dataclass
class Tuple5Flow4(BasicFlow):
    """5-tuple flow for IPv4."""
    flow_id: Tuple5Conn4 = None
    
    def __init__(self, flow_id: Tuple5Conn4, 
                 packet_seq: List[BasicPacket] = None,
                 reverse_index: List[int] = None):
        super().__init__()
        self.flow_id = flow_id
        if packet_seq is not None:
            self.packet_seq = packet_seq
            for pkt in packet_seq:
                self.start_time = min(self.start_time, pkt.ts)
                self.end_time = max(self.end_time, pkt.ts)
                self.code |= pkt.tp
        if reverse_index is not None:
            self.reverse_index = reverse_index


@dataclass
class Tuple5Flow6(BasicFlow):
    """5-tuple flow for IPv6."""
    flow_id: Tuple5Conn6 = None
    
    def __init__(self, flow_id: Tuple5Conn6,
                 packet_seq: List[BasicPacket] = None,
                 reverse_index: List[int] = None):
        super().__init__()
        self.flow_id = flow_id
        if packet_seq is not None:
            self.packet_seq = packet_seq
            for pkt in packet_seq:
                self.start_time = min(self.start_time, pkt.ts)
                self.end_time = max(self.end_time, pkt.ts)
                self.code |= pkt.tp
        if reverse_index is not None:
            self.reverse_index = reverse_index
