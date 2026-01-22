"""
Edge definitions for traffic graph.
Corresponds to edge_define.cpp/hpp in the C++ implementation.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
from enum import IntEnum

from ..flow_construct.flow_define import BasicFlow, Tuple5Flow4, Tuple5Flow6
from ..packet_parse.packet_info import ip_to_str


class AggType(IntEnum):
    """Aggregation type enumeration."""
    SRC_AGG = 0
    DST_AGG = 1
    SRC_P_AGG = 2
    DST_P_AGG = 3
    NO_AGG = 4


AGG_NAMES = ["SRC_AGG", "DST_AGG", "SRC_P_AGG", "DST_P_AGG", "NO_AGG"]


def is_src_agg(code: int) -> bool:
    return bool((code >> AggType.SRC_AGG) & 0x1)


def is_dst_agg(code: int) -> bool:
    return bool((code >> AggType.DST_AGG) & 0x1)


def is_srcp_agg(code: int) -> bool:
    return bool((code >> AggType.SRC_P_AGG) & 0x1)


def is_dstp_agg(code: int) -> bool:
    return bool((code >> AggType.DST_P_AGG) & 0x1)


def is_no_agg(code: int) -> bool:
    return bool((code >> AggType.NO_AGG) & 0x1)


def set_src_agg(code: int) -> int:
    return code | (1 << AggType.SRC_AGG)


def set_dst_agg(code: int) -> int:
    return code | (1 << AggType.DST_AGG)


def set_srcp_agg(code: int) -> int:
    return code | (1 << AggType.SRC_P_AGG)


def set_dstp_agg(code: int) -> int:
    return code | (1 << AggType.DST_P_AGG)


def set_no_agg(code: int) -> int:
    return 1 << AggType.NO_AGG


@dataclass
class LongEdge:
    """Long edge representing a flow with detailed statistics."""
    
    flow: BasicFlow
    length_distribution: Dict[int, int] = field(default_factory=dict)
    type_distribution: Dict[int, int] = field(default_factory=dict)
    time_distribution: Dict[int, int] = field(default_factory=dict)
    
    # Constants
    HUGE_FLOW_BYTE_LINE = 5000 * 1024
    HUGE_FLOW_COUNT_LINE = 8000
    PULSE_FLOW_TIME_LINE = 50000
    PULSE_FLOW_CTR_LINE = 2
    INVALID_PACKET_LINE = 10
    
    def get_raw_flow(self) -> BasicFlow:
        return self.flow
    
    def get_length_distribution(self) -> Dict[int, int]:
        return self.length_distribution
    
    def get_type_distribution(self) -> Dict[int, int]:
        return self.type_distribution
    
    def get_time_interval_distribution(self) -> Dict[int, int]:
        return self.time_distribution
    
    def get_avg_packet_rate(self) -> float:
        """Get average packet rate."""
        time_range = self.get_time_range()
        duration = time_range[1] - time_range[0]
        if duration < 1e-9:
            return 0.0
        return len(self.flow.packet_seq) / duration
    
    def is_huge_flow(self) -> bool:
        """Check if this is a huge flow."""
        total_bytes = sum(k * v for k, v in self.length_distribution.items())
        total_count = len(self.flow.packet_seq)
        return total_bytes > self.HUGE_FLOW_BYTE_LINE or total_count > self.HUGE_FLOW_COUNT_LINE
    
    def is_pulse_flow(self) -> bool:
        """Check if this is a pulse flow."""
        time_range = self.get_time_range()
        duration = time_range[1] - time_range[0]
        if duration < 1e-9:
            return False
        rate = len(self.flow.packet_seq) / duration
        return rate > self.PULSE_FLOW_CTR_LINE
    
    def is_invalid_flow(self) -> bool:
        """Check if this is an invalid flow."""
        return len(self.flow.packet_seq) < self.INVALID_PACKET_LINE
    
    def get_src_str(self) -> str:
        """Get source address as string."""
        if isinstance(self.flow, Tuple5Flow4):
            return ip_to_str(self.flow.flow_id.src_ip, is_ipv6=False)
        elif isinstance(self.flow, Tuple5Flow6):
            return ip_to_str(self.flow.flow_id.src_ip, is_ipv6=True)
        return ""
    
    def get_dst_str(self) -> str:
        """Get destination address as string."""
        if isinstance(self.flow, Tuple5Flow4):
            return ip_to_str(self.flow.flow_id.dst_ip, is_ipv6=False)
        elif isinstance(self.flow, Tuple5Flow6):
            return ip_to_str(self.flow.flow_id.dst_ip, is_ipv6=True)
        return ""
    
    def get_time_range(self) -> Tuple[float, float]:
        """Get time range of the flow."""
        return (self.flow.get_str_time(), self.flow.get_end_time())
    
    def show_edge(self) -> None:
        """Display edge information."""
        print(f"LongEdge: {self.get_src_str()} -> {self.get_dst_str()}, "
              f"packets: {len(self.flow.packet_seq)}, "
              f"time_range: {self.get_time_range()}")


@dataclass
class ShortEdge:
    """Short edge representing aggregated flows."""
    
    flows: List[BasicFlow]
    agg_indicator: int
    
    def get_agg_code(self) -> int:
        return self.agg_indicator
    
    def get_agg_size(self) -> int:
        return len(self.flows)
    
    def get_time(self) -> float:
        """Get start time of first flow."""
        if self.flows:
            return self.flows[0].get_str_time()
        return 0.0
    
    def get_time_range(self) -> Tuple[float, float]:
        """Get time range across all flows."""
        if not self.flows:
            return (0.0, 0.0)
        
        min_time = min(f.get_str_time() for f in self.flows)
        max_time = max(f.get_end_time() for f in self.flows)
        return (min_time, max_time)
    
    def get_src_str(self) -> str:
        """Get source address as string."""
        if not self.flows:
            return ""
        flow = self.flows[0]
        if isinstance(flow, Tuple5Flow4):
            return ip_to_str(flow.flow_id.src_ip, is_ipv6=False)
        elif isinstance(flow, Tuple5Flow6):
            return ip_to_str(flow.flow_id.src_ip, is_ipv6=True)
        return ""
    
    def get_dst_str(self) -> str:
        """Get destination address as string."""
        if not self.flows:
            return ""
        flow = self.flows[0]
        if isinstance(flow, Tuple5Flow4):
            return ip_to_str(flow.flow_id.dst_ip, is_ipv6=False)
        elif isinstance(flow, Tuple5Flow6):
            return ip_to_str(flow.flow_id.dst_ip, is_ipv6=True)
        return ""
    
    def get_avg_interval(self) -> float:
        """Get average packet interval."""
        if not self.flows:
            return 0.0
        pkt_seq = self.flows[0].packet_seq
        if not pkt_seq:
            return 0.0
        total = sum(pkt.ts for pkt in pkt_seq)
        return total / len(pkt_seq)
    
    def get_flow_index(self, idx: int) -> BasicFlow:
        """Get flow at index."""
        return self.flows[idx]
    
    def get_pkt_seq_size(self) -> int:
        """Get packet sequence size of first flow."""
        if self.flows:
            return len(self.flows[0].packet_seq)
        return 0
    
    def get_pkt_seq_code(self) -> int:
        """Get packet code of first flow."""
        if self.flows:
            return self.flows[0].get_pkt_code()
        return 0
    
    def get_src_list(self) -> List[str]:
        """Get list of source addresses."""
        result = []
        for flow in self.flows:
            if isinstance(flow, Tuple5Flow4):
                result.append(ip_to_str(flow.flow_id.src_ip, is_ipv6=False))
            elif isinstance(flow, Tuple5Flow6):
                result.append(ip_to_str(flow.flow_id.src_ip, is_ipv6=True))
        return result
    
    def get_dst_list(self) -> List[str]:
        """Get list of destination addresses."""
        result = []
        for flow in self.flows:
            if isinstance(flow, Tuple5Flow4):
                result.append(ip_to_str(flow.flow_id.dst_ip, is_ipv6=False))
            elif isinstance(flow, Tuple5Flow6):
                result.append(ip_to_str(flow.flow_id.dst_ip, is_ipv6=True))
        return result
    
    def show_edge(self, max_show: int = 5) -> None:
        """Display edge information."""
        print(f"ShortEdge: agg_code={self.agg_indicator}, flows={len(self.flows)}")
        for i, flow in enumerate(self.flows[:max_show]):
            if isinstance(flow, Tuple5Flow4):
                print(f"  [{i}] {ip_to_str(flow.flow_id.src_ip, False)} -> "
                      f"{ip_to_str(flow.flow_id.dst_ip, False)}")
            elif isinstance(flow, Tuple5Flow6):
                print(f"  [{i}] {ip_to_str(flow.flow_id.src_ip, True)} -> "
                      f"{ip_to_str(flow.flow_id.dst_ip, True)}")
