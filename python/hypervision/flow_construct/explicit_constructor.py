"""
Explicit flow constructor.
Corresponds to explicit_constructor.cpp/hpp in the C++ implementation.
"""

import time
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

from ..packet_parse.packet_basic import BasicPacket, BasicPacket4, BasicPacket6, BasicPacketBad
from ..packet_parse.packet_info import (
    Tuple5Conn4, Tuple5Conn6, tuple4_extend, convert_packet2stack_code,
    StackType, STACK_NAMES, get_pkt_stack_code
)
from .flow_define import BasicFlow, Tuple5Flow4, Tuple5Flow6


# Constants
EPS = 1e-9


class ExplicitFlowConstructor:
    """Constructs flows from parsed packets."""
    
    def __init__(self, parse_result: List[BasicPacket]):
        """
        Initialize constructor.
        
        Args:
            parse_result: List of parsed packets.
        """
        self.parse_result = parse_result
        self.construct_result4: List[Tuple5Flow4] = []
        self.construct_result6: List[Tuple5Flow6] = []
        
        # Configuration
        self.FLOW_TIME_OUT = 64.0
        self.EVICT_FLOW_TIME_OUT = 256.0
    
    def config_via_json(self, config: dict) -> None:
        """
        Configure from JSON.
        
        Args:
            config: Configuration dictionary.
        """
        if 'flow_time_out' in config:
            self.FLOW_TIME_OUT = float(config['flow_time_out'])
            if self.FLOW_TIME_OUT < EPS:
                raise ValueError("Invalid configuration for flow time out.")
        
        if 'evict_flow_time_out' in config:
            self.EVICT_FLOW_TIME_OUT = float(config['evict_flow_time_out'])
            if self.EVICT_FLOW_TIME_OUT < EPS:
                raise ValueError("Invalid configuration for evicting timeout flow.")
    
    def construct_flow(self) -> None:
        """Construct flows from packets."""
        start_time = time.time()
        
        if self.parse_result is None:
            raise RuntimeError("Packet parse result not provided.")
        
        # Hash tables for flow tracking
        flow_table_4: Dict[Tuple5Conn4, Tuple5Flow4] = {}
        flow_table_6: Dict[Tuple5Conn6, Tuple5Flow6] = {}
        
        flows_to_add_4: List[Tuple5Flow4] = []
        flows_to_add_6: List[Tuple5Flow6] = []
        
        last_check_time = self.parse_result[0].ts if self.parse_result else 0.0
        
        for i, pkt in enumerate(self.parse_result):
            if isinstance(pkt, BasicPacketBad):
                continue
            
            timestamp = pkt.ts
            
            if isinstance(pkt, BasicPacket4):
                stack_code = convert_packet2stack_code(pkt.tp)
                flow_id = tuple4_extend(pkt.flow_id, stack_code)
                
                if flow_id not in flow_table_4:
                    new_flow = Tuple5Flow4(flow_id)
                    new_flow.emplace_packet(pkt, i)
                    flow_table_4[flow_id] = new_flow
                else:
                    flow_table_4[flow_id].emplace_packet(pkt, i)
                    
            elif isinstance(pkt, BasicPacket6):
                stack_code = convert_packet2stack_code(pkt.tp)
                flow_id = tuple4_extend(pkt.flow_id, stack_code)
                
                if flow_id not in flow_table_6:
                    new_flow = Tuple5Flow6(flow_id)
                    new_flow.emplace_packet(pkt, i)
                    flow_table_6[flow_id] = new_flow
                else:
                    flow_table_6[flow_id].emplace_packet(pkt, i)
            
            # Check for flow eviction
            if timestamp - last_check_time - self.EVICT_FLOW_TIME_OUT > EPS:
                last_check_time = timestamp
                
                # Evict timed out IPv4 flows
                evicted_4 = []
                for fid, flow in flow_table_4.items():
                    if timestamp - flow.get_end_time() - self.FLOW_TIME_OUT > EPS:
                        evicted_4.append(fid)
                        flows_to_add_4.append(flow)
                for fid in evicted_4:
                    del flow_table_4[fid]
                
                # Evict timed out IPv6 flows
                evicted_6 = []
                for fid, flow in flow_table_6.items():
                    if timestamp - flow.get_end_time() - self.FLOW_TIME_OUT > EPS:
                        evicted_6.append(fid)
                        flows_to_add_6.append(flow)
                for fid in evicted_6:
                    del flow_table_6[fid]
        
        # Add remaining flows
        flows_to_add_4.extend(flow_table_4.values())
        flows_to_add_6.extend(flow_table_6.values())
        
        self.construct_result4 = flows_to_add_4
        self.construct_result6 = flows_to_add_6
        
        print(f"[LOG] Number of flows: {len(self.construct_result4) + len(self.construct_result6)} "
              f"[{len(self.construct_result4)} IPv4 | {len(self.construct_result6)} IPv6]")
        
        # Double check for flow merging
        self._flow_double_check()
        
        print(f"[TIMER] construct_flow: {time.time() - start_time:.6f}s")
    
    def _flow_double_check(self) -> None:
        """Merge flows with same flow_id that are close in time."""
        start_time = time.time()
        
        self.construct_result4 = self._flow_double_check_impl(self.construct_result4, Tuple5Flow4)
        self.construct_result6 = self._flow_double_check_impl(self.construct_result6, Tuple5Flow6)
        
        print(f"[LOG] After double check - Number of flows: "
              f"{len(self.construct_result4) + len(self.construct_result6)} "
              f"[{len(self.construct_result4)} IPv4 | {len(self.construct_result6)} IPv6]")
        print(f"[TIMER] flow_double_check: {time.time() - start_time:.6f}s")
    
    def _flow_double_check_impl(self, flows: List, flow_class) -> List:
        """Implementation of flow double check for either IPv4 or IPv6."""
        # Group flows by flow_id
        flow_groups = defaultdict(list)
        for flow in flows:
            flow_groups[flow.flow_id].append(flow)
        
        result = []
        for flow_id, group in flow_groups.items():
            if len(group) == 1:
                result.append(group[0])
            else:
                # Sort by start time
                group.sort(key=lambda f: f.get_str_time())
                
                # Merge flows that are close in time
                merged_flows = []
                current_group = [group[0]]
                
                for i in range(1, len(group)):
                    prev_flow = current_group[-1]
                    curr_flow = group[i]
                    
                    if curr_flow.get_str_time() - prev_flow.get_end_time() >= self.FLOW_TIME_OUT:
                        # Merge current group
                        merged_flows.append(self._merge_flows(current_group, flow_id, flow_class))
                        current_group = [curr_flow]
                    else:
                        current_group.append(curr_flow)
                
                # Don't forget the last group
                merged_flows.append(self._merge_flows(current_group, flow_id, flow_class))
                result.extend(merged_flows)
        
        return result
    
    def _merge_flows(self, flows: List, flow_id, flow_class) -> BasicFlow:
        """Merge multiple flows into one."""
        all_packets = []
        all_indices = []
        
        for flow in flows:
            all_packets.extend(flow.packet_seq)
            all_indices.extend(flow.reverse_index)
        
        return flow_class(flow_id, all_packets, all_indices)
    
    def dump_flow_statistic(self) -> None:
        """Print flow statistics."""
        start_time = time.time()
        
        print(f"[LOG] Constructed IPv4 flow: {len(self.construct_result4):8d}, "
              f"IPv6 flow: {len(self.construct_result6):8d}")
        print("[LOG] Flow statistic by protocol stack:")
        
        # IPv4 statistics
        stats4 = {i: 0 for i in range(StackType.F_UNKNOWN)}
        for flow in self.construct_result4:
            for i in range(StackType.F_UNKNOWN):
                if flow.flow_id.stack_code == get_pkt_stack_code(StackType(i)):
                    stats4[i] += 1
        
        # IPv6 statistics
        stats6 = {i: 0 for i in range(StackType.F_UNKNOWN)}
        for flow in self.construct_result6:
            for i in range(StackType.F_UNKNOWN):
                if flow.flow_id.stack_code == get_pkt_stack_code(StackType(i)):
                    stats6[i] += 1
        
        print(f"[Sum IPv4 Flow]: {len(self.construct_result4)}")
        for i in range(StackType.F_UNKNOWN):
            print(f"[{STACK_NAMES[i]:8s}]: {stats4[i]}")
        
        print(f"[Sum IPv6 Flow]: {len(self.construct_result6)}")
        for i in range(StackType.F_UNKNOWN):
            print(f"[{STACK_NAMES[i]:8s}]: {stats6[i]}")
        
        print(f"[TIMER] dump_flow_statistic: {time.time() - start_time:.6f}s")
    
    def get_constructed_raw_flow(self) -> List[BasicFlow]:
        """Get all constructed flows as a single list."""
        return self.construct_result4 + self.construct_result6
