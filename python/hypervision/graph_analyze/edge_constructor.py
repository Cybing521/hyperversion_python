"""
Edge constructor for traffic graph.
Corresponds to edge_constructor.cpp/hpp in the C++ implementation.
"""

import time
import math
from typing import List, Dict, Tuple, Set
from collections import defaultdict

from ..flow_construct.flow_define import BasicFlow, Tuple5Flow4, Tuple5Flow6
from ..packet_parse.packet_info import ip_to_str
from .edge_define import (
    LongEdge, ShortEdge,
    set_src_agg, set_dst_agg, set_srcp_agg, set_dstp_agg, set_no_agg,
    is_src_agg, is_dst_agg, is_srcp_agg, is_dstp_agg, is_no_agg
)


class EdgeConstructor:
    """Constructs edges from flows."""
    
    def __init__(self, flows: List[BasicFlow]):
        """
        Initialize constructor.
        
        Args:
            flows: List of constructed flows.
        """
        self.parse_result = flows
        self.short_edges: List[ShortEdge] = []
        self.long_edges: List[LongEdge] = []
        self.short_packet_sum = 0
        self.long_packet_sum = 0
        
        # Configuration
        self.LENGTH_BIN_SIZE = 50
        self.TIME_BIN_SIZE = 0.001  # 1ms
        self.EDGE_LONG_LINE = 10
        self.EDGE_AGG_LINE = 2
    
    def config_via_json(self, config: dict) -> None:
        """Configure from JSON."""
        if 'length_bin_size' in config:
            self.LENGTH_BIN_SIZE = int(config['length_bin_size'])
        if 'edge_long_line' in config:
            self.EDGE_LONG_LINE = int(config['edge_long_line'])
        if 'edge_agg_line' in config:
            self.EDGE_AGG_LINE = int(config['edge_agg_line'])
    
    def do_construct(self) -> None:
        """Perform edge construction."""
        short_flows = []
        long_flows = []
        
        # Classify flows
        self._flow_classification(short_flows, long_flows)
        
        # Construct edges
        self._construct_long_flow(long_flows)
        self._construct_short_flow(short_flows)
    
    def _flow_classification(self, short_flows: List[BasicFlow], long_flows: List[BasicFlow]) -> None:
        """Classify flows into short and long."""
        sum_short = 0
        sum_long = 0
        
        for flow in self.parse_result:
            if len(flow.reverse_index) > self.EDGE_LONG_LINE:
                long_flows.append(flow)
                sum_long += len(flow.packet_seq)
            else:
                short_flows.append(flow)
                sum_short += len(flow.packet_seq)
        
        print(f"[LOG] Before aggregation: {len(short_flows)} short edges [{sum_short} pkts], "
              f"{len(long_flows)} long edges [{sum_long} pkts]")
    
    def _construct_long_flow(self, long_flows: List[BasicFlow]) -> None:
        """Construct long edges from flows."""
        start_time = time.time()
        
        self.long_edges = []
        self.long_packet_sum = 0
        
        for flow in long_flows:
            pkt_seq = flow.packet_seq
            
            len_db = defaultdict(int)
            type_db = defaultdict(int)
            time_db = defaultdict(int)
            
            time_ctr = pkt_seq[0].ts if pkt_seq else 0.0
            
            for pkt in pkt_seq:
                fuzzing_len = (pkt.length // self.LENGTH_BIN_SIZE) * self.LENGTH_BIN_SIZE
                fuzzing_time = int(max(pkt.ts - time_ctr, 0.0) / self.TIME_BIN_SIZE)
                time_ctr = max(time_ctr, pkt.ts)
                
                len_db[fuzzing_len] += 1
                type_db[pkt.tp] += 1
                time_db[fuzzing_time] += 1
            
            long_edge = LongEdge(
                flow=flow,
                length_distribution=dict(len_db),
                type_distribution=dict(type_db),
                time_distribution=dict(time_db)
            )
            self.long_edges.append(long_edge)
            self.long_packet_sum += len(pkt_seq)
        
        print(f"[TIMER] construct_long_flow: {time.time() - start_time:.6f}s")
    
    def _construct_short_flow(self, short_flows: List[BasicFlow]) -> None:
        """Construct short edges from flows with aggregation."""
        start_time = time.time()
        
        self.short_edges = []
        self.short_packet_sum = 0
        
        # Get unified addresses
        def get_unified_addr(flow):
            if isinstance(flow, Tuple5Flow4):
                return (flow.flow_id.src_ip, flow.flow_id.dst_ip)
            elif isinstance(flow, Tuple5Flow6):
                return (flow.flow_id.src_ip, flow.flow_id.dst_ip)
            return (0, 0)
        
        f_src_vec = []
        f_dst_vec = []
        
        for flow in short_flows:
            src, dst = get_unified_addr(flow)
            f_src_vec.append(src)
            f_dst_vec.append(dst)
        
        is_fetched = [False] * len(short_flows)
        
        # Aggregation by src+dst
        src_dst_agg_select = defaultdict(list)
        for i, flow in enumerate(short_flows):
            tag = (f_src_vec[i], f_dst_vec[i], flow.get_pkt_code())
            src_dst_agg_select[tag].append(i)
        
        src_dst_agg_res = []
        for tag, ids in src_dst_agg_select.items():
            if len(ids) > self.EDGE_AGG_LINE:
                src_dst_agg_res.append(ids)
                for idx in ids:
                    is_fetched[idx] = True
        
        # Aggregation by src
        src_agg_select = defaultdict(list)
        for i, flow in enumerate(short_flows):
            if is_fetched[i]:
                continue
            tag = (f_src_vec[i], flow.get_pkt_code())
            src_agg_select[tag].append(i)
        
        src_agg_res = []
        for tag, ids in src_agg_select.items():
            if len(ids) > self.EDGE_AGG_LINE:
                src_agg_res.append(ids)
                for idx in ids:
                    is_fetched[idx] = True
        
        # Aggregation by dst
        dst_agg_select = defaultdict(list)
        for i, flow in enumerate(short_flows):
            if is_fetched[i]:
                continue
            tag = (f_dst_vec[i], flow.get_pkt_code())
            dst_agg_select[tag].append(i)
        
        dst_agg_res = []
        for tag, ids in dst_agg_select.items():
            if len(ids) > self.EDGE_AGG_LINE:
                dst_agg_res.append(ids)
                for idx in ids:
                    is_fetched[idx] = True
        
        def get_port(flow):
            if isinstance(flow, Tuple5Flow4):
                return (flow.flow_id.src_port, flow.flow_id.dst_port)
            elif isinstance(flow, Tuple5Flow6):
                return (flow.flow_id.src_port, flow.flow_id.dst_port)
            return (0, 0)
        
        def set_port_agg_code(ids: List[int], code: int) -> int:
            port0 = get_port(short_flows[ids[0]])
            src_p_agg = True
            dst_p_agg = True
            
            for idx in ids:
                port = get_port(short_flows[idx])
                if port[0] != port0[0]:
                    src_p_agg = False
                if port[1] != port0[1]:
                    dst_p_agg = False
                if not src_p_agg and not dst_p_agg:
                    break
            
            if src_p_agg:
                code = set_srcp_agg(code)
            if dst_p_agg:
                code = set_dstp_agg(code)
            return code
        
        # Create short edges for src+dst aggregated flows
        for ids in src_dst_agg_res:
            code = 0
            code = set_src_agg(code)
            code = set_dst_agg(code)
            code = set_port_agg_code(ids, code)
            
            flows_to_add = [short_flows[i] for i in ids]
            for flow in flows_to_add:
                self.short_packet_sum += len(flow.packet_seq)
            
            self.short_edges.append(ShortEdge(flows_to_add, code))
        
        # Create short edges for src aggregated flows
        for ids in src_agg_res:
            code = 0
            code = set_src_agg(code)
            code = set_port_agg_code(ids, code)
            
            flows_to_add = [short_flows[i] for i in ids]
            for flow in flows_to_add:
                self.short_packet_sum += len(flow.packet_seq)
            
            self.short_edges.append(ShortEdge(flows_to_add, code))
        
        # Create short edges for dst aggregated flows
        for ids in dst_agg_res:
            code = 0
            code = set_dst_agg(code)
            code = set_port_agg_code(ids, code)
            
            flows_to_add = [short_flows[i] for i in ids]
            for flow in flows_to_add:
                self.short_packet_sum += len(flow.packet_seq)
            
            self.short_edges.append(ShortEdge(flows_to_add, code))
        
        # Create short edges for non-aggregated flows
        for i, flow in enumerate(short_flows):
            if not is_fetched[i]:
                code = set_no_agg(0)
                self.short_packet_sum += len(flow.packet_seq)
                self.short_edges.append(ShortEdge([flow], code))
        
        print(f"[TIMER] construct_short_flow: {time.time() - start_time:.6f}s")
    
    def show_short_edge_statistic(self) -> None:
        """Show short edge statistics."""
        num_no_agg = 0
        num_srcdst_agg = 0
        num_dst_agg = 0
        num_src_agg = 0
        num_srcp_agg = 0
        num_dstp_agg = 0
        
        for edge in self.short_edges:
            code = edge.get_agg_code()
            if is_no_agg(code):
                num_no_agg += 1
            else:
                if is_src_agg(code) and is_dst_agg(code):
                    num_srcdst_agg += 1
                elif is_src_agg(code):
                    num_src_agg += 1
                else:
                    num_dst_agg += 1
                
                if is_srcp_agg(code):
                    num_srcp_agg += 1
                if is_dstp_agg(code):
                    num_dstp_agg += 1
        
        print(f"[NO_AGG  ]: {num_no_agg:6d}")
        print(f"[SRC_DST ]: {num_srcdst_agg:6d}")
        print(f"[SRC_AGG ]: {num_src_agg:6d}")
        print(f"[DST_AGG ]: {num_dst_agg:6d}")
        print(f"[SRCP_AGG]: {num_srcp_agg:6d}")
        print(f"[DSTP_AGG]: {num_dstp_agg:6d}")
        print(f"[SUM     ]: {num_no_agg + num_srcdst_agg + num_dst_agg + num_src_agg:6d}")
    
    def get_edge(self) -> Tuple[List[ShortEdge], List[LongEdge]]:
        """Get constructed edges."""
        return (self.short_edges, self.long_edges)
