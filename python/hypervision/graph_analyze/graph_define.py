"""
Traffic graph definition and analysis.
Corresponds to graph_define.cpp/hpp and graph_analysis*.cpp in the C++ implementation.
"""

import time
import math
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict

import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import DBSCAN, KMeans
from scipy.spatial.distance import euclidean

try:
    from z3 import Bool, Int, Optimize, sat, If
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    print("[WARN] z3-solver not available, some features will be limited")

from .edge_define import (
    LongEdge, ShortEdge,
    is_src_agg, is_dst_agg, is_srcp_agg, is_dstp_agg, is_no_agg
)


HUG = 1e10
EPS = 1e-9


class TrafficGraph:
    """Traffic flow interaction graph."""
    
    def __init__(self, short_edges: List[ShortEdge], long_edges: List[LongEdge]):
        """
        Initialize traffic graph.
        
        Args:
            short_edges: List of short edges.
            long_edges: List of long edges.
        """
        self.short_edges = short_edges
        self.long_edges = long_edges
        
        # Graph structure
        self.vertex_set_long: Set[str] = set()
        self.vertex_set_short: Set[str] = set()
        self.vertex_set_short_reduce: Set[str] = set()
        
        self.long_edge_out: Dict[str, List[int]] = defaultdict(list)
        self.long_edge_in: Dict[str, List[int]] = defaultdict(list)
        self.short_edge_in: Dict[str, List[int]] = defaultdict(list)
        self.short_edge_in_agg: Dict[str, List[int]] = defaultdict(list)
        self.short_edge_out: Dict[str, List[int]] = defaultdict(list)
        self.short_edge_out_agg: Dict[str, List[int]] = defaultdict(list)
        
        # Scores
        self.short_edge_score: List[float] = []
        self.long_edge_score: List[float] = []
        self.pkt_score: Optional[List[float]] = None
        
        # Configuration
        self.proto_cluster = True
        self.val_K = 10
        self.al, self.bl, self.cl = 0.1, 1.0, 0.5
        self.as_, self.bs, self.cs = 0.1, 1.0, 0.5
        self.uc, self.us, self.ul = 0.01, 0.001, 0.05
        self.vc, self.vs, self.vl = 10, 20, 10
        self.select_ratio = 0.01
        self.offset_l, self.offset_s = 0.0, 0.0
        
        self.HUGE_SHORT_LINE = 50
        self.HUGE_AGG_SHORT_LINE = 100
    
    def config_via_json(self, config: dict) -> None:
        """Configure from JSON."""
        if 'proto_cluster' in config:
            self.proto_cluster = bool(config['proto_cluster'])
        if 'val_K' in config:
            self.val_K = int(config['val_K'])
        if 'al' in config:
            self.al = float(config['al'])
        if 'bl' in config:
            self.bl = float(config['bl'])
        if 'cl' in config:
            self.cl = float(config['cl'])
        if 'as' in config:
            self.as_ = float(config['as'])
        if 'bs' in config:
            self.bs = float(config['bs'])
        if 'cs' in config:
            self.cs = float(config['cs'])
        if 'uc' in config:
            self.uc = float(config['uc'])
        if 'us' in config:
            self.us = float(config['us'])
        if 'ul' in config:
            self.ul = float(config['ul'])
        if 'vc' in config:
            self.vc = int(config['vc'])
        if 'vs' in config:
            self.vs = int(config['vs'])
        if 'vl' in config:
            self.vl = int(config['vl'])
        if 'select_ratio' in config:
            self.select_ratio = float(config['select_ratio'])
    
    def parse_edge(self) -> None:
        """Parse edges and build graph structure."""
        self.short_edge_score = [0.0] * len(self.short_edges)
        self.long_edge_score = [0.0] * len(self.long_edges)
        
        self._parse_short_edge()
        self._parse_long_edge()
    
    def _parse_short_edge(self) -> None:
        """Parse short edges."""
        start_time = time.time()
        
        for i, edge in enumerate(self.short_edges):
            src = edge.get_src_str()
            dst = edge.get_dst_str()
            agg_code = edge.get_agg_code()
            
            self.vertex_set_short.add(src)
            self.vertex_set_short.add(dst)
            
            if is_no_agg(agg_code):
                self.short_edge_out[src].append(i)
                self.short_edge_in[dst].append(i)
                self.vertex_set_short_reduce.add(src)
                self.vertex_set_short_reduce.add(dst)
            else:
                if is_src_agg(agg_code):
                    self.short_edge_out_agg[src].append(i)
                    self.vertex_set_short_reduce.add(src)
                if is_dst_agg(agg_code):
                    self.short_edge_in_agg[dst].append(i)
                    self.vertex_set_short_reduce.add(dst)
        
        print(f"[TIMER] parse_short_edge: {time.time() - start_time:.6f}s")
    
    def _parse_long_edge(self) -> None:
        """Parse long edges."""
        start_time = time.time()
        
        for i, edge in enumerate(self.long_edges):
            src = edge.get_src_str()
            dst = edge.get_dst_str()
            
            self.vertex_set_long.add(src)
            self.vertex_set_long.add(dst)
            
            self.long_edge_out[src].append(i)
            self.long_edge_in[dst].append(i)
        
        print(f"[TIMER] parse_long_edge: {time.time() - start_time:.6f}s")
    
    def _get_inout_degree(self, addr: str) -> Tuple[int, int]:
        """Get in/out degree for an address."""
        in_degree = 0
        out_degree = 0
        
        if addr in self.short_edge_out:
            out_degree += len(self.short_edge_out[addr])
        if addr in self.short_edge_in:
            in_degree += len(self.short_edge_in[addr])
        if addr in self.short_edge_out_agg:
            for idx in self.short_edge_out_agg[addr]:
                out_degree += self.short_edges[idx].get_agg_size()
        if addr in self.short_edge_in_agg:
            for idx in self.short_edge_in_agg[addr]:
                in_degree += self.short_edges[idx].get_agg_size()
        
        return (in_degree, out_degree)
    
    def _extract_feature_short(self, index: int) -> List[float]:
        """Extract features for short edge."""
        edge = self.short_edges[index]
        src = edge.get_src_str()
        dst = edge.get_dst_str()
        agg_code = edge.get_agg_code()
        
        src_degree = self._get_inout_degree(src)
        dst_degree = self._get_inout_degree(dst)
        
        features = [
            float(is_src_agg(agg_code)),
            float(is_srcp_agg(agg_code)),
            float(is_dst_agg(agg_code)),
            float(is_dstp_agg(agg_code)),
            float(src_degree[0]),
            float(src_degree[1]),
            float(dst_degree[0]),
            float(dst_degree[1]),
        ]
        
        if self.proto_cluster:
            features.append(float(edge.get_pkt_seq_code()))
        
        return features
    
    def _extract_feature_short2(self, index: int) -> List[float]:
        """Extract extended features for short edge."""
        edge = self.short_edges[index]
        src = edge.get_src_str()
        dst = edge.get_dst_str()
        agg_code = edge.get_agg_code()
        
        src_degree = self._get_inout_degree(src)
        dst_degree = self._get_inout_degree(dst)
        
        return [
            float(is_src_agg(agg_code)),
            float(is_srcp_agg(agg_code)),
            float(is_dst_agg(agg_code)),
            float(is_dstp_agg(agg_code)),
            float(src_degree[0]),
            float(src_degree[1]),
            float(dst_degree[0]),
            float(dst_degree[1]),
            float(edge.get_agg_size()),
            float(edge.get_pkt_seq_size()),
            float(edge.get_agg_code()),
            float(edge.get_avg_interval()),
        ]
    
    def _extract_feature_long(self, index: int) -> List[float]:
        """Extract features for long edge."""
        edge = self.long_edges[index]
        src = edge.get_src_str()
        dst = edge.get_dst_str()
        
        features = [
            float(len(self.long_edge_out.get(src, []))),
            float(len(self.long_edge_in.get(src, []))),
            float(len(self.long_edge_out.get(dst, []))),
            float(len(self.long_edge_in.get(dst, []))),
        ]
        
        if self.proto_cluster:
            features.append(float(edge.get_raw_flow().get_pkt_code()))
        
        return features
    
    def _extract_feature_long2(self, index: int) -> List[float]:
        """Extract extended features for long edge."""
        edge = self.long_edges[index]
        src = edge.get_src_str()
        dst = edge.get_dst_str()
        time_pair = edge.get_time_range()
        
        type_dist = edge.get_type_distribution()
        len_dist = edge.get_length_distribution()
        
        max_type = max(type_dist.items(), key=lambda x: x[1]) if type_dist else (0, 0)
        max_len = max(len_dist.items(), key=lambda x: x[1]) if len_dist else (0, 0)
        
        num_ctr = sum(len_dist.values())
        byte_ctr = sum(k * v for k, v in len_dist.items())
        
        return [
            float(len(self.long_edge_out.get(src, []))),
            float(len(self.long_edge_in.get(src, []))),
            float(len(self.long_edge_out.get(dst, []))),
            float(len(self.long_edge_in.get(dst, []))),
            float(max_type[0]),
            float(max_type[1]),
            float(max_len[0]),
            float(max_len[1]),
            float(num_ctr),
            float(time_pair[1] - time_pair[0]),
            float(edge.get_avg_packet_rate()),
        ]
    
    def connected_component(self) -> List[List[str]]:
        """Find connected components in the graph."""
        start_time = time.time()
        
        # Build adjacency for all vertices
        all_vertices = self.vertex_set_short_reduce | self.vertex_set_long
        adj = defaultdict(set)
        
        # Add edges from short edges
        for i, edge in enumerate(self.short_edges):
            src = edge.get_src_str()
            dst = edge.get_dst_str()
            if src in all_vertices and dst in all_vertices:
                adj[src].add(dst)
                adj[dst].add(src)
        
        # Add edges from long edges
        for edge in self.long_edges:
            src = edge.get_src_str()
            dst = edge.get_dst_str()
            adj[src].add(dst)
            adj[dst].add(src)
        
        # BFS to find components
        visited = set()
        components = []
        
        for vertex in all_vertices:
            if vertex in visited:
                continue
            
            component = []
            queue = [vertex]
            visited.add(vertex)
            
            while queue:
                v = queue.pop(0)
                component.append(v)
                
                for neighbor in adj[v]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
            
            components.append(component)
        
        print(f"[LOG] Found {len(components)} connected components")
        print(f"[TIMER] connected_component: {time.time() - start_time:.6f}s")
        
        return components
    
    def _component_select(self, components: List[List[str]]) -> List[int]:
        """Select components for processing."""
        # Sort by size descending
        indexed = [(i, len(c)) for i, c in enumerate(components)]
        indexed.sort(key=lambda x: -x[1])
        
        # Select top components based on ratio
        total_vertices = sum(len(c) for c in components)
        target = int(total_vertices * self.select_ratio)
        
        selected = []
        current = 0
        for idx, size in indexed:
            if current >= target and selected:
                break
            selected.append(idx)
            current += size
        
        return selected
    
    def graph_detect(self) -> None:
        """Run graph-based detection."""
        components = self.connected_component()
        self._proc_components(components)
    
    def _proc_components(self, components: List[List[str]]) -> None:
        """Process all components."""
        start_time = time.time()
        
        selected = self._component_select(components)
        
        for idx in selected:
            self._proc_each_component(components[idx])
        
        print(f"[TIMER] proc_components: {time.time() - start_time:.6f}s")
    
    def _acquire_edge_index(self, addr_ls: List[str]) -> Tuple[Set[int], Set[int]]:
        """Get edge indices for a set of addresses."""
        long_index = set()
        short_index = set()
        
        for addr in addr_ls:
            if addr in self.long_edge_out:
                long_index.update(self.long_edge_out[addr])
            if addr in self.short_edge_out:
                short_index.update(self.short_edge_out[addr])
            if addr in self.short_edge_out_agg:
                short_index.update(self.short_edge_out_agg[addr])
            if addr in self.short_edge_in_agg:
                short_index.update(self.short_edge_in_agg[addr])
        
        return (long_index, short_index)
    
    def _proc_each_component(self, addr_ls: List[str]) -> None:
        """Process a single component."""
        long_index, short_index = self._acquire_edge_index(addr_ls)
        
        # Process short edges
        if len(short_index) >= 1:
            self._process_short(short_index)
        
        # Process long edges
        if len(long_index) >= 1:
            self._process_long(long_index)
    
    def _process_short(self, short_index: Set[int]) -> None:
        """Process short edges in a component."""
        if len(short_index) < 2:
            return
        
        # Extract features
        features = []
        index_list = list(short_index)
        for idx in index_list:
            features.append(self._extract_feature_short(idx))
        
        if not features:
            return
        
        # Normalize and cluster
        X = np.array(features)
        scaler = MinMaxScaler()
        X_scaled = scaler.fit_transform(X)
        
        # DBSCAN clustering
        dbscan = DBSCAN(eps=self.us, min_samples=self.vs)
        assignments = dbscan.fit_predict(X_scaled)
        
        # Find unique clusters (excluding noise -1)
        unique_clusters = set(assignments) - {-1}
        if len(unique_clusters) == 0:
            return
        
        # Get cluster representatives
        cluster_indices = defaultdict(list)
        for i, label in enumerate(assignments):
            if label != -1:
                cluster_indices[label].append(i)
        
        # Extract features for second-stage clustering
        representative_indices = []
        cluster_sizes = []
        aggregate_sizes = []
        time_ranges = []
        origin_index_vec = []
        
        processed_clusters = set()
        for i, label in enumerate(assignments):
            if label == -1:
                # Non-clustered aggregated edges
                edge = self.short_edges[index_list[i]]
                if not is_no_agg(edge.get_agg_code()):
                    representative_indices.append(index_list[i])
                    cluster_sizes.append(1)
                    origin_index_vec.append([index_list[i]])
                    aggregate_sizes.append(edge.get_agg_size())
                    tr = edge.get_time_range()
                    time_ranges.append(tr[1] - tr[0])
            elif label not in processed_clusters:
                processed_clusters.add(label)
                members = cluster_indices[label]
                representative_indices.append(index_list[members[0]])
                cluster_sizes.append(len(members))
                origin_index_vec.append([index_list[m] for m in members])
                aggregate_sizes.append(self.short_edges[index_list[members[0]]].get_agg_size())
                
                # Calculate time range for cluster
                times = []
                for m in members:
                    edge = self.short_edges[index_list[m]]
                    times.append(edge.get_time())
                time_ranges.append(max(times) - min(times) if len(times) > 1 else 0)
        
        if not representative_indices:
            return
        
        # Second stage clustering with KMeans
        features2 = [self._extract_feature_short2(idx) for idx in representative_indices]
        X2 = np.array(features2)
        scaler2 = MinMaxScaler()
        X2_scaled = scaler2.fit_transform(X2)
        
        n_clusters = min(self.val_K, len(features2))
        if n_clusters < 2:
            return
        
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        kmeans.fit(X2_scaled)
        centroids = kmeans.cluster_centers_
        
        # Calculate loss for each representative
        losses = []
        for i, vec in enumerate(X2_scaled):
            min_dist = min(euclidean(vec, c) for c in centroids)
            loss = (self.as_ * min_dist + 
                    self.bs * math.log2(aggregate_sizes[i] * cluster_sizes[i] + 1) -
                    self.cs * time_ranges[i])
            losses.append(loss)
        
        # Assign scores to edges
        for i, indices in enumerate(origin_index_vec):
            for idx in indices:
                self.short_edge_score[idx] = losses[i]
    
    def _process_long(self, long_index: Set[int]) -> None:
        """Process long edges in a component."""
        if len(long_index) < 2:
            return
        
        # Extract features
        features = []
        index_list = list(long_index)
        for idx in index_list:
            features.append(self._extract_feature_long(idx))
        
        if not features:
            return
        
        # Normalize and cluster
        X = np.array(features)
        scaler = MinMaxScaler()
        X_scaled = scaler.fit_transform(X)
        
        # DBSCAN clustering
        dbscan = DBSCAN(eps=self.ul, min_samples=self.vl)
        assignments = dbscan.fit_predict(X_scaled)
        
        # Get clustering info
        cluster_sizes = defaultdict(int)
        cluster_time_start = defaultdict(lambda: float('inf'))
        cluster_time_end = defaultdict(lambda: float('-inf'))
        cluster_indices = defaultdict(list)
        
        for i, label in enumerate(assignments):
            if label != -1:
                cluster_sizes[label] += 1
                cluster_indices[label].append(index_list[i])
                tr = self.long_edges[index_list[i]].get_time_range()
                cluster_time_start[label] = min(cluster_time_start[label], tr[0])
                cluster_time_end[label] = max(cluster_time_end[label], tr[1])
        
        # Build address index
        addr_rank = defaultdict(int)
        origin_indices = []
        cluster_sizes_list = []
        cluster_times = []
        origin_index_vec = []
        
        processed = set()
        for i, label in enumerate(assignments):
            if label == -1 or label in processed:
                continue
            processed.add(label)
            
            origin_indices.append(index_list[i])
            cluster_sizes_list.append(cluster_sizes[label])
            cluster_times.append(cluster_time_end[label] - cluster_time_start[label])
            origin_index_vec.append(cluster_indices[label])
            
            edge = self.long_edges[index_list[i]]
            src = edge.get_src_str()
            dst = edge.get_dst_str()
            addr_rank[src] += 1
            addr_rank[dst] += 1
        
        if not origin_indices:
            return
        
        # Simple loss calculation without Z3 (fallback)
        # For full functionality, Z3 solver would be used here
        for i, indices in enumerate(origin_index_vec):
            # Extract features for this group
            group_features = [self._extract_feature_long2(idx) for idx in indices]
            
            if not group_features:
                continue
            
            X_group = np.array(group_features)
            
            if len(group_features) >= self.val_K:
                scaler_group = MinMaxScaler()
                X_group_scaled = scaler_group.fit_transform(X_group)
                
                n_clusters = min(self.val_K, len(group_features))
                kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
                kmeans.fit(X_group_scaled)
                centroids = kmeans.cluster_centers_
                
                for j, idx in enumerate(indices):
                    min_dist = min(euclidean(X_group_scaled[j], c) for c in centroids)
                    loss = (self.al * min_dist +
                            self.bl * math.log2(cluster_sizes_list[i] + 1) -
                            self.cl * cluster_times[i])
                    self.long_edge_score[idx] = loss
            else:
                for idx in indices:
                    loss = (self.bl * math.log2(cluster_sizes_list[i] + 1) -
                            self.cl * cluster_times[i])
                    self.long_edge_score[idx] = loss
    
    def get_final_pkt_score(self, labels: List[bool]) -> List[float]:
        """
        Get final packet scores.
        
        Args:
            labels: Binary labels for each packet.
            
        Returns:
            List of anomaly scores for each packet.
        """
        start_time = time.time()
        
        num_packets = len(labels)
        self.pkt_score = [0.0] * num_packets
        
        # Assign scores from short edges
        for i, edge in enumerate(self.short_edges):
            score = self.short_edge_score[i]
            for flow in edge.flows:
                for idx in flow.reverse_index:
                    if idx < num_packets:
                        self.pkt_score[idx] = max(self.pkt_score[idx], score)
        
        # Assign scores from long edges
        for i, edge in enumerate(self.long_edges):
            score = self.long_edge_score[i]
            flow = edge.get_raw_flow()
            for idx in flow.reverse_index:
                if idx < num_packets:
                    self.pkt_score[idx] = max(self.pkt_score[idx], score)
        
        print(f"[TIMER] get_final_pkt_score: {time.time() - start_time:.6f}s")
        
        return self.pkt_score
    
    def dump_graph_statistic(self) -> None:
        """Print graph statistics."""
        print(f"[LOG] Graph Statistics:")
        print(f"  Short edges: {len(self.short_edges)}")
        print(f"  Long edges: {len(self.long_edges)}")
        print(f"  Short vertices: {len(self.vertex_set_short)}")
        print(f"  Long vertices: {len(self.vertex_set_long)}")
