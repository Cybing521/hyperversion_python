"""
Main HyperVision detector.
Corresponds to detector_main.hpp in the C++ implementation.
"""

import time
import json
from typing import List, Optional, Tuple

from .packet_parse import PcapParser, BasicPacket
from .flow_construct import ExplicitFlowConstructor, BasicFlow
from .graph_analyze import EdgeConstructor, TrafficGraph, ShortEdge, LongEdge
from .dataset_construct import BasicDataset


class HypervisionDetector:
    """
    Main HyperVision detector class.
    
    This implements the flow interaction graph based attack traffic detection
    as described in the NDSS'23 paper.
    """
    
    def __init__(self):
        """Initialize detector."""
        self.config = {}
        self.file_path = ""
        
        self.parse_result: Optional[List[BasicPacket]] = None
        self.labels: Optional[List[bool]] = None
        self.loss: Optional[List[float]] = None
        self.flows: Optional[List[BasicFlow]] = None
        self.short_edges: Optional[List[ShortEdge]] = None
        self.long_edges: Optional[List[LongEdge]] = None
        
        self.save_result_enable = False
        self.save_result_path = "../temp/default.json"
    
    def config_via_json(self, config: dict) -> None:
        """
        Configure detector from JSON.
        
        Args:
            config: Configuration dictionary.
        """
        required_keys = ['dataset_construct', 'flow_construct', 'edge_construct', 
                        'graph_analyze', 'result_save']
        
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required configuration key: {key}")
        
        self.config = config
        
        save_config = config.get('result_save', {})
        if 'save_result_enable' in save_config:
            self.save_result_enable = bool(save_config['save_result_enable'])
        if 'save_result_path' in save_config:
            self.save_result_path = str(save_config['save_result_path'])
    
    def start(self) -> None:
        """Start the detection process."""
        start_time = time.time()
        
        # Step 1: Parse packets or load dataset
        if ('packet_parse' in self.config and 
            'target_file_path' in self.config['packet_parse']):
            
            print("[LOG] Parse packet from file.")
            self.file_path = self.config['packet_parse']['target_file_path']
            
            parser = PcapParser(self.file_path)
            parser.parse_raw_packet()
            parser.parse_basic_packet_fast()
            self.parse_result = parser.get_basic_packet_rep()
            
            print("[LOG] Split datasets.")
            dataset = BasicDataset(self.parse_result)
            dataset.configure_via_json(self.config['dataset_construct'])
            dataset.do_dataset_construct()
            self.labels = dataset.get_label()
            
        elif ('data_path' in self.config.get('dataset_construct', {}) and
              'label_path' in self.config.get('dataset_construct', {})):
            
            print("[LOG] Load & split datasets.")
            dataset = BasicDataset()
            dataset.configure_via_json(self.config['dataset_construct'])
            dataset.import_dataset()
            self.labels = dataset.get_label()
            self.parse_result = dataset.get_raw_pkt()
        else:
            print("[LOG] Dataset not found.")
            return
        
        # Step 2: Construct flows
        print("[LOG] Construct flow.")
        flow_constructor = ExplicitFlowConstructor(self.parse_result)
        flow_constructor.config_via_json(self.config['flow_construct'])
        flow_constructor.construct_flow()
        self.flows = flow_constructor.get_constructed_raw_flow()
        
        # Step 3: Construct edges
        print("[LOG] Construct edge.")
        edge_constructor = EdgeConstructor(self.flows)
        edge_constructor.config_via_json(self.config['edge_construct'])
        edge_constructor.do_construct()
        self.short_edges, self.long_edges = edge_constructor.get_edge()
        
        # Step 4: Construct and analyze graph
        print("[LOG] Construct Graph.")
        graph = TrafficGraph(self.short_edges, self.long_edges)
        graph.config_via_json(self.config['graph_analyze'])
        graph.parse_edge()
        graph.graph_detect()
        self.loss = graph.get_final_pkt_score(self.labels)
        
        # Step 5: Save results
        if self.save_result_enable:
            self.do_save(self.save_result_path)
        
        total_time = time.time() - start_time
        print(f"[TIMER] Total execution time: {total_time:.6f}s")
    
    def do_save(self, save_path: str) -> None:
        """
        Save detection results.
        
        Args:
            save_path: Path to save results.
        """
        start_time = time.time()
        
        with open(save_path, 'w') as f:
            for i in range(len(self.labels)):
                label = 1 if self.labels[i] else 0
                score = self.loss[i] if self.loss else 0.0
                f.write(f"{label} {score:.4f}\n")
        
        print(f"[LOG] Results saved to {save_path}")
        print(f"[TIMER] do_save: {time.time() - start_time:.6f}s")
    
    def get_results(self) -> Tuple[List[bool], List[float]]:
        """
        Get detection results.
        
        Returns:
            Tuple of (labels, scores).
        """
        return (self.labels, self.loss)
