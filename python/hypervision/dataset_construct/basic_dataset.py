"""
Basic dataset construction.
Corresponds to basic_dataset.cpp/hpp in the C++ implementation.
"""

import time
from typing import List, Dict, Set, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor

from ..packet_parse.packet_basic import BasicPacket, BasicPacket4, BasicPacket6, BasicPacketBad
from ..packet_parse.packet_info import ip_to_str, str_to_ip4, str_to_ip6


class BasicDataset:
    """Dataset constructor for attack labeling."""
    
    def __init__(self, parse_result: Optional[List[BasicPacket]] = None):
        """
        Initialize dataset constructor.
        
        Args:
            parse_result: List of parsed packets.
        """
        self.parse_result = parse_result
        self.parse_train: List[BasicPacket] = []
        self.parse_test: List[BasicPacket] = []
        self.train_ratio = 0.25
        
        self.labels: List[bool] = []
        self.attack_time_after = 0.0
        
        self.attacker_src4: List[str] = []
        self.attacker_src6: List[str] = []
        self.attacker_dst4: List[str] = []
        self.attacker_dst6: List[str] = []
        self.attacker_srcdst4: List[Tuple[str, str]] = []
        self.attacker_srcdst6: List[Tuple[str, str]] = []
        
        self.export_data_path = ""
        self.export_label_path = ""
        self.load_data_path = ""
        self.load_label_path = ""
    
    def configure_via_json(self, config: dict) -> None:
        """Configure from JSON."""
        if 'train_ratio' in config:
            self.train_ratio = float(config['train_ratio'])
        if 'attack_time_after' in config:
            self.attack_time_after = float(config['attack_time_after'])
        
        if 'attacker_src4' in config:
            self.attacker_src4 = list(config['attacker_src4'])
        if 'attacker_src6' in config:
            self.attacker_src6 = list(config['attacker_src6'])
        if 'attacker_dst4' in config:
            self.attacker_dst4 = list(config['attacker_dst4'])
        if 'attacker_dst6' in config:
            self.attacker_dst6 = list(config['attacker_dst6'])
        if 'attacker_srcdst4' in config:
            self.attacker_srcdst4 = [(p[0], p[1]) for p in config['attacker_srcdst4']]
        if 'attacker_srcdst6' in config:
            self.attacker_srcdst6 = [(p[0], p[1]) for p in config['attacker_srcdst6']]
        
        if 'export_data_path' in config:
            self.export_data_path = str(config['export_data_path'])
        if 'export_label_path' in config:
            self.export_label_path = str(config['export_label_path'])
        if 'data_path' in config:
            self.load_data_path = str(config['data_path'])
        if 'label_path' in config:
            self.load_label_path = str(config['label_path'])
    
    def set_attacker_match_list(self, 
                                attacker_src4: List[str] = None,
                                attacker_src6: List[str] = None,
                                attacker_dst4: List[str] = None,
                                attacker_dst6: List[str] = None,
                                attacker_srcdst4: List[Tuple[str, str]] = None,
                                attacker_srcdst6: List[Tuple[str, str]] = None) -> None:
        """Set attacker match lists."""
        if attacker_src4:
            self.attacker_src4 = attacker_src4
        if attacker_src6:
            self.attacker_src6 = attacker_src6
        if attacker_dst4:
            self.attacker_dst4 = attacker_dst4
        if attacker_dst6:
            self.attacker_dst6 = attacker_dst6
        if attacker_srcdst4:
            self.attacker_srcdst4 = attacker_srcdst4
        if attacker_srcdst6:
            self.attacker_srcdst6 = attacker_srcdst6
    
    def do_dataset_construct(self) -> None:
        """Construct dataset with labels."""
        start_time = time.time()
        
        if self.parse_result is None:
            raise RuntimeError("Parse result not provided.")
        
        # Convert attacker addresses to sets for fast lookup
        src4_set = set(self.attacker_src4)
        dst4_set = set(self.attacker_dst4)
        srcdst4_set = set(self.attacker_srcdst4)
        
        src6_set = set(self.attacker_src6)
        dst6_set = set(self.attacker_dst6)
        srcdst6_set = set(self.attacker_srcdst6)
        
        # Get start time for attack_time_after filtering
        min_time = float('inf')
        for pkt in self.parse_result:
            if not isinstance(pkt, BasicPacketBad):
                min_time = min(min_time, pkt.ts)
        
        attack_start = min_time + self.attack_time_after
        
        # Label packets
        self.labels = []
        attack_count = 0
        
        for pkt in self.parse_result:
            is_attack = False
            
            if isinstance(pkt, BasicPacketBad):
                is_attack = False
            elif pkt.ts < attack_start:
                is_attack = False
            elif isinstance(pkt, BasicPacket4):
                src = ip_to_str(pkt.flow_id.src_ip, is_ipv6=False)
                dst = ip_to_str(pkt.flow_id.dst_ip, is_ipv6=False)
                
                if src in src4_set:
                    is_attack = True
                elif dst in dst4_set:
                    is_attack = True
                elif (src, dst) in srcdst4_set:
                    is_attack = True
                    
            elif isinstance(pkt, BasicPacket6):
                src = ip_to_str(pkt.flow_id.src_ip, is_ipv6=True)
                dst = ip_to_str(pkt.flow_id.dst_ip, is_ipv6=True)
                
                if src in src6_set:
                    is_attack = True
                elif dst in dst6_set:
                    is_attack = True
                elif (src, dst) in srcdst6_set:
                    is_attack = True
            
            self.labels.append(is_attack)
            if is_attack:
                attack_count += 1
        
        print(f"[LOG] Dataset constructed: {len(self.labels)} packets, {attack_count} attacks")
        print(f"[TIMER] do_dataset_construct: {time.time() - start_time:.6f}s")
    
    def import_dataset(self) -> None:
        """Import dataset from files."""
        start_time = time.time()
        
        # Load packet data
        with open(self.load_data_path, 'r') as f:
            lines = f.readlines()
        
        self.parse_result = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line[0] == '4':
                pkt = BasicPacket4.from_string(line)
                self.parse_result.append(pkt)
            elif line[0] == '6':
                pkt = BasicPacket6.from_string(line)
                self.parse_result.append(pkt)
            else:
                self.parse_result.append(BasicPacketBad())
        
        # Load labels
        with open(self.load_label_path, 'r') as f:
            label_str = f.read().strip()
        
        self.labels = [c == '1' for c in label_str]
        
        assert len(self.labels) == len(self.parse_result), \
            f"Label count {len(self.labels)} != packet count {len(self.parse_result)}"
        
        print(f"[LOG] Imported {len(self.parse_result)} packets, {sum(self.labels)} attacks")
        print(f"[TIMER] import_dataset: {time.time() - start_time:.6f}s")
    
    def get_train_test_dataset(self) -> Tuple[List[BasicPacket], List[BasicPacket]]:
        """Get train and test datasets."""
        return (self.parse_train, self.parse_test)
    
    def get_label(self) -> List[bool]:
        """Get labels."""
        return self.labels
    
    def get_raw_pkt(self) -> List[BasicPacket]:
        """Get raw packets."""
        return self.parse_result
