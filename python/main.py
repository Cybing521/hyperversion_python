#!/usr/bin/env python3
"""
HyperVision - Flow Interaction Graph based Attack Traffic Detection

This is a Python implementation of HyperVision, originally published in NDSS'23:
"Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow Interaction Graph Analysis"

Original C++ implementation: https://github.com/fuchuanpu/HyperVision
Authors: Chuanpu Fu, Qi Li, Ke Xu (Tsinghua University)

Usage:
    python main.py --config <config_file.json>
"""

import argparse
import json
import sys
from pathlib import Path

from hypervision import HypervisionDetector


def main():
    parser = argparse.ArgumentParser(
        description='HyperVision - Flow Interaction Graph based Attack Detection'
    )
    parser.add_argument(
        '--config', '-c',
        type=str,
        default='../configuration/lrscan/http_lrscan.json',
        help='Configuration file path (JSON format)'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[ERROR] Configuration file not found: {config_path}")
        sys.exit(1)
    
    print(f"[LOG] Loading configuration from: {config_path}")
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Create and run detector
    detector = HypervisionDetector()
    detector.config_via_json(config)
    detector.start()
    
    # Get results
    labels, scores = detector.get_results()
    
    if labels and scores:
        # Calculate basic metrics
        total = len(labels)
        attacks = sum(labels)
        benign = total - attacks
        
        print("\n" + "=" * 50)
        print("Detection Results Summary")
        print("=" * 50)
        print(f"Total packets:  {total}")
        print(f"Attack packets: {attacks} ({100*attacks/total:.2f}%)")
        print(f"Benign packets: {benign} ({100*benign/total:.2f}%)")
        
        # Score statistics
        if scores:
            attack_scores = [s for l, s in zip(labels, scores) if l]
            benign_scores = [s for l, s in zip(labels, scores) if not l]
            
            if attack_scores:
                print(f"\nAttack score - min: {min(attack_scores):.4f}, "
                      f"max: {max(attack_scores):.4f}, "
                      f"avg: {sum(attack_scores)/len(attack_scores):.4f}")
            if benign_scores:
                print(f"Benign score - min: {min(benign_scores):.4f}, "
                      f"max: {max(benign_scores):.4f}, "
                      f"avg: {sum(benign_scores)/len(benign_scores):.4f}")
        
        print("=" * 50)


if __name__ == '__main__':
    main()
