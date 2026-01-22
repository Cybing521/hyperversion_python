# HyperVision Python Implementation

This is a **Python port** of the HyperVision system, originally implemented in C++.

## Original Work

This implementation is based on the research paper and code from:

> **Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow Interaction Graph Analysis**
> 
> - **Authors**: Chuanpu Fu, Qi Li, Ke Xu (Tsinghua University)
> - **Conference**: 30th Network and Distributed System Security Symposium (NDSS'23)
> - **Paper**: [NDSS'23 Paper Link](https://www.ndss-symposium.org/ndss-paper/detecting-unknown-encrypted-malicious-traffic-in-real-time-via-flow-interaction-graph-analysis/)
> - **Original C++ Repository**: [https://github.com/fuchuanpu/HyperVision](https://github.com/fuchuanpu/HyperVision)

## Citation

If you use this code in your research, please cite the original paper:

```bibtex
@inproceedings{NDSS23-HyperVision,
  author    = {Chuanpu Fu and Qi Li and Ke Xu},
  title     = {Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow 
               Interaction Graph Analysis},
  booktitle = {NDSS},
  publisher = {ISOC},
  year      = {2023}
}
```

## Installation

### Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`

### Setup

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python main.py --config <path_to_config.json>
```

### Example

```bash
# Using configuration from parent directory
python main.py --config ../configuration/lrscan/http_lrscan.json
```

### Programmatic Usage

```python
import json
from hypervision import HypervisionDetector

# Load configuration
with open('config.json', 'r') as f:
    config = json.load(f)

# Create and run detector
detector = HypervisionDetector()
detector.config_via_json(config)
detector.start()

# Get results
labels, scores = detector.get_results()
```

## Project Structure

```
python/
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── hypervision/           # Main package
    ├── __init__.py
    ├── detector.py        # Main detector class
    ├── packet_parse/      # PCAP parsing module
    │   ├── __init__.py
    │   ├── packet_info.py
    │   ├── packet_basic.py
    │   └── pcap_parser.py
    ├── flow_construct/    # Flow construction module
    │   ├── __init__.py
    │   ├── flow_define.py
    │   └── explicit_constructor.py
    ├── graph_analyze/     # Graph analysis module
    │   ├── __init__.py
    │   ├── edge_define.py
    │   ├── edge_constructor.py
    │   └── graph_define.py
    └── dataset_construct/ # Dataset construction module
        ├── __init__.py
        └── basic_dataset.py
```

## Configuration

The configuration JSON file should contain the following sections:

```json
{
  "packet_parse": {
    "target_file_path": "path/to/pcap/file.pcap"
  },
  "dataset_construct": {
    "train_ratio": 0.25,
    "attack_time_after": 0.0,
    "attacker_src4": ["10.0.0.1"],
    "attacker_dst4": ["192.168.1.1"]
  },
  "flow_construct": {
    "flow_time_out": 64.0,
    "evict_flow_time_out": 256.0
  },
  "edge_construct": {
    "length_bin_size": 50,
    "edge_long_line": 10,
    "edge_agg_line": 2
  },
  "graph_analyze": {
    "proto_cluster": true,
    "val_K": 10,
    "al": 0.1,
    "bl": 1.0,
    "cl": 0.5,
    "as": 0.1,
    "bs": 1.0,
    "cs": 0.5
  },
  "result_save": {
    "save_result_enable": true,
    "save_result_path": "./results.txt"
  }
}
```

## Differences from C++ Implementation

1. **Performance**: The Python implementation is significantly slower than C++ due to:
   - Interpreted language overhead
   - Single-threaded packet parsing (C++ uses multi-threading)
   - Python's GIL limiting parallelism

2. **Dependencies**: 
   - Uses `scapy` instead of PcapPlusPlus for packet parsing
   - Uses `scikit-learn` instead of mlpack for clustering
   - Uses `numpy` instead of Armadillo for matrix operations

3. **Z3 Solver**: The Z3-based optimization in long edge processing is simplified in this version.

## License

This Python port follows the same GPL-3.0 license as the original C++ implementation.

## Acknowledgments

- Original authors: Chuanpu Fu, Qi Li, Ke Xu
- Original repository: [fuchuanpu/HyperVision](https://github.com/fuchuanpu/HyperVision)
