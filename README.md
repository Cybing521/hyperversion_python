# HyperVision

A demo of the flow interaction graph based attack traffic detection system, i.e., HyperVision:

___Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow Interaction Graph Analysis___  
In the $30^{th}$ Network and Distributed System Security Symposium ([NDSS'23](https://www.ndss-symposium.org/ndss-paper/detecting-unknown-encrypted-malicious-traffic-in-real-time-via-flow-interaction-graph-analysis/)).  
[Chuanpu Fu](https://www.fuchuanpu.cn), [Qi Li](https://sites.google.com/site/qili2012), and [Ke Xu](http://www.thucsnet.org/xuke.html).  

---

## 🔄 Reproduction Source

This repository is a **reproduction/port** of the original HyperVision implementation.

| Item | Information |
|------|-------------|
| **Original Repository** | [https://github.com/fuchuanpu/HyperVision](https://github.com/fuchuanpu/HyperVision) |
| **Original Authors** | Chuanpu Fu, Qi Li, Ke Xu (Tsinghua University) |
| **Paper** | [NDSS'23](https://www.ndss-symposium.org/ndss-paper/detecting-unknown-encrypted-malicious-traffic-in-real-time-via-flow-interaction-graph-analysis/) |
| **This Port** | Includes both C++ (original) and Python implementations |

---

## 📦 Implementations

This repository contains **two implementations**:

### 1. C++ Implementation (Original)

The original high-performance implementation using:
- PcapPlusPlus for packet parsing
- mlpack for machine learning
- Z3 for SMT solving

See the [C++ Usage](#0x01-software-c) section below.

### 2. Python Implementation (New)

A Python port for easier experimentation and integration:
- scapy for packet parsing
- scikit-learn for machine learning
- Pure Python with numpy

**Quick start:**

```bash
cd python
pip install -r requirements.txt
python main.py --config ../configuration/lrscan/http_lrscan.json
```

See [`python/README.md`](python/README.md) for detailed documentation.

---

## __0x00__ Hardware
- AWS EC2 c4.4xlarge, 100GB SSD, canonical `Ubuntu` 22.04 LTS (amd64, 3/3/2023).
- Tencent Cloud CVM, _with similar OS and hardware configurations_.

## __0x01__ Software (C++)

The demo can be built from a clean `Ubuntu` env.

```bash
# Establish env.
git clone https://github.com/fuchuanpu/HyperVision.git
cd HyperVision
sudo ./env/install_all.sh

# Download dataset.
wget https://www.hypervision.fuchuanpu.xyz/hypervision-dataset.tar.gz
tar -xvf hypervision-dataset.tar.gz
rm $_

# Build and run HyperVision.
./script/rebuild.sh
./script/expand.sh
cd build && ../script/run_all_brute.sh && cd ..

# Analyze the results.
cd ./result_analyze
./batch_analyzer.py -g brute
cat ./log/brute/*.log | grep AU_ROC
cd -
```

## __0x02__ Python Implementation

```bash
# Navigate to Python implementation
cd python

# Install dependencies
pip install -r requirements.txt

# Run with configuration
python main.py --config ../configuration/lrscan/http_lrscan.json
```

For more details, see [`python/README.md`](python/README.md).

## __0x03__ Reference

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

## License

GPL-3.0 License - See [LICENSE](LICENSE) for details.
