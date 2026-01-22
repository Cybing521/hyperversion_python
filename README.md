# HyperVision

基于流交互图的攻击流量检测系统演示项目。

___Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow Interaction Graph Analysis___  
发表于第 30 届网络与分布式系统安全研讨会 ([NDSS'23](https://www.ndss-symposium.org/ndss-paper/detecting-unknown-encrypted-malicious-traffic-in-real-time-via-flow-interaction-graph-analysis/))  
作者: [Chuanpu Fu](https://www.fuchuanpu.cn), [Qi Li](https://sites.google.com/site/qili2012), [Ke Xu](http://www.thucsnet.org/xuke.html) (清华大学)

---

## 🔄 复现来源

本仓库是原版 HyperVision 的 **复现/移植** 版本。

| 项目 | 信息 |
|------|------|
| **原始仓库** | [https://github.com/fuchuanpu/HyperVision](https://github.com/fuchuanpu/HyperVision) |
| **原作者** | Chuanpu Fu, Qi Li, Ke Xu (清华大学) |
| **论文** | [NDSS'23](https://www.ndss-symposium.org/ndss-paper/detecting-unknown-encrypted-malicious-traffic-in-real-time-via-flow-interaction-graph-analysis/) |
| **本仓库** | 包含 C++ (原版) 和 Python (新增) 两种实现 |

---

## 📦 实现版本

本仓库包含 **两种实现**：

### 1. C++ 实现 (原版)

高性能原版实现，使用：
- PcapPlusPlus 进行数据包解析
- mlpack 进行机器学习
- Z3 进行 SMT 求解

详见下方 [C++ 使用方法](#0x01-软件环境-c)。

### 2. Python 实现 (新增)

Python 移植版本，便于实验和集成：
- scapy 进行数据包解析
- scikit-learn 进行机器学习
- 纯 Python + numpy 实现

**快速开始：**

```bash
cd python
pip install -r requirements.txt
python main.py --config ../configuration/lrscan/http_lrscan.json
```

详见 [`python/README.md`](python/README.md)。

---

## __0x00__ 硬件要求

- AWS EC2 c4.4xlarge, 100GB SSD, `Ubuntu` 22.04 LTS (amd64)
- 腾讯云 CVM，_类似的系统和硬件配置_

## __0x01__ 软件环境 (C++)

可在干净的 `Ubuntu` 环境下构建。

```bash
# 建立环境
git clone https://github.com/fuchuanpu/HyperVision.git
cd HyperVision
sudo ./env/install_all.sh

# 下载数据集
wget https://www.hypervision.fuchuanpu.xyz/hypervision-dataset.tar.gz
tar -xvf hypervision-dataset.tar.gz
rm $_

# 构建并运行 HyperVision
./script/rebuild.sh
./script/expand.sh
cd build && ../script/run_all_brute.sh && cd ..

# 分析结果
cd ./result_analyze
./batch_analyzer.py -g brute
cat ./log/brute/*.log | grep AU_ROC
cd -
```

## __0x02__ Python 实现

```bash
# 进入 Python 实现目录
cd python

# 安装依赖
pip install -r requirements.txt

# 运行
python main.py --config ../configuration/lrscan/http_lrscan.json
```

详见 [`python/README.md`](python/README.md)。

## __0x03__ 引用

如果您在研究中使用了本代码，请引用原论文：

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

## 许可证

GPL-3.0 许可证 - 详见 [LICENSE](LICENSE)。
