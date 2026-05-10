# LLIoT

**SoK: Understanding the state of IoT-specific vulnerabilities via CVE characterization with LLIoT**

LLIoT is an LLM-assisted framework for systematically identifying and characterizing IoT-specific CVE vulnerabilities at scale. This repository contains the code and dataset accompanying our research paper.


LLIoT defines a 4-layer IoT ecosystem for consistent CVE classification:

| Layer | Description | Examples |
|-------|-------------|----------|
| **Device** | Physical IoT devices with internet connectivity, limited resources | Smart thermostats, IP cameras, smart TVs, Amazon Echo |
| **Communication** | IoT-specific protocols for data transfer | ZigBee, BLE, MQTT, CoAP, LoRaWAN, 6LoWPAN |
| **Application** | Mobile apps and orchestration platforms | Home Assistant, SmartThings, IFTTT, OpenHAB |
| **Cloud** | Remote IoT-specific cloud services | AWS IoT, Azure IoT, Google Cloud IoT |

### Classification Rules

- **IoT-specific CVE:** Affects technologies purpose-built for IoT where the deployment context is IoT
- **Non-IoT CVE:** General-purpose hardware/software (smartphones, computers, routers)


### Dataset Statistics (2013–2024)

| Metric | Value |
|--------|-------|
| Total CVEs analyzed | 211,182 |
| IoT-specific CVEs | 15,116 |
| Non-IoT CVEs | 196,066 |
| Newly identified (vs prior datasets) | 8,368 |

---

## Citation

If you use this code or dataset in your research, please cite:

```bibtex
@inproceedings{rezaei2025lliot,
  title={SoK: Understanding the state of IoT-specific vulnerabilities via CVE characterization with LLIoT},
  author={Rezaei, Tina and Bayhan, Suzan and Continella, Andrea and van der Ham-de Vos, Jeroen and van Rijswijk-Deij, Roland},
  booktitle={2026 IEEE 11th European Symposium on Security and Privacy (EuroS\&P)},
  year={2026},
  organization={IEEE}
}
```


## Requirements

- Linux (developed and tested)
- Python 3.7+
- Docker & Docker Compose
- PostgreSQL (via Docker)

### Configuration
Copy `env.example` to `.env` and update credentials if preferred.

### Database Setup & dataset restore
```bash
# Start the PostgreSQL database and restore data dump
sudo docker compose up -d
# Wait until dump restore is completed. You can check with `sudo docker compose logs`. You can 
```

# Installation
```bash
# Make a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

## Repository Structure

This repository is organized into three main components, each corresponding to a phase of the study as described in the paper methodology.

```
LLIoT/
├── expert_review/          # Phase 1: Expert Review & LLM Validation
├── dataset_benchmark/      # Phase 2: Dataset Assessment
├── characterization/       # Phase 3: Vulnerability Characterization
├── cve_data_collcetion/    # CVE data collection, and labelling
├── initdb/                 # Database initialization scripts
└── docker-compose.yml      # PostgreSQL container setup
```

---

## Phase 1: Expert Review and LLM Classification

**Goal:** Establish ground-truth labels and validate LLM classification performance.

### Directory: `expert_review/`

| Subdirectory | Description |
|--------------|-------------|
| `sampling_CVEs/` | Dictionary-based CVE sampling using IoT-specific keywords across 4 layers (device, communication, application, cloud) |
| `manual_review/` | Scripts for aggregating expert reviews, calculating inter-rater agreement (Krippendorff's α), and applying tie-breaker decisions |
| `LLM_classification/` | LLM-based classification using Ollama (supports GPT-4o, O3, Deepseek-r1, Llama4-scout) |
| `llm_human_analysis/` | Conflict resolution between human and LLM labels, accuracy evaluation |

### Key Scripts

```bash
# Sample CVEs using IoT keyword dictionaries
python expert_review/sampling_CVEs/dictionary_based_sampling.py

# Run LLM classification (requires Ollama)
python expert_review/LLM_classification/classification.py <model-name> <prompt-file>

# Evaluate LLM accuracy against ground truth
python expert_review/LLM_classification/llm_evaluation.py

# Calculate inter-rater agreement
python expert_review/manual_review/inter_rater_agreement.py

# Resolve human-LLM conflicts
python expert_review/llm_human_analysis/find_LLM_human_conflicts.py
```

---

## Phase 2: Dataset Assessment

Benchmark LLIoT against existing IoT CVE datasets and validate label consistency.

### Directory: `dataset_benchmark/`

| File | Description |
|------|-------------|
| `dataset_comparison.py` | Compare LLIoT with VarIoT and Chen et al. datasets, generate Venn diagrams |
| `consistency_analysis.py` | Measure LLM labeling consistency (unanimity rate, maximum-class agreement) |
| `dl_VarIoT.py` | Download and parse VarIoT dataset |
| `API_batch/` | Batch processing scripts for OpenAI API |

### Key Scripts

```bash
# Compare datasets and generate overlap analysis
python dataset_benchmark/dataset_comparison.py

# Analyze LLM consistency across multiple runs
python dataset_benchmark/consistency_analysis.py
```


## Phase 3: Vulnerability Characterization

Analyze how IoT vulnerabilities differ from traditional IT vulnerabilities.

### Directory: `characterization/`

### Scripts

```bash
# Generate temporal distribution plots
python characterization/IoT_vs_nonIoT_histogram.py

# Analyze CVSS severity distributions
python characterization/CVSS_analysis.py

# Analyze CWE weakness trends
python characterization/CWE_analysis.py
```


## Data Collection

### Directory: `data_collcetion/`

Django-based application for fetching CVE data from NVD and CVE.org APIs in case you want to update the dataset and run the LLM classification. 



```bash
cd /path/to/LLIoT/cve_data_collection

# Fetch CVEs from NVD (start_year and end_year are required)
python3 data_collcetion/manage.py fetch_cves 2013 2024

# Classify CVEs with an LLM (requires DB data and API keys in .env)
python3 data_collcetion/manage.py classify_cves 2013 2024 o3 prompt_v20.txt
```

---

