# Threat Intelligence Pipeline (TIP)

## 🎯 Overview

The Threat Intelligence Pipeline (TIP) is an enterprise-grade vulnerability analysis system that automatically retrieves, processes, and correlates Common Vulnerabilities and Exposures (CVEs) with their corresponding Common Weakness Enumeration (CWE), Common Attack Pattern Enumeration and Classification (CAPEC), and MITRE ATT&CK & D3FEND techniques.

## 🚀 Key Features

- **Enterprise Performance**: Connection pooling, advanced caching, parallel processing
- **Robust Error Handling**: Custom exceptions, retry strategies, automatic recovery
- **Comprehensive Monitoring**: Real-time metrics, health checks, detailed reporting
- **Flexible Configuration**: JSON-based config, environment variables, multiple execution modes
- **Single Command Operation**: Run entire pipeline with one command

---

## 📦 Installation

**Prerequisites:** Python 3.8+ and NVD API key (recommended)

```bash
git clone https://github.com/NullSpace-BitCradle/Threat_Intelligence_Pipeline.git
cd Threat_Intelligence_Pipeline
pip install -r requirements.txt
python setup.py
```

---

## 🎯 Quick Start

```bash
# Run complete pipeline
python tip.py

# Check system status
python tip.py --status

# Advanced options
python tip.py --force        # Force update
python tip.py --db-only      # Database updates only
python tip.py --cve-only     # CVE processing only
python tip.py --verbose      # Verbose logging
```

---

## 🔧 Scheduling

**Linux/Mac (Cron):**

```bash
# Daily updates at 2 AM
0 2 * * * cd /path/to/Threat_Intelligence_Pipeline && python tip.py
```

**Windows (Task Scheduler):**

- Create a task to run `python tip.py` daily
- Set working directory to Threat_Intelligence_Pipeline folder

---

## 🔑 NVD API Key Setup

**Required for optimal performance** - without it, you'll hit rate limits quickly.

1. Get your API key: [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Set as environment variable:

```bash
# Linux/Mac
export NVD_API_KEY="your-api-key-here"

# Windows
set NVD_API_KEY=your-api-key-here

# Or create .env file
echo NVD_API_KEY=your-api-key-here > .env
```

---

## 📊 System Status

```bash
python tip.py --status
```

Shows database status, last update time, and pipeline readiness.

---

## 🏗️ Architecture

**Core Components:**

- **CVE Processor**: Handles CVE → CWE → CAPEC → Techniques → D3FEND mapping
- **Database Manager**: Downloads and processes CAPEC, CWE, Techniques, D3FEND data
- **Pipeline Orchestrator**: Manages pipeline execution and monitoring
- **Performance Optimizer**: HTTP session management, caching, thread pooling
- **Error Handler**: Custom exceptions, structured logging, recovery strategies

**Data Flow:** Database Updates → CVE Retrieval → CVE Processing → Output Generation

---

## 🔧 Configuration

**Main config:** `config.json` - API settings, database URLs, processing parameters, logging

**Environment Variables:**

- `NVD_API_KEY`: Your NVD API key for optimal performance
- `LOG_LEVEL`: Override logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

---

## 📁 Project Structure

```text
Threat_Intelligence_Pipeline/
├── tip.py                    # 🎯 Main entry point
├── setup.py                  # 🛠️ Setup script for initialization
├── pipeline_orchestrator.py  # 🎭 Unified orchestration
├── cve_processor.py          # ⚙️ Unified CVE processing
├── database_manager.py       # 🗄️ Unified database management
├── config.py                 # ⚙️ Configuration management
├── config.json               # 📋 Configuration file
├── database_optimizer.py     # 🚀 Database optimization
├── performance_optimizer.py  # ⚡ Performance optimization
├── error_handler.py          # 🛡️ Error handling
├── error_recovery.py         # 🔄 Error recovery
├── validation.py             # ✅ Data validation
├── requirements.txt          # 📦 Dependencies
├── LICENSE                   # 📄 License
├── lastUpdate.txt            # 🕒 Last update timestamp (generated)
├── database/                 # 📊 CVE database files
│   ├── CVE-1999.jsonl
│   ├── CVE-2000.jsonl
│   └── ... (all years)
├── resources/                # 🗃️ Database resources
│   ├── capec_db.json
│   ├── cwe_db.json
│   ├── techniques_db.json
│   └── defend_db.jsonl
├── results/                  # 📈 Results and summaries
│   ├── new_cves.jsonl
│   └── update_summary.json
├── logs/                     # 📝 Log files
│   ├── tip.log
│   └── tip_errors.json
└── docs/                     # 🌐 Web interface
    ├── index.html
    ├── css/
    ├── js/
    └── mitre/
```

---

## 🌐 Web Interface

Interactive MITRE ATT&CK and D3FEND matrix visualization:

```bash
python setup.py                    # Run setup (if not done)
python -m http.server 8000         # Start server
# Open http://localhost:8000/docs/index.html
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Original Author**: [Galeax](https://github.com/Galeax) for the initial design and implementation of the Threat Intelligence Pipeline
- **NVD (National Vulnerability Database)** for providing CVE data
- **MITRE Corporation** for CAPEC, CWE, and ATT&CK frameworks
- **D3FEND** for defensive countermeasure mappings
- **Open source community** for the excellent tools and libraries

---

**🎉 Threat Intelligence Pipeline - Simplifying vulnerability analysis with enterprise-grade performance and reliability!**
