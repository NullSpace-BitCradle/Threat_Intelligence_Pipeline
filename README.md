# Threat Intelligence Pipeline (TIP)

## 🎯 Overview

The Threat Intelligence Pipeline (TIP) is an enterprise-grade vulnerability analysis system that automatically retrieves, processes, and correlates Common Vulnerabilities and Exposures (CVEs) with their corresponding Common Weakness Enumeration (CWE), Common Attack Pattern Enumeration and Classification (CAPEC), and MITRE ATT&CK & D3FEND techniques. The system provides comprehensive threat intelligence mapping for security professionals, researchers, and organizations.

---

## 🚀 Features

### Enterprise-Grade Performance

- **Optimized HTTP Sessions**: Connection pooling and retry strategies
- **Advanced Caching**: LRU cache with TTL for improved performance
- **Parallel Processing**: Multi-threaded execution with configurable thread pools
- **Batch Processing**: Efficient handling of large datasets
- **Performance Monitoring**: Real-time metrics and profiling

### Robust Error Handling & Recovery

- **Custom Exception Classes**: Specialized error types for different failure scenarios
- **Retry Strategies**: Exponential backoff, circuit breaker patterns
- **Automatic Recovery**: Self-healing mechanisms for transient failures
- **Structured Logging**: Comprehensive logging with file rotation
- **Error Analytics**: Detailed error tracking and reporting

### Comprehensive Monitoring

- **Performance Metrics**: Execution time, throughput, and resource usage
- **Health Checks**: System status monitoring and alerting
- **Update Tracking**: Intelligent update detection and scheduling
- **Detailed Reporting**: JSON summaries and performance analytics

### Flexible Configuration

- **Centralized Config**: JSON-based configuration management
- **Environment Variables**: Secure API key management
- **Multiple Execution Modes**: Database-only, CVE-only, or full pipeline
- **Customizable Parameters**: Thread counts, batch sizes, timeouts

### Automated Orchestration

- **Single Command Updates**: Run entire pipeline with one command
- **Intelligent Scheduling**: Automatic update detection and execution
- **Sequential Processing**: Proper dependency management
- **Parallel Execution**: Optimized processing where possible

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- NVD API key (recommended for optimal performance)

### Quick Setup

```bash
git clone https://github.com/NullSpace-BitCradle/Threat_Intelligence_Pipeline.git
cd ThreatIntelligencePipeline
pip install -r requirements.txt
python setup.py
```

### Dependencies

The project uses minimal, well-maintained dependencies:

- `requests` - HTTP client with session management
- `pandas` - Data processing and analysis
- `tqdm` - Progress bars for long-running operations
- `numpy` - Numerical operations
- `openpyxl` - Excel file processing

---

## 🎯 Quick Start

### One-Command Setup (Recommended)

```bash
# Run complete pipeline with one command
python tip.py

# Check system status
python tip.py --status
```

This single command will:

1. ✅ Create necessary directories and placeholder files
2. ✅ Update all databases (CAPEC, CWE, Techniques, D3FEND)
3. ✅ Retrieve new CVEs from NVD
4. ✅ Process CVE → CWE → CAPEC → Techniques → D3FEND mappings
5. ✅ Generate comprehensive reports and summaries
6. ✅ Update timestamps for intelligent scheduling

### Advanced Usage

```bash
# Force update even if not needed
python tip.py --force

# Run only database updates
python tip.py --db-only

# Run only CVE processing
python tip.py --cve-only

# Verbose logging
python tip.py --verbose
```

---

## 🔧 Usage

### Local Scheduling

**Linux/Mac (Cron):**

```bash
# Daily updates at 2 AM
0 2 * * * cd /path/to/ThreatIntelligencePipeline && python tip.py
```

**Windows (Task Scheduler):**

- Create a task to run `python tip.py` daily
- Set working directory to ThreatIntelligencePipeline folder

### Manual Execution

The system provides a single, unified command for all operations:

```bash
# Complete pipeline
python tip.py

# Specific operations
python tip.py --db-only      # Database updates only
python tip.py --cve-only     # CVE processing only
python tip.py --force        # Force update
```

---

## 🔑 NVD API Key Setup

This project requires an NVD API key for optimal performance. Without it, you'll hit rate limits quickly.

### Get Your API Key

1. Visit [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Fill out the form and wait for approval
3. Set your API key as an environment variable:

**Linux/Mac:**

```bash
export NVD_API_KEY="your-api-key-here"
```

**Windows:**

```cmd
set NVD_API_KEY=your-api-key-here
```

**Or create a `.env` file:**

```env
NVD_API_KEY=your-api-key-here
```

---

## 📊 System Status

Check your system status anytime:

```bash
python tip.py --status
```

**Example Output:**

```text
Threat Intelligence Pipeline Status:
========================================

Database Status:
  [OK] CAPEC: 559 entries (updated: 2025-09-01T20:26:41.170594)
  [OK] CWE: 968 entries (updated: 2025-09-01T20:26:44.130098)
  [OK] TECHNIQUES: 883 entries (updated: 2025-09-01T20:26:45.947109)
  [OK] DEFEND: Unknown entries (updated: Unknown)

Last Update: 2025-09-01T23:14:13.519527
Pipeline Ready: Yes
```

---

## 🏗️ Architecture

### Core Components

1. **CVE Processor** (`cve_processor.py`)
   - Unified CVE processing pipeline
   - Handles CVE → CWE → CAPEC → Techniques → D3FEND mapping
   - Advanced caching and thread pooling

2. **Database Manager** (`database_manager.py`)
   - Unified database operations
   - Downloads and processes CAPEC, CWE, Techniques, D3FEND data
   - Centralized database update logic

3. **Pipeline Orchestrator** (`pipeline_orchestrator.py`)
   - Streamlined pipeline management
   - Intelligent update detection
   - Performance monitoring and reporting

4. **Database Optimizer** (`database_optimizer.py`)
   - Efficient data storage and retrieval
   - Memory optimization for large datasets
   - Streaming processing for large files

5. **Performance Optimizer** (`performance_optimizer.py`)
   - HTTP session management with connection pooling
   - Advanced caching with LRU and TTL
   - Thread pool optimization
   - Performance monitoring and metrics

6. **Error Handler** (`error_handler.py`)
   - Custom exception classes
   - Structured logging with file rotation
   - Error categorization and severity levels
   - Real-time monitoring and alerting

7. **Error Recovery** (`error_recovery.py`)
   - Retry strategies (exponential backoff, circuit breaker)
   - Automatic recovery mechanisms
   - Fallback strategies for different failure types

### Data Flow

1. **Database Updates**: CAPEC → CWE → Techniques → D3FEND
2. **CVE Retrieval**: Fetch new CVEs from NVD API
3. **CVE Processing**: CVE → CWE → CAPEC → Techniques → D3FEND
4. **Output Generation**: JSONL files, summaries, and reports

---

## ⚡ Performance

### Optimization Features

- **Connection Pooling**: Reuse HTTP connections for better performance
- **Intelligent Caching**: LRU cache with configurable TTL
- **Parallel Processing**: Multi-threaded execution with optimal thread counts
- **Batch Processing**: Efficient handling of large datasets
- **Memory Management**: Streaming processing for large files

### Performance Metrics

- **Execution Time**: Tracked for each pipeline stage
- **Throughput**: Items processed per second
- **Resource Usage**: Memory and CPU utilization
- **Cache Performance**: Hit rates and efficiency
- **Error Rates**: Success/failure tracking

### Benchmarks

- **Database Updates**: ~70 seconds for all databases
- **CVE Processing**: ~1.6 seconds for typical daily updates
- **Full Pipeline**: ~90 seconds for complete update cycle
- **Memory Usage**: Optimized for large datasets with streaming

---

## 📈 Monitoring

### Real-time Monitoring

- **Console Output**: Live progress tracking with progress bars
- **Log Files**: Detailed logging with rotation (`logs/tip.log`)
- **JSON Reports**: Structured summaries (`results/update_summary.json`)
- **Performance Metrics**: Execution times and resource usage

### Health Checks

- **Update Status**: Success/failure tracking
- **Database Integrity**: Validation of data consistency
- **System Resources**: Memory and CPU monitoring
- **Error Rates**: Automatic alerting for high error rates

### Logging

- **Console Logging**: Real-time progress and status updates
- **File Logging**: Detailed logs with rotation (10MB max, 5 backups)
- **JSON Logging**: Structured error logs for analysis
- **Performance Logging**: Execution time and resource usage tracking

---

## 🛡️ Error Handling

### Error Categories

- **API Errors**: Network timeouts, rate limits, authentication failures
- **Data Errors**: Invalid JSON, missing fields, format issues
- **System Errors**: File I/O, memory issues, configuration problems
- **Processing Errors**: Data validation, transformation failures

### Recovery Strategies

- **Exponential Backoff**: Progressive delay increases for retries
- **Circuit Breaker**: Automatic failure detection and recovery
- **Fallback Mechanisms**: Alternative data sources and processing paths
- **Graceful Degradation**: Continue processing with partial data

### Error Reporting

- **Structured Logs**: JSON format for easy parsing and analysis
- **Error Analytics**: Categorization and trend analysis
- **Alert Thresholds**: Automatic notifications for critical errors
- **Recovery Tracking**: Success rates and recovery time metrics

---

## 🔧 Configuration

### Configuration File (`config.json`)

```json
{
  "api": {
    "nvd": {
      "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0/",
      "api_key_env": "NVD_API_KEY",
      "timeout": 30,
      "retry_limit": 3,
      "retry_delay": 5,
      "results_per_page": 2000
    }
  },
  "database": {
    "capec": {
      "url": "https://capec.mitre.org/data/xml/capec_latest.xml.zip",
      "file": "resources/capec_db.json"
    },
    "cwe": {
      "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
      "file": "resources/cwe_db.json"
    }
  },
  "processing": {
    "max_threads": 10,
    "batch_size": 1000,
    "enable_concurrent_processing": true,
    "cache_size": 1000,
    "cache_ttl": 3600
  },
  "logging": {
    "level": "INFO",
    "file": "logs/tip.log",
    "max_size": "10MB",
    "backup_count": 5
  }
}
```

### Environment Variables

- `NVD_API_KEY`: Your NVD API key for optimal performance
- `LOG_LEVEL`: Override logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

---

## 📁 Project Structure

```text
ThreatIntelligencePipeline/
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

The project includes a web interface for visualizing MITRE ATT&CK and D3FEND matrices:

1. **Run setup**: `python setup.py` (if not already done)
2. **Start server**: `python -m http.server 8000`
3. **Open browser**: Navigate to `http://localhost:8000/docs/index.html`
4. **View** interactive MITRE ATT&CK and D3FEND matrices
5. **Explore** CVE mappings and relationships
6. **Analyze** threat intelligence data

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
