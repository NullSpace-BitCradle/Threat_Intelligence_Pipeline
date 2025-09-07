# Threat Intelligence Pipeline (TIP)

## 🎯 Overview

The Threat Intelligence Pipeline (TIP) is an enterprise-grade vulnerability analysis system that automatically retrieves, processes, and correlates Common Vulnerabilities and Exposures (CVEs) with their corresponding Common Weakness Enumeration (CWE), Common Attack Pattern Enumeration and Classification (CAPEC), and MITRE ATT&CK & D3FEND techniques.

## 🚀 Key Features

- **Enterprise Performance**: Connection pooling, advanced caching, parallel processing
- **Robust Error Handling**: Custom exceptions, retry strategies, automatic recovery
- **Comprehensive Monitoring**: Real-time metrics, health checks, detailed reporting
- **API Rate Limiting**: Token bucket and sliding window rate limiters with adaptive backoff
- **Request Tracking**: Context-aware logging with request ID correlation
- **Health Monitoring**: System health checks with database, API, and resource monitoring
- **Prometheus Metrics**: Full metrics collection with counters, gauges, histograms, and summaries
- **Web Interface**: REST API for monitoring, control, and metrics export
- **Configuration Validation**: JSON schema validation with detailed error reporting
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

# Health monitoring
python tip.py --health-check
python tip.py --metrics

# Start web interface
python tip.py --web-interface

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

## 📊 System Status & Monitoring

### Command Line Monitoring
```bash
# System health check
python tip.py --health-check

# Show metrics
python tip.py --metrics

# Pipeline status
python tip.py --status
```

### Web Interface Monitoring
```bash
# Start web interface
python tip.py --web-interface --web-port 8080

# Access monitoring endpoints
curl http://localhost:8080/health      # Health status
curl http://localhost:8080/metrics     # Prometheus metrics
curl http://localhost:8080/status      # Pipeline status
curl http://localhost:8080/requests    # Request tracking
```

### Available Metrics
- **API Metrics**: Request counts, durations, success rates
- **Database Metrics**: Operation counts, performance, error rates
- **CVE Processing**: Processing times, success rates, throughput
- **System Metrics**: Memory usage, CPU, disk space
- **Error Metrics**: Error counts by category and severity
- **Cache Metrics**: Hit/miss ratios, performance

---

## 🏗️ Architecture

**Core Components:**

- **CVE Processor**: Handles CVE → CWE → CAPEC → Techniques → D3FEND mapping
- **Database Manager**: Downloads and processes CAPEC, CWE, Techniques, D3FEND data
- **Pipeline Orchestrator**: Manages pipeline execution and monitoring
- **Performance Optimizer**: HTTP session management, caching, thread pooling
- **Error Handler**: Custom exceptions, structured logging, recovery strategies
- **Rate Limiter**: API rate limiting with token bucket and sliding window algorithms
- **Health Checker**: System health monitoring and alerting
- **Request Tracker**: Request ID correlation and context-aware logging
- **Metrics Collector**: Prometheus-compatible metrics collection
- **Web Interface**: REST API for monitoring and control
- **Config Validator**: JSON schema validation for configuration

**Data Flow:** Database Updates → CVE Retrieval → CVE Processing → Output Generation

**Monitoring Flow:** Health Checks → Metrics Collection → Request Tracking → Web Interface

---

## 🔧 Configuration

**Main config:** `config.json` - API settings, database URLs, processing parameters, logging

**Configuration Validation:**
- JSON schema validation ensures configuration correctness
- Detailed error reporting for invalid configurations
- Automatic validation on startup

**Environment Variables:**

- `NVD_API_KEY`: Your NVD API key for optimal performance
- `LOG_LEVEL`: Override logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

**New Configuration Options:**
```json
{
  "processing": {
    "cache_size": 1000,
    "cache_ttl": 3600,
    "use_async_processing": false,
    "max_connections": 100,
    "connection_pool_size": 20
  },
  "error_handling": {
    "enable_circuit_breaker": true,
    "enable_retry": true,
    "enable_recovery": true,
    "alert_thresholds": {
      "critical": 1,
      "high": 5,
      "medium": 20,
      "low": 50
    }
  }
}
```

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
├── rate_limiter.py           # 🚦 API rate limiting
├── health_check.py           # 🏥 Health monitoring
├── request_tracker.py        # 📊 Request tracking
├── metrics.py                # 📈 Metrics collection
├── web_interface.py          # 🌐 Web API interface
├── config_validator.py       # ✅ Configuration validation
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

### Monitoring & Control API
```bash
# Start web interface
python tip.py --web-interface --web-port 8080

# Available endpoints
curl http://localhost:8080/health      # Health status
curl http://localhost:8080/metrics     # Prometheus metrics
curl http://localhost:8080/status      # Pipeline status
curl http://localhost:8080/requests    # Request tracking
curl http://localhost:8080/config      # Configuration info

# Control endpoints
curl -X POST http://localhost:8080/api/run              # Run pipeline
curl -X POST http://localhost:8080/api/update-databases # Update databases
curl -X POST http://localhost:8080/api/process-cves     # Process CVEs
```

### MITRE ATT&CK Visualization
```bash
python setup.py                    # Run setup (if not done)
python -m http.server 8000         # Start server
# Open http://localhost:8000/docs/index.html
```

---

## 🆕 Recent Enhancements

### Production-Ready Features
- **API Rate Limiting**: Prevents rate limit violations with token bucket and sliding window algorithms
- **Health Monitoring**: Comprehensive system health checks for database, API, and resource monitoring
- **Request Tracking**: Context-aware logging with request ID correlation for better debugging
- **Prometheus Metrics**: Full metrics collection system with counters, gauges, histograms, and summaries
- **Configuration Validation**: JSON schema validation with detailed error reporting
- **Web Interface**: REST API for monitoring, control, and metrics export

### Monitoring & Observability
- Real-time health status monitoring
- Performance metrics collection and export
- Request correlation and debugging
- Error rate tracking and alerting
- System resource monitoring

### Operational Excellence
- Circuit breaker patterns for fault tolerance
- Adaptive rate limiting with backoff strategies
- Comprehensive error recovery mechanisms
- Production-grade logging and monitoring
- Web-based operational interface

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
