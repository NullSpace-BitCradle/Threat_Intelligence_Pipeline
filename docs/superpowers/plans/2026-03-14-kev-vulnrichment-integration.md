# KEV + Vulnrichment Pipeline Integration Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate CISA KEV catalog and CISA Vulnrichment SSVC decisions into the TIP enrichment pipeline so every processed CVE is tagged with its KEV status and CISA's severity assessment.

**Architecture:** Two new processor modules (kev_processor.py, vulnrichment_processor.py) that download and index CISA data, plus extensions to database_manager.py and cve_processor.py to wire them into the existing pipeline. Follows the existing pattern: download source -> process into indexed JSON -> lookup during CVE enrichment.

**Tech Stack:** Python 3.12, requests, GitHub API (for Vulnrichment incremental updates), existing TIP infrastructure (config, error handling, performance monitoring)

**Spec:** `docs/superpowers/specs/2026-03-14-tip-v2-redesign-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/tip/core/kev_processor.py` | Create | Download KEV JSON, index by CVE ID, provide lookup |
| `src/tip/core/vulnrichment_processor.py` | Create | Fetch Vulnrichment data via GitHub API, extract SSVC + CVSS, provide lookup |
| `src/tip/core/database_manager.py` | Modify | Add kev and vulnrichment to database registry and update_all_databases |
| `src/tip/core/cve_processor.py` | Modify | Add Steps 6-7 (KEV lookup, Vulnrichment lookup) to process_cve_pipeline |
| `config.json` | Modify | Add database.kev and database.vulnrichment config entries |
| `tests/test_kev_processor.py` | Create | Tests for KEV processor |
| `tests/test_vulnrichment_processor.py` | Create | Tests for Vulnrichment processor |
| `tests/conftest.py` | Modify | Add KEV and Vulnrichment fixtures |

---

## Chunk 1: KEV Processor

### Task 1: Add KEV config and test fixtures

**Files:**
- Modify: `config.json`
- Modify: `tests/conftest.py`

- [ ] **Step 1: Add KEV database entry to config.json**

Add to the `database` section of `config.json`, after the `defend` entry:

```json
"kev": {
    "url": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    "file": "resources/kev_db.json"
}
```

- [ ] **Step 2: Add KEV test fixtures to conftest.py**

Add these fixtures to `tests/conftest.py`:

```python
@pytest.fixture
def sample_kev_data() -> Dict[str, Any]:
    """Sample CISA KEV catalog data (raw format from cisagov/kev-data)"""
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.03.14",
        "dateReleased": "2026-03-14T00:00:00.0000Z",
        "count": 3,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "TestVendor",
                "product": "TestProduct",
                "vulnerabilityName": "TestVendor TestProduct SQL Injection",
                "dateAdded": "2024-06-15",
                "shortDescription": "A SQL injection vulnerability exists.",
                "requiredAction": "Apply vendor patch.",
                "dueDate": "2024-07-06",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
                "cwes": ["CWE-89"]
            },
            {
                "cveID": "CVE-2024-9999",
                "vendorProject": "OtherVendor",
                "product": "OtherProduct",
                "vulnerabilityName": "OtherVendor RCE",
                "dateAdded": "2024-08-01",
                "shortDescription": "Remote code execution.",
                "requiredAction": "Apply update.",
                "dueDate": "2024-08-22",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": ""
            },
            {
                "cveID": "CVE-2024-5678",
                "vendorProject": "AcmeCorp",
                "product": "WebServer",
                "vulnerabilityName": "AcmeCorp Path Traversal",
                "dateAdded": "2024-09-10",
                "shortDescription": "Path traversal vulnerability.",
                "requiredAction": "Upgrade to latest version.",
                "dueDate": "2024-10-01",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": ""
            }
        ]
    }


@pytest.fixture
def sample_kev_db() -> Dict[str, Any]:
    """Sample KEV database indexed by CVE ID (processed format, matches sample_kev_data)"""
    return {
        "CVE-2024-1234": {
            "inKEV": True,
            "dateAdded": "2024-06-15",
            "dueDate": "2024-07-06",
            "knownRansomwareCampaignUse": "Known",
            "requiredAction": "Apply vendor patch.",
            "vendorProject": "TestVendor",
            "product": "TestProduct"
        },
        "CVE-2024-9999": {
            "inKEV": True,
            "dateAdded": "2024-08-01",
            "dueDate": "2024-08-22",
            "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "Apply update.",
            "vendorProject": "OtherVendor",
            "product": "OtherProduct"
        },
        "CVE-2024-5678": {
            "inKEV": True,
            "dateAdded": "2024-09-10",
            "dueDate": "2024-10-01",
            "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "Upgrade to latest version.",
            "vendorProject": "AcmeCorp",
            "product": "WebServer"
        }
    }
```

- [ ] **Step 3: Commit**

```bash
git add config.json tests/conftest.py
git commit -m "feat: add KEV config entry and test fixtures"
```

---

### Task 2: KEV Processor - tests first

**Files:**
- Create: `tests/test_kev_processor.py`

- [ ] **Step 1: Write KEV processor tests**

```python
"""Tests for CISA KEV Processor"""
import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestKEVProcessor:
    """Tests for KEV data processing"""

    def test_process_kev_data_indexes_by_cve_id(self, sample_kev_data):
        """Processing raw KEV data should produce a dict indexed by CVE ID"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        result = processor._process_kev_data(sample_kev_data)

        assert "CVE-2024-1234" in result
        assert "CVE-2024-9999" in result
        assert "CVE-2024-5678" in result
        assert len(result) == 3

    def test_process_kev_data_extracts_required_fields(self, sample_kev_data):
        """Each indexed entry should contain the expected KEV fields"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        result = processor._process_kev_data(sample_kev_data)

        entry = result["CVE-2024-1234"]
        assert entry["inKEV"] is True
        assert entry["dateAdded"] == "2024-06-15"
        assert entry["dueDate"] == "2024-07-06"
        assert entry["knownRansomwareCampaignUse"] == "Known"
        assert entry["requiredAction"] == "Apply vendor patch."
        assert entry["vendorProject"] == "TestVendor"
        assert entry["product"] == "TestProduct"

    def test_process_kev_data_handles_missing_optional_fields(self):
        """Entries without optional fields (cwes, notes) should still process"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        raw = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "V",
                    "product": "P",
                    "vulnerabilityName": "N",
                    "dateAdded": "2024-01-01",
                    "shortDescription": "D",
                    "requiredAction": "A",
                    "dueDate": "2024-02-01"
                }
            ]
        }
        result = processor._process_kev_data(raw)
        assert "CVE-2024-0001" in result
        assert result["CVE-2024-0001"]["inKEV"] is True

    def test_process_kev_data_empty_catalog(self):
        """Empty vulnerability list should return empty dict"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        result = processor._process_kev_data({"vulnerabilities": []})
        assert result == {}

    def test_lookup_cve_found(self, sample_kev_db):
        """Looking up a CVE that is in KEV should return its data"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        processor.kev_db = sample_kev_db

        result = processor.lookup("CVE-2024-1234")
        assert result is not None
        assert result["inKEV"] is True
        assert result["vendorProject"] == "TestVendor"

    def test_lookup_cve_not_found(self, sample_kev_db):
        """Looking up a CVE not in KEV should return None"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        processor.kev_db = sample_kev_db

        result = processor.lookup("CVE-2024-0000")
        assert result is None

    def test_lookup_before_load_returns_none(self):
        """Looking up before loading the database should return None"""
        from tip.core.kev_processor import KEVProcessor
        processor = KEVProcessor()
        result = processor.lookup("CVE-2024-1234")
        assert result is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/d1881b/Development/Threat_Intelligence_Pipeline && python -m pytest tests/test_kev_processor.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tip.core.kev_processor'`

- [ ] **Step 3: Commit failing tests**

```bash
git add tests/test_kev_processor.py
git commit -m "test: add KEV processor tests (red)"
```

---

### Task 3: KEV Processor - implementation

**Files:**
- Create: `src/tip/core/kev_processor.py`

- [ ] **Step 1: Implement KEV processor**

```python
"""
CISA Known Exploited Vulnerabilities (KEV) Processor

Downloads the KEV catalog from cisagov/kev-data, indexes by CVE ID,
and provides O(1) lookup during CVE enrichment.
"""
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger, NetworkError, FileOperationError
from tip.utils.error_recovery import with_recovery, create_api_context
from tip.utils.performance_optimizer import performance_timer

config = get_config()


class KEVProcessor:
    """Processes CISA KEV catalog data for CVE enrichment"""

    def __init__(self):
        self.config = config
        self.logger = get_logger('kev_processor')
        self.kev_db: Dict[str, Any] = {}
        self.db_path = config.get('database.kev.file', 'resources/kev_db.json')

    @performance_timer("download_kev")
    @with_recovery("download_kev", recovery_strategy="api")
    def download(self) -> Dict[str, Any]:
        """Download KEV catalog from CISA"""
        url = config.get(
            'database.kev.url',
            'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
        )
        context = create_api_context("download_kev", url)

        try:
            self.logger.info(f"Downloading KEV catalog from {url}")
            timeout = config.get('api.nvd.timeout', 60)
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            raw_data = response.json()
            self.logger.info(
                f"Downloaded KEV catalog: {raw_data.get('count', '?')} entries"
            )
            return raw_data
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Failed to download KEV catalog: {e}", url=url, context=context)

    def _process_kev_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw KEV JSON into CVE-indexed lookup dict"""
        indexed = {}
        for vuln in raw_data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue
            indexed[cve_id] = {
                "inKEV": True,
                "dateAdded": vuln.get("dateAdded", ""),
                "dueDate": vuln.get("dueDate", ""),
                "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                "requiredAction": vuln.get("requiredAction", ""),
                "vendorProject": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
            }
        self.logger.info(f"Indexed {len(indexed)} KEV entries by CVE ID")
        return indexed

    def update(self) -> bool:
        """Download, process, and save KEV database"""
        try:
            raw_data = self.download()
            self.kev_db = self._process_kev_data(raw_data)
            self._save(self.kev_db)
            return True
        except Exception as e:
            self.logger.error(f"Failed to update KEV database: {e}")
            return False

    def load(self) -> bool:
        """Load KEV database from disk"""
        try:
            if Path(self.db_path).exists():
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.kev_db = json.load(f)
                self.logger.info(f"Loaded {len(self.kev_db)} KEV entries from {self.db_path}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to load KEV database: {e}")
            return False

    def _save(self, data: Dict[str, Any]):
        """Save processed KEV database to disk"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        self.logger.info(f"Saved {len(data)} KEV entries to {self.db_path}")

    def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a CVE in the KEV catalog. Returns entry dict or None."""
        return self.kev_db.get(cve_id)
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /home/d1881b/Development/Threat_Intelligence_Pipeline && python -m pytest tests/test_kev_processor.py -v`
Expected: All 7 tests PASS

- [ ] **Step 3: Commit**

```bash
git add src/tip/core/kev_processor.py
git commit -m "feat: implement KEV processor"
```

---

### Task 4: Wire KEV into database_manager.py

**Files:**
- Modify: `src/tip/core/database_manager.py`

- [ ] **Step 1: Add KEV import and database entry**

At the top of `database_manager.py`, add import after existing imports (after line 26):

```python
from tip.core.kev_processor import KEVProcessor
```

In `__init__`, add to `self.databases` dict after the `defend` entry (after line 69):

```python
'kev': {
    'url': config.get('database.kev.url'),
    'file': config.get_database_path('kev'),
    'processor': self._update_kev_database
}
```

- [ ] **Step 2: Add KEV processing method**

Add this method to the `DatabaseManager` class (after `_extract_d3fend_techniques`):

```python
def _update_kev_database(self) -> Dict[str, Any]:
    """Download and process CISA KEV data"""
    kev_processor = KEVProcessor()
    raw_data = kev_processor.download()
    return kev_processor._process_kev_data(raw_data)
```

- [ ] **Step 3: Add 'kev' to update_all_databases order**

In `update_all_databases`, change the update_order list (line 442):

```python
update_order = ['capec', 'cwe', 'techniques', 'defend', 'kev']
```

- [ ] **Step 4: Add 'kev' case to update_database method**

In `update_database`, add a new elif block after the `defend` case (after line 428):

```python
elif db_name == 'kev':
    # Process KEV
    data = db_config['processor']()
    self._save_database(data, db_config['file'])
    return True
```

- [ ] **Step 5: Run existing tests to verify no regressions**

Run: `cd /home/d1881b/Development/Threat_Intelligence_Pipeline && python -m pytest tests/ -v --timeout=30`
Expected: All existing tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/tip/core/database_manager.py
git commit -m "feat: wire KEV processor into database manager"
```

---

### Task 5: Wire KEV into cve_processor.py

**Files:**
- Modify: `src/tip/core/cve_processor.py`

- [ ] **Step 1: Add KEV import and initialization**

At the top of `cve_processor.py`, add import:

```python
from tip.core.kev_processor import KEVProcessor
```

In the `CVEProcessor.__init__` method, add after existing initializations:

```python
self.kev_processor = KEVProcessor()
self.kev_processor.load()
```

- [ ] **Step 2: Add Step 6 to process_cve_pipeline**

In `process_cve_pipeline`, after Step 5 (OWASP, around line 455) and before the `except` block, add:

```python
                # Step 6: KEV lookup
                kev_data = self.kev_processor.lookup(cve_id)
                if kev_data:
                    result[cve_id]["KEV"] = kev_data
```

- [ ] **Step 3: Run all tests**

Run: `cd /home/d1881b/Development/Threat_Intelligence_Pipeline && python -m pytest tests/ -v --timeout=30`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add src/tip/core/cve_processor.py
git commit -m "feat: add KEV lookup to CVE enrichment pipeline (Step 6)"
```

---

## Chunk 2: Vulnrichment Processor

### Task 6: Add Vulnrichment config and test fixtures

**Files:**
- Modify: `config.json`
- Modify: `tests/conftest.py`

- [ ] **Step 1: Add Vulnrichment database entry to config.json**

Add to the `database` section of `config.json`, after the `kev` entry:

```json
"vulnrichment": {
    "repo": "cisagov/vulnrichment",
    "file": "resources/vulnrichment_db.json",
    "state_file": "resources/vulnrichment_state.json"
}
```

- [ ] **Step 2: Add Vulnrichment test fixtures to conftest.py**

Add to `tests/conftest.py`:

```python
@pytest.fixture
def sample_vulnrichment_cve() -> Dict[str, Any]:
    """Sample Vulnrichment per-CVE JSON (simplified from cisagov/vulnrichment format)"""
    return {
        "containers": {
            "adp": [
                {
                    "providerMetadata": {
                        "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0"
                    },
                    "title": "CISA ADP Vulnrichment",
                    "metrics": [
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {
                                    "id": "CVE-2024-1234",
                                    "options": [
                                        {"Exploitation": "active"},
                                        {"Automatable": "yes"},
                                        {"Technical Impact": "total"}
                                    ]
                                }
                            }
                        },
                        {
                            "cvssV3_1": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            ]
        }
    }


@pytest.fixture
def sample_vulnrichment_db() -> Dict[str, Any]:
    """Sample Vulnrichment database indexed by CVE ID (processed format)"""
    return {
        "CVE-2024-1234": {
            "ssvcExploitStatus": "active",
            "ssvcAutomatable": "yes",
            "ssvcTechnicalImpact": "total",
            "cisaCVSS": {
                "baseScore": 9.8,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
        }
    }
```

- [ ] **Step 3: Commit**

```bash
git add config.json tests/conftest.py
git commit -m "feat: add Vulnrichment config entry and test fixtures"
```

---

### Task 7: Vulnrichment Processor - tests first

**Files:**
- Create: `tests/test_vulnrichment_processor.py`

- [ ] **Step 1: Write Vulnrichment processor tests**

```python
"""Tests for CISA Vulnrichment Processor"""
import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestVulnrichmentProcessor:
    """Tests for Vulnrichment data processing"""

    def test_extract_ssvc_from_cve_json(self, sample_vulnrichment_cve):
        """Extracting SSVC data from a per-CVE JSON should return structured result"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        result = processor._extract_enrichment(sample_vulnrichment_cve)

        assert result is not None
        assert result["ssvcExploitStatus"] == "active"
        assert result["ssvcAutomatable"] == "yes"
        assert result["ssvcTechnicalImpact"] == "total"

    def test_extract_cisa_cvss(self, sample_vulnrichment_cve):
        """CISA CVSS score and vector should be extracted"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        result = processor._extract_enrichment(sample_vulnrichment_cve)

        assert result is not None
        assert result["cisaCVSS"]["baseScore"] == 9.8
        assert "CVSS:3.1" in result["cisaCVSS"]["vector"]

    def test_extract_no_adp_container(self):
        """CVE JSON without ADP container should return None"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        result = processor._extract_enrichment({"containers": {}})
        assert result is None

    def test_extract_no_ssvc_metrics(self):
        """ADP container without SSVC metrics should return None"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        data = {
            "containers": {
                "adp": [
                    {
                        "providerMetadata": {"orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0"},
                        "title": "CISA ADP Vulnrichment",
                        "metrics": []
                    }
                ]
            }
        }
        result = processor._extract_enrichment(data)
        assert result is None

    def test_lookup_found(self, sample_vulnrichment_db):
        """Looking up a CVE with Vulnrichment data should return it"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        processor.vulnrichment_db = sample_vulnrichment_db

        result = processor.lookup("CVE-2024-1234")
        assert result is not None
        assert result["ssvcExploitStatus"] == "active"

    def test_lookup_not_found(self, sample_vulnrichment_db):
        """Looking up a CVE without Vulnrichment data should return None"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        processor.vulnrichment_db = sample_vulnrichment_db

        result = processor.lookup("CVE-2024-0000")
        assert result is None

    def test_lookup_before_load(self):
        """Looking up before loading should return None"""
        from tip.core.vulnrichment_processor import VulnrichmentProcessor
        processor = VulnrichmentProcessor()
        result = processor.lookup("CVE-2024-1234")
        assert result is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/d1881b/Development/Threat_Intelligence_Pipeline && python -m pytest tests/test_vulnrichment_processor.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tip.core.vulnrichment_processor'`

- [ ] **Step 3: Commit failing tests**

```bash
git add tests/test_vulnrichment_processor.py
git commit -m "test: add Vulnrichment processor tests (red)"
```

---

### Task 8: Vulnrichment Processor - implementation

**Files:**
- Create: `src/tip/core/vulnrichment_processor.py`

- [ ] **Step 1: Implement Vulnrichment processor**

```python
"""
CISA Vulnrichment Processor

Fetches CISA Vulnrichment data (SSVC decisions + CISA CVSS overrides) from
the cisagov/vulnrichment GitHub repo. Uses the GitHub API for incremental
updates and a shallow clone for bootstrap.
"""
import json
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger, NetworkError
from tip.utils.performance_optimizer import performance_timer

config = get_config()

# CISA ADP provider org ID (identifies the CISA enrichment container)
CISA_ADP_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0"


class VulnrichmentProcessor:
    """Processes CISA Vulnrichment data for CVE enrichment"""

    def __init__(self):
        self.config = config
        self.logger = get_logger('vulnrichment_processor')
        self.vulnrichment_db: Dict[str, Any] = {}
        self.db_path = config.get('database.vulnrichment.file', 'resources/vulnrichment_db.json')
        self.state_path = config.get('database.vulnrichment.state_file', 'resources/vulnrichment_state.json')
        self.repo = config.get('database.vulnrichment.repo', 'cisagov/vulnrichment')

    def _extract_enrichment(self, cve_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract SSVC decision and CISA CVSS from a per-CVE Vulnrichment JSON.

        Args:
            cve_json: Raw JSON from cisagov/vulnrichment for a single CVE

        Returns:
            Dict with ssvcExploitStatus, ssvcAutomatable, ssvcTechnicalImpact,
            and cisaCVSS if found. None if no CISA ADP data present.
        """
        adp_containers = cve_json.get("containers", {}).get("adp", [])

        # Find the CISA ADP container
        cisa_adp = None
        for container in adp_containers:
            org_id = container.get("providerMetadata", {}).get("orgId", "")
            if org_id == CISA_ADP_ORG_ID:
                cisa_adp = container
                break

        if not cisa_adp:
            return None

        metrics = cisa_adp.get("metrics", [])
        if not metrics:
            return None

        result: Dict[str, Any] = {}
        found_ssvc = False

        for metric in metrics:
            # Extract SSVC decision
            other = metric.get("other", {})
            if other.get("type") == "ssvc":
                options = other.get("content", {}).get("options", [])
                for option in options:
                    if "Exploitation" in option:
                        result["ssvcExploitStatus"] = option["Exploitation"]
                        found_ssvc = True
                    if "Automatable" in option:
                        result["ssvcAutomatable"] = option["Automatable"]
                        found_ssvc = True
                    if "Technical Impact" in option:
                        result["ssvcTechnicalImpact"] = option["Technical Impact"]
                        found_ssvc = True

            # Extract CISA CVSS
            cvss = metric.get("cvssV3_1")
            if cvss:
                result["cisaCVSS"] = {
                    "baseScore": cvss.get("baseScore"),
                    "vector": cvss.get("vectorString", "")
                }

        return result if found_ssvc else None

    @performance_timer("update_vulnrichment")
    def update(self) -> bool:
        """Update Vulnrichment database using GitHub API (incremental) or clone (bootstrap)"""
        try:
            state = self._load_state()
            last_sha = state.get("last_commit_sha")

            if last_sha:
                # Incremental update via GitHub API
                self.logger.info(f"Incremental Vulnrichment update from SHA {last_sha[:8]}...")
                success = self._incremental_update(last_sha)
            else:
                # Bootstrap via shallow clone
                self.logger.info("Bootstrap: cloning Vulnrichment repo (first run)...")
                success = self._bootstrap_clone()

            if success:
                self._save(self.vulnrichment_db)
            return success

        except Exception as e:
            self.logger.error(f"Failed to update Vulnrichment database: {e}")
            return False

    def _incremental_update(self, last_sha: str) -> bool:
        """Fetch only changed CVE files since last_sha using GitHub API"""
        try:
            # Get current HEAD SHA
            url = f"https://api.github.com/repos/{self.repo}/commits?per_page=1"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            current_sha = response.json()[0]["sha"]

            if current_sha == last_sha:
                self.logger.info("Vulnrichment repo unchanged since last update")
                return True

            # Get diff between last and current
            compare_url = f"https://api.github.com/repos/{self.repo}/compare/{last_sha}...{current_sha}"
            response = requests.get(compare_url, timeout=60)
            response.raise_for_status()
            compare_data = response.json()

            # Load existing db
            self.load()

            # Process changed files
            changed_files = compare_data.get("files", [])
            cve_files = [f for f in changed_files if f["filename"].endswith(".json") and "CVE-" in f["filename"]]

            self.logger.info(f"Processing {len(cve_files)} changed Vulnrichment files...")

            for file_info in cve_files:
                if file_info["status"] == "removed":
                    # Extract CVE ID from path like "2024/0xxx/CVE-2024-0001.json"
                    cve_id = Path(file_info["filename"]).stem
                    self.vulnrichment_db.pop(cve_id, None)
                    continue

                # Fetch file content
                raw_url = file_info.get("raw_url")
                if not raw_url:
                    continue

                try:
                    resp = requests.get(raw_url, timeout=30)
                    resp.raise_for_status()
                    cve_json = resp.json()
                    cve_id = Path(file_info["filename"]).stem
                    enrichment = self._extract_enrichment(cve_json)
                    if enrichment:
                        self.vulnrichment_db[cve_id] = enrichment
                except Exception as e:
                    self.logger.debug(f"Error processing {file_info['filename']}: {e}")
                    continue

            # Save state
            self._save_state({"last_commit_sha": current_sha})
            self.logger.info(f"Incremental update complete. DB has {len(self.vulnrichment_db)} entries.")
            return True

        except Exception as e:
            self.logger.error(f"Incremental update failed: {e}")
            return False

    def _bootstrap_clone(self) -> bool:
        """Bootstrap by shallow-cloning the full repo and processing all CVEs"""
        clone_dir = Path(self.db_path).parent / "_vulnrichment_clone"
        try:
            # Shallow clone
            subprocess.run(
                ["git", "clone", "--depth=1", f"https://github.com/{self.repo}.git", str(clone_dir)],
                check=True, capture_output=True, text=True, timeout=600
            )

            # Get HEAD SHA for state tracking
            result = subprocess.run(
                ["git", "-C", str(clone_dir), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True
            )
            head_sha = result.stdout.strip()

            # Process all CVE JSON files
            self.vulnrichment_db = {}
            cve_count = 0
            for json_file in clone_dir.rglob("CVE-*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        cve_json = json.load(f)
                    enrichment = self._extract_enrichment(cve_json)
                    if enrichment:
                        cve_id = json_file.stem
                        self.vulnrichment_db[cve_id] = enrichment
                        cve_count += 1
                except Exception as e:
                    self.logger.debug(f"Error processing {json_file.name}: {e}")
                    continue

            self._save_state({"last_commit_sha": head_sha})
            self.logger.info(f"Bootstrap complete. Processed {cve_count} CVEs with SSVC data.")
            return True

        except subprocess.TimeoutExpired:
            self.logger.error("Vulnrichment clone timed out after 10 minutes")
            return False
        except Exception as e:
            self.logger.error(f"Bootstrap clone failed: {e}")
            return False
        finally:
            # Clean up clone
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)

    def load(self) -> bool:
        """Load Vulnrichment database from disk"""
        try:
            if Path(self.db_path).exists():
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.vulnrichment_db = json.load(f)
                self.logger.info(f"Loaded {len(self.vulnrichment_db)} Vulnrichment entries")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to load Vulnrichment database: {e}")
            return False

    def _save(self, data: Dict[str, Any]):
        """Save processed Vulnrichment database to disk"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        self.logger.info(f"Saved {len(data)} Vulnrichment entries to {self.db_path}")

    def _load_state(self) -> Dict[str, Any]:
        """Load update state (last processed commit SHA)"""
        try:
            if Path(self.state_path).exists():
                with open(self.state_path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_state(self, state: Dict[str, Any]):
        """Save update state"""
        Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_path, 'w') as f:
            json.dump(state, f, indent=2)

    def lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a CVE's Vulnrichment data. Returns entry dict or None."""
        return self.vulnrichment_db.get(cve_id)
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /home/d1881b/Development/Threat_Intelligence_Pipeline && python -m pytest tests/test_vulnrichment_processor.py -v`
Expected: All 7 tests PASS

- [ ] **Step 3: Commit**

```bash
git add src/tip/core/vulnrichment_processor.py
git commit -m "feat: implement Vulnrichment processor with incremental GitHub API updates"
```

---

### Task 9: Wire Vulnrichment into database_manager.py and cve_processor.py

**Files:**
- Modify: `src/tip/core/database_manager.py`
- Modify: `src/tip/core/cve_processor.py`

- [ ] **Step 1: Add Vulnrichment to database_manager.py**

Add import at top:

```python
from tip.core.vulnrichment_processor import VulnrichmentProcessor
```

Add to `self.databases` dict after `kev`:

```python
'vulnrichment': {
    'file': config.get_database_path('vulnrichment'),
    'processor': self._update_vulnrichment_database
}
```

Add processing method:

```python
def _update_vulnrichment_database(self) -> Dict[str, Any]:
    """Download and process CISA Vulnrichment data"""
    vr_processor = VulnrichmentProcessor()
    vr_processor.update()
    return vr_processor.vulnrichment_db
```

Add to `update_order`:

```python
update_order = ['capec', 'cwe', 'techniques', 'defend', 'kev', 'vulnrichment']
```

Add elif to `update_database`:

```python
elif db_name == 'vulnrichment':
    data = db_config['processor']()
    self._save_database(data, db_config['file'])
    return True
```

- [ ] **Step 2: Add Vulnrichment to cve_processor.py**

Add import:

```python
from tip.core.vulnrichment_processor import VulnrichmentProcessor
```

In `__init__`, add:

```python
self.vulnrichment_processor = VulnrichmentProcessor()
self.vulnrichment_processor.load()
```

In `process_cve_pipeline`, after the KEV step (Step 6), add:

```python
                # Step 7: Vulnrichment SSVC + CVSS lookup
                vr_data = self.vulnrichment_processor.lookup(cve_id)
                if vr_data:
                    result[cve_id]["VULNRICHMENT"] = vr_data
```

- [ ] **Step 3: Run all tests**

Run: `cd /home/d1881b/Development/Threat_Intelligence_Pipeline && python -m pytest tests/ -v --timeout=30`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add src/tip/core/database_manager.py src/tip/core/cve_processor.py
git commit -m "feat: wire Vulnrichment into database manager and CVE pipeline (Step 7)"
```

---

### Task 10: Integration test

**Files:**
- Modify: `tests/conftest.py`

- [ ] **Step 1: Add KEV and Vulnrichment database entries to temp_config_file fixture**

In the `temp_config_file` fixture in `conftest.py`, add to the `"database"` dict:

```python
"kev": {"file": str(tmp_path / "kev_db.json")},
"vulnrichment": {
    "file": str(tmp_path / "vulnrichment_db.json"),
    "state_file": str(tmp_path / "vulnrichment_state.json")
}
```

- [ ] **Step 2: Add KEV and Vulnrichment files to temp_database_files fixture**

Add to the `temp_database_files` fixture, **before the `return` statement** (after the techniques_db write):

```python
# Write KEV database
kev_path = resources_dir / "kev_db.json"
with open(kev_path, 'w') as f:
    json.dump({}, f)

# Write Vulnrichment database
vr_path = resources_dir / "vulnrichment_db.json"
with open(vr_path, 'w') as f:
    json.dump({}, f)
```

Add to the return dict:

```python
"kev": kev_path,
"vulnrichment": vr_path,
```

- [ ] **Step 3: Run full test suite**

Run: `cd /home/d1881b/Development/Threat_Intelligence_Pipeline && python -m pytest tests/ -v --timeout=30`
Expected: All tests PASS (including both new test files)

- [ ] **Step 4: Final commit**

```bash
git add tests/conftest.py
git commit -m "feat: complete KEV + Vulnrichment integration (sub-project 1)"
```

---
