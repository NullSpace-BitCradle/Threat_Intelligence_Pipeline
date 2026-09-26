# TIP MCP demo: CVE-2023-44487 (HTTP/2 Rapid Reset)

A scripted MCP client session against the TIP MCP server over stdio, run on
this repo's `docs/data` index and `docs/database` shards. Each step shows the
analyst question, the tool call a model would make, and the result (long
lists and strings trimmed for reading; `meta` counts are the full numbers).

Regenerate with `python scripts/mcp_demo.py`; `python scripts/mcp_demo.py
--check` fails if this file no longer matches a fresh run. To ask the same
questions interactively, open the repo in Claude Code, which reads `.mcp.json`
and launches the `tip-mcp` server.

## Step 1: What is CVE-2023-44487?

```text
lookup_entity({"entity_id": "CVE-2023-44487"})
```

CVE-2023-44487: CVSS 7.5 HIGH, KEV True, 83 relationships.

```json
{
  "ok": true,
  "data": {
    "type": "cve",
    "id": "CVE-2023-44487",
    "name": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
    "phase": "vulnerability",
    "description": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
    "cvss_score": 7.5,
    "severity": "HIGH",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "published": "2023-10-10T14:15:10.883",
    "last_modified": "2026-08-11T19:37:30.880",
    "references": [
      "http://www.openwall.com/lists/oss-security/2023/10/10/6",
      "http://www.openwall.com/lists/oss-security/2023/10/10/7",
      "http://www.openwall.com/lists/oss-security/2023/10/13/4",
      "http://www.openwall.com/lists/oss-security/2023/10/13/9",
      "http://www.openwall.com/lists/oss-security/2023/10/18/4",
      "http://www.openwall.com/lists/oss-security/2023/10/18/8",
      "http://www.openwall.com/lists/oss-security/2023/10/19/6",
      "http://www.openwall.com/lists/oss-security/2023/10/20/8",
      "... 165 more"
    ],
    "kev_detail": {
      "dateAdded": "2023-10-10",
      "dueDate": "2023-10-31",
      "knownRansomwareCampaignUse": "Unknown",
      "requiredAction": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "vendorProject": "IETF",
      "product": "HTTP/2"
    },
    "cvss_version": "3.1",
    "prov": {
      "source": "NVD",
      "tier": "authoritative"
    },
    "kev": true,
    "rels": [
      {
        "target_id": "G0007",
        "rel_type": "apt_group",
        "source": "Pipeline (technique overlap)",
        "tier": "derived"
      },
      {
        "target_id": "G0010",
        "rel_type": "apt_group",
        "source": "Pipeline (technique overlap)",
        "tier": "derived"
      },
      {
        "target_id": "G0016",
        "rel_type": "apt_group",
        "source": "Pipeline (technique overlap)",
        "tier": "derived"
      },
      {
        "target_id": "G0030",
        "rel_type": "apt_group",
        "source": "Pipeline (technique overlap)",
        "tier": "derived"
      },
      {
        "target_id": "G0032",
        "rel_type": "apt_group",
        "source": "Pipeline (technique overlap)",
        "tier": "derived"
      },
      {
        "target_id": "G0034",
        "rel_type": "apt_group",
        "source": "Pipeline (technique overlap)",
        "tier": "derived"
      },
      {
        "target_id": "G0037",
        "rel_type": "apt_group",
        "source": "Pipeline (technique overlap)",
        "tier": "derived"
      },
      {
        "target_id": "G0061",
        "rel_type": "apt_group",
        "source": "Pipeline (technique overlap)",
        "tier": "derived"
      },
      "... 75 more"
    ]
  },
  "meta": {
    "source": "entity_index.json",
    "rel_count": 83,
    "enriched_from_shard": true
  }
}
```

## Step 2: Which ATT&CK techniques does it map to?

```text
pivot_from_entity({"entity_id": "CVE-2023-44487", "target_type": "technique"})
```

9 techniques: T1134, T1134.001, T1134.002, T1134.003, T1499, T1528, T1539, T1550.004, T1606.

```json
{
  "ok": true,
  "data": [
    {
      "id": "T1134",
      "type": "technique",
      "name": "Access Token Manipulation",
      "rel_type": "technique"
    },
    {
      "id": "T1134.001",
      "type": "technique",
      "name": "Token Impersonation/Theft",
      "rel_type": "technique"
    },
    {
      "id": "T1134.002",
      "type": "technique",
      "name": "Create Process with Token",
      "rel_type": "technique"
    },
    {
      "id": "T1134.003",
      "type": "technique",
      "name": "Make and Impersonate Token",
      "rel_type": "technique"
    },
    {
      "id": "T1499",
      "type": "technique",
      "name": "Endpoint Denial of Service",
      "rel_type": "technique"
    },
    {
      "id": "T1528",
      "type": "technique",
      "name": "Steal Application Access Token",
      "rel_type": "technique"
    },
    {
      "id": "T1539",
      "type": "technique",
      "name": "Steal Web Session Cookie",
      "rel_type": "technique"
    },
    {
      "id": "T1550.004",
      "type": "technique",
      "name": "Web Session Cookie",
      "rel_type": "technique"
    },
    "... 1 more"
  ],
  "meta": {
    "source": "entity_index.json",
    "count": 9
  }
}
```

## Step 3: What is the attack chain behind T1499 (Endpoint Denial of Service)?

```text
build_attack_chain({"technique_id": "T1499", "limit": 10})
```

3 CAPEC patterns, 52 weaknesses, 122 CVEs, 11 D3FEND defenses (lists capped at 10; 10 of the 10 CVEs shown are in KEV).

```json
{
  "ok": true,
  "data": {
    "technique": {
      "id": "T1499",
      "name": "Endpoint Denial of Service"
    },
    "capecs": [
      {
        "id": "CAPEC-125",
        "name": "Flooding",
        "source": "MITRE CAPEC Database",
        "tier": "official"
      },
      {
        "id": "CAPEC-131",
        "name": "Resource Leak Exposure",
        "source": "MITRE CAPEC Database",
        "tier": "official"
      },
      {
        "id": "CAPEC-227",
        "name": "Sustained Client Engagement",
        "source": "MITRE CAPEC Database",
        "tier": "official"
      }
    ],
    "cwes": [
      {
        "id": "CWE-226",
        "name": "Sensitive Information in Resource Not Removed Before Reuse",
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "source": "MITRE CWE Database",
        "tier": "official"
      },
      {
        "id": "CWE-244",
        "name": "Improper Clearing of Heap Memory Before Release ('Heap Inspection')",
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "source": "MITRE CWE Database",
        "tier": "official"
      },
      {
        "id": "CWE-299",
        "name": "Improper Check for Certificate Revocation",
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "source": "MITRE CWE Database",
        "tier": "official"
      },
      {
        "id": "CWE-370",
        "name": "Missing Check for Certificate Revocation after Initial Check",
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "source": "MITRE CWE Database",
        "tier": "official"
      },
      {
        "id": "CWE-400",
        "name": "Uncontrolled Resource Consumption",
        "via_capecs": [
          "CAPEC-227"
        ],
        "source": "MITRE CWE Database",
        "tier": "official"
      },
      {
        "id": "CWE-401",
        "name": "Missing Release of Memory after Effective Lifetime",
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "source": "MITRE CWE Database",
        "tier": "official"
      },
      {
        "id": "CWE-404",
        "name": "Improper Resource Shutdown or Release",
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "source": "MITRE CWE Database",
        "tier": "official"
      },
      {
        "id": "CWE-405",
        "name": "Asymmetric Resource Consumption (Amplification)",
        "via_capecs": [
          "CAPEC-227"
        ],
        "source": "MITRE CWE Database",
        "tier": "official"
      },
      "... 2 more"
    ],
    "cves": [
      {
        "id": "CVE-2021-44228",
        "name": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoint... (241 chars)",
        "kev": true,
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "via_cwes": [
          "CWE-400"
        ],
        "source": "NVD Enrichment",
        "tier": "authoritative"
      },
      {
        "id": "CVE-2018-0158",
        "name": "A vulnerability in the Internet Key Exchange Version 2 (IKEv2) module of Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a memory leak or a reload of an affected device that leads to a d... (272 chars)",
        "kev": true,
        "cvss_score": 8.6,
        "severity": "HIGH",
        "via_cwes": [
          "CWE-401"
        ],
        "source": "NVD Enrichment",
        "tier": "authoritative"
      },
      {
        "id": "CVE-2020-3566",
        "name": "A vulnerability in the Distance Vector Multicast Routing Protocol (DVMRP) feature of Cisco IOS XR Software could allow an unauthenticated, remote attacker to exhaust process memory of an affected device",
        "kev": true,
        "cvss_score": 8.6,
        "severity": "HIGH",
        "via_cwes": [
          "CWE-400",
          "CWE-770"
        ],
        "source": "NVD Enrichment",
        "tier": "authoritative"
      },
      {
        "id": "CVE-2020-3569",
        "name": "Multiple vulnerabilities in the Distance Vector Multicast Routing Protocol (DVMRP) feature of Cisco IOS XR Software could allow an unauthenticated, remote attacker to either immediately crash the Internet Group Management Protocol (IGMP) pr... (302 chars)",
        "kev": true,
        "cvss_score": 8.6,
        "severity": "HIGH",
        "via_cwes": [
          "CWE-400",
          "CWE-770"
        ],
        "source": "NVD Enrichment",
        "tier": "authoritative"
      },
      {
        "id": "CVE-2022-0028",
        "name": "A PAN-OS URL filtering policy misconfiguration could allow a network-based attacker to conduct reflected and amplified TCP denial-of-service (RDoS) attacks",
        "kev": true,
        "cvss_score": 8.6,
        "severity": "HIGH",
        "via_cwes": [
          "CWE-406"
        ],
        "source": "NVD Enrichment",
        "tier": "authoritative"
      },
      {
        "id": "CVE-2026-20349",
        "name": "A vulnerability in the Remote Access SSL VPN service for Cisco Secure Firewall Adaptive Security Appliance (ASA) Software and Cisco Secure Firewall Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause the d... (415 chars)",
        "kev": true,
        "cvss_score": 8.6,
        "severity": "HIGH",
        "via_cwes": [
          "CWE-244"
        ],
        "source": "NVD Enrichment",
        "tier": "authoritative"
      },
      {
        "id": "CVE-2018-8405",
        "name": "An elevation of privilege vulnerability exists when the DirectX Graphics Kernel (DXGKRNL) driver improperly handles objects in memory, aka \"DirectX Graphics Kernel Elevation of Privilege Vulnerability.\" This affects Windows Server 2012 R2, ... (320 chars)",
        "kev": true,
        "cvss_score": 7.8,
        "severity": "HIGH",
        "via_cwes": [
          "CWE-404"
        ],
        "source": "NVD Enrichment",
        "tier": "authoritative"
      },
      {
        "id": "CVE-2018-8406",
        "name": "An elevation of privilege vulnerability exists when the DirectX Graphics Kernel (DXGKRNL) driver improperly handles objects in memory, aka \"DirectX Graphics Kernel Elevation of Privilege Vulnerability.\" This affects Windows Server 2016, Win... (267 chars)",
        "kev": true,
        "cvss_score": 7.8,
        "severity": "HIGH",
        "via_cwes": [
          "CWE-404"
        ],
        "source": "NVD Enrichment",
        "tier": "authoritative"
      },
      "... 2 more"
    ],
    "defenses": [
      {
        "id": "D3-APCA",
        "name": "Application Protocol Command Analysis",
        "source": "MITRE D3FEND",
        "tier": "official"
      },
      {
        "id": "D3-CSPP",
        "name": "Client-server Payload Profiling",
        "source": "MITRE D3FEND",
        "tier": "official"
      },
      {
        "id": "D3-ISVA",
        "name": "Inbound Session Volume Analysis",
        "source": "MITRE D3FEND",
        "tier": "official"
      },
      {
        "id": "D3-ITF",
        "name": "Inbound Traffic Filtering",
        "source": "MITRE D3FEND",
        "tier": "official"
      },
      {
        "id": "D3-NTCD",
        "name": "Network Traffic Community Deviation",
        "source": "MITRE D3FEND",
        "tier": "official"
      },
      {
        "id": "D3-NTF",
        "name": "Network Traffic Filtering",
        "source": "MITRE D3FEND",
        "tier": "official"
      },
      {
        "id": "D3-NTSA",
        "name": "Network Traffic Signature Analysis",
        "source": "MITRE D3FEND",
        "tier": "official"
      },
      {
        "id": "D3-PHDURA",
        "name": "Per Host Download-Upload Ratio Analysis",
        "source": "MITRE D3FEND",
        "tier": "official"
      },
      "... 2 more"
    ]
  },
  "meta": {
    "source": "entity_index.json",
    "walk": "technique <- capec <- cwe -> cve; technique -> defend",
    "totals": {
      "capecs": 3,
      "cwes": 52,
      "cves": 122,
      "defenses": 11
    },
    "limit": 10,
    "truncated": true
  }
}
```

## Step 4: How do I defend against CVE-2023-44487?

```text
get_defenses({"cve_id": "CVE-2023-44487"})
```

44 D3FEND defenses reached through 9 techniques; 44 carry a relationship verb.

```json
{
  "ok": true,
  "data": [
    {
      "id": "D3-ABPI",
      "name": "Application-based Process Isolation",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1550.004"
      ],
      "direct": true,
      "relationship": "isolates"
    },
    {
      "id": "D3-AEM",
      "name": "Application Exception Monitoring",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1134",
        "T1134.002",
        "T1134.003"
      ],
      "direct": true,
      "relationship": "monitors"
    },
    {
      "id": "D3-AM",
      "name": "Access Modeling",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1134"
      ],
      "direct": true,
      "relationship": "maps"
    },
    {
      "id": "D3-ANCI",
      "name": "Authentication Cache Invalidation",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1134",
        "T1134.001",
        "T1134.002",
        "T1134.003",
        "T1528",
        "T1539",
        "T1550.004",
        "T1606"
      ],
      "direct": true,
      "relationship": "deletes"
    },
    {
      "id": "D3-APCA",
      "name": "Application Protocol Command Analysis",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1499",
        "T1550.004"
      ],
      "direct": true,
      "relationship": "monitors"
    },
    {
      "id": "D3-CCSA",
      "name": "Credential Compromise Scope Analysis",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1134",
        "T1134.001",
        "T1134.002",
        "T1134.003",
        "T1528",
        "T1539",
        "T1550.004",
        "T1606"
      ],
      "direct": true,
      "relationship": "analyzes"
    },
    {
      "id": "D3-CH",
      "name": "Credential Hardening",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1134",
        "T1134.001",
        "T1134.002",
        "T1134.003",
        "T1528",
        "T1539",
        "T1550.004",
        "T1606"
      ],
      "direct": true,
      "relationship": "hardens"
    },
    {
      "id": "D3-CI",
      "name": "Configuration Inventory",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1134"
      ],
      "direct": true,
      "relationship": "inventories"
    },
    "... 36 more"
  ],
  "meta": {
    "query": {
      "cve_id": "CVE-2023-44487"
    },
    "source": "entity_index.json",
    "count": 44,
    "techniques": [
      "T1134",
      "T1134.001",
      "T1134.002",
      "T1134.003",
      "T1499",
      "T1528",
      "T1539",
      "T1550.004",
      "... 1 more"
    ]
  }
}
```

## Step 5: Is it in CISA KEV, and how urgent is the patch?

```text
kev_status({"cve_id": "CVE-2023-44487"})
```

In KEV: True; added 2023-10-10, due 2023-10-31, ransomware use Unknown.

```json
{
  "ok": true,
  "data": {
    "cve_id": "CVE-2023-44487",
    "in_kev": true,
    "date_added": "2023-10-10",
    "due_date": "2023-10-31",
    "known_ransomware_campaign_use": "Unknown",
    "required_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
    "vendor_project": "IETF",
    "product": "HTTP/2",
    "ssvc": null
  },
  "meta": {
    "kev_source": "kev_db.json",
    "ssvc_source": null,
    "in_entity_graph": true
  }
}
```
