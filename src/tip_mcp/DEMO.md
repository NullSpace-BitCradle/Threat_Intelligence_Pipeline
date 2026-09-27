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

CVE-2023-44487: CVSS 7.5 HIGH, KEV True, 21 relationships.

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
    "ssvc": {
      "ssvcExploitStatus": "active",
      "ssvcAutomatable": "yes",
      "ssvcTechnicalImpact": "partial"
    },
    "cisa_cvss": {
      "baseScore": 7.5,
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    },
    "epss": {
      "score": 0.99999,
      "percentile": 0.99998,
      "date": "2026-09-26",
      "model_version": "v2026.06.15"
    },
    "cvss_version": "3.1",
    "cwe_inherited": [],
    "prov": {
      "source": "NVD",
      "tier": "authoritative"
    },
    "kev": true,
    "rels": [
      {
        "target_id": "CAPEC-147",
        "rel_type": "capec",
        "source": "Pipeline (CWE→CAPEC chain)",
        "tier": "derived"
      },
      {
        "target_id": "CAPEC-227",
        "rel_type": "capec",
        "source": "Pipeline (CWE→CAPEC chain)",
        "tier": "derived"
      },
      {
        "target_id": "CAPEC-492",
        "rel_type": "capec",
        "source": "Pipeline (CWE→CAPEC chain)",
        "tier": "derived"
      },
      {
        "target_id": "CWE-400",
        "rel_type": "cwe",
        "source": "NVD Enrichment",
        "tier": "authoritative"
      },
      {
        "target_id": "D3-APCA",
        "rel_type": "defend",
        "source": "Pipeline (Technique→D3FEND chain)",
        "tier": "derived",
        "relationship": "monitors",
        "name": "Application Protocol Command Analysis"
      },
      {
        "target_id": "D3-CSPP",
        "rel_type": "defend",
        "source": "Pipeline (Technique→D3FEND chain)",
        "tier": "derived",
        "relationship": "analyzes",
        "name": "Client-server Payload Profiling"
      },
      {
        "target_id": "D3-DQSA",
        "rel_type": "defend",
        "source": "CTID technique, then D3FEND",
        "tier": "derived"
      },
      {
        "target_id": "D3-ISVA",
        "rel_type": "defend",
        "source": "Pipeline (Technique→D3FEND chain)",
        "tier": "derived",
        "relationship": "analyzes",
        "name": "Inbound Session Volume Analysis"
      },
      "... 13 more"
    ]
  },
  "meta": {
    "source": "entity_index.json",
    "rel_count": 21,
    "enriched_from_shard": true,
    "epss_source": "epss_curated.json"
  }
}
```

## Step 2: Which ATT&CK techniques does it map to?

```text
pivot_from_entity({"entity_id": "CVE-2023-44487", "target_type": "technique"})
```

2 techniques: T1190, T1499. Tiers of these links: 2 official.

```json
{
  "ok": true,
  "data": [
    {
      "id": "T1190",
      "type": "technique",
      "name": "Exploit Public-Facing Application",
      "rel_type": "technique",
      "source": "MITRE CTID Mappings Explorer (KEV)",
      "tier": "official",
      "mapping_type": [
        "exploitation_technique"
      ],
      "comment": "This vulnerability is exploited through a 'Rapid Reset' flaw in HTTP/2 endpoints. Attackers initiate this vulnerability by sending a crafted sequence of HTTP requests using HEADERS followed by RST_STREAM frames. This allows them to generate... (375 chars)"
    },
    {
      "id": "T1499",
      "type": "technique",
      "name": "Endpoint Denial of Service",
      "rel_type": "technique",
      "source": "MITRE CTID Mappings Explorer (KEV)",
      "tier": "official",
      "mapping_type": [
        "primary_impact"
      ],
      "comment": "This vulnerability is exploited through a 'Rapid Reset' flaw in HTTP/2 endpoints. Attackers initiate this vulnerability by sending a crafted sequence of HTTP requests using HEADERS followed by RST_STREAM frames. This allows them to generate... (375 chars)"
    }
  ],
  "meta": {
    "source": "entity_index.json",
    "count": 2
  }
}
```

## Step 3: What is the attack chain behind T1499 (Endpoint Denial of Service)?

```text
build_attack_chain({"technique_id": "T1499", "limit": 10})
```

23 CVEs linked to the technique (each explained by its CWE and CAPEC path; 6 without one), through 3 CAPEC patterns and 5 weaknesses (3 of the 5 shown reach at least one of those CAPECs only by inheritance from a parent CWE, so they are derived), and 11 D3FEND defenses. Lists capped at 10; 10 of the 10 CVEs shown are in KEV. Tiers of the CVEs shown: 4 official, 6 derived; of the weaknesses shown: 2 official, 3 derived.

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
        "id": "CWE-400",
        "name": "Uncontrolled Resource Consumption",
        "via_capecs": [
          "CAPEC-227"
        ],
        "inherited": false,
        "inherited_capecs": [],
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
        "inherited": true,
        "inherited_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "source": "TIP generator (CAPEC inherited from a CWE ChildOf ancestor)",
        "tier": "derived"
      },
      {
        "id": "CWE-404",
        "name": "Improper Resource Shutdown or Release",
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "inherited": false,
        "inherited_capecs": [],
        "source": "MITRE CWE Database",
        "tier": "official"
      },
      {
        "id": "CWE-770",
        "name": "Allocation of Resources Without Limits or Throttling",
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-227"
        ],
        "inherited": true,
        "inherited_capecs": [
          "CAPEC-227"
        ],
        "source": "TIP generator (CAPEC inherited from a CWE ChildOf ancestor)",
        "tier": "derived"
      },
      {
        "id": "CWE-772",
        "name": "Missing Release of Resource after Effective Lifetime",
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "inherited": true,
        "inherited_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "source": "TIP generator (CAPEC inherited from a CWE ChildOf ancestor)",
        "tier": "derived"
      }
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
        "via_capecs": [
          "CAPEC-227"
        ],
        "source": "Pipeline (CAPEC→Technique chain)",
        "tier": "derived",
        "link_source": "Pipeline (CAPEC→Technique chain)",
        "link_tier": "derived"
      },
      {
        "id": "CVE-2024-54085",
        "name": "AMI’s SPx contains\na vulnerability in the BMC where an Attacker may bypass authentication remotely through the Redfish Host Interface",
        "kev": true,
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "via_cwes": [],
        "via_capecs": [],
        "source": "MITRE CTID Mappings Explorer (KEV)",
        "tier": "official",
        "link_source": "MITRE CTID Mappings Explorer (KEV)",
        "link_tier": "official",
        "mapping_type": [
          "primary_impact"
        ],
        "comment": "By sending a malicious request to the Redfish Host Interface, an attacker can manipulate the HTTP header, tricking the Baseboard Management Controller (BMC) into thinking that the request originates from a trusted source, leading to authent... (367 chars)"
      },
      {
        "id": "CVE-2021-35394",
        "name": "Realtek Jungle SDK version v2.x up to v3.4.14B provides a diagnostic tool called 'MP Daemon' that is usually compiled as 'UDPServer' binary",
        "kev": true,
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "via_cwes": [],
        "via_capecs": [],
        "source": "MITRE CTID Mappings Explorer (KEV)",
        "tier": "official",
        "link_source": "MITRE CTID Mappings Explorer (KEV)",
        "link_tier": "official",
        "mapping_type": [
          "secondary_impact"
        ],
        "comment": "The vulnerability in Realtek Jungle chipsets is exploited by remote, unauthenticated attackers using UDP packets to a server on port 9034, enabling remote execution of arbitrary commands. The attack involves injecting a shell command that d... (1078 chars)"
      },
      {
        "id": "CVE-2025-42599",
        "name": "Active! mail 6 BuildInfo: 6.60.05008561 and earlier contains a stack-based buffer overflow vulnerability",
        "kev": true,
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "via_cwes": [],
        "via_capecs": [],
        "source": "MITRE CTID Mappings Explorer (KEV)",
        "tier": "official",
        "link_source": "MITRE CTID Mappings Explorer (KEV)",
        "link_tier": "official",
        "mapping_type": [
          "primary_impact"
        ],
        "comment": "This stack-based buffer overflow vulnerability in Active! mail allows an unauthenticated attacker to achieve remote code execution, as well as execute a denial of service attack by crashing the server."
      },
      {
        "id": "CVE-2020-5735",
        "name": "Amcrest cameras and NVR are vulnerable to a stack-based buffer overflow over port 37777",
        "kev": true,
        "cvss_score": 8.8,
        "severity": "HIGH",
        "via_cwes": [],
        "via_capecs": [],
        "source": "MITRE CTID Mappings Explorer (KEV)",
        "tier": "official",
        "link_source": "MITRE CTID Mappings Explorer (KEV)",
        "link_tier": "official",
        "mapping_type": [
          "secondary_impact"
        ],
        "comment": "CVE-2020-5735 is a stack-based buffer overflow vulnerability in Amcrest cameras and NVR that allows an authenticated remote attacker to possibly execute unauthorized code over port 37777 and crash the device."
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
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-131"
        ],
        "source": "Pipeline (CAPEC→Technique chain)",
        "tier": "derived",
        "link_source": "Pipeline (CAPEC→Technique chain)",
        "link_tier": "derived",
        "inherited": true
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
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-227"
        ],
        "source": "Pipeline (CAPEC→Technique chain)",
        "tier": "derived",
        "link_source": "Pipeline (CAPEC→Technique chain)",
        "link_tier": "derived"
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
        "via_capecs": [
          "CAPEC-125",
          "CAPEC-227"
        ],
        "source": "Pipeline (CAPEC→Technique chain)",
        "tier": "derived",
        "link_source": "Pipeline (CAPEC→Technique chain)",
        "link_tier": "derived"
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
    "walk": "cves: the technique's own cve rels; each explained by cve -> cwe -> capec -> technique; defenses: technique -> defend. A CVE linked by MITRE CTID (official) or by inference (inferred) is labeled by that link.",
    "totals": {
      "capecs": 3,
      "cwes": 5,
      "cves": 23,
      "defenses": 11
    },
    "cves_without_path": 6,
    "limit": 10,
    "truncated": true,
    "link_tiers": {
      "derived": 16,
      "official": 7
    },
    "note": "6 of the 23 CVEs linked to T1499 have no CWE path to its CAPEC patterns; their via lists are empty."
  }
}
```

## Step 4: Which D3FEND countermeasures does MITRE map to T1499?

```text
get_defenses({"technique_id": "T1499"})
```

11 D3FEND defenses mapped to T1499; tiers: 11 official.

```json
{
  "ok": true,
  "data": [
    {
      "id": "D3-APCA",
      "name": "Application Protocol Command Analysis",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1499"
      ]
    },
    {
      "id": "D3-CSPP",
      "name": "Client-server Payload Profiling",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1499"
      ]
    },
    {
      "id": "D3-ISVA",
      "name": "Inbound Session Volume Analysis",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1499"
      ]
    },
    {
      "id": "D3-ITF",
      "name": "Inbound Traffic Filtering",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1499"
      ]
    },
    {
      "id": "D3-NTCD",
      "name": "Network Traffic Community Deviation",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1499"
      ]
    },
    {
      "id": "D3-NTF",
      "name": "Network Traffic Filtering",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1499"
      ]
    },
    {
      "id": "D3-NTSA",
      "name": "Network Traffic Signature Analysis",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1499"
      ]
    },
    {
      "id": "D3-PHDURA",
      "name": "Per Host Download-Upload Ratio Analysis",
      "mapping_source": "MITRE D3FEND",
      "tier": "official",
      "via_techniques": [
        "T1499"
      ]
    },
    "... 3 more"
  ],
  "meta": {
    "source": "entity_index.json",
    "query": {
      "technique_id": "T1499"
    },
    "count": 11
  }
}
```

## Step 5: And from the CVE side: which defenses do its mapped techniques reach?

```text
get_defenses({"cve_id": "CVE-2023-44487"})
```

14 D3FEND defenses reached through 2 techniques; 11 carry a relationship verb. Tiers: 14 derived, because TIP derives the CVE to technique links (CAPEC to technique chain), so these are leads, not MITRE mappings of the CVE.

```json
{
  "ok": true,
  "data": [
    {
      "id": "D3-APCA",
      "name": "Application Protocol Command Analysis",
      "via_techniques": [
        "T1190",
        "T1499"
      ],
      "relationship": "monitors",
      "mapping_source": "CVE→technique: MITRE CTID Mappings Explorer (KEV); technique→D3FEND: MITRE D3FEND (CTID technique, then D3FEND: derived)",
      "tier": "derived",
      "technique_links": [
        {
          "id": "T1190",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "exploitation_technique"
          ]
        },
        {
          "id": "T1499",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "primary_impact"
          ]
        }
      ]
    },
    {
      "id": "D3-CSPP",
      "name": "Client-server Payload Profiling",
      "via_techniques": [
        "T1190",
        "T1499"
      ],
      "relationship": "analyzes",
      "mapping_source": "CVE→technique: MITRE CTID Mappings Explorer (KEV); technique→D3FEND: MITRE D3FEND (CTID technique, then D3FEND: derived)",
      "tier": "derived",
      "technique_links": [
        {
          "id": "T1190",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "exploitation_technique"
          ]
        },
        {
          "id": "T1499",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "primary_impact"
          ]
        }
      ]
    },
    {
      "id": "D3-DQSA",
      "name": "Database Query String Analysis",
      "via_techniques": [
        "T1190"
      ],
      "mapping_source": "CVE→technique: MITRE CTID Mappings Explorer (KEV); technique→D3FEND: MITRE D3FEND (CTID technique, then D3FEND: derived)",
      "tier": "derived",
      "technique_links": [
        {
          "id": "T1190",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "exploitation_technique"
          ]
        }
      ]
    },
    {
      "id": "D3-ISVA",
      "name": "Inbound Session Volume Analysis",
      "via_techniques": [
        "T1190",
        "T1499"
      ],
      "relationship": "analyzes",
      "mapping_source": "CVE→technique: MITRE CTID Mappings Explorer (KEV); technique→D3FEND: MITRE D3FEND (CTID technique, then D3FEND: derived)",
      "tier": "derived",
      "technique_links": [
        {
          "id": "T1190",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "exploitation_technique"
          ]
        },
        {
          "id": "T1499",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "primary_impact"
          ]
        }
      ]
    },
    {
      "id": "D3-ITF",
      "name": "Inbound Traffic Filtering",
      "via_techniques": [
        "T1190",
        "T1499"
      ],
      "relationship": "filters",
      "mapping_source": "CVE→technique: MITRE CTID Mappings Explorer (KEV); technique→D3FEND: MITRE D3FEND (CTID technique, then D3FEND: derived)",
      "tier": "derived",
      "technique_links": [
        {
          "id": "T1190",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "exploitation_technique"
          ]
        },
        {
          "id": "T1499",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "primary_impact"
          ]
        }
      ]
    },
    {
      "id": "D3-NTCD",
      "name": "Network Traffic Community Deviation",
      "via_techniques": [
        "T1190",
        "T1499"
      ],
      "relationship": "analyzes",
      "mapping_source": "CVE→technique: MITRE CTID Mappings Explorer (KEV); technique→D3FEND: MITRE D3FEND (CTID technique, then D3FEND: derived)",
      "tier": "derived",
      "technique_links": [
        {
          "id": "T1190",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "exploitation_technique"
          ]
        },
        {
          "id": "T1499",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "primary_impact"
          ]
        }
      ]
    },
    {
      "id": "D3-NTF",
      "name": "Network Traffic Filtering",
      "via_techniques": [
        "T1190",
        "T1499"
      ],
      "relationship": "filters",
      "mapping_source": "CVE→technique: MITRE CTID Mappings Explorer (KEV); technique→D3FEND: MITRE D3FEND (CTID technique, then D3FEND: derived)",
      "tier": "derived",
      "technique_links": [
        {
          "id": "T1190",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "exploitation_technique"
          ]
        },
        {
          "id": "T1499",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "primary_impact"
          ]
        }
      ]
    },
    {
      "id": "D3-NTSA",
      "name": "Network Traffic Signature Analysis",
      "via_techniques": [
        "T1190",
        "T1499"
      ],
      "relationship": "analyzes",
      "mapping_source": "CVE→technique: MITRE CTID Mappings Explorer (KEV); technique→D3FEND: MITRE D3FEND (CTID technique, then D3FEND: derived)",
      "tier": "derived",
      "technique_links": [
        {
          "id": "T1190",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "exploitation_technique"
          ]
        },
        {
          "id": "T1499",
          "source": "MITRE CTID Mappings Explorer (KEV)",
          "tier": "official",
          "mapping_type": [
            "primary_impact"
          ]
        }
      ]
    },
    "... 6 more"
  ],
  "meta": {
    "query": {
      "cve_id": "CVE-2023-44487"
    },
    "source": "entity_index.json",
    "count": 14,
    "techniques": [
      "T1190",
      "T1499"
    ],
    "path": "cve -> technique -> defend; each defense carries the weakest tier on its path"
  }
}
```

## Step 6: Is it in CISA KEV, and how urgent is the patch?

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
    "ssvc": {
      "ssvcExploitStatus": "active",
      "ssvcAutomatable": "yes",
      "ssvcTechnicalImpact": "partial"
    },
    "epss": {
      "score": 0.99999,
      "percentile": 0.99998,
      "date": "2026-09-26",
      "model_version": "v2026.06.15"
    }
  },
  "meta": {
    "kev_source": "kev_db.json",
    "ssvc_source": "entity_index.json",
    "epss_source": "epss_curated.json",
    "in_entity_graph": true
  }
}
```
