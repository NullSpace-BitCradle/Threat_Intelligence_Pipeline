"""I21 F2: the inferred technique tier (ISC-4, ISC-5, ISC-6).

Each inference rule has a test; inference fills only a CVE with no technique
from CTID, the CWE chain, or an inherited parent; no vector, or one the rules
do not cover, gets nothing.
"""
import pytest

from tip.core import technique_inference as ti
from tip.core.ctid_processor import SOURCE as CTID_SOURCE

V31 = "CVSS:3.1/AV:{av}/AC:L/PR:N/UI:{ui}/S:U/C:{c}/I:{i}/A:H"
V40 = "CVSS:4.0/AV:{av}/AC:L/AT:N/PR:N/UI:{ui}/VC:{c}/VI:{i}/VA:H/SC:N/SI:N/SA:N"


def v31(av="N", ui="N", c="H", i="H"):
    return V31.format(av=av, ui=ui, c=c, i=i)


def v40(av="N", ui="N", c="H", i="H"):
    return V40.format(av=av, ui=ui, c=c, i=i)


# ── ISC-4: one test per rule, v3 and v4 ─────────────────────────────


@pytest.mark.parametrize("vector", [v31(), "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N", v40()])
def test_network_without_interaction_is_t1190(vector):
    assert ti.infer_rule(vector) == "network-no-interaction"
    (link,) = ti.inferred_links([], vector)
    assert link["id"] == "T1190"
    assert link["rule"] == "network-no-interaction"
    assert "AV:N and UI:N" in link["source"]


@pytest.mark.parametrize("vector", [
    v31(ui="R"), v31(av="L", ui="R"), v31(av="A", ui="R"),
    v40(ui="P"), v40(av="L", ui="A"),
])
def test_user_interaction_is_t1203(vector):
    assert ti.infer_rule(vector) == "user-interaction"
    assert ti.inferred_links([], vector)[0]["id"] == "T1203"


@pytest.mark.parametrize("vector", [v31(av="L"), v40(av="L")])
def test_local_full_impact_is_t1068(vector):
    assert ti.infer_rule(vector) == "local-full-impact"
    assert ti.inferred_links([], vector)[0]["id"] == "T1068"


@pytest.mark.parametrize("vector", [
    v31(av="L", c="H", i="N"),   # local read only: impact does not support escalation
    v31(av="L", c="N", i="H"),
    v40(av="L", c="L", i="H"),
])
def test_local_without_full_impact_gets_nothing(vector):
    assert ti.infer_rule(vector) is None


def test_each_rule_names_its_technique_in_one_line():
    for rule, (tech, name, cond) in ti.RULES.items():
        src = ti.rule_source(rule)
        assert tech in src and cond in src and "\n" not in src


# ── ISC-5: inference fills only an empty slot ───────────────────────


@pytest.mark.parametrize("sourced", [["T1059"], ["1059"], ["t1059.001"]])
def test_any_sourced_technique_blocks_inference(sourced):
    assert ti.inferred_links(sourced, v31()) == []


def test_chain_technique_blocks_inference():
    out = ti.extra_technique_links(["1059"], [], None, v31())
    assert out["TECHNIQUES_INFERRED"] == []


def test_inherited_technique_blocks_inference():
    out = ti.extra_technique_links([], ["T1134"], None, v31())
    assert out["TECHNIQUES_INFERRED"] == []


def test_ctid_technique_blocks_inference_and_is_recorded():
    entry = {"group": "xxe", "techniques": [
        {"id": "T1190", "mapping_type": ["exploitation_technique"], "comment": "XXE"},
        {"id": "T1005", "mapping_type": ["secondary_impact"], "comment": None},
    ]}
    out = ti.extra_technique_links([], [], entry, v31(ui="R"))
    assert out["TECHNIQUES_INFERRED"] == []
    assert out["TECHNIQUES_CTID"] == [
        {"id": "T1190", "mapping_type": ["exploitation_technique"], "source": CTID_SOURCE, "comment": "XXE"},
        {"id": "T1005", "mapping_type": ["secondary_impact"], "source": CTID_SOURCE},
    ]


def test_empty_slot_is_filled():
    out = ti.extra_technique_links([], [], None, v31())
    assert out["TECHNIQUES_CTID"] == []
    assert [t["id"] for t in out["TECHNIQUES_INFERRED"]] == ["T1190"]


def test_garbage_sourced_ids_do_not_block():
    assert ti.inferred_links(["", "not-a-technique"], v31())[0]["id"] == "T1190"


# ── ISC-6: no vector, or an uncovered one, gets nothing ─────────────


@pytest.mark.parametrize("vector", [
    None, "", 7.5,
    "AV:N/AC:L/Au:N/C:P/I:P/A:P",           # CVSS v2: no user interaction metric
    v31(av="P"), v31(av="P", ui="R"), v40(av="P", ui="P"),
    v31(av="A"),                            # adjacent, no interaction
    "CVSS:3.1/AV:N/AC:L/PR:N/S:U/C:H/I:H/A:H",   # UI missing
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:Z/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/garbage",
    "CVSS:2.0/AV:N/UI:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # R is not a v4 value
])
def test_uncovered_vector_gets_nothing(vector):
    assert ti.infer_rule(vector) is None
    assert ti.inferred_links([], vector) == []
    assert ti.extra_technique_links([], [], None, vector)["TECHNIQUES_INFERRED"] == []
