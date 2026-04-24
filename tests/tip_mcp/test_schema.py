"""Tests for tip_mcp.schema envelope helpers."""

from tip_mcp.schema import ErrorCode, error_response, ok_response


def test_ok_response_has_ok_true_and_data():
    resp = ok_response({"foo": "bar"})
    assert resp["ok"] is True
    assert resp["data"] == {"foo": "bar"}
    assert "error" not in resp


def test_ok_response_accepts_meta():
    resp = ok_response([1, 2, 3], meta={"count": 3})
    assert resp["meta"] == {"count": 3}


def test_ok_response_omits_meta_when_none():
    resp = ok_response({"x": 1})
    assert "meta" not in resp


def test_error_response_has_ok_false_and_code():
    resp = error_response(ErrorCode.NOT_FOUND, "missing")
    assert resp["ok"] is False
    assert resp["error"]["code"] == "not_found"
    assert resp["error"]["message"] == "missing"


def test_error_response_accepts_hint():
    resp = error_response(ErrorCode.BAD_PARAM, "bad", hint="try again")
    assert resp["error"]["hint"] == "try again"


def test_error_response_omits_hint_when_none():
    resp = error_response(ErrorCode.BAD_PARAM, "bad")
    assert "hint" not in resp["error"]


def test_error_response_accepts_string_code():
    resp = error_response("custom_code", "custom")
    assert resp["error"]["code"] == "custom_code"


def test_error_code_enum_membership():
    expected = {"not_found", "invalid_type", "index_not_loaded", "bad_param"}
    assert {e.value for e in ErrorCode} == expected
