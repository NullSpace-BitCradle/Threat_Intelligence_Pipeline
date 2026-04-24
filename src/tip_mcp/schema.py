"""Response envelope helpers for TIP MCP tools.

Every tool returns either a success envelope {ok, data, meta?} or an error
envelope {ok: false, error: {code, message, hint?}}. Kept pure-stdlib so tests
can run without the mcp package installed.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional


class ErrorCode(str, Enum):
    """Stable error codes for tool responses."""

    NOT_FOUND = "not_found"
    INVALID_TYPE = "invalid_type"
    INDEX_NOT_LOADED = "index_not_loaded"
    BAD_PARAM = "bad_param"


def ok_response(data: Any, meta: Optional[dict] = None) -> dict:
    """Build a success envelope."""
    out: dict = {"ok": True, "data": data}
    if meta is not None:
        out["meta"] = meta
    return out


def error_response(
    code: "ErrorCode | str",
    message: str,
    hint: Optional[str] = None,
) -> dict:
    """Build an error envelope."""
    code_value = code.value if isinstance(code, ErrorCode) else str(code)
    err: dict = {"code": code_value, "message": message}
    if hint is not None:
        err["hint"] = hint
    return {"ok": False, "error": err}
