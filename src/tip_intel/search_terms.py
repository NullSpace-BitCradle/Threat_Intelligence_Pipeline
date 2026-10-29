"""Search tokenizer shared by the entity-index generator and the MCP search,
so a query splits on the same punctuation the index was built with. Pure
stdlib.
"""
import re


def tokenize_name(name: str) -> list[str]:
    """Split a name into lowercase search tokens (words 3+ chars)."""
    if not name:
        return []
    words = re.split(r"[\s\-_/,.:;()\[\]]+", name.lower())
    return [w for w in words if len(w) >= 3]
