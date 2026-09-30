"""Deterministic retrieval over the bundled local cybersecurity knowledge catalog."""

import json
import re
import unicodedata
from pathlib import Path
from typing import Any


KNOWLEDGE_PATH = Path(__file__).resolve().parents[2] / "data" / "cybersecurity_knowledge.json"
_WORDS = re.compile(r"[a-z0-9]+(?:\.[a-z0-9]+)*")


def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(_WORDS.findall(normalized))


def _load_entries() -> list[dict[str, Any]]:
    try:
        with KNOWLEDGE_PATH.open("r", encoding="utf-8-sig") as source:
            entries = json.load(source)
    except (OSError, json.JSONDecodeError):
        return []
    return entries if isinstance(entries, list) else []


def _relevance(query: str, entry: dict[str, Any]) -> float:
    score = 0.0
    entry_id = str(entry.get("id", "")).casefold()
    if entry_id and re.search(rf"(?<![a-z0-9]){re.escape(entry_id)}(?![a-z0-9.])", query):
        score += 100.0

    title = _normalize(str(entry.get("title", "")))
    if title and title in query:
        score += 10.0

    query_terms = set(_WORDS.findall(query))
    if title:
        score += 1.5 * len(query_terms.intersection(_WORDS.findall(title)))

    for keyword in entry.get("keywords", []):
        normalized_keyword = _normalize(str(keyword))
        if not normalized_keyword:
            continue
        if normalized_keyword in query:
            score += 3.0
        else:
            score += 1.0 * len(query_terms.intersection(_WORDS.findall(normalized_keyword)))
    return score


def retrieve_security_context(query: str, top_k: int = 3) -> list[dict[str, Any]]:
    """Return relevant local knowledge; these records are context, never incident evidence."""
    if not isinstance(query, str) or not query.strip() or not isinstance(top_k, int) or top_k <= 0:
        return []
    normalized_query = _normalize(query)
    if not normalized_query:
        return []

    ranked = []
    for entry in _load_entries():
        score = _relevance(normalized_query, entry)
        if score <= 0:
            continue
        ranked.append((score, str(entry.get("id", "")), entry))
    ranked.sort(key=lambda item: (-item[0], item[1]))

    return [
        {
            "id": entry["id"],
            "title": entry["title"],
            "description": entry["description"],
            "guidance": entry["guidance"],
            "relevance_score": score,
        }
        for score, _, entry in ranked[:top_k]
    ]