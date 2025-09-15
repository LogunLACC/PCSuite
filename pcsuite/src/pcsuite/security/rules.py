from __future__ import annotations
from typing import List, Dict, Any
from pathlib import Path
import yaml


def load_rules(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    files: List[Path] = []
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = [f for f in p.glob("*.yml")] + [f for f in p.glob("*.yaml")]
    rules: List[Dict[str, Any]] = []
    for f in files:
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                data["__path"] = str(f)
                rules.append(data)
        except Exception:
            continue
    return rules


def _field_get(event: Dict[str, Any], field: str) -> str:
    v = event.get(field)
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return ""


def match_event(event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """Very small Sigma-like matcher.

    Supports detection:
      contains: { field: [substr, ...] }
      equals: { field: [value, ...] }
    """
    det = rule.get("detection") or {}
    if not isinstance(det, dict):
        return False
    contains = det.get("contains") or {}
    equals = det.get("equals") or {}
    # contains
    for field, values in (contains.items() if isinstance(contains, dict) else []):
        fv = _field_get(event, field)
        ok = any(str(v).lower() in fv.lower() for v in (values or []))
        if not ok:
            return False
    # equals
    for field, values in (equals.items() if isinstance(equals, dict) else []):
        fv = _field_get(event, field)
        ok = any(str(v) == fv for v in (values or []))
        if not ok:
            return False
    return True if (contains or equals) else False


def evaluate_events(events: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for r in rules:
        title = r.get("title") or r.get("id") or Path(r.get("__path","rule.yml")).name
        count = 0
        first = None
        for e in events:
            if match_event(e, r):
                count += 1
                if first is None:
                    first = e
        if count:
            matches.append({"rule": str(title), "count": count, "sample": first or {}})
    return matches

