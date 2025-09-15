from __future__ import annotations
from typing import List, Dict, Any
import re
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


def match_block(event: Dict[str, Any], det: Dict[str, Any]) -> bool:
    """Very small Sigma-like matcher.

    Supports detection:
      contains: { field: [substr, ...] }
      equals: { field: [value, ...] }
      startswith/endswith/regex similarly
    """
    contains = det.get("contains") or {}
    equals = det.get("equals") or {}
    startswith = det.get("startswith") or {}
    endswith = det.get("endswith") or {}
    regex = det.get("regex") or {}
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
    # startswith
    for field, values in (startswith.items() if isinstance(startswith, dict) else []):
        fv = _field_get(event, field)
        ok = any(fv.startswith(str(v)) for v in (values or []))
        if not ok:
            return False
    # endswith
    for field, values in (endswith.items() if isinstance(endswith, dict) else []):
        fv = _field_get(event, field)
        ok = any(fv.endswith(str(v)) for v in (values or []))
        if not ok:
            return False
    # regex
    for field, values in (regex.items() if isinstance(regex, dict) else []):
        fv = _field_get(event, field)
        ok = False
        for pat in (values or []):
            try:
                if re.search(str(pat), fv):
                    ok = True
                    break
            except re.error:
                continue
        if not ok:
            return False
    return True if (contains or equals or startswith or endswith or regex) else False


def match_event(event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    det = rule.get("detection") or {}
    if not isinstance(det, dict):
        return False
    if "all" in det and isinstance(det["all"], list):
        # AND across a list of detection blocks
        for blk in det["all"]:
            if not isinstance(blk, dict):
                return False
            if not match_block(event, blk):
                return False
        return True
    if "any" in det and isinstance(det["any"], list):
        # OR across blocks
        for blk in det["any"]:
            if isinstance(blk, dict) and match_block(event, blk):
                return True
        return False
    # Flat single block
    return match_block(event, det)


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
            matches.append({
                "rule": str(title),
                "count": count,
                "sample": first or {},
                "severity": r.get("severity"),
                "action": r.get("action"),
                "path": r.get("__path"),
            })
    return matches
