
from dataclasses import dataclass
from pathlib import Path
import os
import yaml
import glob
import datetime

DATA_DIR = Path(__file__).parent.parent / "data"
SIGNATURES_PATH = DATA_DIR / "signatures.yml"
EXCLUSIONS_PATH = DATA_DIR / "exclusions.yml"
REPORTS_DIR = Path.cwd() / "reports"

@dataclass
class Target:
	path: str
	size: int

def _load_yaml(path):
	if not path.exists():
		return {}
	with open(path, "r", encoding="utf-8") as f:
		return yaml.safe_load(f) or {}

def _expand_env_glob(pattern):
	# Expand environment variables and glob
	expanded = os.path.expandvars(pattern)
	return glob.glob(expanded, recursive=True)

def _is_excluded(path, exclusions):
	# Simple exclusion check (can be improved)
	for ex in exclusions:
		if Path(path).match(ex):
			return True
	return False

def enumerate_targets(categories):
	sigs = _load_yaml(SIGNATURES_PATH)
	excls = _load_yaml(EXCLUSIONS_PATH)
	exclusions = excls.get("paths", []) if isinstance(excls, dict) else []
	targets = []
	if not sigs or "categories" not in sigs:
		return []
	for cat in categories:
		cat = cat.strip()
		catdef = sigs["categories"].get(cat)
		if not catdef:
			continue
		globs = catdef.get("globs", [])
		for pattern in globs:
			for fpath in _expand_env_glob(pattern):
				if not os.path.isfile(fpath):
					continue
				if _is_excluded(fpath, exclusions):
					continue
				try:
					size = os.path.getsize(fpath)
				except Exception:
					size = 0
				targets.append(Target(path=fpath, size=size))
	return targets

def write_audit_report(targets, action="preview"):
	REPORTS_DIR.mkdir(exist_ok=True)
	ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
	report_path = REPORTS_DIR / f"{action}_{ts}.json"
	import json
	with open(report_path, "w", encoding="utf-8") as f:
		json.dump([t.__dict__ for t in targets], f, indent=2)
	return str(report_path)

def execute_cleanup(categories):
	# TODO: honor dry-run flag elsewhere; perform deletions + quarantine
	pass
