
from dataclasses import dataclass
from pathlib import Path
import os
import yaml
import glob
import datetime
import json
import shutil
import stat

DATA_DIR = Path(__file__).parent.parent / "data"
SIGNATURES_PATH = DATA_DIR / "signatures.yml"
EXCLUSIONS_PATH = DATA_DIR / "exclusions.yml"
REPORTS_DIR = Path.cwd() / "reports"
QUARANTINE_DIR = REPORTS_DIR / "quarantine"

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
	with open(report_path, "w", encoding="utf-8") as f:
		json.dump([t.__dict__ for t in targets], f, indent=2)
	return str(report_path)

def execute_cleanup(categories, dry_run: bool = False):
	# Move files to a timestamped quarantine directory and record rollback metadata
	sigs = _load_yaml(SIGNATURES_PATH)
	excls = _load_yaml(EXCLUSIONS_PATH)
	exclusions = excls.get("paths", []) if isinstance(excls, dict) else []
	REPORTS_DIR.mkdir(exist_ok=True)
	if not dry_run:
		QUARANTINE_DIR.mkdir(exist_ok=True)
	# Enumerate
	targets = enumerate_targets(categories)
	if not targets:
		return {
			"moved": 0,
			"failed": 0,
			"cleanup_report": None,
			"rollback_file": None,
			"dry_run": dry_run,
		}
	# Timestamped run dir
	ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
	run_dir = QUARANTINE_DIR / ts
	if not dry_run:
		run_dir.mkdir(parents=True, exist_ok=True)

	results = []
	rollback_entries = []
	idx = 0
	for t in targets:
		src = t.path
		# Ensure path is a file and still exists
		if not os.path.isfile(src):
			results.append({"src": src, "dst": None, "size": t.size, "ok": False, "error": "not a file"})
			continue
		# Destination in quarantine
		idx += 1
		dst = str(run_dir / f"{idx:06d}_{os.path.basename(src)}")
		ok = False
		err = None
		if dry_run:
			ok = True
		else:
			try:
				# Make file writable in case of read-only attribute
				try:
					os.chmod(src, stat.S_IWRITE)
				except Exception:
					pass
				# Move into quarantine
				shutil.move(src, dst)
				ok = True
			except Exception as e:
				err = str(e)
		results.append({"src": src, "dst": dst if ok else None, "size": t.size, "ok": ok, "error": err})
		if ok and not dry_run:
			rollback_entries.append({"src": src, "dst": dst, "size": t.size})

	# Write cleanup audit and rollback files
	action = "cleanup_dryrun" if dry_run else "cleanup"
	cleanup_report = REPORTS_DIR / f"{action}_{ts}.json"
	with open(cleanup_report, "w", encoding="utf-8") as f:
		json.dump(results, f, indent=2)
	rollback_file = None
	if not dry_run:
		rollback_file = REPORTS_DIR / f"rollback_{ts}.json"
		with open(rollback_file, "w", encoding="utf-8") as f:
			json.dump(rollback_entries, f, indent=2)

	return {
		"moved": sum(1 for r in results if r.get("ok")),
		"failed": sum(1 for r in results if not r.get("ok")),
		"cleanup_report": str(cleanup_report),
		"rollback_file": str(rollback_file) if rollback_file else None,
		"dry_run": dry_run,
	}

def find_latest_rollback():
	REPORTS_DIR.mkdir(exist_ok=True)
	files = sorted(REPORTS_DIR.glob("rollback_*.json"))
	return str(files[-1]) if files else ""

def execute_rollback(rollback_path: str | None = None, dry_run: bool = False):
	# Restore files from quarantine using a rollback mapping file
	if not rollback_path:
		rollback_path = find_latest_rollback()
	if not rollback_path:
		return {"restored": 0, "failed": 0, "restore_report": None, "dry_run": dry_run}
	try:
		with open(rollback_path, "r", encoding="utf-8") as f:
			entries = json.load(f)
	except Exception:
		entries = []
	results = []
	for e in entries:
		src = e.get("src")  # original location
		dst = e.get("dst")  # quarantine file
		ok = False
		err = None
		if dry_run:
			# Assume would restore if mapping exists
			ok = True
		else:
			try:
				if not dst or not os.path.isfile(dst):
					raise FileNotFoundError("quarantined file not found")
				Path(src).parent.mkdir(parents=True, exist_ok=True)
				# If destination exists already, replace it
				if os.path.exists(src):
					# Move existing to a side name to prevent overwrite loss
					side = src + ".pcsuite.bak"
					try:
						shutil.move(src, side)
					except Exception:
						pass
				shutil.move(dst, src)
				ok = True
			except Exception as ex:
				err = str(ex)
		results.append({"src": src, "from": dst, "ok": ok, "error": err})

	ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
	action = "restore_dryrun" if dry_run else "restore"
	restore_report = REPORTS_DIR / f"{action}_{ts}.json"
	with open(restore_report, "w", encoding="utf-8") as f:
		json.dump(results, f, indent=2)
	return {
		"restored": sum(1 for r in results if r.get("ok")),
		"failed": sum(1 for r in results if not r.get("ok")),
		"restore_report": str(restore_report),
		"dry_run": dry_run,
	}
