import subprocess
from typing import Tuple


def run(cmd: list[str], shell: bool = False, timeout: int | None = None) -> Tuple[int, str, str]:
    """Run a command and capture exit code, stdout, stderr."""
    try:
        cp = subprocess.run(
            cmd if not shell else " ".join(cmd),
            shell=shell,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return cp.returncode, cp.stdout, cp.stderr
    except Exception as e:
        return 1, "", str(e)


def pwsh(command: str, timeout: int | None = None) -> Tuple[int, str, str]:
    """Run a PowerShell command and return (code, out, err)."""
    return run(["powershell", "-NoProfile", "-Command", command], timeout=timeout)


def cmdline(command: str, timeout: int | None = None) -> Tuple[int, str, str]:
    return run(["cmd", "/c", command], timeout=timeout)
