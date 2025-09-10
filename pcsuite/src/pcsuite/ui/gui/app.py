import tkinter as tk
from tkinter import ttk, messagebox
from typing import List
import threading
import sys

from pcsuite.core import fs, shell as core_shell


DEFAULT_CATEGORIES = ["temp", "browser", "dumps", "do", "recycle"]
SCOPES = ("auto", "user", "all")


class PCSuiteGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("PCSuite")
        self.geometry("900x600")
        self._build_ui()

    def _build_ui(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)

        self.clean_tab = ttk.Frame(nb)
        self.system_tab = ttk.Frame(nb)
        self.security_tab = ttk.Frame(nb)

        nb.add(self.clean_tab, text="Clean")
        nb.add(self.system_tab, text="System")
        nb.add(self.security_tab, text="Security")

        # Clean tab
        self._build_clean_tab(self.clean_tab)
        self._build_system_tab(self.system_tab)
        self._build_security_tab(self.security_tab)

    def _build_clean_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        # Categories
        cat_frame = ttk.LabelFrame(top, text="Categories")
        cat_frame.pack(side=tk.LEFT, padx=10)
        self.cat_vars = {}
        for i, c in enumerate(DEFAULT_CATEGORIES):
            v = tk.BooleanVar(value=c in ("temp", "browser", "dumps"))
            self.cat_vars[c] = v
            cb = ttk.Checkbutton(cat_frame, text=c, variable=v)
            cb.grid(row=i, column=0, sticky="w")

        # Scope
        right = ttk.Frame(top)
        right.pack(side=tk.LEFT, padx=20)
        ttk.Label(right, text="Scope:").grid(row=0, column=0, sticky="w")
        self.scope_var = tk.StringVar(value="auto")
        scope_box = ttk.Combobox(right, textvariable=self.scope_var, values=SCOPES, state="readonly", width=10)
        scope_box.grid(row=0, column=1, padx=5)

        # Buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(side=tk.TOP, fill=tk.X, padx=10)
        ttk.Button(btn_frame, text="Preview", command=self.on_preview).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Run Cleanup", command=self.on_run).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Rollback Latest", command=self.on_rollback).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Purge (Dry-Run)", command=lambda: self.on_purge(dry=True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Purge (Apply)", command=lambda: self.on_purge(dry=False)).pack(side=tk.LEFT, padx=5)

        # Output box
        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.output = tk.Text(out_frame, wrap="word")
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(out_frame, command=self.output.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.output.config(yscrollcommand=sb.set)

    def _build_system_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        ttk.Button(top, text="Refresh Info", command=self.on_sys_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Refresh Drives", command=self.on_sys_drives).pack(side=tk.LEFT, padx=5)

        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.sys_output = tk.Text(out_frame, wrap="none")
        self.sys_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ssb = ttk.Scrollbar(out_frame, command=self.sys_output.yview)
        ssb.pack(side=tk.RIGHT, fill=tk.Y)
        self.sys_output.config(yscrollcommand=ssb.set)

    def _build_security_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        ttk.Button(top, text="Audit", command=self.on_sec_audit).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Ports (limit 50)", command=self.on_sec_ports).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Defender Quick Scan", command=self.on_sec_def_scan).pack(side=tk.LEFT, padx=5)
        self.restart_explorer_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Restart Explorer after minimal apply", variable=self.restart_explorer_var).pack(side=tk.LEFT, padx=10)

        btn2 = ttk.Frame(parent)
        btn2.pack(side=tk.TOP, fill=tk.X, padx=10)
        ttk.Button(btn2, text="Harden Minimal (What-if)", command=lambda: self.on_sec_harden_minimal(False)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn2, text="Harden Minimal (Apply)", command=lambda: self.on_sec_harden_minimal(True)).pack(side=tk.LEFT, padx=5)

        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.sec_output = tk.Text(out_frame, wrap="none")
        self.sec_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        s2 = ttk.Scrollbar(out_frame, command=self.sec_output.yview)
        s2.pack(side=tk.RIGHT, fill=tk.Y)
        self.sec_output.config(yscrollcommand=s2.set)

    def _selected_categories(self) -> List[str]:
        return [c for c, v in self.cat_vars.items() if v.get()]

    def _append(self, text: str) -> None:
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def _append_sys(self, text: str) -> None:
        self.sys_output.insert(tk.END, text + "\n")
        self.sys_output.see(tk.END)

    def _append_sec(self, text: str) -> None:
        self.sec_output.insert(tk.END, text + "\n")
        self.sec_output.see(tk.END)

    def on_preview(self) -> None:
        cats = self._selected_categories()
        scope = self.scope_var.get()
        self._append(f"Previewing categories={cats} scope={scope} ...")

        def task():
            try:
                targets = fs.enumerate_targets(cats, scope=scope)
                total = sum(t.size for t in targets)
                report = fs.write_audit_report(targets, action="preview")
                self._append(f"Targets: {len(targets)}, Total bytes: {total:,}")
                self._append(f"Audit report: {report}")
            except Exception as e:
                messagebox.showerror("Preview failed", str(e))

        threading.Thread(target=task, daemon=True).start()

    def _run_cli(self, args: list[str]):
        # Run the CLI module via the current Python interpreter directly (no shell)
        return core_shell.run([sys.executable, "-m", "pcsuite.cli.main", *args])

    def on_sys_info(self) -> None:
        self.sys_output.delete("1.0", tk.END)
        self._append_sys("Loading system info ...")

        def task():
            code, out, err = self._run_cli(["system", "info"])
            if code == 0:
                self._append_sys(out.strip())
            else:
                messagebox.showerror("System Info failed", err or out)

        threading.Thread(target=task, daemon=True).start()

    def on_sys_drives(self) -> None:
        self.sys_output.delete("1.0", tk.END)
        self._append_sys("Loading drives ...")

        def task():
            code, out, err = self._run_cli(["system", "drives"])
            if code == 0:
                self._append_sys(out.strip())
            else:
                messagebox.showerror("Drives failed", err or out)

        threading.Thread(target=task, daemon=True).start()

    def on_sec_audit(self) -> None:
        self.sec_output.delete("1.0", tk.END)
        self._append_sec("Running security audit ...")

        def task():
            code, out, err = self._run_cli(["security", "audit"])
            if code == 0:
                self._append_sec(out.strip())
            else:
                messagebox.showerror("Audit failed", err or out)

        threading.Thread(target=task, daemon=True).start()

    def on_sec_ports(self) -> None:
        self.sec_output.delete("1.0", tk.END)
        self._append_sec("Listing ports ...")

        def task():
            code, out, err = self._run_cli(["security", "ports", "--limit", "50"])
            if code == 0:
                self._append_sec(out.strip())
            else:
                messagebox.showerror("Ports failed", err or out)

        threading.Thread(target=task, daemon=True).start()

    def on_sec_def_scan(self) -> None:
        self._append_sec("Starting Defender quick scan ...")

        def task():
            code, out, err = self._run_cli(["security", "defender-scan"])
            if code == 0:
                self._append_sec(out.strip() or "Scan command sent")
            else:
                messagebox.showerror("Defender scan failed", err or out)

        threading.Thread(target=task, daemon=True).start()

    def on_sec_harden_minimal(self, apply: bool) -> None:
        self._append_sec(f"Harden minimal (apply={apply}) ...")

        def task():
            args = ["security", "harden", "--profile", "minimal"]
            if apply:
                args += ["--apply", "--yes"]
                if self.restart_explorer_var.get():
                    args += ["--restart-explorer"]
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_sec(out.strip())
            else:
                messagebox.showerror("Harden failed", err or out)

        threading.Thread(target=task, daemon=True).start()

    def on_run(self) -> None:
        if not messagebox.askyesno("Confirm Cleanup", "Move files to quarantine? You can rollback later."):
            return
        cats = self._selected_categories()
        scope = self.scope_var.get()
        self._append(f"Running cleanup categories={cats} scope={scope} ...")

        def task():
            try:
                res = fs.execute_cleanup(cats, dry_run=False, scope=scope)
                self._append(f"Moved: {res['moved']}, Failed: {res['failed']}")
                self._append(f"Cleanup report: {res['cleanup_report']}")
                self._append(f"Rollback file: {res['rollback_file']}")
            except Exception as e:
                messagebox.showerror("Cleanup failed", str(e))

        threading.Thread(target=task, daemon=True).start()

    def on_rollback(self) -> None:
        if not messagebox.askyesno("Confirm Rollback", "Restore files from latest quarantine run?"):
            return
        self._append("Rolling back latest run ...")

        def task():
            try:
                res = fs.execute_rollback(None, dry_run=False)
                self._append(f"Restored: {res['restored']}, Failed: {res['failed']}")
                self._append(f"Restore report: {res['restore_report']}")
            except Exception as e:
                messagebox.showerror("Rollback failed", str(e))

        threading.Thread(target=task, daemon=True).start()

    def on_purge(self, dry: bool) -> None:
        if not dry:
            if not messagebox.askyesno("Confirm Purge", "Permanently delete quarantined files from latest run? This cannot be undone."):
                return
        self._append(f"Purging quarantine (dry_run={dry}) ...")

        def task():
            try:
                res = fs.purge_quarantine(run=None, all_runs=False, older_than_days=None, dry_run=dry)
                self._append(f"Target runs: {len(res['target_runs'])}, Freed bytes: {res['freed_bytes']:,}")
                self._append(f"Purge report: {res['purge_report']}")
            except Exception as e:
                messagebox.showerror("Purge failed", str(e))

        threading.Thread(target=task, daemon=True).start()


def launch_gui():
    app = PCSuiteGUI()
    app.mainloop()


def main():
    launch_gui()
