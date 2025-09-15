import tkinter as tk
from tkinter import ttk, messagebox, filedialog
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
        self.edr_tab = ttk.Frame(nb)
        self.registry_tab = ttk.Frame(nb)
        self.drivers_tab = ttk.Frame(nb)
        self.optimize_tab = ttk.Frame(nb)
        self.process_tab = ttk.Frame(nb)
        self.services_tab = ttk.Frame(nb)
        self.schedule_tab = ttk.Frame(nb)

        nb.add(self.clean_tab, text="Clean")
        nb.add(self.system_tab, text="System")
        nb.add(self.security_tab, text="Security")
        nb.add(self.edr_tab, text="EDR")
        nb.add(self.registry_tab, text="Registry")
        nb.add(self.drivers_tab, text="Drivers")
        nb.add(self.optimize_tab, text="Optimize")
        nb.add(self.process_tab, text="Processes")
        nb.add(self.services_tab, text="Services")
        nb.add(self.schedule_tab, text="Schedule")

        # Clean tab
        self._build_clean_tab(self.clean_tab)
        self._build_system_tab(self.system_tab)
        self._build_security_tab(self.security_tab)
        self._build_edr_tab(self.edr_tab)
        self._build_registry_tab(self.registry_tab)
        self._build_drivers_tab(self.drivers_tab)
        self._build_optimize_tab(self.optimize_tab)
        self._build_process_tab(self.process_tab)
        self._build_services_tab(self.services_tab)
        self._build_schedule_tab(self.schedule_tab)

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

        # Firewall & reputation controls
        fw = ttk.Frame(parent)
        fw.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        ttk.Button(fw, text="Firewall Status", command=self.on_sec_fw_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(fw, text="Firewall Enable (Dry)", command=lambda: self.on_sec_fw_toggle(True, True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(fw, text="Firewall Disable (Dry)", command=lambda: self.on_sec_fw_toggle(False, True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(fw, text="Firewall Enable (Apply)", command=lambda: self.on_sec_fw_toggle(True, False)).pack(side=tk.LEFT, padx=5)
        ttk.Button(fw, text="Firewall Disable (Apply)", command=lambda: self.on_sec_fw_toggle(False, False)).pack(side=tk.LEFT, padx=5)

        rep = ttk.Frame(parent)
        rep.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        ttk.Label(rep, text="Reputation Path:").pack(side=tk.LEFT)
        self.rep_path = tk.Entry(rep, width=50)
        self.rep_path.pack(side=tk.LEFT, padx=5)
        ttk.Button(rep, text="Check", command=self.on_sec_reputation).pack(side=tk.LEFT, padx=5)

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

    # EDR tab
    def _build_edr_tab(self, parent: ttk.Frame) -> None:
        # Controls
        row1 = ttk.Frame(parent)
        row1.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)
        ttk.Button(row1, text="Status", command=self.on_edr_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(row1, text="Triage", command=self.on_edr_triage).pack(side=tk.LEFT, padx=5)
        ttk.Label(row1, text="Ports limit:").pack(side=tk.LEFT, padx=8)
        self.edr_ports_limit = tk.Entry(row1, width=6)
        self.edr_ports_limit.insert(0, "50")
        self.edr_ports_limit.pack(side=tk.LEFT)
        ttk.Button(row1, text="Ports", command=self.on_edr_ports).pack(side=tk.LEFT, padx=5)

        row2 = ttk.Frame(parent)
        row2.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)
        self.edr_isolate_enable = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Enable", variable=self.edr_isolate_enable).pack(side=tk.LEFT)
        self.edr_isolate_dry = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Dry-run", variable=self.edr_isolate_dry).pack(side=tk.LEFT, padx=6)
        self.edr_block_out = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Block Outbound", variable=self.edr_block_out).pack(side=tk.LEFT, padx=6)
        # Preset checkboxes
        self.preset_profile = tk.StringVar(value="none")
        ttk.Label(row2, text="Profile:").pack(side=tk.LEFT, padx=6)
        ttk.Combobox(row2, textvariable=self.preset_profile, values=("none","minimal","basic","enterprise"), state="readonly", width=12).pack(side=tk.LEFT)
        self.preset_ntp = tk.BooleanVar(value=False)
        self.preset_win = tk.BooleanVar(value=False)
        self.preset_msb = tk.BooleanVar(value=False)
        self.preset_m365 = tk.BooleanVar(value=False)
        self.preset_teams = tk.BooleanVar(value=False)
        self.preset_oned = tk.BooleanVar(value=False)
        self.preset_edge = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="NTP", variable=self.preset_ntp).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="WinUpdate", variable=self.preset_win).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="MS-Basic", variable=self.preset_msb).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="M365-Core", variable=self.preset_m365).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="Teams", variable=self.preset_teams).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="OneDrive", variable=self.preset_oned).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(row2, text="Edge Update", variable=self.preset_edge).pack(side=tk.LEFT, padx=4)
        ttk.Label(row2, text="DNS TTL(s):").pack(side=tk.LEFT, padx=6)
        self.edr_dns_ttl = tk.Entry(row2, width=6)
        self.edr_dns_ttl.insert(0, "3600")
        self.edr_dns_ttl.pack(side=tk.LEFT)
        ttk.Label(row2, text="+Extra hosts (comma):").pack(side=tk.LEFT, padx=6)
        self.edr_allow_extra = tk.Entry(row2, width=28)
        self.edr_allow_extra.pack(side=tk.LEFT)
        ttk.Button(row2, text="Preview Allowlist", command=self.on_edr_preview_allow).pack(side=tk.LEFT, padx=5)
        ttk.Button(row2, text="Isolate", command=self.on_edr_isolate).pack(side=tk.LEFT, padx=5)

        row3 = ttk.Frame(parent)
        row3.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)
        ttk.Label(row3, text="Rules path:").pack(side=tk.LEFT)
        self.edr_rules_path = tk.Entry(row3, width=40)
        self.edr_rules_path.pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Detect", command=self.on_edr_detect).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Browse File", command=self.on_edr_browse_rules_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Browse Folder", command=self.on_edr_browse_rules_dir).pack(side=tk.LEFT, padx=5)

        row4 = ttk.Frame(parent)
        row4.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)
        ttk.Label(row4, text="Quarantine file:").pack(side=tk.LEFT)
        self.edr_quar_path = tk.Entry(row4, width=40)
        self.edr_quar_path.pack(side=tk.LEFT, padx=5)
        self.edr_quar_dry = tk.BooleanVar(value=True)
        ttk.Checkbutton(row4, text="Dry-run", variable=self.edr_quar_dry).pack(side=tk.LEFT, padx=6)
        ttk.Button(row4, text="Quarantine", command=self.on_edr_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(row4, text="Browse", command=self.on_edr_browse_quar_file).pack(side=tk.LEFT, padx=5)

        # Watch controls
        row5 = ttk.LabelFrame(parent, text="Watch")
        row5.pack(side=tk.TOP, fill=tk.X, padx=10, pady=6)
        ttk.Label(row5, text="Interval (s):").pack(side=tk.LEFT)
        self.watch_interval = tk.Entry(row5, width=6)
        self.watch_interval.insert(0, "2.0")
        self.watch_interval.pack(side=tk.LEFT, padx=4)
        self.watch_sec = tk.BooleanVar(value=True)
        self.watch_ps = tk.BooleanVar(value=True)
        ttk.Checkbutton(row5, text="Security", variable=self.watch_sec).pack(side=tk.LEFT, padx=6)
        ttk.Checkbutton(row5, text="PowerShell", variable=self.watch_ps).pack(side=tk.LEFT, padx=6)
        ttk.Button(row5, text="Start", command=self.on_edr_watch_start).pack(side=tk.LEFT, padx=5)
        ttk.Button(row5, text="Stop", command=self.on_edr_watch_stop).pack(side=tk.LEFT, padx=5)

        # Agent policy (Auto-response & Sink)
        pol = ttk.LabelFrame(parent, text="Agent Policy & Sink")
        pol.pack(side=tk.TOP, fill=tk.X, padx=10, pady=6)
        self.auto_resp = tk.BooleanVar(value=False)
        ttk.Checkbutton(pol, text="Enable Auto-response", variable=self.auto_resp).pack(side=tk.LEFT, padx=6)
        self.auto_iso_block = tk.BooleanVar(value=True)
        ttk.Checkbutton(pol, text="Block Outbound", variable=self.auto_iso_block).pack(side=tk.LEFT, padx=6)
        self.auto_iso_dry = tk.BooleanVar(value=True)
        ttk.Checkbutton(pol, text="Dry-run", variable=self.auto_iso_dry).pack(side=tk.LEFT, padx=6)
        ttk.Label(pol, text="Heartbeat(s):").pack(side=tk.LEFT, padx=6)
        self.hb_interval = tk.Entry(pol, width=8)
        self.hb_interval.insert(0, "300")
        self.hb_interval.pack(side=tk.LEFT)

        sink = ttk.LabelFrame(parent, text="HTTP Sink")
        sink.pack(side=tk.TOP, fill=tk.X, padx=10, pady=6)
        ttk.Label(sink, text="URL:").pack(side=tk.LEFT)
        self.sink_url = tk.Entry(sink, width=40)
        self.sink_url.pack(side=tk.LEFT, padx=4)
        ttk.Label(sink, text="Token:").pack(side=tk.LEFT)
        self.sink_token = tk.Entry(sink, width=28)
        self.sink_token.pack(side=tk.LEFT, padx=4)
        self.sink_verify = tk.BooleanVar(value=True)
        ttk.Checkbutton(sink, text="Verify TLS", variable=self.sink_verify).pack(side=tk.LEFT, padx=6)
        ttk.Button(sink, text="Write Agent Config", command=self.on_agent_write_config).pack(side=tk.LEFT, padx=8)

        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.edr_output = tk.Text(out_frame, wrap="none")
        self.edr_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        eb = ttk.Scrollbar(out_frame, command=self.edr_output.yview)
        eb.pack(side=tk.RIGHT, fill=tk.Y)
        self.edr_output.config(yscrollcommand=eb.set)

    def _append_edr(self, text: str) -> None:
        self.edr_output.insert(tk.END, text + "\n")
        self.edr_output.see(tk.END)

    def on_edr_status(self) -> None:
        def task():
            code, out, err = self._run_cli(["edr", "status"])
            if code == 0:
                self._append_edr(out.strip())
            else:
                messagebox.showerror("EDR Status", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_edr_triage(self) -> None:
        def task():
            code, out, err = self._run_cli(["edr", "triage"])
            if code == 0:
                self._append_edr(out.strip())
            else:
                messagebox.showerror("EDR Triage", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_edr_ports(self) -> None:
        n = (self.edr_ports_limit.get() or "50").strip()
        if not n.isdigit():
            n = "50"
        def task():
            code, out, err = self._run_cli(["edr", "ports", "--limit", n])
            if code == 0:
                self._append_edr(out.strip())
            else:
                messagebox.showerror("EDR Ports", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_edr_isolate(self) -> None:
        enable = self.edr_isolate_enable.get()
        dry = self.edr_isolate_dry.get()
        def task():
            args = ["edr", "isolate", "--enable", str(enable)]
            if dry:
                args += ["--dry-run"]
            else:
                args += ["--no-dry-run"]
            if self.edr_block_out.get():
                args += ["--block-outbound"]
                prof = (self.preset_profile.get() or "none").strip().lower()
                if prof and prof != "none":
                    args += ["--profile", prof]
                if self.preset_ntp.get():
                    args += ["--preset", "ntp"]
                if self.preset_win.get():
                    args += ["--preset", "winupdate"]
                if self.preset_msb.get():
                    args += ["--preset", "microsoft-basic"]
                if self.preset_m365.get():
                    args += ["--preset", "m365-core"]
                if self.preset_teams.get():
                    args += ["--preset", "teams"]
                if self.preset_oned.get():
                    args += ["--preset", "onedrive"]
                if self.preset_edge.get():
                    args += ["--preset", "edge-update"]
                ttl = (self.edr_dns_ttl.get() or "").strip()
                try:
                    if ttl:
                        float(ttl)
                        args += ["--dns-ttl", ttl]
                except Exception:
                    pass
                extra = (self.edr_allow_extra.get() or "").strip()
                if extra:
                    for h in [x.strip() for x in extra.split(",") if x.strip()]:
                        args += ["--allow-host", h]
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_edr(out.strip())
            else:
                messagebox.showerror("EDR Isolate", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_edr_detect(self) -> None:
        path = (self.edr_rules_path.get() or "").strip()
        if not path:
            messagebox.showinfo("EDR Detect", "Enter rules file or directory path.")
            return
        def task():
            code, out, err = self._run_cli(["edr", "detect", "--rules", path])
            if code == 0:
                self._append_edr(out.strip())
            else:
                messagebox.showerror("EDR Detect", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_edr_quarantine(self) -> None:
        path = (self.edr_quar_path.get() or "").strip()
        if not path:
            messagebox.showinfo("Quarantine", "Enter a file path to quarantine.")
            return
        dry = self.edr_quar_dry.get()
        def task():
            args = ["edr", "quarantine-file", path]
            if dry:
                args += ["--dry-run"]
            else:
                args += ["--no-dry-run", "--yes"]
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_edr(out.strip())
            else:
                messagebox.showerror("Quarantine", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_edr_preview_allow(self) -> None:
        presets = []
        if self.preset_ntp.get(): presets.append("ntp")
        if self.preset_win.get(): presets.append("winupdate")
        if self.preset_msb.get(): presets.append("microsoft-basic")
        if self.preset_m365.get(): presets.append("m365-core")
        extra = (self.edr_allow_extra.get() or "").strip()
        args = ["edr", "allowlist"]
        prof = (self.preset_profile.get() or "none").strip().lower()
        if prof and prof != "none":
            args += ["--profile", prof]
        for p in presets:
            args += ["--preset", p]
        ttl = (self.edr_dns_ttl.get() or "").strip()
        try:
            if ttl:
                float(ttl)
                args += ["--dns-ttl", ttl]
        except Exception:
            pass
        if extra:
            for h in [x.strip() for x in extra.split(",") if x.strip()]:
                args += ["--allow-host", h]
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_edr(out.strip())
            else:
                messagebox.showerror("Allowlist", err or out)
        threading.Thread(target=task, daemon=True).start()

    # Watch support
    def on_edr_watch_start(self) -> None:
        try:
            import threading as _t
            from pcsuite.security import logs as _logs
            from pcsuite.security import rules as _rules
        except Exception as e:
            messagebox.showerror("Watch", str(e)); return
        path = (self.edr_rules_path.get() or "").strip()
        if not path:
            messagebox.showinfo("Watch", "Enter rules file or directory."); return
        try:
            interval = float((self.watch_interval.get() or "2.0"))
        except Exception:
            interval = 2.0
        rules = _rules.load_rules(path)
        self._append_edr(f"Loaded {len(rules)} rule(s) from {path}")
        self._watch_stop = _t.Event()
        self._watch_last = {"security": 0, "powershell": 0}
        def loop():
            while not self._watch_stop.is_set():
                evs = []
                if self.watch_sec.get():
                    d, self._watch_last["security"] = _logs.delta_security_events(self._watch_last["security"])
                    evs.extend(d)
                if self.watch_ps.get():
                    d, self._watch_last["powershell"] = _logs.delta_powershell_events(self._watch_last["powershell"])
                    evs.extend(d)
                if evs:
                    matches = _rules.evaluate_events(evs, rules)
                    if matches:
                        self._append_edr(f"Matches: {len(matches)}")
                        for m in matches:
                            self._append_edr(f"- {m.get('rule')}: {m.get('count')}")
                self._watch_stop.wait(interval if interval > 0.2 else 0.2)
        self._watch_thread = _t.Thread(target=loop, daemon=True)
        self._watch_thread.start()

    def on_edr_watch_stop(self) -> None:
        st = getattr(self, "_watch_stop", None)
        th = getattr(self, "_watch_thread", None)
        if st:
            try:
                st.set()
            except Exception:
                pass
        if th:
            try:
                th.join(timeout=0.1)
            except Exception:
                pass

    def on_agent_write_config(self) -> None:
        # Compose agent configure args from GUI fields
        args = ["edr", "agent", "configure"]
        # rules path
        rpath = (self.edr_rules_path.get() or "").strip()
        if rpath:
            args += ["--rules", rpath]
        # interval for watch loop
        interval = (self.watch_interval.get() or "2.0").strip()
        try:
            float(interval)
            args += ["--interval", interval]
        except Exception:
            pass
        # sources
        sources = []
        if self.watch_sec.get(): sources.append("security")
        if self.watch_ps.get(): sources.append("powershell")
        if sources:
            args += ["--sources", ",".join(sources)]
        # auto-response config
        if self.auto_resp.get():
            args += ["--auto-response"]
            prof = (self.preset_profile.get() or "none").strip().lower()
            if prof and prof != "none":
                args += ["--isolate-profile", prof]
            if self.preset_ntp.get(): args += ["--isolate-preset", "ntp"]
            if self.preset_win.get(): args += ["--isolate-preset", "winupdate"]
            if self.preset_msb.get(): args += ["--isolate-preset", "microsoft-basic"]
            if self.preset_m365.get(): args += ["--isolate-preset", "m365-core"]
            if self.preset_teams.get(): args += ["--isolate-preset", "teams"]
            if self.preset_oned.get(): args += ["--isolate-preset", "onedrive"]
            if self.preset_edge.get(): args += ["--isolate-preset", "edge-update"]
            if self.edr_block_out.get(): args += ["--isolate-block-out"]
            if self.auto_iso_dry.get(): args += ["--isolate-dry-run"]
            ttl = (self.edr_dns_ttl.get() or "").strip()
            try:
                if ttl:
                    float(ttl)
                    args += ["--isolate-dns-ttl", ttl]
            except Exception:
                pass
        # sink
        url = (self.sink_url.get() or "").strip()
        if url:
            args += ["--sink-url", url]
        token = (self.sink_token.get() or "").strip()
        if token:
            args += ["--sink-token", token]
        if not self.sink_verify.get():
            args += ["--no-sink-verify"]
        hb = (self.hb_interval.get() or "").strip()
        try:
            if hb:
                float(hb)
                args += ["--heartbeat-interval", hb]
        except Exception:
            pass
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_edr(out.strip() or "Agent config written")
            else:
                messagebox.showerror("Agent Config", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_edr_browse_rules_file(self) -> None:
        path = filedialog.askopenfilename(title="Select rules file", filetypes=[("YAML files", "*.yml *.yaml"), ("All files", "*.*")])
        if path:
            self.edr_rules_path.delete(0, tk.END)
            self.edr_rules_path.insert(0, path)

    def on_edr_browse_rules_dir(self) -> None:
        path = filedialog.askdirectory(title="Select rules folder")
        if path:
            self.edr_rules_path.delete(0, tk.END)
            self.edr_rules_path.insert(0, path)

    def on_edr_browse_quar_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to quarantine")
        if path:
            self.edr_quar_path.delete(0, tk.END)
            self.edr_quar_path.insert(0, path)

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


    # Registry tab
    def _build_registry_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        ttk.Button(top, text="Preview", command=self.on_reg_preview).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Run (Dry)", command=lambda: self.on_reg_run(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Run (Apply)", command=lambda: self.on_reg_run(False)).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Rollback Latest", command=self.on_reg_rollback).pack(side=tk.LEFT, padx=5)

        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.reg_output = tk.Text(out_frame, wrap="none")
        self.reg_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rb = ttk.Scrollbar(out_frame, command=self.reg_output.yview)
        rb.pack(side=tk.RIGHT, fill=tk.Y)
        self.reg_output.config(yscrollcommand=rb.set)

    # Drivers tab
    def _build_drivers_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        ttk.Button(top, text="List", command=self.on_drv_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Scan", command=self.on_drv_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Update (Dry)", command=lambda: self.on_drv_update(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Update (Apply)", command=lambda: self.on_drv_update(False)).pack(side=tk.LEFT, padx=5)

        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.drv_output = tk.Text(out_frame, wrap="none")
        self.drv_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        db = ttk.Scrollbar(out_frame, command=self.drv_output.yview)
        db.pack(side=tk.RIGHT, fill=tk.Y)
        self.drv_output.config(yscrollcommand=db.set)

    # Optimize tab
    def _build_optimize_tab(self, parent: ttk.Frame) -> None:
        # Profiles
        prof = ttk.LabelFrame(parent, text="Profiles")
        prof.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        ttk.Button(prof, text="List Profiles", command=self.on_opt_list_profiles).pack(side=tk.LEFT, padx=5)
        ttk.Label(prof, text="Profile:").pack(side=tk.LEFT)
        self.opt_profile = tk.Entry(prof, width=24)
        self.opt_profile.insert(0, "default")
        self.opt_profile.pack(side=tk.LEFT, padx=5)
        ttk.Button(prof, text="Apply (Dry)", command=lambda: self.on_opt_apply(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(prof, text="Apply (Apply)", command=lambda: self.on_opt_apply(False)).pack(side=tk.LEFT, padx=5)

        # Network
        net = ttk.LabelFrame(parent, text="Network Stack")
        net.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        ttk.Button(net, text="Recommend", command=lambda: self.on_opt_net(False)).pack(side=tk.LEFT, padx=5)
        ttk.Button(net, text="Apply", command=lambda: self.on_opt_net(True)).pack(side=tk.LEFT, padx=5)

        # Power plan
        pwr = ttk.LabelFrame(parent, text="Power Plan")
        pwr.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        ttk.Label(pwr, text="Plan:").pack(side=tk.LEFT)
        self.power_var = tk.StringVar(value="balanced")
        ttk.Combobox(pwr, textvariable=self.power_var, values=("balanced","high","ultimate","power saver"), state="readonly", width=16).pack(side=tk.LEFT, padx=5)
        ttk.Button(pwr, text="Switch (Dry)", command=lambda: self.on_opt_power(False)).pack(side=tk.LEFT, padx=5)
        ttk.Button(pwr, text="Switch (Apply)", command=lambda: self.on_opt_power(True)).pack(side=tk.LEFT, padx=5)

        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.opt_output = tk.Text(out_frame, wrap="none")
        self.opt_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ob = ttk.Scrollbar(out_frame, command=self.opt_output.yview)
        ob.pack(side=tk.RIGHT, fill=tk.Y)
        self.opt_output.config(yscrollcommand=ob.set)

    # Process tab
    def _build_process_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Top N:").pack(side=tk.LEFT)
        self.proc_limit = tk.Entry(top, width=6)
        self.proc_limit.insert(0, "20")
        self.proc_limit.pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="List", command=self.on_proc_list).pack(side=tk.LEFT, padx=5)
        ttk.Label(top, text="Kill PID:").pack(side=tk.LEFT, padx=10)
        self.proc_kill_pid = tk.Entry(top, width=8)
        self.proc_kill_pid.pack(side=tk.LEFT)
        ttk.Button(top, text="Kill (Dry)", command=lambda: self.on_proc_kill(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="Kill (Apply)", command=lambda: self.on_proc_kill(False)).pack(side=tk.LEFT, padx=5)

        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.proc_output = tk.Text(out_frame, wrap="none")
        self.proc_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pb = ttk.Scrollbar(out_frame, command=self.proc_output.yview)
        pb.pack(side=tk.RIGHT, fill=tk.Y)
        self.proc_output.config(yscrollcommand=pb.set)

    # Services tab
    def _build_services_tab(self, parent: ttk.Frame) -> None:
        top = ttk.Frame(parent)
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text="Status:").pack(side=tk.LEFT)
        self.svc_status = tk.StringVar(value="running")
        ttk.Combobox(top, textvariable=self.svc_status, values=("all","running","stopped"), state="readonly", width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(top, text="List", command=self.on_svc_list).pack(side=tk.LEFT, padx=5)

        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.svc_output = tk.Text(out_frame, wrap="none")
        self.svc_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(out_frame, command=self.svc_output.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.svc_output.config(yscrollcommand=sb.set)

    # Schedule tab
    def _build_schedule_tab(self, parent: ttk.Frame) -> None:
        top = ttk.LabelFrame(parent, text="List Tasks")
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        ttk.Button(top, text="List Tasks", command=self.on_sched_list).pack(side=tk.LEFT, padx=5)

        make = ttk.LabelFrame(parent, text="Create Task")
        make.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        ttk.Label(make, text="Name:").pack(side=tk.LEFT)
        self.sch_name = tk.Entry(make, width=28)
        self.sch_name.pack(side=tk.LEFT, padx=5)
        ttk.Label(make, text="When:").pack(side=tk.LEFT)
        self.sch_when = tk.Entry(make, width=12)
        self.sch_when.insert(0, "DAILY")
        self.sch_when.pack(side=tk.LEFT, padx=5)
        ttk.Label(make, text="Command:").pack(side=tk.LEFT)
        self.sch_cmd = tk.Entry(make, width=40)
        self.sch_cmd.insert(0, "pcsuite clean run --category temp")
        self.sch_cmd.pack(side=tk.LEFT, padx=5)
        ttk.Button(make, text="Create (Dry)", command=lambda: self.on_sched_create(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(make, text="Create (Apply)", command=lambda: self.on_sched_create(False)).pack(side=tk.LEFT, padx=5)

        rem = ttk.LabelFrame(parent, text="Delete Task")
        rem.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        ttk.Label(rem, text="Name:").pack(side=tk.LEFT)
        self.sch_del_name = tk.Entry(rem, width=28)
        self.sch_del_name.pack(side=tk.LEFT, padx=5)
        ttk.Button(rem, text="Delete (Dry)", command=lambda: self.on_sched_delete(True)).pack(side=tk.LEFT, padx=5)
        ttk.Button(rem, text="Delete (Apply)", command=lambda: self.on_sched_delete(False)).pack(side=tk.LEFT, padx=5)

        out_frame = ttk.Frame(parent)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.sch_output = tk.Text(out_frame, wrap="none")
        self.sch_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scb = ttk.Scrollbar(out_frame, command=self.sch_output.yview)
        scb.pack(side=tk.RIGHT, fill=tk.Y)
        self.sch_output.config(yscrollcommand=scb.set)

    # Security helpers
    def on_sec_fw_status(self) -> None:
        self._append_sec("Querying firewall status ...")
        def task():
            code, out, err = self._run_cli(["security", "firewall"])
            if code == 0:
                self._append_sec(out.strip())
            else:
                messagebox.showerror("Firewall", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_sec_fw_toggle(self, enable: bool, dry: bool) -> None:
        if not dry and not messagebox.askyesno("Firewall", f"Set firewall {'ON' if enable else 'OFF'} for all profiles?"):
            return
        self._append_sec(f"Firewall set all profiles -> {'ON' if enable else 'OFF'} (dry={dry}) ...")
        args = ["security", "firewall", "--enable" if enable else "--no-enable"]
        if dry:
            args += ["--dry-run"]
        else:
            args += ["--no-dry-run"]
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_sec(out.strip())
            else:
                messagebox.showerror("Firewall", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_sec_reputation(self) -> None:
        path = (self.rep_path.get() or "").strip()
        if not path:
            messagebox.showinfo("Reputation", "Enter a file path to check.")
            return
        self._append_sec(f"Checking reputation: {path}")
        def task():
            code, out, err = self._run_cli(["security", "reputation", path])
            if code == 0:
                self._append_sec(out.strip())
            else:
                messagebox.showerror("Reputation", err or out)
        threading.Thread(target=task, daemon=True).start()

    # Registry actions
    def _append_reg(self, text: str) -> None:
        self.reg_output.insert(tk.END, text + "\n")
        self.reg_output.see(tk.END)

    def on_reg_preview(self) -> None:
        self._append_reg("Previewing registry targets ...")
        def task():
            code, out, err = self._run_cli(["registry", "preview"])
            if code == 0:
                self._append_reg(out.strip())
            else:
                messagebox.showerror("Registry", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_reg_run(self, dry: bool) -> None:
        if not dry:
            if not messagebox.askyesno("Registry", "Apply registry cleanup? (backups are created)"):
                return
        self._append_reg(f"Running registry cleanup (dry={dry}) ...")
        args = ["registry", "run"]
        args += (["--dry-run"] if dry else [])
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_reg(out.strip())
            else:
                messagebox.showerror("Registry", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_reg_rollback(self) -> None:
        if not messagebox.askyesno("Registry", "Restore registry from latest backup manifest?"):
            return
        self._append_reg("Rolling back registry ...")
        def task():
            code, out, err = self._run_cli(["registry", "rollback", "--yes"])
            if code == 0:
                self._append_reg(out.strip())
            else:
                messagebox.showerror("Registry", err or out)
        threading.Thread(target=task, daemon=True).start()

    # Drivers
    def _append_drv(self, text: str) -> None:
        self.drv_output.insert(tk.END, text + "\n")
        self.drv_output.see(tk.END)

    def on_drv_list(self) -> None:
        self._append_drv("Listing drivers ...")
        def task():
            code, out, err = self._run_cli(["drivers", "list"])
            if code == 0:
                self._append_drv(out.strip())
            else:
                messagebox.showerror("Drivers", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_drv_scan(self) -> None:
        self._append_drv("Triggering Windows Update scan ...")
        def task():
            code, out, err = self._run_cli(["drivers", "scan"])
            if code == 0:
                self._append_drv(out.strip() or "Scan triggered")
            else:
                messagebox.showerror("Drivers", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_drv_update(self, dry: bool) -> None:
        if not dry and not messagebox.askyesno("Drivers", "Start Windows Update download/install?"):
            return
        self._append_drv(f"Windows Update cycle (dry={dry}) ...")
        args = ["drivers", "update"]
        args += (["--dry-run"] if dry else ["--no-dry-run", "--yes"])
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_drv(out.strip())
            else:
                messagebox.showerror("Drivers", err or out)
        threading.Thread(target=task, daemon=True).start()

    # Optimize
    def _append_opt(self, text: str) -> None:
        self.opt_output.insert(tk.END, text + "\n")
        self.opt_output.see(tk.END)

    def on_opt_list_profiles(self) -> None:
        self._append_opt("Listing optimize profiles ...")
        def task():
            code, out, err = self._run_cli(["optimize", "list-profiles"])
            if code == 0:
                self._append_opt(out.strip())
            else:
                messagebox.showerror("Optimize", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_opt_apply(self, dry: bool) -> None:
        profile = (self.opt_profile.get() or "").strip()
        if not profile:
            messagebox.showinfo("Optimize", "Enter a profile name.")
            return
        if not dry and not messagebox.askyesno("Optimize", f"Apply profile '{profile}'?"):
            return
        self._append_opt(f"Applying profile '{profile}' (dry={dry}) ...")
        args = ["optimize", "apply", profile]
        args += (["--dry-run"] if dry else ["--no-dry-run", "--yes"])
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_opt(out.strip())
            else:
                messagebox.showerror("Optimize", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_opt_net(self, do_apply: bool) -> None:
        self._append_opt("Network stack recommendations ...")
        def task():
            args = ["optimize", "net"]
            if do_apply:
                args.append("--apply")
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_opt(out.strip())
            else:
                messagebox.showerror("Optimize", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_opt_power(self, do_apply: bool) -> None:
        prof = (self.power_var.get() or "balanced").strip()
        self._append_opt(f"Power plan -> {prof} (apply={do_apply}) ...")
        def task():
            args = ["optimize", "power-plan", "--profile", prof]
            if do_apply:
                args.append("--apply")
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_opt(out.strip())
            else:
                messagebox.showerror("Optimize", err or out)
        threading.Thread(target=task, daemon=True).start()

    # Processes
    def _append_proc(self, text: str) -> None:
        self.proc_output.insert(tk.END, text + "\n")
        self.proc_output.see(tk.END)

    def on_proc_list(self) -> None:
        n = (self.proc_limit.get() or "20").strip()
        if not n.isdigit():
            n = "20"
        self._append_proc(f"Listing top {n} processes ...")
        def task():
            code, out, err = self._run_cli(["process", "list", "--limit", n])
            if code == 0:
                self._append_proc(out.strip())
            else:
                messagebox.showerror("Processes", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_proc_kill(self, dry: bool) -> None:
        pid = (self.proc_kill_pid.get() or "").strip()
        if not pid.isdigit():
            messagebox.showinfo("Processes", "Enter a numeric PID.")
            return
        if not dry and not messagebox.askyesno("Processes", f"Kill PID {pid}?"):
            return
        self._append_proc(f"Killing PID {pid} (dry={dry}) ...")
        args = ["process", "kill", "--pid", pid]
        args += (["--dry-run"] if dry else ["--no-dry-run", "--yes"])
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_proc(out.strip())
            else:
                messagebox.showerror("Processes", err or out)
        threading.Thread(target=task, daemon=True).start()

    # Services
    def _append_svc(self, text: str) -> None:
        self.svc_output.insert(tk.END, text + "\n")
        self.svc_output.see(tk.END)

    def on_svc_list(self) -> None:
        status = (self.svc_status.get() or "all").strip()
        args = ["services", "list"]
        if status in ("running", "stopped"):
            args += ["--status", status]
        self._append_svc(f"Listing services (status={status}) ...")
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_svc(out.strip())
            else:
                messagebox.showerror("Services", err or out)
        threading.Thread(target=task, daemon=True).start()

    # Schedule
    def _append_sched(self, text: str) -> None:
        self.sch_output.insert(tk.END, text + "\n")
        self.sch_output.see(tk.END)

    def on_sched_list(self) -> None:
        self._append_sched("Listing tasks ...")
        def task():
            code, out, err = self._run_cli(["tasks", "list"])
            if code == 0:
                self._append_sched(out.strip())
            else:
                messagebox.showerror("Schedule", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_sched_create(self, dry: bool) -> None:
        name = (self.sch_name.get() or "").strip()
        when = (self.sch_when.get() or "").strip()
        cmd = (self.sch_cmd.get() or "").strip()
        if not name or not when or not cmd:
            messagebox.showinfo("Schedule", "Provide name, when, and command.")
            return
        if not dry and not messagebox.askyesno("Schedule", f"Create task '{name}'?"):
            return
        self._append_sched(f"Creating task '{name}' (dry={dry}) ...")
        args = ["schedule", "create", "--name", name, "--when", when, "--command", cmd]
        args += (["--dry-run"] if dry else ["--no-dry-run", "--yes"])
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_sched(out.strip())
            else:
                messagebox.showerror("Schedule", err or out)
        threading.Thread(target=task, daemon=True).start()

    def on_sched_delete(self, dry: bool) -> None:
        name = (self.sch_del_name.get() or "").strip()
        if not name:
            messagebox.showinfo("Schedule", "Provide task name to delete.")
            return
        if not dry and not messagebox.askyesno("Schedule", f"Delete task '{name}'?"):
            return
        self._append_sched(f"Deleting task '{name}' (dry={dry}) ...")
        args = ["schedule", "delete", "--name", name]
        args += (["--dry-run"] if dry else ["--no-dry-run", "--yes"])
        def task():
            code, out, err = self._run_cli(args)
            if code == 0:
                self._append_sched(out.strip())
            else:
                messagebox.showerror("Schedule", err or out)
        threading.Thread(target=task, daemon=True).start()
def launch_gui():
    app = PCSuiteGUI()
    app.mainloop()


def main():
    launch_gui()
