"""LiteVPN - a tiny Windows front end for WireGuard.

Requires: Windows, Python 3.8+ (stdlib only), WireGuard for Windows
          (https://www.wireguard.com/install/). Runs elevated (auto-prompts).
"""
import ctypes
import os
import re
import shutil
import subprocess
import sys
import time
import tkinter as tk
from tkinter import filedialog, messagebox

APP_DIR = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "LiteVPN")
WG_HOME = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "WireGuard")
WIREGUARD = os.path.join(WG_HOME, "wireguard.exe")
WG = os.path.join(WG_HOME, "wg.exe")
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    if getattr(sys, "frozen", False):
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        params = subprocess.list2cmdline(sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)


def run(args):
    return subprocess.run(args, capture_output=True, text=True, creationflags=NO_WINDOW)


def secure_dir():
    """Create the config folder and restrict it to SYSTEM + Administrators."""
    os.makedirs(APP_DIR, exist_ok=True)
    run(["icacls", APP_DIR, "/inheritance:r", "/grant:r",
         "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])


def tunnels():
    return sorted(f[:-5] for f in os.listdir(APP_DIR) if f.endswith(".conf"))


def conf_path(name):
    return os.path.join(APP_DIR, name + ".conf")


def is_up(name):
    out = run(["sc", "query", f"WireGuardTunnel${name}"]).stdout
    return "RUNNING" in out


def last_handshake(name):
    out = run([WG, "show", name, "latest-handshakes"]).stdout.strip()
    if not out:
        return None
    try:
        ts = max(int(line.split()[-1]) for line in out.splitlines())
    except ValueError:
        return None
    if ts == 0:
        return None
    return max(0, int(time.time()) - ts)


def fmt_ago(sec):
    if sec is None:
        return "no handshake yet"
    if sec < 60:
        return f"{sec}s ago"
    if sec < 3600:
        return f"{sec // 60}m ago"
    return f"{sec // 3600}h ago"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LiteVPN")
        self.geometry("340x330")
        self.resizable(False, False)

        self.status = tk.Label(self, text="Disconnected", font=("Segoe UI", 14, "bold"), fg="#b00020")
        self.status.pack(pady=(14, 0))
        self.detail = tk.Label(self, text="", fg="#555")
        self.detail.pack()

        self.listbox = tk.Listbox(self, height=7, exportselection=False)
        self.listbox.pack(fill="x", padx=16, pady=10)

        row = tk.Frame(self)
        row.pack(pady=4)
        self.toggle_btn = tk.Button(row, text="Connect", width=12, command=self.toggle)
        self.toggle_btn.grid(row=0, column=0, padx=4)
        tk.Button(row, text="Import .conf", width=12, command=self.import_conf).grid(row=0, column=1, padx=4)
        tk.Button(self, text="Delete tunnel", command=self.delete).pack(pady=4)

        self.refresh_list()
        self.tick()

    # ---- helpers
    def selected(self):
        sel = self.listbox.curselection()
        return self.listbox.get(sel[0]) if sel else None

    def refresh_list(self, keep=None):
        keep = keep or self.selected()
        self.listbox.delete(0, "end")
        names = tunnels()
        for n in names:
            self.listbox.insert("end", n)
        if names:
            idx = names.index(keep) if keep in names else 0
            self.listbox.selection_set(idx)

    # ---- actions
    def import_conf(self):
        path = filedialog.askopenfilename(title="Select WireGuard config",
                                          filetypes=[("WireGuard config", "*.conf")])
        if not path:
            return
        name = re.sub(r"[^A-Za-z0-9_=+.-]", "_", os.path.splitext(os.path.basename(path))[0])[:15]
        if not name:
            messagebox.showerror("LiteVPN", "Invalid file name.")
            return
        shutil.copyfile(path, conf_path(name))
        self.refresh_list(keep=name)

    def toggle(self):
        name = self.selected()
        if not name:
            messagebox.showinfo("LiteVPN", "Import a .conf file first.")
            return
        if is_up(name):
            res = run([WIREGUARD, "/uninstalltunnelservice", name])
        else:
            res = run([WIREGUARD, "/installtunnelservice", conf_path(name)])
        if res.returncode != 0:
            messagebox.showerror("LiteVPN", (res.stderr or res.stdout or "Command failed").strip())
        self.update_status()

    def delete(self):
        name = self.selected()
        if not name or not messagebox.askyesno("LiteVPN", f"Delete '{name}'?"):
            return
        if is_up(name):
            run([WIREGUARD, "/uninstalltunnelservice", name])
        os.remove(conf_path(name))
        self.refresh_list()

    # ---- status loop
    def update_status(self):
        name = self.selected()
        if name and is_up(name):
            self.status.config(text="Connected", fg="#1b8a3a")
            self.detail.config(text=f"{name} - handshake {fmt_ago(last_handshake(name))}")
            self.toggle_btn.config(text="Disconnect")
        else:
            self.status.config(text="Disconnected", fg="#b00020")
            self.detail.config(text="")
            self.toggle_btn.config(text="Connect")

    def tick(self):
        self.update_status()
        self.after(2000, self.tick)


def main():
    if os.name != "nt":
        sys.exit("LiteVPN is Windows-only.")
    if not is_admin():
        relaunch_as_admin()
        return
    if not (os.path.exists(WIREGUARD) and os.path.exists(WG)):
        messagebox.showerror("LiteVPN", "WireGuard for Windows is not installed.\n"
                                        "Get it from https://www.wireguard.com/install/")
        return
    secure_dir()
    App().mainloop()


if __name__ == "__main__":
    main()
