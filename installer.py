import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os, sys, shutil, subprocess, winreg, threading, time

BG       = "#0a0a0c"
SIDEBAR  = "#0e0e11"
CARD     = "#16161a"
CARD_HOV = "#1c1c22"
BORDER   = "#24242b"
FG       = "#ececec"
SUB      = "#7c7c88"
ACCENT   = "#00e0a4"
DANGER   = "#ff4757"
WARN     = "#ffb300"

FONT   = ("Segoe UI", 10)
FONT_B = ("Segoe UI Semibold", 10)
FONT_H = ("Segoe UI Semibold", 14)

APP_NAME    = "Aegis Cleaner"
EXE_NAME    = "AegisCleaner.exe"
REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_UNINST  = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisCleaner"


def _shade(hex_color, factor):
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    r = max(0, min(255, int(r*factor)))
    g = max(0, min(255, int(g*factor)))
    b = max(0, min(255, int(b*factor)))
    return f"#{r:02x}{g:02x}{b:02x}"


def resource_path(rel):
    try:
        base = sys._MEIPASS
    except Exception:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, rel)


def default_install_dir():
    return os.path.join(os.path.expandvars(r'%LOCALAPPDATA%'), APP_NAME)


def is_installed():
    d = default_install_dir()
    return os.path.exists(os.path.join(d, EXE_NAME))


def reg_set_autostart(exe_path):
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0,
                           winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, f'"{exe_path}"')
        winreg.CloseKey(k)
        return True
    except Exception:
        return False


def reg_remove_autostart():
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0,
                           winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(k, APP_NAME)
        except FileNotFoundError:
            pass
        winreg.CloseKey(k)
        return True
    except Exception:
        return False


def reg_write_uninstall(install_dir, exe_path):
    try:
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_UNINST)
        winreg.SetValueEx(k, "DisplayName",     0, winreg.REG_SZ, APP_NAME)
        winreg.SetValueEx(k, "DisplayIcon",     0, winreg.REG_SZ, exe_path)
        winreg.SetValueEx(k, "DisplayVersion",  0, winreg.REG_SZ, "1.0.0")
        winreg.SetValueEx(k, "Publisher",       0, winreg.REG_SZ, "Aegis")
        winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ, install_dir)
        winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ, f'"{exe_path}"')
        winreg.SetValueEx(k, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "NoRepair", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(k)
        return True
    except Exception:
        return False


def reg_remove_uninstall():
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_UNINST)
        return True
    except Exception:
        return False


def create_shortcut(link_path, target, icon=None, workdir=None):
    icon = icon or target
    workdir = workdir or os.path.dirname(target)
    ps = f"""
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut('{link_path}')
    $sc.TargetPath = '{target}'
    $sc.WorkingDirectory = '{workdir}'
    $sc.IconLocation = '{icon}'
    $sc.Save()
    """
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=15)
        return True
    except Exception:
        return False


class HoverButton(tk.Label):
    def __init__(self, parent, text, command, color=ACCENT, fg="#000",
                 pad=(22, 10), font=None):
        super().__init__(parent, text=text, bg=color, fg=fg, cursor="hand2",
                         font=font or FONT_B, padx=pad[0], pady=pad[1])
        self._color = color
        self._hover = _shade(color, 1.18)
        self._command = command
        self.bind("<Enter>",    lambda e: self.config(bg=self._hover))
        self.bind("<Leave>",    lambda e: self.config(bg=self._color))
        self.bind("<Button-1>", lambda e: self._command())


class CheckBox(tk.Frame):
    def __init__(self, parent, text, default=True, bg=CARD):
        super().__init__(parent, bg=bg)
        self.var = tk.BooleanVar(value=default)
        self.box = tk.Label(self, text="X" if default else "",
                            bg=ACCENT if default else CARD_HOV,
                            fg="#000" if default else SUB,
                            font=("Segoe UI Semibold", 11),
                            width=2, height=1, cursor="hand2")
        self.box.pack(side="left")
        self.lbl = tk.Label(self, text=text, bg=bg, fg=FG,
                            font=FONT, cursor="hand2")
        self.lbl.pack(side="left", padx=(10, 0))
        for w in (self.box, self.lbl):
            w.bind("<Button-1>", self._toggle)

    def _toggle(self, _):
        self.var.set(not self.var.get())
        if self.var.get():
            self.box.config(text="X", bg=ACCENT, fg="#000")
        else:
            self.box.config(text="", bg=CARD_HOV, fg=SUB)

    def get(self):
        return self.var.get()


class InstallerApp:
    def __init__(self, root):
        self.root = root
        root.title(f"{APP_NAME} - установка")
        root.geometry("640x540")
        root.configure(bg=BG)
        root.resizable(False, False)

        try:
            ip = resource_path("icon.ico")
            if os.path.exists(ip):
                root.iconbitmap(ip)
        except Exception:
            pass

        self.install_dir = tk.StringVar(value=default_install_dir())
        self.progress = None
        self.progress_val = 0
        self._build()

    def _build(self):
        top = tk.Frame(self.root, bg=SIDEBAR, height=100)
        top.pack(fill="x"); top.pack_propagate(False)

        logo = tk.Frame(top, bg=SIDEBAR)
        logo.pack(side="left", padx=28, pady=20)
        tk.Label(logo, text="A", bg=SIDEBAR, fg=ACCENT,
                 font=("Segoe UI Semibold", 30)).pack(side="left")
        tbox = tk.Frame(logo, bg=SIDEBAR)
        tbox.pack(side="left", padx=(12, 0))
        tk.Label(tbox, text="AEGIS CLEANER", bg=SIDEBAR, fg=FG,
                 font=("Segoe UI Semibold", 18)).pack(anchor="w")
        tk.Label(tbox, text="Установка программы", bg=SIDEBAR, fg=SUB,
                 font=("Segoe UI", 10)).pack(anchor="w")

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=28, pady=20)

        tk.Label(body, text="Папка установки", bg=BG, fg=SUB,
                 font=("Segoe UI", 9)).pack(anchor="w")
        row = tk.Frame(body, bg=BG); row.pack(fill="x", pady=(6, 20))
        self.dir_entry = tk.Entry(row, textvariable=self.install_dir,
                                  bg=CARD, fg=FG, insertbackground=ACCENT,
                                  relief="flat", font=("Consolas", 10), bd=0)
        self.dir_entry.pack(side="left", fill="x", expand=True, ipady=10)

        def browse():
            d = filedialog.askdirectory(title="Куда установить?",
                                        initialdir=self.install_dir.get())
            if d:
                self.install_dir.set(os.path.join(d, APP_NAME))
        HoverButton(row, "Обзор", browse, color=CARD_HOV, fg=FG,
                    pad=(14, 10)).pack(side="left", padx=(8, 0))

        tk.Label(body, text="Параметры", bg=BG, fg=SUB,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 6))
        opts = tk.Frame(body, bg=CARD); opts.pack(fill="x", pady=(0, 20))
        self.cb_autostart = CheckBox(opts, "Добавить в автозагрузку", True, bg=CARD)
        self.cb_autostart.pack(anchor="w", padx=18, pady=(16, 8))
        self.cb_desktop = CheckBox(opts, "Создать ярлык на рабочем столе", True, bg=CARD)
        self.cb_desktop.pack(anchor="w", padx=18, pady=(0, 8))
        self.cb_run = CheckBox(opts, "Запустить после установки", True, bg=CARD)
        self.cb_run.pack(anchor="w", padx=18, pady=(0, 16))

        self.status_lbl = tk.Label(body, text="", bg=BG, fg=SUB,
                                   font=("Segoe UI", 9))
        self.status_lbl.pack(anchor="w")

        self.progress = tk.Canvas(body, height=6, bg=CARD, highlightthickness=0)
        self.progress.pack(fill="x", pady=(8, 0))
        self._draw_progress()

        bottom = tk.Frame(self.root, bg=BG)
        bottom.pack(fill="x", side="bottom")
        tk.Frame(bottom, bg=BORDER, height=1).pack(fill="x")

        btn_row = tk.Frame(bottom, bg=BG)
        btn_row.pack(fill="x", padx=28, pady=18)

        if is_installed():
            HoverButton(btn_row, "Удалить", self.do_uninstall,
                        color=DANGER, fg="#fff").pack(side="left")
            HoverButton(btn_row, "Переустановить", self.do_install,
                        color=WARN, fg="#000").pack(side="left", padx=8)
        else:
            HoverButton(btn_row, "Установить", self.do_install).pack(side="right")
        HoverButton(btn_row, "Отмена", self.root.destroy,
                    color=CARD_HOV, fg=FG).pack(side="right", padx=8)

    def _draw_progress(self):
        self.progress.delete("all")
        w = self.progress.winfo_width() or 580
        h = 6
        self.progress.create_rectangle(0, 0, w, h, fill=CARD, outline="")
        if self.progress_val > 0:
            self.progress.create_rectangle(0, 0, w * self.progress_val / 100, h,
                                           fill=ACCENT, outline="")

    def _set_progress(self, pct, text=""):
        self.progress_val = pct
        self._draw_progress()
        if text:
            self.status_lbl.config(text=text)
        self.root.update_idletasks()

    def do_install(self):
        def worker():
            try:
                target = self.install_dir.get().strip()
                if not target:
                    self.root.after(0, lambda: messagebox.showerror(
                        "Aegis", "Укажи папку установки."))
                    return

                self.root.after(0, lambda: self._set_progress(10, "Создание папки..."))
                os.makedirs(target, exist_ok=True)
                time.sleep(0.2)

                self.root.after(0, lambda: self._set_progress(30, "Копирование программы..."))
                src_exe = resource_path(EXE_NAME)
                if not os.path.exists(src_exe):
                    self.root.after(0, lambda: messagebox.showerror(
                        "Aegis",
                        f"Не найден {EXE_NAME}.\nСначала собери основной .exe."))
                    return
                dst_exe = os.path.join(target, EXE_NAME)
                shutil.copy2(src_exe, dst_exe)
                time.sleep(0.2)

                self.root.after(0, lambda: self._set_progress(50, "Копирование иконки..."))
                src_icon = resource_path("icon.ico")
                dst_icon = os.path.join(target, "icon.ico")
                if os.path.exists(src_icon):
                    shutil.copy2(src_icon, dst_icon)
                time.sleep(0.2)

                if self.cb_autostart.get():
                    self.root.after(0, lambda: self._set_progress(65, "Автозагрузка..."))
                    reg_set_autostart(dst_exe)
                    time.sleep(0.2)

                if self.cb_desktop.get():
                    self.root.after(0, lambda: self._set_progress(78, "Создание ярлыка..."))
                    desktop = os.path.join(os.path.expandvars(r'%USERPROFILE%'), 'Desktop')
                    create_shortcut(
                        os.path.join(desktop, f"{APP_NAME}.lnk"),
                        dst_exe, dst_icon, target)
                    time.sleep(0.2)

                self.root.after(0, lambda: self._set_progress(88, "Регистрация..."))
                reg_write_uninstall(target, dst_exe)

                start_menu = os.path.join(os.path.expandvars(r'%APPDATA%'),
                    r'Microsoft\Windows\Start Menu\Programs')
                try:
                    create_shortcut(
                        os.path.join(start_menu, f"{APP_NAME}.lnk"),
                        dst_exe, dst_icon, target)
                except Exception:
                    pass

                self.root.after(0, lambda: self._set_progress(100, "Готово."))
                time.sleep(0.3)

                if self.cb_run.get():
                    try:
                        subprocess.Popen([dst_exe], cwd=target,
                                         creationflags=subprocess.DETACHED_PROCESS)
                    except Exception:
                        pass

                self.root.after(0, lambda: messagebox.showinfo(
                    "Aegis", f"Установка завершена.\n\nПапка: {target}"))
                self.root.after(0, self.root.destroy)

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Aegis", f"Ошибка установки:\n{e}"))

        threading.Thread(target=worker, daemon=True).start()

    def do_uninstall(self):
        if not messagebox.askyesno("Aegis",
            "Удалить Aegis Cleaner?\n\n"
            "Программа, автозагрузка, ярлыки и запись в системе будут удалены.\n"
            "Карантин останется."):
            return

        def worker():
            try:
                target = self.install_dir.get().strip()
                self.root.after(0, lambda: self._set_progress(20, "Автозагрузка..."))
                reg_remove_autostart()
                time.sleep(0.2)

                self.root.after(0, lambda: self._set_progress(45, "Ярлыки..."))
                desktop = os.path.join(os.path.expandvars(r'%USERPROFILE%'), 'Desktop')
                for p in [
                    os.path.join(desktop, f"{APP_NAME}.lnk"),
                    os.path.join(os.path.expandvars(r'%APPDATA%'),
                                 r'Microsoft\Windows\Start Menu\Programs',
                                 f"{APP_NAME}.lnk"),
                ]:
                    try:
                        if os.path.exists(p): os.remove(p)
                    except Exception:
                        pass
                time.sleep(0.2)

                self.root.after(0, lambda: self._set_progress(65, "Регистрация..."))
                reg_remove_uninstall()
                time.sleep(0.2)

                self.root.after(0, lambda: self._set_progress(85, "Файлы..."))
                if os.path.isdir(target):
                    try:
                        shutil.rmtree(target)
                    except Exception:
                        pass

                self.root.after(0, lambda: self._set_progress(100, "Готово."))
                self.root.after(0, lambda: messagebox.showinfo(
                    "Aegis", "Aegis Cleaner удалён."))
                self.root.after(0, self.root.destroy)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Aegis", f"Ошибка удаления:\n{e}"))

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    InstallerApp(root)
    root.mainloop()
