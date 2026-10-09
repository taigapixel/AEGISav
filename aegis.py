# ============================================================
#   AEGIS CLEANER — антивирус-утилита на Python
#   Диспетчер задач + сканер + карантин + realtime + VirusTotal
#   Определение: по расширениям, классам угроз, маскировке, правам процессов
# ============================================================
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil, os, sys, shutil, json, time, threading, queue, hashlib, requests
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ============================================================
#   ПАЛИТРА
# ============================================================
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
FONT_H = ("Segoe UI Semibold", 15)
FONT_T = ("Segoe UI Semibold", 22)

# ============================================================
#   ПУТИ
# ============================================================
AEGIS_DIR      = os.path.join(os.path.expandvars(r'%LOCALAPPDATA%'), 'Aegis')
QUARANTINE_DIR = os.path.join(AEGIS_DIR, 'quarantine')
LOG_FILE       = os.path.join(AEGIS_DIR, 'events.log')
CONFIG_FILE    = os.path.join(AEGIS_DIR, 'config.json')
VT_CACHE_FILE  = os.path.join(AEGIS_DIR, 'vt_cache.json')
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# ============================================================
#   БАЗА ЗНАНИЙ
# ============================================================

# --- Системные процессы: НИКОГДА не убивать ---
SYSTEM_PROCS = {'system','registry','memory compression','smss.exe','csrss.exe',
                'wininit.exe','services.exe','lsass.exe','winlogon.exe',
                'svchost.exe','dwm.exe','fontdrvhost.exe','ctfmon.exe',
                'sihost.exe','taskhostw.exe','runtimebroker.exe','explorer.exe',
                'conhost.exe','searchindexer.exe','spoolsv.exe','audiodg.exe'}

# --- Доверенные процессы: не подсвечивать как подозрительные ---
TRUSTED_PROCS = SYSTEM_PROCS | {
    'chrome.exe','firefox.exe','msedge.exe','opera.exe','brave.exe',
    'code.exe','devenv.exe','pycharm64.exe','idea64.exe','notepad++.exe',
    'notepad.exe','winrar.exe','7zfm.exe','winzip32.exe',
    'vlc.exe','mpc-hc64.exe','potplayer.exe','musicbee.exe',
    'steam.exe','steamwebhelper.exe','epicgameslauncher.exe',
    'word.exe','excel.exe','powerpnt.exe','outlook.exe','onenote.exe',
    'python.exe','pythonw.exe','pip.exe','git.exe','node.exe','npm.exe',
}

# --- Опасные расширения: по ним Windows исполняет код ---
DANGEROUS_EXT = {
    '.scr': 'Экранная заставка (исполняемый код)',
    '.vbs': 'VBScript — часто используется для заражения',
    '.vbe': 'Зашифрованный VBScript',
    '.js':  'JavaScript — может запускать код',
    '.jse': 'Зашифрованный JavaScript',
    '.wsf': 'Windows Script File — смешанный скрипт',
    '.wsh': 'Windows Script Host',
    '.hta': 'HTML Application — исполняется как .exe',
    '.ps1': 'PowerShell-скрипт',
    '.psm1': 'PowerShell-модуль',
    '.bat': 'Пакетный файл',
    '.cmd': 'Командный файл',
    '.pif': 'Program Information File (старый .exe)',
    '.com': 'DOS-программа',
    '.jar': 'Java-приложение',
    '.msi': 'Установщик Windows',
    '.cpl': 'Панель управления (исполняемый)',
    '.reg': 'Патч реестра',
    '.lnk': 'Ярлык (может скрывать запуск)',
}

# --- Расширения-маскировки: photo.jpg.exe / doc.pdf.scr ---
MASK_EXT = {'.jpg','.jpeg','.png','.gif','.bmp','.webp','.svg',
            '.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx',
            '.txt','.rtf','.csv','.mp3','.wav','.flac','.mp4',
            '.avi','.mkv','.mov','.zip','.rar','.7z','.tar','.gz'}

# --- Маркеры угроз (латиница) ---
THREAT_SIGNATURES = {
    'trojan':    'Trojan',
    'backdoor':  'Backdoor',
    'rootkit':   'Rootkit',
    'ransom':    'Ransomware',
    'worm':      'Worm',
    'miner':     'Crypto Miner',
    'coinminer': 'Crypto Miner',
    'stealer':   'Stealer',
    'keylog':    'Keylogger',
    'spy':       'Spyware',
    'rat':       'RAT (Remote Access Trojan)',
    'botnet':    'Botnet',
    'bot':       'Bot',
    'adware':    'Adware',
    'dropper':   'Dropper',
    'loader':    'Loader',
    'injector':  'Injector',
    'exploit':   'Exploit',
    'phish':     'Phishing',
    'hacktool':  'HackTool',
    'keygen':    'Keygen (PUA)',
    'crack':     'Crack (PUA)',
    'patch':     'Patcher (PUA)',
    'activator': 'Activator (PUA)',
    'cheat':     'Game Cheat',
    'malware':   'Malware',
    'virus':     'Virus',
}

# --- Права процессов: что процесс УМЕЕТ делать ---
CAPABILITY_PATTERNS = {
    'webcam': [
        'obs', 'obs64', 'obs32', 'xsplit', 'streamlabs',
        'manycam', 'youcam', 'cyberlink', 'logi', 'logitech',
        'webcam', 'camera', 'zoom', 'skype', 'teams', 'discord',
        'faceit', 'snapcamera', 'splitcam',
    ],
    'microphone': [
        'audacity', 'voicemeeter', 'voicemod', 'morphvox',
        'microphone', 'mic', 'voice', 'cable',
    ],
    'screen': [
        'sharex', 'snagit', 'greenshot', 'lightshot',
        'anydesk', 'teamviewer', 'rustdesk', 'radmin',
        'vnc', 'tightvnc', 'ultravnc', 'realvnc',
        'ammyy', 'supremo', 'dwagent', 'screenconnect',
        'parsec', 'splashtop', 'mstsc', 'rdp',
    ],
    'input': [
        'autohotkey', 'autohk', 'ahk', 'automacro', 'autoclick',
        'tinytask', 'clickermann', 'macro', 'puloversmacro',
        'keyboard', 'mouse', 'keypress', 'mouseclick',
    ],
    'network': [
        'wireshark', 'tshark', 'fiddler', 'charles',
        'nmap', 'zenmap', 'masscan', 'netcat', 'ncat',
        'ettercap', 'cain', 'burpsuite', 'mitmproxy',
        'tcpdump', 'windump', 'packetcapture',
    ],
    'filesystem': [
        'encrypt', 'decrypt', 'cipher', 'cryptor',
        'ransom', 'locker', 'wiper',
    ],
}

# --- Расширения, которые НИКОГДА не кидать в карантин (по умолчанию) ---
DEFAULT_SAFE_EXT = {'.txt', '.log', '.md', '.ini', '.cfg'}

# --- Папки для сканирования ---
QUICK_DIRS = [
    os.path.expandvars(r'%TEMP%'),
    os.path.expandvars(r'%USERPROFILE%\Downloads'),
    os.path.expandvars(r'%APPDATA%'),
    os.path.expandvars(r'%LOCALAPPDATA%'),
    r'C:\Windows\Temp',
    r'C:\Users\Public',
]
WATCH_DIRS = QUICK_DIRS + [os.path.expandvars(r'%LOCALAPPDATA%\Temp')]

# --- Папки, которые пропускаем при долгом скане ---
SKIP_DIRS = {'windows','$recycle.bin','system volume information',
             'program files','program files (x86)','appdata','node_modules',
             '.git','$windows.~bt','$windows.~ws'}

# --- Папки автозагрузки ---
STARTUP_DIRS = [
    os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
    os.path.expandvars(r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
]


# ============================================================
#   АНАЛИЗ ФАЙЛОВ И ПРОЦЕССОВ
# ============================================================
def analyze_file(path):
    """
    Проверяет файл по трём признакам:
    1) опасное расширение
    2) маркер угрозы в имени
    3) скрытое двойное расширение (photo.jpg.exe)
    Возвращает строку-причину или None.
    """
    if not path or not os.path.isfile(path):
        return None
    name = os.path.basename(path).lower()
    ext  = os.path.splitext(name)[1]

    # 1) Опасное расширение
    if ext in DANGEROUS_EXT:
        return f"Опасное расширение {ext} — {DANGEROUS_EXT[ext]}"

    # 2) Маркер угрозы в имени
    for marker, kind in THREAT_SIGNATURES.items():
        for sep in ('', '_', '-', '.', ' '):
            if f"{sep}{marker}{sep}" in name or name.startswith(marker) or name.endswith(marker):
                return f"Класс угрозы: {kind} (маркер «{marker}»)"

    # 3) Двойное расширение (маскировка)
    parts = name.split('.')
    if len(parts) >= 3:
        inner = '.' + parts[-2]
        outer = '.' + parts[-1]
        if outer in DANGEROUS_EXT and inner in MASK_EXT:
            return f"Маскировка: {inner}{outer} — подделка под документ/медиа"

    return None


def is_suspicious(path):
    """Обёртка для realtime."""
    return analyze_file(path)


def process_capabilities(name):
    """Возвращает строку прав процесса, например 'WEBCAM / SCREEN'."""
    if not name:
        return ""
    low = name.lower()
    if low in TRUSTED_PROCS:
        return ""
    caps = []
    for cap, patterns in CAPABILITY_PATTERNS.items():
        for pat in patterns:
            if pat in low:
                caps.append(cap)
                break
    seen = set()
    result = []
    for c in caps:
        if c not in seen:
            seen.add(c); result.append(c)
    return " / ".join(result).upper()


# ============================================================
#   АНИМИРОВАННЫЕ ВИДЖЕТЫ
# ============================================================
def _shade(hex_color, factor):
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    r = max(0, min(255, int(r*factor)))
    g = max(0, min(255, int(g*factor)))
    b = max(0, min(255, int(b*factor)))
    return f"#{r:02x}{g:02x}{b:02x}"


class PulsingDot(tk.Canvas):
    def __init__(self, parent, size=22, color=ACCENT, bg=SIDEBAR):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0)
        self.size = size; self.color = color; self.phase = 0
        self.halo = self.create_oval(0,0,0,0, outline=color, width=1)
        self.dot  = self.create_oval(0,0,0,0, fill=color, outline="")
        self.paused = False
        self.animate()

    def set_color(self, color):
        self.color = color
        self.itemconfig(self.dot, fill=color)
        self.itemconfig(self.halo, outline=color)

    def pause(self):  self.paused = True
    def resume(self): self.paused = False

    def animate(self):
        if not self.paused:
            self.phase = (self.phase + 2) % 60
            t = self.phase / 60.0
            cx = cy = self.size / 2
            dr = self.size * 0.28
            self.coords(self.dot, cx-dr, cy-dr, cx+dr, cy+dr)
            r = self.size * (0.30 + 0.55 * t)
            self.coords(self.halo, cx-r, cy-r, cx+r, cy+r)
            self.itemconfig(self.halo, width=max(1, int(3 * (1 - t))))
        self.after(35, self.animate)


class HoverButton(tk.Label):
    def __init__(self, parent, text, command, color=ACCENT, fg="#000000",
                 pad=(18, 9), font=None):
        super().__init__(parent, text=text, bg=color, fg=fg, cursor="hand2",
                         font=font or FONT_B, padx=pad[0], pady=pad[1])
        self._color = color
        self._hover = _shade(color, 1.18)
        self._command = command
        self.bind("<Enter>",    lambda e: self.config(bg=self._hover))
        self.bind("<Leave>",    lambda e: self.config(bg=self._color))
        self.bind("<Button-1>", lambda e: self._command())


class AnimatedBar(tk.Canvas):
    def __init__(self, parent, height=6, color=ACCENT, bg=CARD):
        super().__init__(parent, height=height, bg=bg, highlightthickness=0)
        self.color = color; self.offset = 0; self.running = False
        self.bind("<Configure>", lambda e: self._draw())

    def start(self):  self.running = True; self._tick()
    def stop(self):   self.running = False; self._draw()

    def _tick(self):
        if not self.running: self._draw(); return
        self.offset = (self.offset + 3) % 40
        self._draw()
        self.after(25, self._tick)

    def _draw(self):
        self.delete("all")
        w = self.winfo_width(); h = self.winfo_height()
        if w <= 1: return
        self.create_rectangle(0, 0, w, h, fill=CARD, outline="")
        for x in range(-40, w, 40):
            x0 = x + self.offset
            self.create_rectangle(x0, 0, x0 + 22, h, fill=self.color, outline="")


class Toast:
    _stack = []
    def __init__(self, root, title, subtitle, color=WARN, icon="⚠", duration=4200):
        self.root = root
        self.win = tk.Toplevel(root)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self.win.configure(bg=color)
        w, h = 400, 84
        sw = root.winfo_screenwidth()
        y_offset = 20 + len(Toast._stack) * (h + 10)
        self.target_x = sw - w - 24
        self.target_y = y_offset
        self.start_y  = -h

        inner = tk.Frame(self.win, bg=color); inner.pack(fill="both", expand=True)
        tk.Label(inner, text=icon, bg=color, fg="#000",
                 font=("Segoe UI", 22)).pack(side="left", padx=(14, 6))
        box = tk.Frame(inner, bg=color); box.pack(side="left", fill="both",
                                                  expand=True, pady=12)
        tk.Label(box, text=title, bg=color, fg="#000",
                 font=("Segoe UI Semibold", 11), anchor="w").pack(fill="x")
        tk.Label(box, text=subtitle, bg=color, fg="#141414",
                 font=("Segoe UI", 9), anchor="w", wraplength=310,
                 justify="left").pack(fill="x", pady=(2,0))

        self.win.geometry(f"{w}x{h}+{self.target_x}+{self.start_y}")
        Toast._stack.append(self)
        self._slide_in(self.start_y)
        self.win.after(duration, self._slide_out)

    def _slide_in(self, y):
        if y >= self.target_y:
            self.win.geometry(f"+{self.target_x}+{self.target_y}"); return
        y += max(2, (self.target_y - y) // 3 + 1)
        self.win.geometry(f"+{self.target_x}+{y}")
        self.win.after(12, lambda: self._slide_in(y))

    def _slide_out(self):
        def step(y):
            if y <= self.start_y - 100:
                try: Toast._stack.remove(self)
                except ValueError: pass
                self.win.destroy(); return
            y -= 12
            self.win.geometry(f"+{self.target_x}+{y}")
            self.win.after(12, lambda: step(y))
        step(self.target_y)


class SideButton(tk.Frame):
    def __init__(self, parent, text, icon, command):
        super().__init__(parent, bg=SIDEBAR, height=44)
        self.pack_propagate(False)
        self.command = command; self.active = False

        self.indicator = tk.Frame(self, bg=SIDEBAR, width=3)
        self.indicator.pack(side="left", fill="y")
        self.lbl_icon = tk.Label(self, text=icon, bg=SIDEBAR, fg=SUB,
                                 font=("Segoe UI", 13), width=3)
        self.lbl_icon.pack(side="left")
        self.lbl_text = tk.Label(self, text=text, bg=SIDEBAR, fg=SUB,
                                 font=FONT_B, anchor="w")
        self.lbl_text.pack(side="left", fill="x", expand=True)

        for w in (self, self.lbl_icon, self.lbl_text):
            w.bind("<Enter>", self._hover_on)
            w.bind("<Leave>", self._hover_off)
            w.bind("<Button-1>", lambda e: self.command())
            w.configure(cursor="hand2")

    def _paint(self, bg, fg, indicator):
        self.config(bg=bg)
        self.lbl_icon.config(bg=bg, fg=fg)
        self.lbl_text.config(bg=bg, fg=fg)
        self.indicator.config(bg=indicator)

    def _hover_on(self, e):
        if not self.active: self._paint(CARD, FG, CARD)
    def _hover_off(self, e):
        if not self.active: self._paint(SIDEBAR, SUB, SIDEBAR)
    def set_active(self, on):
        self.active = on
        if on: self._paint(CARD, ACCENT, ACCENT)
        else:  self._paint(SIDEBAR, SUB, SIDEBAR)


# ============================================================
#   VIRUSTOTAL
# ============================================================
class VirusTotal:
    BASE = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, api_key=""):
        self.api_key = api_key
        self.cache = self._load_cache()
        self.session = requests.Session()

    def _load_cache(self):
        if os.path.exists(VT_CACHE_FILE):
            try:
                with open(VT_CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception: return {}
        return {}

    def _save_cache(self):
        try:
            with open(VT_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception: pass

    @staticmethod
    def sha256(path, chunk=65536):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    b = f.read(chunk)
                    if not b: break
                    h.update(b)
            return h.hexdigest()
        except Exception: return None

    def check_file(self, path):
        if not self.api_key:
            return {"status": "error", "message": "API-ключ не задан"}
        digest = self.sha256(path)
        if not digest:
            return {"status": "error", "message": "Не удалось прочитать файл"}
        if digest in self.cache:
            c = dict(self.cache[digest]); c["cached"] = True; return c
        try:
            r = self.session.get(self.BASE + digest,
                                 headers={"x-apikey": self.api_key},
                                 timeout=15)
        except Exception as e:
            return {"status": "error", "message": f"Сеть: {e}"}

        if r.status_code == 404:
            res = {"status": "unknown", "message": "Хэш не найден в VT",
                   "link": f"https://www.virustotal.com/gui/file/{digest}"}
            self.cache[digest] = res; self._save_cache(); return res
        if r.status_code == 401:
            return {"status": "error", "message": "Неверный API-ключ"}
        if r.status_code == 429:
            return {"status": "error", "message": "Лимит запросов VT исчерпан"}
        if r.status_code != 200:
            return {"status": "error", "message": f"HTTP {r.status_code}"}
        try:
            data = r.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            mal   = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            status = "malicious" if mal >= 3 else "clean"
            res = {"status": status, "detections": mal, "total": total,
                   "sha256": digest,
                   "link": f"https://www.virustotal.com/gui/file/{digest}",
                   "message": f"{mal}/{total} антивирусов пометили файл"}
        except Exception as e:
            return {"status": "error", "message": f"Разбор ответа: {e}"}
        self.cache[digest] = res; self._save_cache(); return res


# ============================================================
#   REALTIME-ЗАЩИТА
# ============================================================
class RealtimeWatcher(FileSystemEventHandler):
    def __init__(self, q): self.q = q
    def on_created(self, event):
        if not event.is_directory: self._check(event.src_path)
    def on_moved(self, event):
        if not event.is_directory: self._check(event.dest_path)
    def on_modified(self, event):
        if not event.is_directory: self._check(event.src_path)
    def _check(self, path):
        if QUARANTINE_DIR.lower() in path.lower(): return
        reason = is_suspicious(path)
        if reason:
            time.sleep(0.15)
            self.q.put((path, reason))


class RealtimeEngine:
    def __init__(self, on_threat, vt=None):
        self.q = queue.Queue()
        self.on_threat = on_threat
        self.observers = []
        self.running = False
        self.vt = vt
        self.safe_ext = set()

    def start(self):
        if self.running: return
        handler = RealtimeWatcher(self.q)

        good_dirs = []
        for d in WATCH_DIRS:
            if not os.path.isdir(d):
                continue
            try:
                os.listdir(d)
                good_dirs.append(d)
            except (PermissionError, OSError):
                continue

        if not good_dirs:
            self.running = False
            return

        self.observers = []
        for d in good_dirs:
            try:
                obs = Observer()
                obs.schedule(handler, d, recursive=True)
                obs.start()
                self.observers.append(obs)
            except Exception:
                continue

        self.running = len(self.observers) > 0

    def stop(self):
        if self.observers:
            for obs in self.observers:
                try: obs.stop()
                except Exception: pass
            for obs in self.observers:
                try: obs.join(timeout=1)
                except Exception: pass
            self.observers = []
        self.running = False

    def poll(self):
        events = []
        while True:
            try: events.append(self.q.get_nowait())
            except queue.Empty: break
        for path, reason in events:
            try:
                # Белый список расширений
                ext = os.path.splitext(path)[1].lower()
                if ext in self.safe_ext:
                    continue

                if self.vt and self.vt.api_key and os.path.exists(path):
                    vt_res = self.vt.check_file(path)
                    if vt_res["status"] == "clean": continue
                    if vt_res["status"] == "malicious":
                        reason = f"VT: {vt_res.get('message','вирус')} | {reason}"

                if not os.path.exists(path):
                    continue

                fname = os.path.basename(path)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest = os.path.join(QUARANTINE_DIR, f"{stamp}__{fname}")

                moved = False
                last_err = None
                for attempt in range(3):
                    try:
                        shutil.move(path, dest)
                        moved = True
                        break
                    except (PermissionError, OSError) as e:
                        last_err = e
                        time.sleep(0.3)

                if moved:
                    self.on_threat(dest, reason, original=path)
                else:
                    self.on_threat(path, reason + f" (не удалось перенести: {last_err})",
                                   original=path)
            except Exception as e:
                self.on_threat(path, reason + f" (ошибка: {e})", original=path)


# ============================================================
#   ГЛАВНОЕ ОКНО
# ============================================================
class AegisApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aegis Cleaner")
        self.root.geometry("1280x780")
        self.root.configure(bg=BG)
        self.root.minsize(1050, 660)

        # Иконка окна
        try:
            base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            icon_path = os.path.join(base, "icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

        self.quarantine = []
        self.proc_rows  = {}
        self.scanning   = False
        self.stop_flag  = False
        self.rt_enabled = True
        self.stat_found = 0

        self.config = self._load_config()
        self.vt = VirusTotal(self.config.get("vt_api_key", ""))

        # Белый список расширений
        safe_from_cfg = self.config.get("safe_ext", list(DEFAULT_SAFE_EXT))
        self.safe_ext = set(e.lower() for e in safe_from_cfg)

        self.rt = RealtimeEngine(self._on_realtime_threat, vt=self.vt)
        self.rt.safe_ext = self.safe_ext

        self._style()
        self._build_topbar()
        self._build_sidebar()
        self._build_content()
        self._select_page("dashboard")
        self.rt.start()

        self._tick_clock()
        self._poll_rt()
        self.root.after(4000, self._auto_refresh_procs)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- CONFIG ----------
    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception: return {}
        return {}

    def _save_config(self):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except Exception: pass

    # ---------- STYLE ----------
    def _style(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Aegis.Treeview",
                    background=CARD, fieldbackground=CARD, foreground=FG,
                    rowheight=30, borderwidth=0, font=FONT)
        s.configure("Aegis.Treeview.Heading",
                    background=SIDEBAR, foreground=SUB,
                    font=FONT_B, borderwidth=0, relief="flat")
        s.map("Aegis.Treeview",
              background=[("selected", "#003d2e")],
              foreground=[("selected", FG)])
        s.configure("Aegis.Vertical.TScrollbar",
                    background=CARD, troughcolor=SIDEBAR,
                    borderwidth=0, arrowcolor=SUB)

    # ---------- TOPBAR ----------
    def _build_topbar(self):
        bar = tk.Frame(self.root, bg=SIDEBAR, height=64)
        bar.pack(fill="x", side="top"); bar.pack_propagate(False)

        logo = tk.Frame(bar, bg=SIDEBAR); logo.pack(side="left", padx=(22, 0))
        tk.Label(logo, text="◈", bg=SIDEBAR, fg=ACCENT,
                 font=("Segoe UI Semibold", 20)).pack(side="left")
        tk.Label(logo, text="AEGIS", bg=SIDEBAR, fg=FG,
                 font=("Segoe UI Semibold", 15)).pack(side="left", padx=(6,0))
        tk.Label(logo, text="CLEANER", bg=SIDEBAR, fg=SUB,
                 font=("Segoe UI", 10)).pack(side="left", padx=(6,0), pady=(4,0))

        right = tk.Frame(bar, bg=SIDEBAR); right.pack(side="right", padx=22)
        self.clock = tk.Label(right, text="", bg=SIDEBAR, fg=SUB,
                              font=("Consolas", 10))
        self.clock.pack(side="right", padx=(20, 0))

        status_box = tk.Frame(right, bg=SIDEBAR); status_box.pack(side="right")
        self.pulse = PulsingDot(status_box, size=22, color=ACCENT, bg=SIDEBAR)
        self.pulse.pack(side="left", padx=(0, 8))
        self.rt_label = tk.Label(status_box, text="ЗАЩИТА АКТИВНА", bg=SIDEBAR,
                                 fg=ACCENT, font=("Segoe UI Semibold", 9))
        self.rt_label.pack(side="left")

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")

    # ---------- SIDEBAR ----------
    def _build_sidebar(self):
        self.sidebar = tk.Frame(self.root, bg=SIDEBAR, width=220)
        self.sidebar.pack(side="left", fill="y"); self.sidebar.pack_propagate(False)
        tk.Frame(self.sidebar, bg=SIDEBAR, height=14).pack()
        tk.Label(self.sidebar, text="НАВИГАЦИЯ", bg=SIDEBAR, fg=SUB,
                 font=("Segoe UI", 8), anchor="w").pack(fill="x", padx=22, pady=(0,8))

        items = [
            ("dashboard","Панель","▣"),
            ("procs","Диспетчер задач","☰"),
            ("quick","Быстрая проверка","⚡"),
            ("full","Долгая проверка","◐"),
            ("quarantine","Карантин","☣"),
            ("settings","Настройки","⚙"),
        ]
        self.nav_buttons = {}
        for key, label, icon in items:
            btn = SideButton(self.sidebar, label, icon,
                             lambda k=key: self._select_page(k))
            btn.pack(fill="x", pady=1, padx=10)
            self.nav_buttons[key] = btn

        tk.Frame(self.sidebar, bg=SIDEBAR).pack(fill="both", expand=True)

        bottom = tk.Frame(self.sidebar, bg=CARD)
        bottom.pack(fill="x", side="bottom", padx=12, pady=12)
        tk.Label(bottom, text="🛡  Realtime", bg=CARD, fg=FG,
                 font=FONT_B).pack(anchor="w", padx=12, pady=(10,0))
        self.rt_stat = tk.Label(bottom, text="Следит за папками",
                                bg=CARD, fg=SUB, font=("Segoe UI", 9))
        self.rt_stat.pack(anchor="w", padx=12, pady=(2,12))

    # ---------- CONTENT ----------
    def _build_content(self):
        self.content = tk.Frame(self.root, bg=BG)
        self.content.pack(side="right", fill="both", expand=True)
        self.pages = {}
        self.pages["dashboard"]  = self._page_dashboard()
        self.pages["procs"]      = self._page_procs()
        self.pages["quick"]      = self._page_scan(quick=True)
        self.pages["full"]       = self._page_scan(quick=False)
        self.pages["quarantine"] = self._page_quarantine()
        self.pages["settings"]   = self._page_settings()

    def _select_page(self, key):
        for k, btn in self.nav_buttons.items():
            btn.set_active(k == key)
        for k, page in self.pages.items():
            if k == key: page.pack(fill="both", expand=True, padx=20, pady=18)
            else: page.pack_forget()
        self.current_page = key

    # ==========================================================
    #   DASHBOARD
    # ==========================================================
    def _page_dashboard(self):
        p = tk.Frame(self.content, bg=BG)
        tk.Label(p, text="Панель управления", bg=BG, fg=FG,
                 font=FONT_T).pack(anchor="w", pady=(0,4))
        tk.Label(p, text="Состояние защиты и быстрые действия", bg=BG, fg=SUB,
                 font=FONT).pack(anchor="w", pady=(0,22))

        cards = tk.Frame(p, bg=BG); cards.pack(fill="x", pady=(0,18))
        self.card_found = self._stat_card(cards, "☣", "Найдено угроз", "0", DANGER)
        self.card_quar  = self._stat_card(cards, "🔒", "В карантине", "0", WARN)
        self.card_rt    = self._stat_card(cards, "🛡", "Защита", "ВКЛ", ACCENT)

        actions = tk.Frame(p, bg=BG); actions.pack(fill="x", pady=(4,18))
        self._big_action(actions, "⚡", "Быстрая проверка",
                         "TEMP, Downloads, AppData",
                         lambda: self._goto_and_scan("quick"))
        self._big_action(actions, "◐", "Долгая проверка",
                         "Сканировать все диски",
                         lambda: self._goto_and_scan("full"))

        rt_box = tk.Frame(p, bg=CARD); rt_box.pack(fill="x", pady=(4,0))
        left = tk.Frame(rt_box, bg=CARD); left.pack(side="left", padx=22, pady=18)
        tk.Label(left, text="Защита в реальном времени", bg=CARD, fg=FG,
                 font=FONT_H).pack(anchor="w")
        self.rt_desc = tk.Label(left, text="Следит за TEMP, Downloads, AppData…",
                                bg=CARD, fg=SUB, font=FONT)
        self.rt_desc.pack(anchor="w", pady=(4,0))
        right = tk.Frame(rt_box, bg=CARD); right.pack(side="right", padx=22)
        self.rt_toggle = HoverButton(right, "⏸  Пауза", self._toggle_realtime,
                                     color=CARD_HOV, fg=FG, pad=(18,10))
        self.rt_toggle.pack()
        return p

    def _stat_card(self, parent, icon, title, value, color):
        c = tk.Frame(parent, bg=CARD)
        c.pack(side="left", fill="both", expand=True, padx=(0,12))
        tk.Label(c, text=icon, bg=CARD, fg=color,
                 font=("Segoe UI", 20)).pack(anchor="w", padx=18, pady=(16,0))
        tk.Label(c, text=title, bg=CARD, fg=SUB, font=FONT).pack(anchor="w", padx=18)
        v = tk.Label(c, text=value, bg=CARD, fg=FG,
                     font=("Segoe UI Semibold", 24))
        v.pack(anchor="w", padx=18, pady=(2,16))
        return v

    def _big_action(self, parent, icon, title, sub, cmd):
        c = tk.Frame(parent, bg=CARD, cursor="hand2")
        c.pack(side="left", fill="both", expand=True, padx=(0,12))
        inner = tk.Frame(c, bg=CARD); inner.pack(fill="both", expand=True,
                                                 padx=22, pady=22)
        tk.Label(inner, text=icon, bg=CARD, fg=ACCENT,
                 font=("Segoe UI", 26)).pack(anchor="w")
        tk.Label(inner, text=title, bg=CARD, fg=FG,
                 font=("Segoe UI Semibold", 14)).pack(anchor="w", pady=(8,0))
        tk.Label(inner, text=sub, bg=CARD, fg=SUB, font=FONT).pack(anchor="w", pady=(2,12))
        tk.Label(inner, text="Запустить →", bg=CARD, fg=ACCENT,
                 font=FONT_B).pack(anchor="w")
        def enter(e):
            for w in [c, inner] + list(inner.winfo_children()):
                try: w.config(bg=CARD_HOV)
                except Exception: pass
        def leave(e):
            for w in [c, inner] + list(inner.winfo_children()):
                try: w.config(bg=CARD)
                except Exception: pass
        for w in [c, inner] + list(inner.winfo_children()):
            w.bind("<Enter>", enter); w.bind("<Leave>", leave)
            w.bind("<Button-1>", lambda e: cmd())

    def _goto_and_scan(self, page):
        self._select_page(page)
        self.root.after(150, lambda: self._start_scan(page == "quick"))

    def _toggle_realtime(self):
        if self.rt_enabled:
            self.rt.stop(); self.rt_enabled = False
            self.rt_toggle.config(text="▶  Возобновить")
            self.rt_label.config(text="ЗАЩИТА ПРИОСТАНОВЛЕНА", fg=WARN)
            self.pulse.set_color(WARN); self.pulse.pause()
            self.rt_desc.config(text="Защита остановлена.")
        else:
            self.rt.start(); self.rt_enabled = True
            self.rt_toggle.config(text="⏸  Пауза")
            self.rt_label.config(text="ЗАЩИТА АКТИВНА", fg=ACCENT)
            self.pulse.set_color(ACCENT); self.pulse.resume()
            self.rt_desc.config(text="Следит за TEMP, Downloads, AppData…")

    # ==========================================================
    #   ДИСПЕТЧЕР ЗАДАЧ
    # ==========================================================
    def _page_procs(self):
        p = tk.Frame(self.content, bg=BG)
        tk.Label(p, text="Диспетчер задач", bg=BG, fg=FG,
                 font=FONT_T).pack(anchor="w", pady=(0,4))
        tk.Label(p, text="Процессы, их права и управление автозагрузкой",
                 bg=BG, fg=SUB, font=FONT).pack(anchor="w", pady=(0,18))

        bar = tk.Frame(p, bg=BG); bar.pack(fill="x", pady=(0,12))
        HoverButton(bar, "⟳  Обновить", self.refresh_procs).pack(side="left")
        HoverButton(bar, "✕  Завершить", self.kill_selected,
                    color=DANGER, fg="#fff").pack(side="left", padx=8)
        HoverButton(bar, "⛔  Завершить всё лишнее", self.kill_all,
                    color=DANGER, fg="#fff").pack(side="left")
        HoverButton(bar, "➕  Добавить в автозагрузку", self.add_to_startup,
                    color=WARN, fg="#000").pack(side="left", padx=8)
        HoverButton(bar, "📋  Показать автозагрузку", self.show_autostart,
                    color=ACCENT, fg="#000").pack(side="left")

        wrap = tk.Frame(p, bg=CARD); wrap.pack(fill="both", expand=True)
        cols = ("name","pid","cpu","mem","caps","path")
        self.tv = ttk.Treeview(wrap, columns=cols, show="headings",
                               selectmode="extended", style="Aegis.Treeview")
        for c,t,w in [("name","Процесс",220),("pid","PID",60),("cpu","CPU %",70),
                      ("mem","Память, МБ",100),("caps","Права",200),
                      ("path","Путь",360)]:
            self.tv.heading(c, text=t); self.tv.column(c, width=w, anchor="w")
        for col in cols:
            self.tv.heading(col, text=self.tv.heading(col)["text"],
                            command=lambda c=col: self._sort_procs(c))

        self.tv.tag_configure("caps", foreground=WARN)

        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tv.yview,
                           style="Aegis.Vertical.TScrollbar")
        self.tv.configure(yscrollcommand=sb.set)
        self.tv.pack(side="left", fill="both", expand=True, padx=(8,0), pady=8)
        sb.pack(side="right", fill="y", pady=8)

        self.tv.bind("<Double-1>", lambda e: self.open_process_folder())
        self.tv.bind("<Button-3>", self._proc_context_menu)

        self._sort_state = {"col": None, "reverse": False}
        self.refresh_procs()
        return p

    def refresh_procs(self):
        try: self.tv.delete(*self.tv.get_children())
        except Exception: return
        self.proc_rows.clear()
        for p in psutil.process_iter(['pid','name','memory_info']):
            try:
                pid  = p.info['pid']
                name = p.info['name'] or "?"
                mem  = (p.info['memory_info'].rss/1024/1024) if p.info['memory_info'] else 0
                try:
                    cpu  = p.cpu_percent(interval=None)
                    path = p.exe() if p.exe() else ""
                except Exception:
                    cpu, path = 0, ""
                caps = process_capabilities(name)
                item = self.tv.insert("", "end",
                    values=(name, pid, f"{cpu:.1f}", f"{mem:.1f}", caps, path))
                if caps:
                    self.tv.item(item, tags=("caps",))
                self.proc_rows[pid] = item
            except Exception: continue

    def _sort_procs(self, col):
        state = self._sort_state
        state["reverse"] = not state["reverse"] if state["col"] == col else False
        state["col"] = col
        items = [(self.tv.set(i, col), i) for i in self.tv.get_children("")]
        def key(x):
            v = x[0]
            try: return float(v)
            except ValueError: return v.lower()
        items.sort(key=key, reverse=state["reverse"])
        for idx, (_, i) in enumerate(items):
            self.tv.move(i, "", idx)

    def _auto_refresh_procs(self):
        try:
            if not self.scanning and getattr(self, "current_page", "") == "procs":
                self.refresh_procs()
        except Exception: pass
        self.root.after(4000, self._auto_refresh_procs)

    def _selected_pids(self):
        pids = []
        for item in self.tv.selection():
            try: pids.append(int(self.tv.item(item, "values")[1]))
            except Exception: pass
        return pids

    def kill_selected(self):
        pids = self._selected_pids()
        if not pids:
            messagebox.showinfo("Aegis", "Выбери процессы в списке."); return
        killed = 0
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                if proc.name().lower() in SYSTEM_PROCS: continue
                proc.kill(); killed += 1
            except Exception: pass
        self.refresh_procs()
        self._toast("Процессы завершены", f"Успешно: {killed}", ACCENT, "✔")

    def kill_all(self):
        if not messagebox.askyesno("Aegis", "Завершить все процессы, кроме системных?"):
            return
        killed = 0
        for p in psutil.process_iter(['pid','name']):
            try:
                if p.info['name'] and p.info['name'].lower() in SYSTEM_PROCS: continue
                if p.info['pid'] == os.getpid(): continue
                p.kill(); killed += 1
            except Exception: pass
        self.refresh_procs()
        self._toast("Массовое завершение", f"Завершено: {killed}", ACCENT, "✔")

    def open_process_folder(self):
        sel = self.tv.selection()
        if not sel: return
        path = self.tv.item(sel[0], "values")[5]
        if not path:
            messagebox.showinfo("Aegis", "Путь процесса недоступен."); return
        try: os.startfile(os.path.dirname(path))
        except Exception as e:
            messagebox.showerror("Aegis", f"Не удалось открыть:\n{e}")

    def _proc_context_menu(self, event):
        item = self.tv.identify_row(event.y)
        if not item: return
        self.tv.selection_set(item)
        m = tk.Menu(self.root, tearoff=0, bg=CARD, fg=FG,
                    activebackground=ACCENT, activeforeground="#000",
                    bd=0, font=FONT)
        m.add_command(label="🗂  Открыть папку процесса",
                      command=self.open_process_folder)
        m.add_command(label="✕  Завершить",
                      command=self.kill_selected)
        m.add_separator()
        m.add_command(label="➕  Добавить в автозагрузку",
                      command=self.add_process_to_startup)
        try: m.tk_popup(event.x_root, event.y_root)
        finally: m.grab_release()

    # -------- АВТОЗАГРУЗКА --------
    def add_to_startup(self):
        path = filedialog.askopenfilename(
            title="Выбери файл для автозагрузки",
            filetypes=[("Программы", "*.exe *.bat *.cmd *.lnk"), ("Все файлы", "*.*")]
        )
        if not path: return
        default_name = os.path.splitext(os.path.basename(path))[0]
        name = self._ask_string("Имя записи", "Как назвать в автозагрузке?", default_name)
        if not name: return
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, path)
            winreg.CloseKey(k)
            self._toast("Добавлено в автозагрузку", f"{name}\n{path}", ACCENT, "✔")
        except Exception as e:
            messagebox.showerror("Aegis", f"Не удалось добавить:\n{e}")

    def add_process_to_startup(self):
        sel = self.tv.selection()
        if not sel:
            messagebox.showinfo("Aegis", "Выбери процесс в списке."); return
        vals = self.tv.item(sel[0], "values")
        name = vals[0]; path = vals[5]
        if not path or not os.path.exists(path):
            messagebox.showinfo("Aegis",
                "У процесса нет доступного пути. Нельзя добавить в автозагрузку.")
            return
        if not messagebox.askyesno("Aegis",
                f"Добавить в автозагрузку?\n\n{name}\n{path}"): return
        try:
            import winreg
            key_name = os.path.splitext(name)[0]
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, key_name, 0, winreg.REG_SZ, path)
            winreg.CloseKey(k)
            self._toast("В автозагрузке", f"{key_name} → {path}", ACCENT, "✔")
        except Exception as e:
            messagebox.showerror("Aegis", f"Не удалось:\n{e}")

    def show_autostart(self):
        win = tk.Toplevel(self.root)
        win.title("Автозагрузка")
        win.configure(bg=BG); win.geometry("880x520")
        win.transient(self.root)

        tk.Label(win, text="Автозагрузка", bg=BG, fg=FG,
                 font=FONT_H).pack(anchor="w", padx=20, pady=(18,4))
        tk.Label(win, text="Программы, стартующие вместе с Windows.",
                 bg=BG, fg=SUB, font=("Segoe UI", 9),
                 wraplength=800, justify="left").pack(anchor="w", padx=20, pady=(0,12))

        tv = ttk.Treeview(win, columns=("name","source","path"),
                          show="headings", selectmode="extended",
                          style="Aegis.Treeview")
        tv.heading("name",   text="Программа"); tv.column("name", width=220)
        tv.heading("source", text="Источник");  tv.column("source", width=140)
        tv.heading("path",   text="Путь");      tv.column("path", width=480)
        sb = ttk.Scrollbar(win, orient="vertical", command=tv.yview,
                           style="Aegis.Vertical.TScrollbar")
        tv.configure(yscrollcommand=sb.set)
        tv.pack(fill="both", expand=True, padx=20)
        sb.place(relx=1.0, rely=0.5, anchor="e")

        def load():
            tv.delete(*tv.get_children())
            for name, source, path in self._get_autostart():
                tv.insert("", "end", values=(name, source, path))
        load()

        bar = tk.Frame(win, bg=BG); bar.pack(fill="x", padx=20, pady=14)
        HoverButton(bar, "⟳  Обновить", load).pack(side="left")
        HoverButton(bar, "➕  Добавить", self.add_to_startup,
                    color=WARN, fg="#000").pack(side="left", padx=8)

        def remove_selected():
            sel = tv.selection()
            if not sel: return
            if not messagebox.askyesno("Aegis",
                f"Удалить {len(sel)} записей из автозагрузки?"): return
            for it in sel:
                name, source, path = tv.item(it, "values")
                self._remove_autostart(name, source, path)
            load()
            self._toast("Автозагрузка", "Записи удалены", ACCENT, "✔")

        HoverButton(bar, "🗑  Удалить выбранные", remove_selected,
                    color=DANGER, fg="#fff").pack(side="left")

    def _get_autostart(self):
        result = []
        for d in STARTUP_DIRS:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    result.append((f, "Startup-папка", os.path.join(d, f)))
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i); i += 1
                    result.append((name, "Реестр HKCU", val))
                except OSError: break
            winreg.CloseKey(k)
        except Exception: pass
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i); i += 1
                    result.append((name, "Реестр HKLM", val))
                except OSError: break
            winreg.CloseKey(k)
        except Exception: pass
        return result

    def _remove_autostart(self, name, source, path):
        if "Startup" in source:
            try: os.remove(path)
            except Exception: pass
        elif "HKCU" in source:
            try:
                import winreg
                k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                    winreg.KEY_SET_VALUE)
                winreg.DeleteValue(k, name)
                winreg.CloseKey(k)
            except Exception: pass
        elif "HKLM" in source:
            try:
                import winreg
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                    winreg.KEY_SET_VALUE)
                winreg.DeleteValue(k, name)
                winreg.CloseKey(k)
            except Exception as e:
                messagebox.showerror("Aegis",
                    f"HKLM требует прав администратора:\n{e}")

    def _ask_string(self, title, prompt, default=""):
        dlg = tk.Toplevel(self.root)
        dlg.title(title); dlg.configure(bg=BG)
        dlg.geometry("420x160"); dlg.transient(self.root); dlg.grab_set()
        tk.Label(dlg, text=prompt, bg=BG, fg=FG, font=FONT).pack(padx=20, pady=(20,8), anchor="w")
        e = tk.Entry(dlg, bg=CARD_HOV, fg=FG, insertbackground=ACCENT,
                     relief="flat", font=FONT)
        e.pack(fill="x", padx=20, ipady=8)
        e.insert(0, default); e.focus_set()
        result = {"value": None}
        def ok():
            result["value"] = e.get().strip() or None
            dlg.destroy()
        def cancel():
            dlg.destroy()
        bar = tk.Frame(dlg, bg=BG); bar.pack(fill="x", padx=20, pady=16)
        HoverButton(bar, "OK", ok).pack(side="right")
        HoverButton(bar, "Отмена", cancel,
                    color=CARD_HOV, fg=FG).pack(side="right", padx=8)
        e.bind("<Return>", lambda ev: ok())
        dlg.wait_window()
        return result["value"]

    # ==========================================================
    #   SCAN
    # ==========================================================
    def _page_scan(self, quick=True):
        p = tk.Frame(self.content, bg=BG)
        title = "Быстрая проверка" if quick else "Долгая проверка"
        desc  = ("Сканирует TEMP, Загрузки, AppData, автозагрузку."
                 if quick else
                 "Полное сканирование всех дисков. Может занять время.")
        tk.Label(p, text=title, bg=BG, fg=FG, font=FONT_T).pack(anchor="w", pady=(0,4))
        tk.Label(p, text=desc, bg=BG, fg=SUB, font=FONT).pack(anchor="w", pady=(0,18))

        bar = tk.Frame(p, bg=BG); bar.pack(fill="x", pady=(0,12))
        HoverButton(bar, "▶  Запустить", lambda: self._start_scan(quick)).pack(side="left")
        HoverButton(bar, "■  Стоп", self._stop_scan,
                    color=DANGER, fg="#fff").pack(side="left", padx=8)
        lbl = tk.Label(bar, text="Готов", bg=BG, fg=SUB, font=FONT)
        lbl.pack(side="left", padx=20)

        prog = AnimatedBar(p, height=6, color=ACCENT, bg=CARD)
        prog.pack(fill="x", pady=(0,14))

        log_wrap = tk.Frame(p, bg=CARD); log_wrap.pack(fill="both", expand=True)
        log = tk.Text(log_wrap, bg=CARD, fg=FG, bd=0, font=("Consolas", 10),
                      insertbackground=ACCENT, wrap="word", padx=14, pady=12)
        sb = ttk.Scrollbar(log_wrap, orient="vertical", command=log.yview,
                           style="Aegis.Vertical.TScrollbar")
        log.configure(yscrollcommand=sb.set)
        log.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        log.tag_config("ok", foreground=ACCENT)
        log.tag_config("warn", foreground=WARN)
        log.tag_config("err", foreground=DANGER)
        log.tag_config("dim", foreground=SUB)

        if quick:
            self.prog_quick, self.log_quick, self.status_lbl_quick = prog, log, lbl
        else:
            self.prog_long,  self.log_long,  self.status_lbl_full  = prog, log, lbl
        return p

    def _status_lbl(self, quick):
        return self.status_lbl_quick if quick else self.status_lbl_full

    def _log(self, quick, text, tag=None):
        w = self.log_quick if quick else self.log_long
        w.insert("end", text + "\n", tag); w.see("end")

    def _start_scan(self, quick):
        if self.scanning: return
        self.scanning = True; self.stop_flag = False
        (self.prog_quick if quick else self.prog_long).start()
        (self.log_quick if quick else self.log_long).delete("1.0", "end")
        self._status_lbl(quick).config(text="Сканирование…", fg=ACCENT)
        threading.Thread(target=self._scan_worker, args=(quick,), daemon=True).start()

    def _stop_scan(self):
        self.stop_flag = True

    def _scan_worker(self, quick):
        try:
            if quick:
                self._log(True, "[*] Быстрая проверка запущена.", "ok")
                targets = [d for d in QUICK_DIRS if os.path.isdir(d)]
            else:
                self._log(False, "[*] Долгая проверка запущена.", "ok")
                targets = [f"{d}:\\" for d in "CDEFGH" if os.path.exists(f"{d}:\\")]
            for base in targets:
                if self.stop_flag: break
                self._scan_dir(base, quick)
        finally:
            self.scanning = False
            (self.prog_quick if quick else self.prog_long).stop()
            self._log(quick, f"[✓] Готово. Найдено: {len(self.quarantine)}", "ok")
            self.root.after(0, lambda: self._status_lbl(quick).config(text="Готов", fg=SUB))

    def _scan_dir(self, base, quick):
        for root, dirs, files in os.walk(base):
            if self.stop_flag: return
            # не заходим в папку карантина
            if QUARANTINE_DIR.lower() in root.lower():
                continue
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
            for f in files:
                if self.stop_flag: return
                path = os.path.join(root, f)
                reason = self._check_file(path)
                if reason: self._add_suspect(path, reason, quick)

    def _is_safe_ext(self, path):
        ext = os.path.splitext(path)[1].lower()
        return ext in self.safe_ext

    def _check_file(self, path):
        if self._is_safe_ext(path):
            return None
        reason = analyze_file(path)
        if reason: return reason
        name = os.path.basename(path).lower()
        ext  = os.path.splitext(name)[1]
        parent = os.path.dirname(path).lower()
        in_temp = any(parent.startswith(d.lower()) for d in QUICK_DIRS if d)
        if in_temp and ext == '.exe':
            try:
                if os.path.getsize(path) > 100 * 1024 * 1024:
                    return "Крупный .exe (>100 МБ) в системной папке"
            except Exception:
                pass
        return None

    def _quarantine_file(self, path):
        """Перемещает файл в карантин. Возвращает (новый_путь, ошибка)."""
        try:
            if not os.path.exists(path):
                return None, "файл уже отсутствует"
            fname = os.path.basename(path)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(QUARANTINE_DIR, f"{stamp}__{fname}")
            last_err = None
            for attempt in range(3):
                try:
                    shutil.move(path, dest)
                    return dest, None
                except (PermissionError, OSError) as e:
                    last_err = e
                    time.sleep(0.3)
            return None, str(last_err)
        except Exception as e:
            return None, str(e)

    def _add_suspect(self, path, reason, quick):
        for q in self.quarantine:
            if q.get("original") == path: return
        moved_path, err = self._quarantine_file(path)
        entry = {
            "path": moved_path or path,
            "original": path,
            "reason": reason,
            "moved": bool(moved_path),
        }
        if err:
            entry["reason"] += f" (не удалось переместить: {err})"
        self.quarantine.append(entry)
        self._log(quick, f"⚠  {path}\n    → {reason}", "warn")
        self.root.after(0, self.refresh_quarantine)
        self.root.after(0, lambda: self._animate_counter(self.card_found, len(self.quarantine)))
        self.root.after(0, lambda: self._animate_counter(self.card_quar, len(self.quarantine)))

    # ==========================================================
    #   КАРАНТИН
    # ==========================================================
    def _page_quarantine(self):
        p = tk.Frame(self.content, bg=BG)
        tk.Label(p, text="Карантин", bg=BG, fg=FG, font=FONT_T).pack(anchor="w", pady=(0,4))
        tk.Label(p, text="Все подозрительные файлы. Оригинал перенесён сюда.",
                 bg=BG, fg=SUB, font=FONT).pack(anchor="w", pady=(0,18))

        wrap = tk.Frame(p, bg=CARD); wrap.pack(fill="both", expand=True)
        self.tv_q = ttk.Treeview(wrap, columns=("path","reason","size"),
                                 show="headings", selectmode="extended",
                                 style="Aegis.Treeview")
        self.tv_q.heading("path", text="Файл в карантине"); self.tv_q.column("path", width=460)
        self.tv_q.heading("reason", text="Причина");        self.tv_q.column("reason", width=400)
        self.tv_q.heading("size", text="Размер");           self.tv_q.column("size", width=100)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tv_q.yview,
                           style="Aegis.Vertical.TScrollbar")
        self.tv_q.configure(yscrollcommand=sb.set)
        self.tv_q.pack(side="left", fill="both", expand=True, padx=(8,0), pady=8)
        sb.pack(side="right", fill="y", pady=8)

        bar = tk.Frame(p, bg=BG); bar.pack(fill="x", pady=14)
        HoverButton(bar, "🗑  Удалить навсегда", self.del_perm,
                    color=DANGER, fg="#fff").pack(side="left")
        HoverButton(bar, "✕  Убрать из списка", self.del_from_list).pack(side="left", padx=8)
        HoverButton(bar, "📂  Открыть папку", self.open_folder).pack(side="left")
        HoverButton(bar, "🛡  Проверить в VT", self.vt_check_selected,
                    color=ACCENT, fg="#000").pack(side="left", padx=8)
        return p

    def refresh_quarantine(self):
        try: self.tv_q.delete(*self.tv_q.get_children())
        except Exception: return
        for q in self.quarantine:
            try: size = f"{os.path.getsize(q['path'])/1024:.0f} КБ"
            except Exception: size = "?"
            self.tv_q.insert("", "end",
                             values=(q['path'], q['reason'], size))

    def del_perm(self):
        sel = self.tv_q.selection()
        if not sel: return
        if not messagebox.askyesno("Aegis", "Удалить выбранные файлы безвозвратно?"):
            return
        for it in sel:
            path = self.tv_q.item(it, "values")[0]
            try: os.remove(path)
            except Exception as e:
                messagebox.showerror("Aegis", f"Не удалось удалить:\n{path}\n{e}")
            self.quarantine = [q for q in self.quarantine if q["path"] != path]
        self.refresh_quarantine()
        self._animate_counter(self.card_quar, len(self.quarantine))
        self._toast("Карантин", "Файлы удалены", ACCENT, "✔")

    def del_from_list(self):
        for it in self.tv_q.selection():
            path = self.tv_q.item(it, "values")[0]
            self.quarantine = [q for q in self.quarantine if q["path"] != path]
        self.refresh_quarantine()

    def open_folder(self):
        sel = self.tv_q.selection()
        if not sel: return
        path = self.tv_q.item(sel[0], "values")[0]
        try: os.startfile(os.path.dirname(path))
        except Exception: pass

    def vt_check_selected(self):
        if not self.vt.api_key:
            messagebox.showinfo("Aegis", "Сначала вставь API-ключ в Настройках.")
            return
        sel = self.tv_q.selection()
        if not sel:
            messagebox.showinfo("Aegis", "Выбери файл в списке."); return
        def worker():
            for it in sel:
                path = self.tv_q.item(it, "values")[0]
                res = self.vt.check_file(path)
                self.root.after(0, lambda r=res, p=path: self._vt_result(r, p))
                time.sleep(16)
        threading.Thread(target=worker, daemon=True).start()

    def _vt_result(self, res, path):
        name = os.path.basename(path)
        if res["status"] == "error":
            self._toast("VirusTotal", res["message"], DANGER, "✗"); return
        if res["status"] == "malicious":
            color, title = DANGER, f"ВИРУС! {name}"
        elif res["status"] == "clean":
            color, title = ACCENT, f"Чисто: {name}"
        else:
            color, title = WARN, f"Неизвестен: {name}"
        msg = res.get("message", "")
        for q in self.quarantine:
            if q["path"] == path:
                q["reason"] += f" | VT: {res['status']} {msg}"; break
        self.refresh_quarantine()
        self._toast(title, msg, color, "🛡")
        if res.get("link"):
            try:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"[VT] {path} -> {res['link']}\n")
            except Exception: pass

    # ==========================================================
    #   НАСТРОЙКИ
    # ==========================================================
    def _page_settings(self):
        p = tk.Frame(self.content, bg=BG)
        tk.Label(p, text="Настройки", bg=BG, fg=FG, font=FONT_T).pack(anchor="w", pady=(0,4))
        tk.Label(p, text="Параметры Aegis Cleaner", bg=BG, fg=SUB,
                 font=FONT).pack(anchor="w", pady=(0,18))

        # --- VirusTotal ---
        box_vt = tk.Frame(p, bg=CARD); box_vt.pack(fill="x", pady=(0,12))
        tk.Label(box_vt, text="VirusTotal API", bg=CARD, fg=FG,
                 font=FONT_H).pack(anchor="w", padx=20, pady=(16,4))
        tk.Label(box_vt,
                 text="Вставь бесплатный API-ключ (virustotal.com → профиль → API key).\n"
                      "Проверка по SHA-256, лимит 4 запроса/мин.",
                 bg=CARD, fg=SUB, font=("Segoe UI", 9), justify="left").pack(anchor="w", padx=20)

        row = tk.Frame(box_vt, bg=CARD); row.pack(fill="x", padx=20, pady=(10,4))
        self.vt_entry = tk.Entry(row, show="•", bg=CARD_HOV, fg=FG,
                                 insertbackground=ACCENT, relief="flat",
                                 font=("Consolas", 10), bd=0)
        self.vt_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0,8))
        self.vt_entry.insert(0, self.config.get("vt_api_key", ""))

        self.vt_status = tk.Label(box_vt, text="", bg=CARD, fg=SUB,
                                  font=("Segoe UI", 9))
        self.vt_status.pack(anchor="w", padx=20, pady=(0,6))

        def save_key():
            key = self.vt_entry.get().strip()
            self.config["vt_api_key"] = key
            self._save_config()
            self.vt.api_key = key
            self.rt.vt = self.vt
            if key:
                self.vt_status.config(text="Ключ сохранён. Проверяю…", fg=SUB)
                def test():
                    p2 = os.path.join(AEGIS_DIR, "config.json")
                    if not os.path.exists(p2):
                        with open(p2, "w") as f: f.write("{}")
                    res = self.vt.check_file(p2)
                    if res["status"] == "error":
                        self.root.after(0, lambda: self.vt_status.config(
                            text=f"✗ {res['message']}", fg=DANGER))
                    else:
                        self.root.after(0, lambda: self.vt_status.config(
                            text=f"✓ Ключ работает ({res['status']})", fg=ACCENT))
                threading.Thread(target=test, daemon=True).start()
            else:
                self.vt_status.config(text="Ключ удалён", fg=WARN)

        HoverButton(box_vt, "💾  Сохранить ключ", save_key).pack(anchor="w", padx=20, pady=(0,16))

        # --- Белый список расширений ---
        box_safe = tk.Frame(p, bg=CARD); box_safe.pack(fill="x", pady=(0,12))
        tk.Label(box_safe, text="Не кидать в карантин (расширения)",
                 bg=CARD, fg=FG, font=FONT_H).pack(anchor="w", padx=20, pady=(16,4))
        tk.Label(box_safe,
                 text="Файлы с этими расширениями игнорируются эвристикой.",
                 bg=CARD, fg=SUB, font=("Segoe UI", 9)).pack(anchor="w", padx=20)

        add_row = tk.Frame(box_safe, bg=CARD)
        add_row.pack(fill="x", padx=20, pady=(10, 8))
        self.safe_entry = tk.Entry(add_row, bg=CARD_HOV, fg=FG,
                                   insertbackground=ACCENT, relief="flat",
                                   font=("Consolas", 10), bd=0,
                                   width=12)
        self.safe_entry.pack(side="left", ipady=8)
        self.safe_entry.insert(0, ".txt")

        def add_ext():
            e = self.safe_entry.get().strip().lower()
            if not e: return
            if not e.startswith("."): e = "." + e
            self.safe_ext.add(e)
            self.config["safe_ext"] = sorted(self.safe_ext)
            self._save_config()
            self.rt.safe_ext = self.safe_ext
            _refresh_safe_list()

        HoverButton(add_row, "Добавить", add_ext, pad=(14, 8)).pack(side="left", padx=8)

        self.safe_list_frame = tk.Frame(box_safe, bg=CARD)
        self.safe_list_frame.pack(fill="x", padx=20, pady=(0, 16))

        def _refresh_safe_list():
            for w in self.safe_list_frame.winfo_children():
                w.destroy()
            if not self.safe_ext:
                tk.Label(self.safe_list_frame, text="Список пуст",
                         bg=CARD, fg=SUB, font=("Segoe UI", 9)).pack(anchor="w")
                return
            for ext in sorted(self.safe_ext):
                tag = tk.Frame(self.safe_list_frame, bg=CARD_HOV)
                tag.pack(side="left", padx=(0, 6), pady=2)
                tk.Label(tag, text=ext, bg=CARD_HOV, fg=FG,
                         font=("Consolas", 9), padx=8, pady=4).pack(side="left")
                rem = tk.Label(tag, text="✕", bg=CARD_HOV, fg=DANGER,
                               font=("Segoe UI Semibold", 10),
                               padx=6, cursor="hand2")
                rem.pack(side="left")
                def make_remover(e=ext):
                    def remove():
                        self.safe_ext.discard(e)
                        self.config["safe_ext"] = sorted(self.safe_ext)
                        self._save_config()
                        self.rt.safe_ext = self.safe_ext
                        _refresh_safe_list()
                    return remove
                rem.bind("<Button-1>", lambda ev, r=make_remover(): r())
        _refresh_safe_list()

        # --- Пути ---
        box2 = tk.Frame(p, bg=CARD); box2.pack(fill="x", pady=(0,12))
        tk.Label(box2, text="Пути данных", bg=CARD, fg=FG,
                 font=FONT_H).pack(anchor="w", padx=20, pady=(16,8))
        tk.Label(box2, text=f"Карантин:  {QUARANTINE_DIR}",
                 bg=CARD, fg=SUB, font=("Segoe UI", 9)).pack(anchor="w", padx=20)
        tk.Label(box2, text=f"Лог:  {LOG_FILE}",
                 bg=CARD, fg=SUB, font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(2,16))
        HoverButton(box2, "📂  Открыть папку карантина",
                    lambda: os.startfile(QUARANTINE_DIR)).pack(anchor="w", padx=20, pady=(0,16))
        return p

    # ==========================================================
    #   REALTIME → UI
    # ==========================================================
    def _poll_rt(self):
        if self.rt_enabled: self.rt.poll()
        self.root.after(200, self._poll_rt)

    def _on_realtime_threat(self, path, reason, original=None):
        if any(q.get("original") == original or q["path"] == path
               for q in self.quarantine):
            return
        self.quarantine.append({
            "path": path,
            "original": original or path,
            "reason": reason + " [realtime]",
            "moved": path != original if original else True,
        })
        self.stat_found += 1
        self.root.after(0, self.refresh_quarantine)
        self.root.after(0, lambda: self._animate_counter(self.card_found, len(self.quarantine)))
        self.root.after(0, lambda: self._animate_counter(self.card_quar, len(self.quarantine)))
        self.root.after(0, lambda: self._toast(
            "Обнаружена угроза",
            f"{os.path.basename(original or path)}\n{reason}", DANGER, "⚠"))

    # ==========================================================
    #   UTIL
    # ==========================================================
    def _animate_counter(self, label, target, duration=420, steps=24):
        try: current = int(label.cget("text"))
        except Exception: current = 0
        def step(i):
            if i > steps:
                label.config(text=str(target)); return
            val = int(current + (target - current) * (i / steps))
            label.config(text=str(val))
            self.root.after(duration // steps, lambda: step(i + 1))
        step(1)

    def _toast(self, title, subtitle, color=ACCENT, icon="✓"):
        try: Toast(self.root, title, subtitle, color=color, icon=icon)
        except Exception: pass

    def _tick_clock(self):
        try: self.clock.config(text=datetime.now().strftime("%H:%M:%S"))
        except Exception: pass
        self.root.after(1000, self._tick_clock)

    def _on_close(self):
        try: self.rt.stop()
        except Exception: pass
        self.root.destroy()


# ============================================================
#   ЗАПУСК
# ============================================================
if __name__ == "__main__":
    root = tk.Tk()
    AegisApp(root)
    root.mainloop()