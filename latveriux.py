#!/usr/bin/env python3
import sys, os, shlex, json, subprocess, copy, math, socket, re, platform
try:
    import fcntl, struct
    _HAVE_IOCTL = True
except Exception:
    _HAVE_IOCTL = False

IS_WINDOWS = sys.platform == "win32"
VPN_IFACES = ("tun0", "tun1", "tun2", "tap0", "tap1", "ppp0", "wg0", "wg1")
VPN_NAME_HINTS = (
    "tun", "tap", "ppp", "wg", "wireguard", "openvpn", "vpn",
    "nord", "proton", "mullvad", "tailscale", "zerotier", "hamachi",
)

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QFormLayout, QLabel, QLineEdit, QPushButton, QPlainTextEdit,
    QComboBox, QCheckBox, QSpinBox, QGraphicsView, QGraphicsScene,
    QGraphicsRectItem, QGraphicsLineItem, QGraphicsItem, QListWidget,
    QListWidgetItem, QFileDialog, QMessageBox, QGroupBox, QSplitter,
    QAbstractItemView, QMenu, QScrollArea, QFrame, QStackedWidget, QButtonGroup,
    QDialog, QShortcut, QColorDialog, QInputDialog, QTextBrowser
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QRectF, QPointF, QEvent, QSize, QTimer
from PyQt5.QtGui import (
    QFont, QColor, QBrush, QPen, QPainter, QLinearGradient, QPainterPath,
    QIcon, QPixmap, QPolygonF, QKeySequence, QSyntaxHighlighter, QTextCharFormat
)

def iface_ip(ifname):
    if _HAVE_IOCTL:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            packed = struct.pack("256s", ifname[:15].encode())
            return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24])
        except Exception:
            pass
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "dev", ifname],
            stderr=subprocess.DEVNULL, text=True)
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None

def _windows_vpn_ip():
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        out = subprocess.check_output(["ipconfig"], text=True, errors="ignore", creationflags=flags)
    except Exception:
        return None
    current = ""
    for raw in out.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line.endswith(":") and not line.startswith(" "):
            current = line[:-1].strip()
            continue
        if "IPv4" not in line:
            continue
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        if not m:
            continue
        name = current.lower()
        if any(h in name for h in VPN_NAME_HINTS):
            return m.group(1)
    return None

def detect_vpn_ip():
    if IS_WINDOWS:
        return _windows_vpn_ip()
    for ifname in VPN_IFACES:
        ip = iface_ip(ifname)
        if ip:
            return ip
    return None

def _python_for_gui():
    exe = os.path.abspath(sys.executable)
    if IS_WINDOWS and exe.lower().endswith("python.exe"):
        candidate = exe[:-10] + "pythonw.exe"
        if os.path.isfile(candidate):
            return candidate
    return exe

def app_icon_path():
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("app_icon.png", "latveriux.png"):
        p = os.path.join(here, name)
        if os.path.isfile(p):
            return p
    return None

def make_app_icon():
    path = app_icon_path()
    if path:
        pm = QPixmap(path)
        if not pm.isNull():
            return QIcon(pm)
    pm = QPixmap(128, 128)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setBrush(QBrush(QColor("#09182d")))
    p.setPen(QPen(QColor("#2dd4bf"), 3))
    p.drawRoundedRect(QRectF(6, 6, 116, 116), 28, 28)
    p.setPen(QPen(QColor("#2dd4bf"), 4))
    a, b, c = QPointF(64, 34), QPointF(36, 90), QPointF(92, 90)
    p.drawLine(a, b)
    p.drawLine(b, c)
    p.drawLine(c, a)
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(QColor("#2dd4bf")))
    p.drawEllipse(a, 9, 9)
    p.drawEllipse(b, 9, 9)
    p.drawEllipse(c, 9, 9)
    p.setBrush(QBrush(QColor("#e3b341")))
    p.drawPie(QRectF(a.x() - 9, a.y() - 9, 18, 18), 16 * 280, 16 * 80)
    p.end()
    return QIcon(pm)

STATUS_COLORS = {
    "unscanned": "#6e7681",
    "scanned": "#3fb950",
    "enumerated": "#58a6ff",
    "foothold": "#d29922",
    "owned": "#f85149",
}
STATUS_LIST = list(STATUS_COLORS.keys())
HOST_TYPES = ["PC", "Mobile", "Website", "Domain Controller", "AI", "Other"]
HOST_COLOR_PRESETS = [
    ("Default", ""),
    ("Red", "#f85149"),
    ("Orange", "#d29922"),
    ("Gold", "#e3b341"),
    ("Green", "#3fb950"),
    ("Blue", "#58a6ff"),
    ("Purple", "#a371f7"),
    ("Pink", "#f778ba"),
    ("Teal", "#39d0c5"),
    ("Gray", "#8b949e"),
]

def parse_tags(text):
    return [t.strip() for t in re.split(r"[,;]+", text or "") if t.strip()]

def format_tags(tags):
    if isinstance(tags, str):
        tags = parse_tags(tags)
    return ", ".join(tags or [])

def normalize_host_extra(host):
    if not isinstance(host, dict):
        return host
    tags = host.get("tags", [])
    if isinstance(tags, str):
        tags = parse_tags(tags)
    host["tags"] = tags
    host["color"] = (host.get("color") or "").strip()
    return host

IS_DARK = True

def mono_font(size=11):
    f = QFont("JetBrains Mono, Cascadia Code, Fira Code, DejaVu Sans Mono, Consolas, monospace")
    f.setStyleHint(QFont.Monospace)
    f.setPointSize(size)
    return f

def ui_font(size=11, bold=False):
    f = QFont("Inter, SF Pro Display, Segoe UI, Noto Sans, Ubuntu, Cantarell, sans-serif")
    f.setStyleHint(QFont.SansSerif)
    f.setPointSize(size)
    f.setBold(bold)
    return f

def make_nav_icon(kind, color, size=18):
    scale = 2
    pm = QPixmap(size * scale, size * scale)
    pm.setDevicePixelRatio(scale)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    c = QColor(color)
    pen = QPen(c, 1.7)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)

    def line(x1, y1, x2, y2):
        p.drawLine(QPointF(x1, y1), QPointF(x2, y2))

    if kind == "map":
        pts = [(4, 6), (14, 4.5), (8.5, 14)]
        line(*pts[0], *pts[1])
        line(*pts[1], *pts[2])
        line(*pts[0], *pts[2])
        p.setBrush(QBrush(c))
        for (x, y) in pts:
            p.drawEllipse(QPointF(x, y), 2.1, 2.1)
    elif kind == "hosts":
        p.setBrush(QBrush(c))
        p.setPen(Qt.NoPen)
        for (x, y) in [(3.5, 3.5), (10, 3.5), (3.5, 10), (10, 10)]:
            p.drawRoundedRect(QRectF(x, y, 4.5, 4.5), 1.2, 1.2)
    elif kind == "terminal":
        p.drawRoundedRect(QRectF(2.5, 3.5, 13, 11), 2.2, 2.2)
        line(5, 7, 7, 9)
        line(7, 9, 5, 11)
        line(8.5, 11.3, 12, 11.3)
    elif kind == "creds":
        p.drawEllipse(QPointF(6, 6), 3.4, 3.4)
        line(8, 8, 14, 14)
        line(14, 14, 12.4, 14)
        line(12.8, 12.2, 11.4, 12.2)
    elif kind == "notes":
        p.drawRoundedRect(QRectF(3.2, 2.4, 11.6, 13.4), 1.8, 1.8)
        line(6.0, 6.0, 12.0, 6.0)
        line(6.0, 9.0, 12.0, 9.0)
        line(6.0, 12.0, 10.4, 12.0)
    elif kind == "settings":
        import math as _m
        cx, cy = 9, 9
        p.setBrush(QBrush(c))
        p.setPen(Qt.NoPen)
        for a in range(0, 360, 45):
            rad = _m.radians(a)
            tx = cx + _m.cos(rad) * 6.6
            ty = cy + _m.sin(rad) * 6.6
            p.save()
            p.translate(tx, ty)
            p.rotate(a)
            p.drawRoundedRect(QRectF(-1.5, -1.5, 3, 3), 0.8, 0.8)
            p.restore()
        p.drawEllipse(QPointF(cx, cy), 5.0, 5.0)
        p.setBrush(QBrush(QColor(0, 0, 0, 0)))
        p.setPen(QPen(QColor(0, 0, 0, 0)))
        p.setCompositionMode(QPainter.CompositionMode_Clear)
        p.setBrush(QBrush(QColor(0, 0, 0, 255)))
        p.drawEllipse(QPointF(cx, cy), 2.2, 2.2)
        p.setCompositionMode(QPainter.CompositionMode_SourceOver)
    p.end()
    return QIcon(pm)

NODE_PALETTE = {
    True: {
        "card": "#10151e",
        "inset": "#080c12",
        "ip": "#f4f7fb",
        "sub": "#8b96a8",
        "ports": "#7dd3c7",
        "sel": "#5eead4",
        "shadow": "#000000",
    },
    False: {
        "card": "#ffffff",
        "inset": "#eef2f7",
        "ip": "#0f172a",
        "sub": "#64748b",
        "ports": "#0f766e",
        "sel": "#0d9488",
        "shadow": "#94a3b8",
    },
}

class CommandWorker(QThread):
    line = pyqtSignal(str)
    done = pyqtSignal(int)
    def __init__(self, argv, cwd=None, env=None):
        super().__init__()
        self.argv = argv
        self.cwd = cwd
        self.env = env
        self._proc = None
        self._stop = False
    def run(self):
        try:
            kwargs = dict(
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, cwd=self.cwd, env=self.env)
            if IS_WINDOWS:
                kwargs["shell"] = True
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                self._proc = subprocess.Popen(subprocess.list2cmdline(self.argv), **kwargs)
            else:
                self._proc = subprocess.Popen(self.argv, **kwargs)
        except FileNotFoundError:
            self.line.emit(f"[!] Command not found: {self.argv[0]}")
            self.done.emit(127)
            return
        except Exception as e:
            self.line.emit(f"[!] Failed: {e}")
            self.done.emit(1)
            return
        try:
            for raw in self._proc.stdout:
                if self._stop:
                    break
                self.line.emit(raw.rstrip("\n"))
        except Exception as e:
            self.line.emit(f"[!] Read error: {e}")
        try:
            self._proc.wait(timeout=3)
        except Exception:
            pass
        self.done.emit(self._proc.returncode if self._proc.returncode is not None else 0)
    def stop(self):
        self._stop = True
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

class TerminalWidget(QWidget):
    _counter = 0
    def __init__(self, panel):
        super().__init__()
        TerminalWidget._counter += 1
        self.session_id = TerminalWidget._counter
        self.panel = panel
        self.history = []
        self.history_idx = -1
        self.worker = None
        self.cwd = os.path.expanduser("~")
        self.env = os.environ.copy()

        self.setObjectName("termpane")
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        bar = QWidget()
        bar.setObjectName("termbar")
        bar.setFixedHeight(32)
        bh = QHBoxLayout(bar)
        bh.setContentsMargins(12, 0, 8, 0)
        bh.setSpacing(6)
        self.dot = QLabel("●")
        self.dot.setObjectName("termdot")
        bh.addWidget(self.dot)
        self.title_lbl = QLabel(f"session {self.session_id}")
        self.title_lbl.setObjectName("termtitle")
        bh.addWidget(self.title_lbl)
        bh.addStretch(1)

        def _mini(txt, tip, slot):
            b = QPushButton(txt)
            b.setObjectName("termmini")
            b.setFixedSize(26, 24)
            b.setToolTip(tip)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(slot)
            return b
        bh.addWidget(_mini("▤", "Split left / right  (Ctrl+Shift+R)",
                           lambda: self.panel.split_terminal(self, Qt.Horizontal)))
        bh.addWidget(_mini("▥", "Split top / bottom  (Ctrl+Shift+D)",
                           lambda: self.panel.split_terminal(self, Qt.Vertical)))
        bh.addWidget(_mini("✕", "Close this pane", lambda: self.panel.close_terminal(self)))
        v.addWidget(bar)

        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setFont(mono_font(12))
        self.console.setMaximumBlockCount(30000)
        self.console.installEventFilter(self)
        v.addWidget(self.console, 1)

        self._write("LATVERIUX terminal  ·  type 'help' for builtins\n")
        self._prompt()

    def _short_cwd(self):
        home = os.path.expanduser("~")
        c = self.cwd
        if c == home:
            return "~"
        if c.startswith(home + os.sep):
            return "~" + c[len(home):]
        return c

    def _write(self, text):
        import re
        clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        clean = re.sub(r'\x1b\].*?\x07', '', clean)
        clean = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', clean)
        self.console.moveCursor(self.console.textCursor().End)
        self.console.insertPlainText(clean)
        self.console.moveCursor(self.console.textCursor().End)

    def _prompt(self):
        self._write(f"{self._short_cwd()} $ ")

    def _do_clear(self):
        self.console.clear()
        self._prompt()

    def set_active_style(self, active):
        self.setProperty("active", "1" if active else "0")
        self.style().unpolish(self)
        self.style().polish(self)

    def eventFilter(self, obj, event):
        if obj is self.console:
            if event.type() == QEvent.FocusIn:
                self.panel._set_active(self)
            elif event.type() == QEvent.MouseButtonPress:
                self.panel._set_active(self)
            if event.type() == QEvent.KeyPress:
                return self._on_key(event)
        return super().eventFilter(obj, event)

    def _on_key(self, event):
        key = event.key()
        modifiers = event.modifiers()

        if (modifiers & Qt.ControlModifier) and (modifiers & Qt.ShiftModifier) and key in (Qt.Key_R, Qt.Key_D, Qt.Key_T, Qt.Key_W):
            return False

        if self.worker and self.worker.isRunning():
            if key == Qt.Key_C and modifiers & Qt.ControlModifier:
                self.worker.stop()
                self._write("^C\n")
                self._prompt()
            return True

        if key == Qt.Key_Return or key == Qt.Key_Enter:
            cursor = self.console.textCursor()
            cursor.movePosition(cursor.End)
            self.console.setTextCursor(cursor)
            full = self.console.toPlainText()
            last_prompt = full.rfind("$ ")
            cmd = full[last_prompt + 2:].strip() if last_prompt != -1 else ""
            self._write("\n")
            if cmd:
                if not self.history or self.history[-1] != cmd:
                    self.history.append(cmd)
                self.history_idx = -1
                self._dispatch(cmd)
            else:
                self._prompt()
            return True

        if key == Qt.Key_Up:
            if self.history:
                if self.history_idx == -1:
                    self.history_idx = len(self.history) - 1
                else:
                    self.history_idx = max(0, self.history_idx - 1)
                self._replace_current_line(self.history[self.history_idx])
            return True

        if key == Qt.Key_Down:
            if self.history and self.history_idx != -1:
                self.history_idx += 1
                if self.history_idx >= len(self.history):
                    self.history_idx = -1
                    self._replace_current_line("")
                else:
                    self._replace_current_line(self.history[self.history_idx])
            return True

        if key == Qt.Key_Backspace:
            full = self.console.toPlainText()
            last_prompt = full.rfind("$ ")
            cursor = self.console.textCursor()
            if last_prompt != -1 and cursor.position() <= last_prompt + 2:
                return True

        return False

    def _replace_current_line(self, text):
        full = self.console.toPlainText()
        last_prompt = full.rfind("$ ")
        if last_prompt == -1:
            return
        new_text = full[:last_prompt + 2] + text
        self.console.setPlainText(new_text)
        self.console.moveCursor(self.console.textCursor().End)

    def _dispatch(self, cmd):
        try:
            argv = shlex.split(cmd)
        except Exception:
            argv = cmd.split()
        if not argv:
            self._prompt()
            return
        name = argv[0]

        if name in ("clear", "cls"):
            self._do_clear()
            return
        if name == "help":
            self._write("builtins: cd <dir>, pwd, export VAR=val, env, clear, help\n"
                        "everything else runs as a normal command in this pane's cwd.\n")
            self._prompt()
            return
        if name == "pwd":
            self._write(self.cwd + "\n")
            self._prompt()
            return
        if name == "cd":
            target = argv[1] if len(argv) > 1 else "~"
            target = os.path.expanduser(target)
            if not os.path.isabs(target):
                target = os.path.normpath(os.path.join(self.cwd, target))
            if os.path.isdir(target):
                self.cwd = target
            else:
                self._write(f"cd: no such directory: {target}\n")
            self._prompt()
            return
        if name == "export":
            for kv in argv[1:]:
                if "=" in kv:
                    k, _, val = kv.partition("=")
                    self.env[k] = val
            self._prompt()
            return
        if name == "env":
            for k in sorted(self.env):
                self._write(f"{k}={self.env[k]}\n")
            self._prompt()
            return

        self._run(argv)

    def _run(self, argv):
        if self.worker and self.worker.isRunning():
            self._write("[!] already running\n")
            self._prompt()
            return
        self.worker = CommandWorker(argv, cwd=self.cwd, env=self.env)
        self.worker.line.connect(lambda line: self._write(line + "\n"))
        self.worker.done.connect(self._done)
        self.worker.start()

    def _done(self, code):
        self._write(f"[*] finished (exit {code})\n")
        self._prompt()

    def stop_worker(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()


class TerminalPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.active_terminal = None
        self.all_terminals = []

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(12)

        head = QHBoxLayout()
        lbl = QLabel("TERMINAL")
        lbl.setObjectName("sectionlabel")
        head.addWidget(lbl)
        self.hint = QLabel("Ctrl+Shift+R  split ⬌     Ctrl+Shift+D  split ⬍     Ctrl+Shift+T  new tab")
        self.hint.setObjectName("hint")
        head.addWidget(self.hint)
        head.addStretch(1)
        new_btn = QPushButton("＋  new session")
        new_btn.setObjectName("ghostbtn")
        new_btn.setCursor(Qt.PointingHandCursor)
        new_btn.clicked.connect(self.new_session)
        head.addWidget(new_btn)
        root.addLayout(head)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("termtabs")
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self._close_session)
        root.addWidget(self.tabs, 1)

        def sc(seq, fn):
            s = QShortcut(QKeySequence(seq), self)
            s.setContext(Qt.WidgetWithChildrenShortcut)
            s.activated.connect(fn)
        sc("Ctrl+Shift+R", lambda: self._split_active(Qt.Horizontal))
        sc("Ctrl+Shift+D", lambda: self._split_active(Qt.Vertical))
        sc("Ctrl+Shift+T", self.new_session)
        sc("Ctrl+Shift+W", self._close_active)

        self.new_session()

    def _make_terminal(self):
        t = TerminalWidget(self)
        self.all_terminals.append(t)
        return t

    def new_session(self):
        container = QWidget()
        cv = QVBoxLayout(container)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.setSpacing(0)
        term = self._make_terminal()
        cv.addWidget(term)
        idx = self.tabs.addTab(container, f"session {term.session_id}")
        self.tabs.setCurrentIndex(idx)
        self._set_active(term)
        term.console.setFocus()

    def _set_active(self, term):
        if self.active_terminal is term:
            return
        if self.active_terminal is not None:
            try:
                self.active_terminal.set_active_style(False)
            except Exception:
                pass
        self.active_terminal = term
        term.set_active_style(True)

    def _current_container(self):
        return self.tabs.currentWidget()

    def _active_in_current(self):
        cont = self._current_container()
        if cont is None:
            return None
        if self.active_terminal is not None and self.active_terminal.window() is self.window():
            w = self.active_terminal
            p = w
            while p is not None and p is not cont:
                p = p.parentWidget()
            if p is cont:
                return self.active_terminal
        terms = cont.findChildren(TerminalWidget)
        return terms[0] if terms else None

    def _split_active(self, orientation):
        term = self._active_in_current()
        if term is not None:
            self.split_terminal(term, orientation)

    def _close_active(self):
        term = self._active_in_current()
        if term is not None:
            self.close_terminal(term)

    def split_terminal(self, term, orientation):
        parent = term.parentWidget()
        new_term = self._make_terminal()
        new_split = QSplitter(orientation)
        new_split.setObjectName("termsplit")
        new_split.setHandleWidth(6)
        new_split.setChildrenCollapsible(False)

        if isinstance(parent, QSplitter):
            idx = parent.indexOf(term)
            sizes = parent.sizes()
            new_split.addWidget(term)
            new_split.addWidget(new_term)
            parent.insertWidget(idx, new_split)
            parent.setSizes(sizes)
        else:
            layout = parent.layout()
            layout.removeWidget(term)
            new_split.addWidget(term)
            new_split.addWidget(new_term)
            layout.addWidget(new_split)

        new_split.setSizes([10000, 10000])
        self._set_active(new_term)
        new_term.console.setFocus()

    def close_terminal(self, term):
        parent = term.parentWidget()
        term.stop_worker()
        if term in self.all_terminals:
            self.all_terminals.remove(term)

        if isinstance(parent, QSplitter):
            term.setParent(None)
            term.deleteLater()
            self._collapse_if_needed(parent)
            cont = self._current_container()
            if cont is not None:
                remaining = cont.findChildren(TerminalWidget)
                if remaining:
                    self._set_active(remaining[0])
                    remaining[0].console.setFocus()
        else:
            i = self.tabs.indexOf(self._current_container())
            if i != -1:
                self._close_session(i)

    def _collapse_if_needed(self, splitter):
        if splitter.count() == 1:
            child = splitter.widget(0)
            grand = splitter.parentWidget()
            if isinstance(grand, QSplitter):
                idx = grand.indexOf(splitter)
                sizes = grand.sizes()
                grand.insertWidget(idx, child)
                splitter.setParent(None)
                splitter.deleteLater()
                grand.setSizes(sizes)
            else:
                layout = grand.layout()
                layout.removeWidget(splitter)
                layout.addWidget(child)
                splitter.setParent(None)
                splitter.deleteLater()

    def _close_session(self, index):
        cont = self.tabs.widget(index)
        if cont is None:
            return
        for t in cont.findChildren(TerminalWidget):
            t.stop_worker()
            if t in self.all_terminals:
                self.all_terminals.remove(t)
        self.tabs.removeTab(index)
        cont.deleteLater()
        if self.tabs.count() == 0:
            self.new_session()


class HostsPanel(QWidget):
    def __init__(self, map_panel_ref):
        super().__init__()
        self.map_ref = map_panel_ref
        self.parsed = []

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        top = QGroupBox("PASTE TARGETS")
        tv = QVBoxLayout(top)
        hint = QLabel("One host per line  ·  also supports  IP hostname  or  IP,hostname")
        hint.setObjectName("hint")
        tv.addWidget(hint)

        self.paste = QPlainTextEdit()
        self.paste.setPlaceholderText(
            "10.10.11.5\n"
            "10.10.11.6 dc01.htb\n"
            "10.10.11.7,web01\n"
            "172.16.0.0/24"
        )
        self.paste.setMinimumHeight(90)
        self.paste.setFont(mono_font(11))
        tv.addWidget(self.paste)

        btn_row = QHBoxLayout()
        parse_btn = QPushButton("Parse list")
        parse_btn.setObjectName("runbtn")
        parse_btn.setMinimumHeight(36)
        parse_btn.clicked.connect(self.parse_paste)
        clear_btn = QPushButton("Clear")
        clear_btn.setMinimumHeight(36)
        clear_btn.clicked.connect(self._clear_paste)
        import_btn = QPushButton("Import file…")
        import_btn.setMinimumHeight(36)
        import_btn.clicked.connect(self.import_file)
        btn_row.addWidget(parse_btn)
        btn_row.addWidget(import_btn)
        btn_row.addWidget(clear_btn)
        btn_row.addStretch(1)
        tv.addLayout(btn_row)
        root.addWidget(top)

        mid = QHBoxLayout()
        left = QVBoxLayout()
        lbl = QLabel("PARSED HOSTS")
        lbl.setObjectName("sectionlabel")
        left.addWidget(lbl)
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        left.addWidget(self.list, 1)
        mid.addLayout(left, 3)

        right = QVBoxLayout()
        right.setSpacing(10)
        self.count_lbl = QLabel("0 hosts")
        self.count_lbl.setObjectName("hint")
        right.addWidget(self.count_lbl)

        add_map_btn = QPushButton("▶  Add to Map")
        add_map_btn.setObjectName("runbtn")
        add_map_btn.setMinimumHeight(38)
        add_map_btn.clicked.connect(self.add_to_map)
        right.addWidget(add_map_btn)

        exp_txt = QPushButton("Export .txt")
        exp_txt.setMinimumHeight(36)
        exp_txt.clicked.connect(lambda: self.export("txt"))
        right.addWidget(exp_txt)

        exp_json = QPushButton("Export .json")
        exp_json.setMinimumHeight(36)
        exp_json.clicked.connect(lambda: self.export("json"))
        right.addWidget(exp_json)

        del_sel = QPushButton("Remove selected")
        del_sel.setMinimumHeight(36)
        del_sel.clicked.connect(self.remove_selected)
        right.addWidget(del_sel)

        right.addStretch(1)
        mid.addLayout(right, 1)
        root.addLayout(mid, 1)

        opt = QHBoxLayout()
        opt.addWidget(QLabel("Default status:"))
        self.status = QComboBox()
        self.status.addItems(STATUS_LIST)
        self.status.setCurrentText("unscanned")
        opt.addWidget(self.status)
        opt.addWidget(QLabel("Default type:"))
        self.htype = QComboBox()
        self.htype.addItems(HOST_TYPES)
        opt.addWidget(self.htype)
        opt.addStretch(1)
        root.addLayout(opt)

    def _clear_paste(self):
        self.paste.clear()
        self.parsed = []
        self.list.clear()
        self.count_lbl.setText("0 hosts")

    def parse_paste(self):
        raw = self.paste.toPlainText()
        self.parsed = []
        self.list.clear()
        seen = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            cleaned = line.replace(",", " ").replace(";", " ").replace("|", " ")
            parts = cleaned.split()
            if not parts:
                continue
            ip = parts[0].strip()
            if ip in seen:
                continue
            seen.add(ip)
            hostname = parts[1].strip() if len(parts) > 1 else ""
            entry = {"ip": ip, "hostname": hostname}
            self.parsed.append(entry)
            label = ip if not hostname else f"{ip}  ({hostname})"
            self.list.addItem(label)
        self.count_lbl.setText(f"{len(self.parsed)} hosts")

    def remove_selected(self):
        rows = sorted({i.row() for i in self.list.selectedIndexes()}, reverse=True)
        for r in rows:
            self.list.takeItem(r)
            if 0 <= r < len(self.parsed):
                self.parsed.pop(r)
        self.count_lbl.setText(f"{len(self.parsed)} hosts")

    def add_to_map(self):
        if not self.map_ref:
            QMessageBox.warning(self, "No map", "Map panel not available")
            return
        if not self.parsed:
            self.parse_paste()
        if not self.parsed:
            QMessageBox.information(self, "Empty", "No hosts to add")
            return
        status = self.status.currentText()
        htype = self.htype.currentText()
        added = self.map_ref.bulk_add_hosts(self.parsed, default_status=status, default_type=htype)
        QMessageBox.information(self, "Done", f"Added / updated {added} new hosts on the map\n(Total unique in list: {len(self.parsed)})")

    def export(self, fmt):
        if not self.parsed:
            self.parse_paste()
        if not self.parsed:
            QMessageBox.information(self, "Empty", "Nothing to export")
            return
        if fmt == "txt":
            path, _ = QFileDialog.getSaveFileName(self, "Export hosts", "hosts.txt", "Text (*.txt)")
            if not path:
                return
            try:
                with open(path, "w") as f:
                    for e in self.parsed:
                        if e.get("hostname"):
                            f.write(f"{e['ip']}  {e['hostname']}\n")
                        else:
                            f.write(e["ip"] + "\n")
                QMessageBox.information(self, "Exported", f"Saved {len(self.parsed)} hosts → {path}")
            except Exception as ex:
                QMessageBox.warning(self, "Error", str(ex))
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Export hosts", "hosts.json", "JSON (*.json)")
            if not path:
                return
            try:
                with open(path, "w") as f:
                    json.dump(self.parsed, f, indent=2)
                QMessageBox.information(self, "Exported", f"Saved {len(self.parsed)} hosts → {path}")
            except Exception as ex:
                QMessageBox.warning(self, "Error", str(ex))

    def import_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import hosts", "", "Text/JSON (*.txt *.json *.list);;All (*)")
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                with open(path) as f:
                    data = json.load(f)
                if isinstance(data, dict) and "hosts" in data:
                    lines = []
                    for ip, h in data["hosts"].items():
                        hn = h.get("hostname", "")
                        lines.append(f"{ip}  {hn}".strip())
                    self.paste.setPlainText("\n".join(lines))
                elif isinstance(data, list):
                    lines = []
                    for item in data:
                        if isinstance(item, dict):
                            ip = item.get("ip", "")
                            hn = item.get("hostname", "")
                            lines.append(f"{ip}  {hn}".strip() if hn else ip)
                        else:
                            lines.append(str(item))
                    self.paste.setPlainText("\n".join(lines))
                else:
                    QMessageBox.warning(self, "Format", "Unsupported JSON structure")
                    return
            else:
                with open(path) as f:
                    self.paste.setPlainText(f.read())
            self.parse_paste()
        except Exception as ex:
            QMessageBox.warning(self, "Import failed", str(ex))


class ClickyCombo(QComboBox):
    def __init__(self):
        super().__init__()
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.NoInsert)
        self.lineEdit().installEventFilter(self)
    def eventFilter(self, obj, event):
        if obj is self.lineEdit() and event.type() == QEvent.MouseButtonPress:
            if event.button() == Qt.LeftButton:
                self.showPopup()
                return True
        return super().eventFilter(obj, event)


class CredCard(QFrame):
    def __init__(self, cred, panel):
        super().__init__()
        self.cred = cred
        self.panel = panel
        self._revealed = False
        self.setObjectName("credcard")
        g = QVBoxLayout(self)
        g.setContentsMargins(16, 14, 14, 14)
        g.setSpacing(10)

        top = QHBoxLayout()
        top.setSpacing(8)
        host = cred.get("host") or "no host"
        self.host_chip = QLabel(host)
        self.host_chip.setObjectName("hostchip")
        top.addWidget(self.host_chip)
        svc = cred.get("service") or "—"
        self.svc_chip = QLabel(svc)
        self.svc_chip.setObjectName("svcchip")
        top.addWidget(self.svc_chip)
        top.addStretch(1)
        del_btn = QPushButton("✕")
        del_btn.setObjectName("credx")
        del_btn.setFixedSize(26, 26)
        del_btn.setToolTip("Delete credential")
        del_btn.setCursor(Qt.PointingHandCursor)
        del_btn.clicked.connect(lambda: self.panel.remove_card(self))
        top.addWidget(del_btn)
        g.addLayout(top)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.user_lbl = QLabel(cred.get("user") or "—")
        self.user_lbl.setObjectName("creduser")
        self.user_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        row.addWidget(self.user_lbl)
        colon = QLabel(":")
        colon.setObjectName("credsep")
        row.addWidget(colon)
        self.pass_lbl = QLabel()
        self.pass_lbl.setObjectName("credpass")
        self.pass_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        row.addWidget(self.pass_lbl)
        row.addStretch(1)

        def _mini(txt, tip, slot):
            b = QPushButton(txt)
            b.setObjectName("credmini")
            b.setToolTip(tip)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(slot)
            return b
        if cred.get("pass"):
            self.reveal_btn = _mini("show", "Reveal / hide password", self._toggle_reveal)
            row.addWidget(self.reveal_btn)
        row.addWidget(_mini("user", "Copy username", lambda: self._copy(cred.get("user", ""))))
        row.addWidget(_mini("pass", "Copy password / hash", lambda: self._copy(cred.get("pass", ""))))
        row.addWidget(_mini("u:p", "Copy user:pass", lambda: self._copy(f"{cred.get('user','')}:{cred.get('pass','')}")))
        g.addLayout(row)

        self.seen_lbl = QLabel("")
        self.seen_lbl.setObjectName("seenchip")
        self.seen_lbl.hide()
        g.addWidget(self.seen_lbl)
        notes = (cred.get("notes") or "").strip()
        self.notes_lbl = QLabel(notes)
        self.notes_lbl.setObjectName("crednotes")
        self.notes_lbl.setWordWrap(True)
        self.notes_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.notes_lbl.setVisible(bool(notes))
        g.addWidget(self.notes_lbl)

        self._render_pass()
        self.refresh_seen()

    def _render_pass(self):
        pw = self.cred.get("pass") or ""
        if not pw:
            self.pass_lbl.setText("—")
            return
        self.pass_lbl.setText(pw if self._revealed else "•" * min(len(pw), 14))

    def _toggle_reveal(self):
        self._revealed = not self._revealed
        self.reveal_btn.setText("hide" if self._revealed else "show")
        self._render_pass()

    def _copy(self, text):
        QApplication.clipboard().setText(text or "")
        self.panel.flash(f"copied  ·  {text[:40]}" if text else "nothing to copy")

    def refresh_seen(self):
        hosts = self.panel.reuse_hosts(self.cred)
        n = len(hosts)
        if n >= 2:
            self.seen_lbl.setText(f"seen on {n} hosts")
            self.seen_lbl.setToolTip("\n".join(hosts))
            self.seen_lbl.show()
        else:
            self.seen_lbl.hide()
            self.seen_lbl.setToolTip("")

    def matches_query(self, q):
        if not q:
            return True
        blob = " ".join([
            self.cred.get("host", ""),
            self.cred.get("user", ""),
            self.cred.get("pass", ""),
            self.cred.get("service", ""),
            self.cred.get("notes", ""),
        ]).lower()
        return q in blob


class CredentialsPanel(QWidget):
    def __init__(self, map_panel_ref):
        super().__init__()
        self.map_ref = map_panel_ref
        self.creds = []
        self.cards = []

        root = QHBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(18)

        left = QWidget()
        left.setMaximumWidth(400)
        left.setMinimumWidth(340)
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(14)

        box = QGroupBox("ADD CREDENTIAL")
        form = QFormLayout(box)
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignLeft)
        self.f_user = QLineEdit()
        self.f_user.setPlaceholderText("administrator")
        self.f_pass = QLineEdit()
        self.f_pass.setPlaceholderText("password / NTLM hash")
        self.f_service = QLineEdit()
        self.f_service.setPlaceholderText("smb, ssh, winrm, http…")
        self.f_host = ClickyCombo()
        self.f_host.lineEdit().setPlaceholderText("select host or type an IP")
        self.f_notes = QPlainTextEdit()
        self.f_notes.setObjectName("hostnotes")
        self.f_notes.setMinimumHeight(110)
        self.f_notes.setMaximumHeight(180)
        self.f_notes.setPlaceholderText("where found, valid on, next use…")

        form.addRow("Username", self.f_user)
        form.addRow("Password / Hash", self.f_pass)
        form.addRow("Service(s)", self.f_service)
        form.addRow("Host", self.f_host)
        form.addRow("Notes", self.f_notes)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("＋  add credential")
        add_btn.setObjectName("runbtn")
        add_btn.setMinimumHeight(38)
        add_btn.clicked.connect(self.add_cred)
        refresh_btn = QPushButton("⟳")
        refresh_btn.setObjectName("ghostbtn")
        refresh_btn.setFixedWidth(46)
        refresh_btn.setMinimumHeight(38)
        refresh_btn.setToolTip("Refresh host list from the map")
        refresh_btn.clicked.connect(self.refresh_hosts)
        btn_row.addWidget(add_btn, 1)
        btn_row.addWidget(refresh_btn)
        lv.addWidget(box)
        lv.addLayout(btn_row)

        for fld in (self.f_user, self.f_pass, self.f_service):
            fld.returnPressed.connect(self.add_cred)

        lv.addStretch(1)
        root.addWidget(left)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(10)
        hdr = QHBoxLayout()
        saved_lbl = QLabel("SAVED CREDENTIALS")
        saved_lbl.setObjectName("sectionlabel")
        hdr.addWidget(saved_lbl)
        self.search = QLineEdit()
        self.search.setObjectName("searchbox")
        self.search.setPlaceholderText("Ctrl+F  search user, host, notes…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(160)
        self.search.textChanged.connect(self._apply_card_filter)
        hdr.addWidget(self.search, 1)
        self.count_lbl = QLabel("0")
        self.count_lbl.setObjectName("countpill")
        hdr.addWidget(self.count_lbl)
        exp_btn = QPushButton("export")
        exp_btn.setObjectName("ghostbtn")
        exp_btn.setToolTip("Export credentials as JSON")
        exp_btn.clicked.connect(self.export_creds)
        hdr.addWidget(exp_btn)
        rv.addLayout(hdr)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setObjectName("credscroll")
        self.cards_host = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_host)
        self.cards_layout.setContentsMargins(2, 2, 8, 2)
        self.cards_layout.setSpacing(10)
        self.empty_lbl = QLabel("No credentials yet.\nAdd one on the left — captured creds show up here as quick-copy cards.")
        self.empty_lbl.setObjectName("emptystate")
        self.empty_lbl.setAlignment(Qt.AlignCenter)
        self.cards_layout.addWidget(self.empty_lbl)
        self.cards_layout.addStretch(1)
        self.scroll.setWidget(self.cards_host)
        rv.addWidget(self.scroll, 1)
        root.addWidget(right, 1)

        self.filter_ips = None
        self.filter_bar = QWidget()
        self.filter_bar.setObjectName("filterbar")
        fb = QHBoxLayout(self.filter_bar)
        fb.setContentsMargins(10, 6, 10, 6)
        fb.setSpacing(8)
        self.filter_lbl = QLabel("")
        self.filter_lbl.setObjectName("hint")
        fb.addWidget(self.filter_lbl, 1)
        clear_f = QPushButton("show all")
        clear_f.setObjectName("ghostbtn")
        clear_f.setCursor(Qt.PointingHandCursor)
        clear_f.clicked.connect(lambda: self.set_host_filter(None))
        fb.addWidget(clear_f)
        self.filter_bar.hide()
        rv.insertWidget(1, self.filter_bar)

        self.refresh_hosts()
        sc = QShortcut(QKeySequence("Ctrl+F"), self)
        sc.setContext(Qt.WidgetWithChildrenShortcut)
        sc.activated.connect(self._focus_search)

    def _focus_search(self):
        self.search.setFocus()
        self.search.selectAll()

    def flash(self, msg):
        w = self.window()
        if hasattr(w, "statusBar"):
            w.statusBar().showMessage("  " + msg, 2500)

    def showEvent(self, event):
        self.refresh_hosts()
        super().showEvent(event)

    def refresh_hosts(self):
        current_text = self.f_host.currentText().strip()
        self.f_host.blockSignals(True)
        self.f_host.clear()
        self.f_host.addItem("— select host —", "")
        if self.map_ref is not None and hasattr(self.map_ref, "hosts"):
            for ip in sorted(self.map_ref.hosts.keys()):
                h = self.map_ref.hosts[ip]
                label = ip if not h.get("hostname") else f"{ip}  ({h['hostname']})"
                self.f_host.addItem(label, ip)
        self.f_host.blockSignals(False)
        if current_text and current_text != "— select host —":
            self.f_host.setEditText(current_text)

    def _resolve_host(self):
        idx = self.f_host.currentIndex()
        data = self.f_host.itemData(idx)
        if data:
            return data
        host = self.f_host.currentText().strip()
        if host.startswith("—"):
            return ""
        if "  (" in host:
            host = host.split("  (")[0].strip()
        return host

    def prepare_add_for_host(self, ip):
        self.refresh_hosts()
        ip = (ip or "").strip()
        found = False
        for i in range(self.f_host.count()):
            if self.f_host.itemData(i) == ip:
                self.f_host.setCurrentIndex(i)
                found = True
                break
        if not found and ip:
            self.f_host.setEditText(ip)
        self.f_user.clear()
        self.f_pass.clear()
        self.f_service.clear()
        self.f_notes.clear()
        self.f_user.setFocus()

    def reuse_hosts(self, cred):
        user = (cred.get("user") or "").strip()
        pwd = (cred.get("pass") or "").strip()
        if not user and not pwd:
            return []
        hosts, seen = [], set()
        for c in self.creds:
            if (c.get("user") or "").strip() != user:
                continue
            if (c.get("pass") or "").strip() != pwd:
                continue
            h = (c.get("host") or "").strip() or "no host"
            if h not in seen:
                seen.add(h)
                hosts.append(h)
        return hosts

    def refresh_reuse_badges(self):
        for card in self.cards:
            card.refresh_seen()

    def set_host_filter(self, ips):
        if ips:
            self.filter_ips = {str(x).strip() for x in ips if str(x).strip()}
        else:
            self.filter_ips = None
        if self.filter_ips:
            shown = ", ".join(sorted(self.filter_ips))
            if len(shown) > 64:
                shown = shown[:61] + "…"
            self.filter_lbl.setText(f"showing  ·  {shown}")
            self.filter_bar.show()
        else:
            self.filter_lbl.setText("")
            self.filter_bar.hide()
        self._apply_card_filter()

    def _apply_card_filter(self):
        q = self.search.text().strip().lower() if hasattr(self, "search") else ""
        any_vis = False
        for card in self.cards:
            host = (card.cred.get("host") or "").strip()
            vis = True if not self.filter_ips else host in self.filter_ips
            if vis and q:
                vis = card.matches_query(q)
            card.setVisible(vis)
            if vis:
                any_vis = True
        if self.empty_lbl is not None:
            if q and self.cards:
                self.empty_lbl.setText("No credentials match that search.")
                self.empty_lbl.setVisible(not any_vis)
            elif self.filter_ips:
                self.empty_lbl.setText("No credentials for the selected host(s).")
                self.empty_lbl.setVisible(not any_vis)
            else:
                self.empty_lbl.setText("No credentials yet.\nAdd one on the left — captured creds show up here as quick-copy cards.")
                self.empty_lbl.setVisible(not self.cards)

    def add_cred(self):
        user = self.f_user.text().strip()
        pwd = self.f_pass.text().strip()
        svc = self.f_service.text().strip()
        host = self._resolve_host()
        if not (user or pwd):
            QMessageBox.warning(self, "Missing", "Need at least a username or a password/hash.")
            return
        cred = {
            "host": host, "user": user, "pass": pwd, "service": svc,
            "notes": self.f_notes.toPlainText().strip(),
        }
        self.creds.append(cred)
        self._add_card(cred)
        self.f_user.clear()
        self.f_pass.clear()
        self.f_service.clear()
        self.f_notes.clear()
        self.f_user.setFocus()
        self.flash("credential saved")
        self.refresh_reuse_badges()

    def _add_card(self, cred):
        if self.empty_lbl is not None:
            self.empty_lbl.setParent(None)
            self.empty_lbl = None
        card = CredCard(cred, self)
        self.cards.append(card)
        self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)
        self.count_lbl.setText(str(len(self.creds)))
        self._apply_card_filter()

    def remove_card(self, card):
        if card in self.cards:
            i = self.cards.index(card)
            self.cards.pop(i)
            if i < len(self.creds):
                self.creds.pop(i)
        card.setParent(None)
        card.deleteLater()
        self.count_lbl.setText(str(len(self.creds)))
        if not self.cards:
            self.empty_lbl = QLabel("No credentials yet.\nAdd one on the left — captured creds show up here as quick-copy cards.")
            self.empty_lbl.setObjectName("emptystate")
            self.empty_lbl.setAlignment(Qt.AlignCenter)
            self.cards_layout.insertWidget(0, self.empty_lbl)
        self._apply_card_filter()
        self.refresh_reuse_badges()

    def export_creds(self):
        if not self.creds:
            QMessageBox.information(self, "Empty", "No credentials to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export credentials", "credentials.json", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(self.creds, f, indent=2)
            self.flash(f"exported {len(self.creds)} credentials")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))



def _md_esc(text):
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _md_inline(text):
    parts = []
    last = 0
    raw = text or ""
    for m in re.finditer(r"`([^`]+)`", raw):
        parts.append(("t", raw[last:m.start()]))
        parts.append(("c", m.group(1)))
        last = m.end()
    parts.append(("t", raw[last:]))
    out = []
    for kind, chunk in parts:
        if kind == "c":
            out.append("<code>%s</code>" % _md_esc(chunk))
            continue
        s = _md_esc(chunk)
        s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', s)
        s = re.sub(r"==(.+?)==", r'<span class="mark">\1</span>', s)
        s = re.sub(r"~~(.+?)~~", r"<s>\1</s>", s)
        s = re.sub(r"\*\*\*(.+?)\*\*\*", r"<b><i>\1</i></b>", s)
        s = re.sub(r"___(.+?)___", r"<b><i>\1</i></b>", s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"__(.+?)__", r"<b>\1</b>", s)
        s = re.sub(r"(?<!\*)\*(?!\s)(.+?)(?<!\s)\*(?!\*)", r"<i>\1</i>", s)
        s = re.sub(r"(?<!_)_(?!\s)(.+?)(?<!\s)_(?!_)", r"<i>\1</i>", s)
        out.append(s)
    return "".join(out)

def md_to_html(text):
    lines = (text or "").splitlines()
    html = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("```"):
            buf = []
            i += 1
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            if i < n:
                i += 1
            html.append("<pre><code>%s</code></pre>" % _md_esc("\n".join(buf)))
            continue
        hm = re.match(r"^(#{1,5})\s+(.*)$", line)
        if hm:
            lvl = len(hm.group(1))
            html.append("<h%d>%s</h%d>" % (lvl, _md_inline(hm.group(2).strip()), lvl))
            i += 1
            continue
        if re.match(r"^(\-\-\-|___|\*\*\*)\s*$", stripped):
            html.append("<hr/>")
            i += 1
            continue
        if stripped.startswith(">"):
            q = []
            while i < n and lines[i].strip().startswith(">"):
                q.append(re.sub(r"^>\s?", "", lines[i].strip()))
                i += 1
            html.append("<blockquote>%s</blockquote>" % "<br/>".join(_md_inline(x) for x in q))
            continue
        ul = re.match(r"^[-*+]\s+(.*)$", line)
        ol = re.match(r"^\d+\.\s+(.*)$", line)
        if ul or ol:
            kind = "ul" if ul else "ol"
            html.append("<%s>" % kind)
            while i < n:
                u = re.match(r"^[-*+]\s+(.*)$", lines[i])
                o = re.match(r"^\d+\.\s+(.*)$", lines[i])
                if kind == "ul" and not u:
                    break
                if kind == "ol" and not o:
                    break
                item = (u or o).group(1)
                tm = re.match(r"^\[([ xX])\]\s+(.*)$", item)
                if tm:
                    chk = "checked " if tm.group(1).lower() == "x" else ""
                    html.append('<li class="task"><input type="checkbox" disabled %s/> %s</li>' % (chk, _md_inline(tm.group(2))))
                else:
                    html.append("<li>%s</li>" % _md_inline(item))
                i += 1
            html.append("</%s>" % kind)
            continue
        if not stripped:
            i += 1
            continue
        para = [line]
        i += 1
        while i < n and lines[i].strip() and not re.match(r"^(#{1,5})\s+", lines[i]) and not lines[i].strip().startswith("```") and not re.match(r"^[-*+]\s+", lines[i]) and not re.match(r"^\d+\.\s+", lines[i]) and not lines[i].strip().startswith(">") and not re.match(r"^(\-\-\-|___|\*\*\*)\s*$", lines[i].strip()):
            para.append(lines[i])
            i += 1
        html.append("<p>%s</p>" % "<br/>".join(_md_inline(x) for x in para))
    return "\n".join(html) if html else "<p></p>"

def md_document(text):
    if IS_DARK:
        css = (
            "body{color:#e6edf5;background:transparent;font-family:Inter,Segoe UI,Noto Sans,sans-serif;"
            "font-size:15px;line-height:1.6;padding:8px 4px;}"
            "h1{font-size:28px;margin:0.55em 0 0.3em;color:#f4f7fb;font-weight:800;}"
            "h2{font-size:22px;margin:0.55em 0 0.28em;color:#f4f7fb;font-weight:800;}"
            "h3{font-size:18px;margin:0.5em 0 0.24em;color:#e6edf5;font-weight:750;}"
            "h4{font-size:16px;margin:0.45em 0 0.2em;color:#d5deea;font-weight:700;}"
            "h5{font-size:14px;margin:0.4em 0 0.18em;color:#c5d0dc;font-weight:700;letter-spacing:0.2px;}"
            "p{margin:0.35em 0 0.7em;}"
            "code{background:#151b24;color:#99f6e4;padding:1px 6px;border-radius:6px;"
            "font-family:'JetBrains Mono',Consolas,monospace;font-size:13px;}"
            "pre{background:#080b11;border:1px solid #243041;border-radius:12px;padding:12px 14px;}"
            "pre code{background:transparent;padding:0;color:#d5deea;}"
            "a{color:#5eead4;text-decoration:none;}"
            "s{color:#9aa6b8;}"
            "blockquote{border-left:3px solid #2dd4bf;margin:0.4em 0;padding:4px 12px;color:#9aa6b8;}"
            "ul,ol{margin:0.3em 0 0.8em 1.2em;}"
            "hr{border:0;border-top:1px solid #243041;margin:1em 0;}"
            ".mark{background:#134e4a;color:#ccfbf1;padding:0 4px;border-radius:4px;}"
        )
    else:
        css = (
            "body{color:#0f172a;background:transparent;font-family:Inter,Segoe UI,Noto Sans,sans-serif;"
            "font-size:15px;line-height:1.6;padding:8px 4px;}"
            "h1{font-size:28px;margin:0.55em 0 0.3em;color:#0f172a;font-weight:800;}"
            "h2{font-size:22px;margin:0.55em 0 0.28em;color:#0f172a;font-weight:800;}"
            "h3{font-size:18px;margin:0.5em 0 0.24em;color:#1e293b;font-weight:750;}"
            "h4{font-size:16px;margin:0.45em 0 0.2em;color:#334155;font-weight:700;}"
            "h5{font-size:14px;margin:0.4em 0 0.18em;color:#475569;font-weight:700;}"
            "p{margin:0.35em 0 0.7em;}"
            "code{background:#e6f7f4;color:#0f766e;padding:1px 6px;border-radius:6px;"
            "font-family:'JetBrains Mono',Consolas,monospace;font-size:13px;}"
            "pre{background:#f8fafc;border:1px solid #dce3ec;border-radius:12px;padding:12px 14px;}"
            "pre code{background:transparent;padding:0;color:#0f172a;}"
            "a{color:#0f766e;text-decoration:none;}"
            "s{color:#64748b;}"
            "blockquote{border-left:3px solid #0d9488;margin:0.4em 0;padding:4px 12px;color:#64748b;}"
            "ul,ol{margin:0.3em 0 0.8em 1.2em;}"
            "hr{border:0;border-top:1px solid #dce3ec;margin:1em 0;}"
            ".mark{background:#ccfbf1;color:#115e59;padding:0 4px;border-radius:4px;}"
        )
    return "<html><head><style>%s</style></head><body>%s</body></html>" % (css, md_to_html(text))

def pages_to_markdown(pages):
    chunks = []
    for page in pages:
        title = (page.get("title") or "Untitled page").strip()
        body = page.get("body") or ""
        host = page.get("host") or ""
        if page.get("kind") == "host" and host:
            title = host if title == host else "%s · %s" % (host, title)
        chunk = "# %s\n\n%s" % (title, body.rstrip())
        chunks.append(chunk.strip() + "\n")
    return "\n---\n\n".join(chunks)

def markdown_to_pages(text, filename=""):
    raw = text.replace("\r\n", "\n")
    if raw.lstrip().startswith("{") and ("\"pages\"" in raw or "'pages'" in raw):
        try:
            data = json.loads(raw)
            pages = data.get("pages") if isinstance(data, dict) else data
            if isinstance(pages, list):
                return pages
        except Exception:
            pass
    parts = re.split(r"\n---\s*\n", raw)
    pages = []
    for part in parts:
        block = part.strip("\n")
        if not block.strip():
            continue
        title = ""
        body = block
        m = re.match(r"^#\s+(.+)\n?(.*)$", block, re.S)
        if m:
            title = m.group(1).strip()
            body = (m.group(2) or "").lstrip("\n")
        if not title:
            title = os.path.splitext(os.path.basename(filename))[0] or "Untitled page"
        pages.append({"kind": "page", "host": "", "title": title, "body": body})
    return pages

class MarkdownHighlighter(QSyntaxHighlighter):
    _HEADING = re.compile(r"^(#{1,5})(\s+)(.*)$")
    _RULE = re.compile(r"^(\-\-\-|___|\*\*\*)\s*$")
    _INLINE = (
        re.compile(r"`[^`]+`"),
        re.compile(r"\*\*\*[^*]+\*\*\*"),
        re.compile(r"\*\*[^*]+\*\*"),
        re.compile(r"(?<!\*)\*[^*\s][^*]*[^*\s]\*(?!\*)"),
        re.compile(r"==[^=]+=="),
        re.compile(r"~~[^~]+~~"),
        re.compile(r"\[[^\]]+\]\([^)]+\)"),
    )

    def highlightBlock(self, text):
        if IS_DARK:
            colors = ("#f4f7fb", "#99f6e4", "#7dd3c7", "#5eead4", "#fbbf24", "#6b7687", "#2dd4bf")
        else:
            colors = ("#0f172a", "#0f766e", "#0d9488", "#0f766e", "#b45309", "#94a3b8", "#0f766e")
        h1, h2, h3, mark, code, muted, accent = colors

        def fmt(color, bold=False, italic=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Bold)
            if italic:
                f.setFontItalic(True)
            return f

        hm = self._HEADING.match(text)
        if hm:
            lvl = len(hm.group(1))
            color = h1 if lvl == 1 else h2 if lvl == 2 else h3
            self.setFormat(0, len(text), fmt(color, bold=True))
            self.setFormat(0, lvl, fmt(muted, bold=True))
            return
        stripped = text.strip()
        if stripped.startswith("```") or self._RULE.match(stripped):
            self.setFormat(0, len(text), fmt(muted, italic=True))
            return
        if stripped.startswith(">"):
            self.setFormat(0, len(text), fmt(muted, italic=True))
        inline_colors = (code, mark, mark, mark, accent, muted, accent)
        inline_style = (
            (False, False),
            (True, True),
            (True, False),
            (False, True),
            (False, False),
            (False, True),
            (False, False),
        )
        for rx, color, style in zip(self._INLINE, inline_colors, inline_style):
            for m in rx.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt(color, bold=style[0], italic=style[1]))

class NotesPanel(QWidget):
    def __init__(self, map_panel_ref=None):
        super().__init__()
        self.map_ref = map_panel_ref
        self.pages = []
        self.current_id = None
        self._loading = False
        self._id_seq = 1

        root = QHBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(16)

        left = QWidget()
        left.setObjectName("notesrail")
        left.setMinimumWidth(260)
        left.setMaximumWidth(340)
        lv = QVBoxLayout(left)
        lv.setContentsMargins(14, 16, 14, 14)
        lv.setSpacing(10)

        head = QLabel("NOTES")
        head.setObjectName("sectionlabel")
        lv.addWidget(head)
        hint = QLabel("Engagement pages  ·  host findings live here too")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        lv.addWidget(hint)

        btnrow = QHBoxLayout()
        btnrow.setSpacing(8)
        new_btn = QPushButton("＋  new page")
        new_btn.setObjectName("runbtn")
        new_btn.setMinimumHeight(36)
        new_btn.setCursor(Qt.PointingHandCursor)
        new_btn.clicked.connect(self.new_page)
        del_btn = QPushButton("delete")
        del_btn.setMinimumHeight(36)
        del_btn.setCursor(Qt.PointingHandCursor)
        del_btn.clicked.connect(self.delete_page)
        btnrow.addWidget(new_btn, 1)
        btnrow.addWidget(del_btn)
        lv.addLayout(btnrow)

        self.search = QLineEdit()
        self.search.setObjectName("searchbox")
        self.search.setPlaceholderText("search notes…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._filter_list)
        lv.addWidget(self.search)

        self.list = QListWidget()
        self.list.setObjectName("noteslist")
        self.list.currentItemChanged.connect(self._on_select)
        lv.addWidget(self.list, 1)

        io = QHBoxLayout()
        save_btn = QPushButton("export .md")
        save_btn.setObjectName("ghostbtn")
        save_btn.setMinimumHeight(34)
        save_btn.clicked.connect(self.save_markdown)
        load_btn = QPushButton("import .md")
        load_btn.setObjectName("ghostbtn")
        load_btn.setMinimumHeight(34)
        load_btn.clicked.connect(self.load_markdown)
        io.addWidget(save_btn)
        io.addWidget(load_btn)
        lv.addLayout(io)

        right = QWidget()
        right.setObjectName("notesheet")
        rv = QVBoxLayout(right)
        rv.setContentsMargins(18, 16, 18, 16)
        rv.setSpacing(10)

        meta = QHBoxLayout()
        self.kind_lbl = QLabel("ENGAGEMENT")
        self.kind_lbl.setObjectName("notekind")
        meta.addWidget(self.kind_lbl)
        meta.addStretch(1)
        self.stamp_lbl = QLabel("")
        self.stamp_lbl.setObjectName("hint")
        meta.addWidget(self.stamp_lbl)
        self.preview_btn = QPushButton("preview")
        self.preview_btn.setObjectName("ghostbtn")
        self.preview_btn.setCheckable(True)
        self.preview_btn.setCursor(Qt.PointingHandCursor)
        self.preview_btn.setMinimumHeight(30)
        self.preview_btn.clicked.connect(self._toggle_preview)
        meta.addWidget(self.preview_btn)
        rv.addLayout(meta)

        self.title = QLineEdit()
        self.title.setObjectName("notetitle")
        self.title.setPlaceholderText("Untitled page")
        self.title.textChanged.connect(self._on_edit)
        rv.addWidget(self.title)

        self.body = QPlainTextEdit()
        self.body.setObjectName("notesbody")
        self.body.setFont(mono_font(12))
        self.body.setPlaceholderText(
            "# Heading 1\n"
            "## Heading 2\n"
            "### Heading 3\n"
            "#### Heading 4\n"
            "##### Heading 5\n\n"
            "**bold**  *italic*  ***both***  ~~strike~~  ==highlight==\n"
            "`inline code`\n\n"
            "- list item\n\n"
            "> quote\n\n"
            "[link](https://example.com)"
        )
        self.body.textChanged.connect(self._on_edit)
        self._md_hi = MarkdownHighlighter(self.body.document())
        rv.addWidget(self.body, 1)

        self.preview = QTextBrowser()
        self.preview.setObjectName("notepreview")
        self.preview.setOpenExternalLinks(True)
        self.preview.hide()
        rv.addWidget(self.preview, 1)
        self._preview_on = False

        split = QSplitter()
        split.setChildrenCollapsible(False)
        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([300, 900])
        root.addWidget(split)

        self._autosave = QTimer(self)
        self._autosave.setSingleShot(True)
        self._autosave.setInterval(400)
        self._autosave.timeout.connect(self._flush_current)

        self.new_page(initial=True)
        self._load_autosave()

    def showEvent(self, event):
        super().showEvent(event)
        self._sync_host_pages()

    def open_host(self, ip):
        self._sync_host_pages()
        for page in self.pages:
            if page.get("kind") == "host" and page.get("host") == ip:
                self._rebuild_list(select_id=page["id"])
                return
        self._rebuild_list(select_id=self.current_id)

    def _now(self):
        import time
        return int(time.time())

    def _fmt(self, ts):
        import time
        if not ts:
            return ""
        return time.strftime("%Y-%m-%d  %H:%M", time.localtime(ts))

    def _page_by_id(self, pid):
        for page in self.pages:
            if page["id"] == pid:
                return page
        return None

    def _next_id(self):
        pid = self._id_seq
        self._id_seq += 1
        return pid

    def new_page(self, initial=False):
        self._flush_current()
        page = {
            "id": self._next_id(),
            "kind": "page",
            "host": "",
            "title": "Untitled page",
            "body": "",
            "updated": self._now(),
        }
        self.pages.append(page)
        self._rebuild_list(select_id=page["id"])
        if not initial:
            self.title.setFocus()
            self.title.selectAll()

    def delete_page(self):
        page = self._page_by_id(self.current_id)
        if not page:
            return
        if page.get("kind") == "host":
            QMessageBox.information(self, "Host note", "Host notes are tied to the map. Clear the text instead of deleting the page.")
            return
        if len([p for p in self.pages if p.get("kind") != "host"]) <= 1:
            page["title"] = "Untitled page"
            page["body"] = ""
            page["updated"] = self._now()
            self._load_into_editor(page)
            self._rebuild_list(select_id=page["id"])
            return
        self.pages = [p for p in self.pages if p["id"] != page["id"]]
        self.current_id = None
        nxt = next((p for p in self.pages if p.get("kind") != "host"), self.pages[0])
        self._rebuild_list(select_id=nxt["id"])

    def _sync_host_pages(self):
        if not self.map_ref:
            return
        self._flush_current()
        existing = {p.get("host"): p for p in self.pages if p.get("kind") == "host"}
        seen = set()
        for ip, host in self.map_ref.hosts.items():
            seen.add(ip)
            notes = (host.get("notes") or "").strip()
            title = host.get("hostname") or ip
            if ip in existing:
                page = existing[ip]
                if self.current_id != page["id"]:
                    page["title"] = title
                    page["body"] = host.get("notes") or ""
                    page["updated"] = page.get("updated") or self._now()
            else:
                self.pages.append({
                    "id": self._next_id(),
                    "kind": "host",
                    "host": ip,
                    "title": title,
                    "body": host.get("notes") or "",
                    "updated": self._now(),
                })
        self.pages = [p for p in self.pages if p.get("kind") != "host" or p.get("host") in seen]
        keep = self.current_id
        self._rebuild_list(select_id=keep)

    def _rebuild_list(self, select_id=None):
        q = self.search.text().strip().lower() if hasattr(self, "search") else ""
        self.list.blockSignals(True)
        self.list.clear()
        pages = sorted(self.pages, key=lambda p: (0 if p.get("kind") != "host" else 1, -(p.get("updated") or 0)))
        chosen = None
        for page in pages:
            blob = " ".join([page.get("title", ""), page.get("body", ""), page.get("host", "")]).lower()
            if q and q not in blob:
                continue
            if page.get("kind") == "host":
                label = f"HOST  {page.get('host', '')}"
                if page.get("title") and page.get("title") != page.get("host"):
                    label += f"  ·  {page.get('title')}"
            else:
                label = page.get("title") or "Untitled page"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, page["id"])
            self.list.addItem(item)
            if select_id is not None and page["id"] == select_id:
                chosen = item
        self.list.blockSignals(False)
        if chosen is None and self.list.count():
            chosen = self.list.item(0)
        if chosen is not None:
            self.list.setCurrentItem(chosen)
        elif self.pages:
            self._load_into_editor(self.pages[0])

    def _filter_list(self):
        self._rebuild_list(select_id=self.current_id)

    def _on_select(self, item, _prev):
        self._flush_current()
        if item is None:
            return
        pid = item.data(Qt.UserRole)
        page = self._page_by_id(pid)
        if page:
            self._load_into_editor(page)

    def _load_into_editor(self, page):
        self._loading = True
        self.current_id = page["id"]
        self.title.setText(page.get("title", ""))
        self.body.setPlainText(page.get("body", ""))
        self._refresh_preview()
        if page.get("kind") == "host":
            self.kind_lbl.setText(f"HOST  ·  {page.get('host', '')}")
            self.title.setReadOnly(True)
        else:
            self.kind_lbl.setText("ENGAGEMENT")
            self.title.setReadOnly(False)
        stamp = self._fmt(page.get("updated"))
        self.stamp_lbl.setText(f"updated  {stamp}" if stamp else "")
        self._loading = False

    def _on_edit(self):
        if self._loading:
            return
        self._refresh_preview()
        self._autosave.start()

    def _toggle_preview(self, on):
        self._preview_on = bool(on)
        self.body.setVisible(not self._preview_on)
        self.preview.setVisible(self._preview_on)
        self.preview_btn.setText("edit" if self._preview_on else "preview")
        self._refresh_preview()

    def _refresh_preview(self):
        if not hasattr(self, "preview"):
            return
        if not self._preview_on:
            return
        self.preview.setHtml(md_document(self.body.toPlainText()))

    def _flush_current(self):
        page = self._page_by_id(self.current_id)
        if not page:
            return
        title = self.title.text().strip() or ("Untitled page" if page.get("kind") != "host" else page.get("host", ""))
        body = self.body.toPlainText()
        if page.get("title") == title and page.get("body") == body:
            return
        page["title"] = title
        page["body"] = body
        page["updated"] = self._now()
        self.stamp_lbl.setText(f"updated  {self._fmt(page['updated'])}")
        if page.get("kind") == "host" and self.map_ref and page.get("host") in self.map_ref.hosts:
            self.map_ref.hosts[page["host"]]["notes"] = body.strip()
        self._write_autosave()
        row = self.list.currentRow()
        if 0 <= row < self.list.count():
            item = self.list.item(row)
            if page.get("kind") == "host":
                label = f"HOST  {page.get('host', '')}"
                if page.get("title") and page.get("title") != page.get("host"):
                    label += f"  ·  {page.get('title')}"
            else:
                label = page.get("title") or "Untitled page"
            item.setText(label)

    def _autosave_path(self):
        d = os.path.join(os.path.expanduser("~"), ".latveriux")
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            d = os.path.expanduser("~")
        return os.path.join(d, "notes.json")

    def _write_autosave(self):
        try:
            with open(self._autosave_path(), "w") as f:
                json.dump({"pages": [p for p in self.pages if p.get("kind") != "host"]}, f, indent=2)
        except Exception:
            pass

    def _load_autosave(self):
        path = self._autosave_path()
        if not os.path.isfile(path):
            return
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            return
        pages = data.get("pages") if isinstance(data, dict) else data
        if not isinstance(pages, list) or not pages:
            return
        self.pages = [p for p in self.pages if p.get("kind") == "host"]
        for raw in pages:
            if not isinstance(raw, dict):
                continue
            self.pages.append({
                "id": self._next_id(),
                "kind": "page",
                "host": "",
                "title": raw.get("title") or "Untitled page",
                "body": raw.get("body") or "",
                "updated": raw.get("updated") or self._now(),
            })
        self._rebuild_list(select_id=self.pages[0]["id"] if self.pages else None)

    def save_markdown(self):
        self._flush_current()
        page = self._page_by_id(self.current_id)
        title = (page.get("title") if page else None) or "notes"
        safe = re.sub(r"[^\w\s.-]+", "", title).strip() or "notes"
        path, _ = QFileDialog.getSaveFileName(self, "Export markdown", safe + ".md", "Markdown (*.md)")
        if not path:
            return
        if not path.lower().endswith(".md"):
            path += ".md"
        payload = pages_to_markdown([page] if page else self.pages)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(payload)
        except Exception as e:
            QMessageBox.warning(self, "Export failed", str(e))

    def load_markdown(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import markdown", "", "Markdown (*.md);;All files (*)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                raw = f.read()
        except Exception as e:
            QMessageBox.warning(self, "Import failed", str(e))
            return
        incoming = markdown_to_pages(raw, path)
        if not incoming:
            QMessageBox.information(self, "Empty", "No notes found in that file")
            return
        self._flush_current()
        first = None
        for rawp in incoming:
            page = {
                "id": self._next_id(),
                "kind": rawp.get("kind") or "page",
                "host": rawp.get("host") or "",
                "title": rawp.get("title") or "Untitled page",
                "body": rawp.get("body") or "",
                "updated": rawp.get("updated") or self._now(),
            }
            self.pages.append(page)
            if first is None:
                first = page["id"]
        self._rebuild_list(select_id=first)
        self._write_autosave()


class HostNode(QGraphicsRectItem):
    W, H = 204, 108
    def __init__(self, host, panel):
        super().__init__(0, 0, self.W, self.H)
        self.host = host
        self.panel = panel
        self.setFlags(QGraphicsItem.ItemIsMovable | QGraphicsItem.ItemIsSelectable | QGraphicsItem.ItemSendsGeometryChanges)
        self.setZValue(1)
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.OpenHandCursor)
    def status_color(self):
        return QColor(STATUS_COLORS.get(self.host.get("status", "unscanned"), "#6e7681"))
    def accent_color(self):
        custom = (self.host.get("color") or "").strip()
        if custom:
            c = QColor(custom)
            if c.isValid():
                return c
        return self.status_color()
    def paint(self, p, opt, widget=None):
        pal = NODE_PALETTE[IS_DARK]
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.TextAntialiasing)
        r = self.rect()
        status_col = self.status_color()
        accent_col = self.accent_color()
        selected = self.isSelected()

        shadow_col = QColor(pal.get("shadow", "#000000"))
        shadow_col.setAlpha(75 if IS_DARK else 38)
        p.setBrush(QBrush(shadow_col))
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(r.adjusted(2, 4, 2, 4), 14, 14)

        p.setBrush(QBrush(QColor(pal["card"])))
        border = QColor(pal["sel"]) if selected else accent_col
        border.setAlpha(255)
        p.setPen(QPen(border, 2.2 if selected else 1.7))
        p.drawRoundedRect(r, 14, 14)

        accent = QRectF(r.left() + 1, r.top() + 11, 4.5, r.height() - 22)
        p.setBrush(QBrush(accent_col))
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(accent, 2.2, 2.2)

        htype = self.host.get("type", "PC")
        icon_x = r.left() + 18
        icon_y = r.top() + 15
        p.setBrush(QBrush(accent_col))
        p.setPen(QPen(accent_col.darker(130), 1.1))

        if htype == "Mobile":
            p.drawRoundedRect(QRectF(icon_x + 5, icon_y, 18, 30), 3.5, 3.5)
            p.setBrush(QBrush(QColor(pal["inset"])))
            p.setPen(Qt.NoPen)
            p.drawRoundedRect(QRectF(icon_x + 8, icon_y + 3.5, 12, 21), 2, 2)
            p.setBrush(QBrush(status_col.lighter(130)))
            p.drawEllipse(QPointF(icon_x + 14, icon_y + 26.5), 2.2, 2.2)
        elif htype == "Website":
            p.drawEllipse(QPointF(icon_x + 14, icon_y + 14), 13, 13)
            p.setPen(QPen(status_col.darker(140), 1.4))
            p.drawLine(int(icon_x + 1), int(icon_y + 14), int(icon_x + 27), int(icon_y + 14))
            p.drawArc(QRectF(icon_x + 5, icon_y + 1, 18, 26), 40 * 16, 100 * 16)
            p.drawArc(QRectF(icon_x + 5, icon_y + 1, 18, 26), 220 * 16, 100 * 16)
        elif htype == "Domain Controller":
            path = QPainterPath()
            path.moveTo(icon_x + 14, icon_y)
            path.lineTo(icon_x + 3, icon_y + 9)
            path.lineTo(icon_x + 8, icon_y + 9)
            path.lineTo(icon_x + 8, icon_y + 28)
            path.lineTo(icon_x + 20, icon_y + 28)
            path.lineTo(icon_x + 20, icon_y + 9)
            path.lineTo(icon_x + 25, icon_y + 9)
            path.closeSubpath()
            p.drawPath(path)
            p.setBrush(QBrush(QColor(pal["inset"])))
            p.setPen(Qt.NoPen)
            p.drawRect(QRectF(icon_x + 11, icon_y + 13, 6, 8))
        elif htype == "AI":
            p.setBrush(QBrush(status_col))
            p.setPen(QPen(status_col.darker(130), 1.0))
            p.drawEllipse(QRectF(icon_x + 2, icon_y + 3, 12, 14))
            p.drawEllipse(QRectF(icon_x + 14, icon_y + 3, 12, 14))
            p.drawEllipse(QRectF(icon_x + 8, icon_y + 14, 12, 12))
            p.setPen(QPen(status_col.darker(150), 1.1))
            p.drawLine(int(icon_x + 8), int(icon_y + 12), int(icon_x + 14), int(icon_y + 18))
            p.drawLine(int(icon_x + 20), int(icon_y + 12), int(icon_x + 14), int(icon_y + 18))
        elif htype == "Other":
            p.drawEllipse(QPointF(icon_x + 14, icon_y + 14), 5.5, 5.5)
            for ang in range(0, 360, 45):
                rad = math.radians(ang)
                p.drawLine(int(icon_x + 14 + math.cos(rad) * 7), int(icon_y + 14 + math.sin(rad) * 7),
                           int(icon_x + 14 + math.cos(rad) * 13), int(icon_y + 14 + math.sin(rad) * 13))
        else:
            p.drawRoundedRect(QRectF(icon_x, icon_y, 28, 18), 3, 3)
            p.setBrush(QBrush(QColor(pal["inset"])))
            p.setPen(Qt.NoPen)
            p.drawRoundedRect(QRectF(icon_x + 2.5, icon_y + 2.5, 23, 13), 2, 2)
            p.setBrush(QBrush(status_col.darker(115)))
            p.drawRect(QRectF(icon_x + 12, icon_y + 18, 4, 5))
            p.drawRoundedRect(QRectF(icon_x + 5, icon_y + 23, 18, 3.5), 1.5, 1.5)

        p.setBrush(QBrush(status_col))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(icon_x + 30, icon_y + 3), 4.2, 4.2)

        p.setPen(QPen(QColor(pal["ip"])))
        p.setFont(ui_font(11, True))
        p.drawText(QRectF(r.left() + 54, r.top() + 12, r.width() - 66, 20), Qt.AlignVCenter | Qt.AlignLeft, self.host.get("ip", ""))

        p.setPen(QPen(QColor(pal["sub"])))
        p.setFont(ui_font(9))
        sub = self.host.get("hostname") or self.host.get("os") or "—"
        p.drawText(QRectF(r.left() + 54, r.top() + 32, r.width() - 66, 16), Qt.AlignLeft, sub[:24])

        ports = self.host.get("ports", "")
        if ports:
            p.setPen(QPen(QColor(pal["ports"])))
            p.setFont(mono_font(9))
            p.drawText(QRectF(r.left() + 16, r.top() + 58, r.width() - 32, 16), Qt.AlignLeft, f"[{ports}]"[:30])
        else:
            p.setPen(QPen(QColor(pal["sub"])))
            p.setFont(ui_font(8))
            p.drawText(QRectF(r.left() + 16, r.top() + 58, r.width() - 32, 16), Qt.AlignLeft, "no ports yet")
        tags = self.host.get("tags") or []
        if isinstance(tags, str):
            tags = parse_tags(tags)
        if tags:
            p.setPen(QPen(accent_col))
            p.setFont(ui_font(8))
            p.drawText(QRectF(r.left() + 16, r.top() + 76, r.width() - 32, 16), Qt.AlignLeft, " · ".join(tags)[:34])
    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            self.panel.redraw_edges()
        return super().itemChange(change, value)
    def mouseDoubleClickEvent(self, event):
        self.panel.load_host(self.host.get("ip", ""))
        super().mouseDoubleClickEvent(event)
    def contextMenuEvent(self, event):
        sc = self.scene()
        sel_nodes = [it for it in sc.selectedItems() if isinstance(it, HostNode)] if sc else []
        ip = self.host.get("ip", "")
        multi = len(sel_nodes) > 1 and self in sel_nodes
        sel_ips = [n.host.get("ip", "") for n in sel_nodes] if multi else [ip]
        n = len(sel_ips)
        menu = QMenu()
        if multi:
            header = menu.addAction(f"◆ {n} hosts selected")
            header.setEnabled(False)
            menu.addSeparator()
            act_copy = menu.addAction("Copy IPs")
            act_dup = menu.addAction(f"Duplicate all ({n})")
            act_del = menu.addAction(f"Delete all ({n})")
            act_unlink = menu.addAction(f"Unlink all ({n})")
        else:
            act_copy = menu.addAction("Copy IP")
            act_dup = menu.addAction("Duplicate")
            act_del = menu.addAction("Delete")
            act_unlink = menu.addAction("Unlink")
        menu.addSeparator()
        act_add_cred = menu.addAction("Add credential")
        act_show_cred = menu.addAction("Show credentials" + (f" ({n})" if multi else ""))
        act_notes = menu.addAction("Open notes")
        menu.addSeparator()
        if multi:
            act_tags_one = menu.addAction("Tags · this host…")
            act_tags_all = menu.addAction(f"Tags · all selected ({n})…")
            color_one = menu.addMenu("Color · this host")
            color_all = menu.addMenu(f"Color · all selected ({n})")
            self.panel.fill_color_menu(color_one, [ip])
            self.panel.fill_color_menu(color_all, sel_ips)
            st_one = menu.addMenu("Status · this host")
            st_all = menu.addMenu(f"Status · all selected ({n})")
            self.panel.fill_status_menu(st_one, [ip])
            self.panel.fill_status_menu(st_all, sel_ips)
            menu.addSeparator()
            act_link_chain = menu.addAction(f"Link selected · chain ({n})")
            act_link_mesh = menu.addAction(f"Link selected · full mesh ({n})")
        else:
            act_tags_one = menu.addAction("Tags…")
            act_tags_all = None
            color_one = menu.addMenu("Color")
            self.panel.fill_color_menu(color_one, [ip])
            st_one = menu.addMenu("Status")
            self.panel.fill_status_menu(st_one, [ip])
            act_link_chain = act_link_mesh = None
        chosen = menu.exec_(event.screenPos())
        if chosen == act_copy:
            QApplication.clipboard().setText("\n".join(sel_ips) if multi else ip)
        elif chosen == act_dup:
            if (not multi) or self.panel.confirm_bulk("duplicate", n):
                for x in (sel_ips if multi else [ip]):
                    self.panel.duplicate_host(x)
        elif chosen == act_del:
            if (not multi) or self.panel.confirm_bulk("delete", n):
                for x in (sel_ips if multi else [ip]):
                    self.panel.delete_host_by_ip(x)
        elif chosen == act_unlink:
            if (not multi) or self.panel.confirm_bulk("unlink", n):
                for x in (sel_ips if multi else [ip]):
                    self.panel.unlink_host(x)
        elif chosen == act_add_cred:
            self.panel.open_add_credential(ip)
        elif chosen == act_show_cred:
            self.panel.open_show_credentials(sel_ips)
        elif chosen == act_notes:
            self.panel.open_host_notes(ip)
        elif chosen == act_tags_one:
            self.panel.prompt_tags([ip])
        elif act_tags_all is not None and chosen == act_tags_all:
            self.panel.prompt_tags(sel_ips)
        elif chosen == act_link_chain:
            self.panel.link_chain(sel_ips)
        elif chosen == act_link_mesh:
            self.panel.link_mesh(sel_ips)

class MapGraphicsView(QGraphicsView):
    def mouseDoubleClickEvent(self, event):
        item = self.itemAt(event.pos())
        if item is None:
            self.scene().clearSelection()
            panel = getattr(self, "map_panel", None)
            if panel is not None:
                panel.clear_host_selection()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

class NetworkMapPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.hosts = {}
        self.nodes = {}
        self.edges = []
        root = QHBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)
        left = QWidget()
        left.setMaximumWidth(380)
        left.setMinimumWidth(320)
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(12)
        box = QGroupBox("HOST DETAILS")
        form = QFormLayout(box)
        self.f_ip = QLineEdit()
        self.f_ip.setPlaceholderText("10.129.203.7")
        self.f_host = QLineEdit()
        self.f_host.setPlaceholderText("FTP-Serv")
        self.f_os = QLineEdit()
        self.f_os.setPlaceholderText("Microsoft Windows")
        self.f_ports = QLineEdit()
        self.f_ports.setPlaceholderText("21,80,443,3389")
        self.f_status = QComboBox()
        self.f_status.addItems(STATUS_LIST)
        self.f_type = QComboBox()
        self.f_type.addItems(HOST_TYPES)
        self.f_tags = QLineEdit()
        self.f_tags.setPlaceholderText("dc, linux, in-scope")
        color_row = QWidget()
        cr = QHBoxLayout(color_row)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(8)
        self.color_swatch = QLabel()
        self.color_swatch.setFixedSize(22, 22)
        self.color_swatch.setObjectName("colorswatch")
        self.f_color = QComboBox()
        for name, val in HOST_COLOR_PRESETS:
            self.f_color.addItem(name, val)
        self.f_color.addItem("Custom…", "__custom__")
        self.f_color.currentIndexChanged.connect(self._on_color_combo)
        self._host_color = ""
        cr.addWidget(self.color_swatch)
        cr.addWidget(self.f_color, 1)
        form.addRow("IP", self.f_ip)
        form.addRow("Hostname", self.f_host)
        form.addRow("OS", self.f_os)
        form.addRow("Ports", self.f_ports)
        form.addRow("Status", self.f_status)
        form.addRow("Type", self.f_type)
        form.addRow("Tags", self.f_tags)
        form.addRow("Color", color_row)
        self._update_swatch()
        lv.addWidget(box)
        btns = QGridLayout()
        btns.setHorizontalSpacing(8)
        btns.setVerticalSpacing(8)
        add_btn = QPushButton("add / update")
        add_btn.setObjectName("runbtn")
        add_btn.setMinimumHeight(36)
        add_btn.setMinimumWidth(120)
        add_btn.clicked.connect(self.add_or_update)
        del_btn = QPushButton("delete")
        del_btn.setMinimumHeight(36)
        del_btn.setMinimumWidth(90)
        del_btn.clicked.connect(self.delete_host)
        link_btn = QPushButton("link selected")
        link_btn.setMinimumHeight(36)
        link_btn.setToolTip("Link all selected hosts together (Ctrl-click 2+ nodes, or pick 2+ in the list)")
        link_btn.clicked.connect(self.link_selected)
        save_btn = QPushButton("save…")
        save_btn.setMinimumHeight(36)
        save_btn.setMinimumWidth(90)
        save_btn.clicked.connect(self.save_json)
        load_btn = QPushButton("load…")
        load_btn.setMinimumHeight(36)
        load_btn.setMinimumWidth(90)
        load_btn.clicked.connect(self.load_json)
        btns.addWidget(add_btn, 0, 0)
        btns.addWidget(del_btn, 0, 1)
        btns.addWidget(link_btn, 1, 0, 1, 2)
        btns.addWidget(save_btn, 2, 0)
        btns.addWidget(load_btn, 2, 1)
        lv.addLayout(btns)
        lv.addWidget(QLabel("HOSTS  ·  double-click to load  ·  RMB for menu"))
        self.search = QLineEdit()
        self.search.setObjectName("searchbox")
        self.search.setPlaceholderText("Ctrl+F  search IP, hostname, tags…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._apply_host_filter)
        lv.addWidget(self.search)
        self.host_list = QListWidget()
        self.host_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.host_list.itemClicked.connect(lambda it: self.load_host(it.text().split()[0]))
        lv.addWidget(self.host_list, 1)
        self.scene = QGraphicsScene()
        self.scene.setSceneRect(-500, -400, 1600, 1100)
        self.view = MapGraphicsView(self.scene)
        self.view.map_panel = self
        self.view.setObjectName("mapview")
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.ScrollHandDrag)
        self.view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.view.setAlignment(Qt.AlignCenter)
        self.view.setMinimumWidth(200)
        self.view.setMinimumHeight(160)
        self.host_list.setMinimumHeight(60)
        split = QSplitter()
        split.setChildrenCollapsible(False)
        split.addWidget(left)
        split.addWidget(self.view)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([340, 900])
        root.addWidget(split)
        sc = QShortcut(QKeySequence("Ctrl+F"), self)
        sc.setContext(Qt.WidgetWithChildrenShortcut)
        sc.activated.connect(self._focus_search)
        self._update_swatch()
    def _focus_search(self):
        self.search.setFocus()
        self.search.selectAll()
    def _center_pos(self):
        center = self.view.mapToScene(self.view.viewport().rect().center())
        cx = center.x() - HostNode.W / 2
        cy = center.y() - HostNode.H / 2
        n = len(self.nodes)
        if n == 0:
            return QPointF(cx, cy)
        ang = n * 2.399963229728653
        rad = 72 * math.sqrt(n)
        return QPointF(cx + math.cos(ang) * rad, cy + math.sin(ang) * rad)
    def add_or_update(self):
        ip = self.f_ip.text().strip()
        if not ip:
            QMessageBox.warning(self, "Missing IP", "Enter an IP")
            return
        host = {
            "ip": ip,
            "hostname": self.f_host.text().strip(),
            "os": self.f_os.text().strip(),
            "ports": self.f_ports.text().strip(),
            "status": self.f_status.currentText(),
            "type": self.f_type.currentText(),
            "notes": self.hosts.get(ip, {}).get("notes", ""),
            "tags": parse_tags(self.f_tags.text()),
            "color": self._host_color,
        }
        self.hosts[ip] = host
        if ip in self.nodes:
            self.nodes[ip].host = host
            self.nodes[ip].update()
        else:
            node = HostNode(host, self)
            node.setPos(self._center_pos())
            self.scene.addItem(node)
            self.nodes[ip] = node
            self.view.centerOn(node)
        self._refresh_list()

    def bulk_add_hosts(self, entries, default_status="unscanned", default_type="PC"):
        added = 0
        for item in entries:
            if isinstance(item, dict):
                ip = (item.get("ip") or "").strip()
                if not ip:
                    continue
                host = {
                    "ip": ip,
                    "hostname": item.get("hostname", "").strip(),
                    "os": item.get("os", "").strip(),
                    "ports": item.get("ports", "").strip(),
                    "status": item.get("status", default_status),
                    "type": item.get("type", default_type),
                    "notes": item.get("notes", "").strip(),
                    "tags": item.get("tags", []),
                    "color": item.get("color", ""),
                }
                normalize_host_extra(host)
            else:
                ip = str(item).strip()
                if not ip:
                    continue
                parts = ip.replace(",", " ").split()
                ip = parts[0]
                hostname = parts[1] if len(parts) > 1 else ""
                host = {
                    "ip": ip,
                    "hostname": hostname,
                    "os": "",
                    "ports": "",
                    "status": default_status,
                    "type": default_type,
                    "notes": "",
                    "tags": [],
                    "color": "",
                }
            if not host["ip"]:
                continue
            self.hosts[host["ip"]] = host
            if host["ip"] not in self.nodes:
                node = HostNode(host, self)
                node.setPos(self._center_pos())
                self.scene.addItem(node)
                self.nodes[host["ip"]] = node
                added += 1
            else:
                self.nodes[host["ip"]].host = host
                self.nodes[host["ip"]].update()
        self._refresh_list()
        return added
    def load_host(self, ip):
        h = self.hosts.get(ip)
        if not h:
            return
        self.f_ip.setText(h.get("ip", ""))
        self.f_host.setText(h.get("hostname", ""))
        self.f_os.setText(h.get("os", ""))
        self.f_ports.setText(h.get("ports", ""))
        idx = self.f_status.findText(h.get("status", "unscanned"))
        self.f_status.setCurrentIndex(max(0, idx))
        tidx = self.f_type.findText(h.get("type", "PC"))
        self.f_type.setCurrentIndex(max(0, tidx))
        self.f_tags.setText(format_tags(h.get("tags", [])))
        self._set_color_ui(h.get("color", ""))
    def selected_ips(self):
        return [it.host.get("ip", "") for it in self.scene.selectedItems() if isinstance(it, HostNode)]
    def clear_host_selection(self):
        self.scene.clearSelection()
        self.host_list.clearSelection()
        self.f_ip.clear()
        self.f_host.clear()
        self.f_os.clear()
        self.f_ports.clear()
        self.f_status.setCurrentIndex(0)
        self.f_type.setCurrentIndex(0)
        self.f_tags.clear()
        self._set_color_ui("")
    def _main(self):
        w = self.window()
        return w if w is not None and hasattr(w, "creds_panel") else None
    def open_add_credential(self, ip):
        main = self._main()
        if main is None:
            return
        main._goto_panel(main.creds_panel)
        main.creds_panel.prepare_add_for_host(ip)
        main.creds_panel.set_host_filter(None)
        main.statusBar().showMessage(f"  add credential  ·  {ip}", 2500)
    def open_show_credentials(self, ips):
        main = self._main()
        if main is None:
            return
        main._goto_panel(main.creds_panel)
        main.creds_panel.refresh_hosts()
        main.creds_panel.set_host_filter(ips)
        n = len(main.creds_panel.filter_ips or [])
        main.statusBar().showMessage(f"  showing credentials  ·  {n} host(s)", 2500)
    def open_host_notes(self, ip):
        main = self._main()
        if main is None or not hasattr(main, "notes_panel"):
            return
        main._goto_panel(main.notes_panel)
        main.notes_panel.open_host(ip)
        main.statusBar().showMessage(f"  notes  ·  {ip}", 2500)
    def _update_swatch(self):
        col = self._host_color or "#3d4656"
        self.color_swatch.setStyleSheet(
            f"background: {col}; border-radius: 6px; border: 1px solid #243044;")
    def _set_color_ui(self, color):
        self._host_color = (color or "").strip()
        self.f_color.blockSignals(True)
        idx = self.f_color.findData(self._host_color)
        if idx < 0:
            idx = 0 if not self._host_color else self.f_color.findData("__custom__")
        self.f_color.setCurrentIndex(max(0, idx))
        self.f_color.blockSignals(False)
        self._update_swatch()
    def _on_color_combo(self, _idx):
        val = self.f_color.currentData()
        if val == "__custom__":
            start = QColor(self._host_color or "#58a6ff")
            picked = QColorDialog.getColor(start, self, "Host color")
            if picked.isValid():
                self._host_color = picked.name()
            self.f_color.blockSignals(True)
            found = self.f_color.findData(self._host_color)
            self.f_color.setCurrentIndex(found if found >= 0 else 0)
            self.f_color.blockSignals(False)
        else:
            self._host_color = val or ""
        self._update_swatch()
    def _touch_host(self, ip):
        h = self.hosts.get(ip)
        node = self.nodes.get(ip)
        if h and node:
            normalize_host_extra(h)
            node.host = h
            node.update()
        if self.f_ip.text().strip() == ip:
            self.load_host(ip)
        self._refresh_list()
    def set_hosts_status(self, ips, status):
        for ip in ips:
            if ip in self.hosts:
                self.hosts[ip]["status"] = status
                self._touch_host(ip)
    def set_hosts_color(self, ips, color):
        for ip in ips:
            if ip in self.hosts:
                self.hosts[ip]["color"] = color or ""
                self._touch_host(ip)
    def set_hosts_tags(self, ips, tags):
        for ip in ips:
            if ip in self.hosts:
                self.hosts[ip]["tags"] = list(tags)
                self._touch_host(ip)
    def fill_status_menu(self, menu, ips):
        for st in STATUS_LIST:
            act = menu.addAction(st)
            act.triggered.connect(lambda _=False, s=st, targets=list(ips): self.set_hosts_status(targets, s))
    def fill_color_menu(self, menu, ips):
        for name, val in HOST_COLOR_PRESETS:
            label = name if name != "Default" else "Default (status color)"
            act = menu.addAction(label)
            act.triggered.connect(lambda _=False, c=val, targets=list(ips): self.set_hosts_color(targets, c))
        menu.addSeparator()
        act_c = menu.addAction("Custom…")
        act_c.triggered.connect(lambda _=False, targets=list(ips): self.prompt_color(targets))
    def prompt_color(self, ips):
        start = "#58a6ff"
        if ips and ips[0] in self.hosts:
            start = self.hosts[ips[0]].get("color") or start
        picked = QColorDialog.getColor(QColor(start), self, "Host color")
        if picked.isValid():
            self.set_hosts_color(ips, picked.name())
    def prompt_tags(self, ips):
        current = ""
        if len(ips) == 1 and ips[0] in self.hosts:
            current = format_tags(self.hosts[ips[0]].get("tags", []))
        text, ok = QInputDialog.getText(self, "Tags", "Comma-separated tags:", QLineEdit.Normal, current)
        if ok:
            self.set_hosts_tags(ips, parse_tags(text))
    def host_matches(self, host, q):
        if not q:
            return True
        tags = host.get("tags") or []
        if isinstance(tags, str):
            tags = parse_tags(tags)
        blob = " ".join([
            host.get("ip", ""), host.get("hostname", ""), host.get("os", ""),
            host.get("ports", ""), host.get("status", ""), host.get("type", ""),
            host.get("notes", ""), " ".join(tags),
        ]).lower()
        return q in blob
    def _apply_host_filter(self):
        q = self.search.text().strip().lower() if hasattr(self, "search") else ""
        for i in range(self.host_list.count()):
            item = self.host_list.item(i)
            ip = item.text().split()[0]
            h = self.hosts.get(ip, {})
            item.setHidden(not self.host_matches(h, q))
        for ip, node in self.nodes.items():
            node.setOpacity(1.0 if self.host_matches(self.hosts.get(ip, {}), q) else 0.28)
    def confirm_bulk(self, verb, n):
        r = QMessageBox.warning(
            self, "Apply to all selected",
            f"This will {verb} all {n} selected hosts.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
        return r == QMessageBox.Yes
    def delete_host(self):
        sel = self.selected_ips()
        if len(sel) > 1:
            if self.confirm_bulk("delete", len(sel)):
                for ip in sel:
                    self.delete_host_by_ip(ip)
            return
        self.delete_host_by_ip(self.f_ip.text().strip())
    def delete_host_by_ip(self, ip):
        if ip not in self.hosts:
            return
        node = self.nodes.pop(ip, None)
        if node:
            self.scene.removeItem(node)
        kept = []
        for a, b, item in self.edges:
            if a == ip or b == ip:
                self.scene.removeItem(item)
            else:
                kept.append((a, b, item))
        self.edges = kept
        self.hosts.pop(ip, None)
        self._refresh_list()
    def duplicate_host(self, ip):
        if ip not in self.hosts:
            return
        h = copy.deepcopy(self.hosts[ip])
        base = h["ip"]
        i = 1
        new_ip = f"{base}-copy{i}"
        while new_ip in self.hosts:
            i += 1
            new_ip = f"{base}-copy{i}"
        h["ip"] = new_ip
        self.hosts[new_ip] = h
        node = HostNode(h, self)
        node.setPos(self._center_pos())
        self.scene.addItem(node)
        self.nodes[new_ip] = node
        self._refresh_list()
    def unlink_host(self, ip):
        kept = []
        for a, b, item in self.edges:
            if a == ip or b == ip:
                self.scene.removeItem(item)
            else:
                kept.append((a, b, item))
        self.edges = kept
        self.redraw_edges()
    def link_ips(self, a, b):
        if a == b or a not in self.hosts or b not in self.hosts:
            return
        for x, y, _ in self.edges:
            if {x, y} == {a, b}:
                return
        line = QGraphicsLineItem()
        line.setPen(QPen(QColor("#2dd4bf"), 2.2, Qt.DashLine))
        line.setZValue(-1)
        self.scene.addItem(line)
        self.edges.append((a, b, line))
        self.redraw_edges()
    def link_chain(self, ips):
        uniq = [ip for i, ip in enumerate(ips) if ip and ip not in ips[:i]]
        for a, b in zip(uniq, uniq[1:]):
            self.link_ips(a, b)
        return max(0, len(uniq) - 1)

    def link_mesh(self, ips):
        uniq = [ip for i, ip in enumerate(ips) if ip and ip not in ips[:i]]
        made = 0
        for i in range(len(uniq)):
            for j in range(i + 1, len(uniq)):
                self.link_ips(uniq[i], uniq[j])
                made += 1
        return made

    def link_selected(self):
        sel = self.selected_ips()
        if len(sel) < 2:
            sel = [it.text().split()[0] for it in self.host_list.selectedItems()]
        if len(sel) < 2:
            QMessageBox.information(self, "Link", "Select 2 or more hosts — Ctrl-click nodes on the map, or pick multiple in the list.")
            return
        n = self.link_chain(sel)
        self.statusBar_flash(f"linked {len(sel)} hosts ({n} edges)")

    def statusBar_flash(self, msg):
        w = self.window()
        if hasattr(w, "statusBar"):
            w.statusBar().showMessage("  " + msg, 2500)

    def redraw_edges(self):
        for a, b, item in self.edges:
            na, nb = self.nodes.get(a), self.nodes.get(b)
            if na and nb:
                ca = na.sceneBoundingRect().center()
                cb = nb.sceneBoundingRect().center()
                item.setLine(ca.x(), ca.y(), cb.x(), cb.y())
    def _refresh_list(self):
        self.host_list.clear()
        for ip, h in sorted(self.hosts.items()):
            label = ip
            if h.get("hostname"):
                label += f"  ({h['hostname']})"
            label += f"  • {h.get('status', '')} • {h.get('type', 'PC')}"
            tags = h.get("tags") or []
            if tags:
                label += f"  · {format_tags(tags)}"
            self.host_list.addItem(QListWidgetItem(label))
        self._apply_host_filter()
    def save_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save map", "engagement.json", "JSON (*.json)")
        if not path:
            return
        data = {"hosts": self.hosts, "positions": {ip: [n.pos().x(), n.pos().y()] for ip, n in self.nodes.items()}, "edges": [[a, b] for a, b, _ in self.edges]}
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            QMessageBox.warning(self, "Save failed", str(e))
    def load_json(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load map", "", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception as e:
            QMessageBox.warning(self, "Load failed", str(e))
            return
        self.scene.clear()
        self.hosts, self.nodes, self.edges = {}, {}, []
        positions = data.get("positions", {})
        for ip, h in data.get("hosts", {}).items():
            self.hosts[ip] = normalize_host_extra(h)
            node = HostNode(h, self)
            pos = positions.get(ip)
            node.setPos(QPointF(*pos) if pos else self._center_pos())
            self.scene.addItem(node)
            self.nodes[ip] = node
        for pair in data.get("edges", []):
            if len(pair) == 2:
                line = QGraphicsLineItem()
                line.setPen(QPen(QColor("#2dd4bf"), 2.2, Qt.DashLine))
                line.setZValue(-1)
                self.scene.addItem(line)
                self.edges.append((pair[0], pair[1], line))
        self.redraw_edges()
        self._refresh_list()

DARK_STYLE = """
* { outline: 0; }
QWidget {
    background: transparent;
    color: #e6edf5;
    font-size: 13px;
    font-family: "Inter", "SF Pro Display", "Segoe UI", "Noto Sans", "Ubuntu", "Cantarell", sans-serif;
}
QMainWindow { background: #07090e; }
QDialog, QMessageBox { background: #10151d; border-radius: 16px; }
QMessageBox QLabel { background: transparent; color: #e6edf5; }
QToolTip {
    background: #151b24; color: #e6edf5;
    border: 1px solid #2a3443; border-radius: 8px;
    padding: 7px 11px; font-size: 12px;
}

QLabel#title {
    color: #f4f7fb; font-size: 21px; font-weight: 800; letter-spacing: 4px;
}

QWidget#sidebar {
    background: #0a0d13;
    border-right: 1px solid #171e28;
}
QWidget#content { background: transparent; }
QLabel#brand { color: #f4f7fb; font-size: 16px; font-weight: 800; letter-spacing: 3.4px; }
QLabel#brandsub { color: #5eead4; font-size: 9px; font-weight: 800; letter-spacing: 2.8px; }
QLabel#navsection { color: #667085; font-size: 9px; font-weight: 800; letter-spacing: 1.9px; padding-left: 4px; }
QPushButton#navitem {
    text-align: left; background: transparent; color: #9aa6b8;
    border: 0; border-radius: 10px; padding: 8px 12px;
    font-weight: 600; font-size: 13px;
}
QPushButton#navitem:hover { background: #121821; color: #f4f7fb; }
QPushButton#navitem:checked {
    background: #10211e; color: #99f6e4; font-weight: 700;
    border: 1px solid #1c3d38;
}
QListWidget#navlist { background: transparent; border: 0; outline: 0; }
QListWidget#navlist::item {
    color: #9aa6b8; border-radius: 10px; padding: 8px 12px; margin: 2px 0;
    font-weight: 600; font-size: 13px;
}
QListWidget#navlist::item:hover { background: #121821; color: #f4f7fb; }
QListWidget#navlist::item:selected { background: #10211e; color: #99f6e4; }
QLabel#dlgtitle { font-size: 17px; font-weight: 800; color: #f4f7fb; letter-spacing: 0.3px; }
QLabel#sectionlabel {
    color: #7b8798; font-size: 10px; font-weight: 800; letter-spacing: 1.7px;
}
QLabel#hint { color: #6b7687; font-size: 11px; }
QLabel#notekind {
    color: #5eead4; font-size: 10px; font-weight: 800; letter-spacing: 1.6px;
}

QLabel#vpnpill {
    font-size: 12px; font-weight: 700; padding: 8px 14px;
    border-radius: 999px; letter-spacing: 0.4px;
    background: #10151d; border: 1px solid #243041; color: #8b96a8;
}
QLabel#vpnpill[state="up"] {
    color: #34d399; border: 1px solid #1c3b2e; background: #0c1914;
}
QLabel#vpnpill[state="down"] {
    color: #f87171; border: 1px solid #3f2222; background: #1a1010;
}

QLabel#countpill {
    color: #99f6e4; background: #10211e; border: 1px solid #1c3d38;
    border-radius: 9px; padding: 3px 11px; font-weight: 800; font-size: 12px;
}

QTabWidget::pane {
    border: 1px solid #1a2230; border-radius: 14px; top: -1px; background: #0c1016;
}
QTabBar { qproperty-drawBase: 0; }
QTabBar::tab {
    background: transparent; color: #7b8798;
    padding: 9px 18px; margin: 0 3px; border: 1px solid transparent;
    border-radius: 10px; font-weight: 700; min-width: 60px;
}
QTabBar::tab:hover { color: #e6edf5; background: #151b24; }
QTabBar::tab:selected {
    background: #10211e; color: #5eead4; border: 1px solid #1c3d38;
}

QTabWidget#termtabs::pane {
    border: 1px solid #171e28; border-radius: 12px; top: -1px; background: #05070b;
}
QTabWidget#termtabs QTabBar::tab {
    padding: 6px 14px; margin: 0 2px; font-size: 12px; font-weight: 600;
    color: #8b96a8; background: #0e141c; border: 1px solid #1a2330;
    border-top-left-radius: 9px; border-top-right-radius: 9px;
    border-bottom-left-radius: 0; border-bottom-right-radius: 0;
}
QTabWidget#termtabs QTabBar::tab:selected {
    color: #99f6e4; background: #10211e; border-color: #1c3d38;
}
QTabBar::close-button {
    image: none;
    subcontrol-position: right;
}

QGroupBox {
    border: 1px solid #1c2532; border-radius: 16px;
    margin-top: 18px; padding: 20px 16px 16px 16px;
    font-weight: 800; color: #c5d0dc; background: #0e131b;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 16px; padding: 0 8px;
    color: #7b8798; font-size: 10px; font-weight: 800; letter-spacing: 1.4px;
}

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
    background: #080b11; border: 1px solid #243041; border-radius: 11px;
    padding: 9px 12px; color: #e6edf5;
    selection-background-color: #0f766e; selection-color: #ffffff;
}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover, QPlainTextEdit:hover { border-color: #354355; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {
    border: 1px solid #2dd4bf; background: #0a1016;
}
QLineEdit::placeholder, QPlainTextEdit::placeholder { color: #566274; }
QLineEdit#preview {
    color: #5eead4; background: #0b1514; border: 1px solid #1c3d38;
    font-family: "JetBrains Mono","Cascadia Code","Fira Code","DejaVu Sans Mono",monospace;
    font-size: 12px; padding: 10px 12px;
}
QComboBox::drop-down { border: 0; width: 26px; margin-right: 4px; }
QComboBox QAbstractItemView {
    background: #121821; color: #e6edf5; padding: 6px;
    selection-background-color: #0f766e; selection-color: #ffffff;
    border: 1px solid #243041; border-radius: 10px; outline: 0;
}

QPlainTextEdit#console {
    background: #04060a; color: #c9d4e0; border: 1px solid #131a23;
    border-radius: 0; padding: 12px;
    font-family: "JetBrains Mono","Cascadia Code","Fira Code","DejaVu Sans Mono",monospace;
    selection-background-color: #134e4a; selection-color: #ffffff;
}
QPlainTextEdit#hostnotes, QPlainTextEdit#notesbody, QTextBrowser#notepreview {
    background: #080b11; color: #e6edf5; border: 1px solid #243041;
    border-radius: 12px; padding: 12px 14px;
    font-size: 13px;
}
QTextBrowser#notepreview { font-size: 15px; }
QLineEdit#notetitle {
    background: transparent; border: 0; border-bottom: 1px solid #243041;
    border-radius: 0; padding: 8px 2px 12px 2px;
    font-size: 22px; font-weight: 800; color: #f4f7fb;
}
QLineEdit#notetitle:focus { border-bottom: 1px solid #2dd4bf; }
QWidget#notesrail {
    background: #0c1118; border: 1px solid #1c2532; border-radius: 16px;
}
QWidget#notesheet {
    background: #0c1118; border: 1px solid #1c2532; border-radius: 16px;
}
QListWidget#noteslist { background: transparent; border: 0; padding: 2px; }
QListWidget#noteslist::item { padding: 10px 12px; border-radius: 10px; margin: 2px 0; }
QListWidget#noteslist::item:selected { background: #10211e; color: #99f6e4; }
QListWidget#noteslist::item:hover { background: #151b24; }

QWidget#termpane { border: 1px solid #171e28; border-radius: 10px; }
QWidget#termpane[active="1"] { border: 1px solid #2dd4bf; }
QWidget#termbar {
    background: #0c1118; border-bottom: 1px solid #171e28;
    border-top-left-radius: 9px; border-top-right-radius: 9px;
}
QLabel#termdot { color: #34d399; font-size: 12px; }
QLabel#termtitle { color: #8b96a8; font-size: 11px; font-weight: 700; letter-spacing: 0.4px; }
QPushButton#termmini {
    background: transparent; color: #7b8798; border: 0; border-radius: 5px;
    font-size: 13px; padding: 0;
}
QPushButton#termmini:hover { background: #1a2332; color: #eaf1f8; }
QSplitter#termsplit::handle { background: #0b0f15; }

QPushButton {
    background: #151b24; color: #d5deea; border: 1px solid #2a3443;
    border-radius: 10px; padding: 9px 16px; font-weight: 700;
}
QPushButton:hover { background: #1c2430; border-color: #3a4658; color: #ffffff; }
QPushButton:pressed { background: #10151d; }
QPushButton:disabled { color: #4b5565; background: #10151d; border-color: #1c2532; }

QPushButton#runbtn {
    background: #0f766e; color: #ffffff; border: 1px solid #14b8a6; font-weight: 800;
}
QPushButton#runbtn:hover { background: #0d9488; border-color: #5eead4; }
QPushButton#runbtn:pressed { background: #115e59; }

QPushButton#stopbtn {
    background: #dc4a43; color: #ffffff; border: 1px solid #f07169; font-weight: 800;
}
QPushButton#stopbtn:hover { background: #ef5b54; }

QPushButton#ghostbtn {
    background: transparent; color: #9aa6b8; border: 1px solid #2a3443;
    border-radius: 9px; padding: 7px 12px; font-weight: 700; font-size: 12px;
}
QPushButton#ghostbtn:hover { background: #151b24; color: #eaf1f8; border-color: #3a4658; }

QPushButton#themebtn {
    background: #10151d; color: #c5d0dc; border: 1px solid #2a3443;
    border-radius: 9px; padding: 8px 14px; font-size: 12px; font-weight: 700;
    text-align: center;
}
QPushButton#themebtn:hover { color: #ffffff; border-color: #3a4658; background: #151b24; }

QScrollArea#credscroll { border: 0; background: transparent; }
QFrame#credcard {
    background: #10161f; border: 1px solid #1e2733; border-radius: 14px;
}
QFrame#credcard:hover { border: 1px solid #2c3d4f; background: #131b25; }
QLabel#hostchip {
    color: #99f6e4; background: #10211e; border: 1px solid #1c3d38;
    border-radius: 7px; padding: 3px 10px; font-weight: 800; font-size: 12px;
    font-family: "JetBrains Mono","DejaVu Sans Mono",monospace;
}
QLabel#svcchip {
    color: #7dd3c7; background: #10211e; border: 1px solid #1c3d38;
    border-radius: 7px; padding: 3px 10px; font-weight: 700; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.6px;
}
QLabel#creduser {
    color: #e6edf5; font-weight: 700; font-size: 13px;
    font-family: "JetBrains Mono","DejaVu Sans Mono",monospace;
}
QLabel#credsep { color: #566274; font-weight: 700; }
QLabel#credpass {
    color: #fbbf24; font-size: 13px;
    font-family: "JetBrains Mono","DejaVu Sans Mono",monospace;
}
QPushButton#credmini {
    background: #151b24; color: #9aa6b8; border: 1px solid #2a3443;
    border-radius: 7px; padding: 4px 9px; font-size: 11px; font-weight: 700;
}
QPushButton#credmini:hover { background: #1c2430; color: #ffffff; border-color: #3a4658; }
QPushButton#credx {
    background: transparent; color: #6b7687; border: 0; border-radius: 6px; font-size: 13px;
}
QPushButton#credx:hover { background: #3a1c1c; color: #f87171; }
QLabel#emptystate { color: #566274; font-size: 13px; padding: 40px 10px; }

QListWidget {
    background: #080b11; border: 1px solid #243041; border-radius: 12px; padding: 6px;
}
QListWidget::item { padding: 9px 12px; border-radius: 8px; margin: 1px 0; }
QListWidget::item:selected { background: #10211e; color: #99f6e4; }
QListWidget::item:hover { background: #121821; }

QGraphicsView#mapview {
    background: #05070b; border: 1px solid #171e28; border-radius: 16px;
}

QCheckBox { color: #d5deea; spacing: 8px; padding: 2px; }
QCheckBox::indicator {
    width: 17px; height: 17px; border: 1px solid #354355; border-radius: 5px; background: #080b11;
}
QCheckBox::indicator:hover { border-color: #2dd4bf; }
QCheckBox::indicator:checked { background: #0f766e; border-color: #0f766e; }

QSpinBox::up-button, QSpinBox::down-button { width: 18px; border: 0; background: #151b24; }

QSplitter::handle { background: transparent; }
QSplitter::handle:horizontal { width: 10px; }
QSplitter::handle:vertical { height: 10px; }

QStatusBar { color: #6b7687; background: #080b11; border-top: 1px solid #171e28; }
QStatusBar::item { border: 0; }

QMenu { background: #121821; color: #e6edf5; border: 1px solid #2a3443; border-radius: 12px; padding: 6px; }
QMenu::item { padding: 8px 28px 8px 16px; border-radius: 7px; }
QMenu::item:selected { background: #0f766e; color: #ffffff; }
QMenu::separator { height: 1px; background: #243041; margin: 5px 10px; }

QScrollBar:vertical { background: transparent; width: 11px; margin: 3px; }
QScrollBar::handle:vertical { background: #2a3443; border-radius: 5px; min-height: 32px; }
QScrollBar::handle:vertical:hover { background: #3a4658; }
QScrollBar:horizontal { background: transparent; height: 11px; margin: 3px; }
QScrollBar::handle:horizontal { background: #2a3443; border-radius: 5px; min-width: 32px; }
QScrollBar::handle:horizontal:hover { background: #3a4658; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QPushButton#sidebartoggle {
    background: #10151d; color: #c5d0dc; border: 1px solid #2a3443;
    border-radius: 9px; font-size: 16px; font-weight: 700; padding: 0;
}
QPushButton#sidebartoggle:hover { color: #ffffff; border-color: #3a4658; background: #151b24; }
QWidget#filterbar {
    background: #10151d; border: 1px solid #243041; border-radius: 10px;
}
QLineEdit#searchbox { padding: 8px 12px; }
QLabel#seenchip {
    color: #fbbf24; background: #241c0c; border: 1px solid #5a4314;
    border-radius: 7px; padding: 3px 10px; font-weight: 700; font-size: 11px;
}
QLabel#crednotes { color: #8b96a8; font-size: 12px; }
QLabel#colorswatch { border-radius: 6px; border: 1px solid #2a3443; }
"""

LIGHT_STYLE = """
* { outline: 0; }
QWidget {
    background: transparent; color: #1e293b; font-size: 13px;
    font-family: "Inter", "SF Pro Display", "Segoe UI", "Noto Sans", "Ubuntu", "Cantarell", sans-serif;
}
QMainWindow { background: #f1f4f8; }
QDialog, QMessageBox { background: #ffffff; border-radius: 16px; }
QMessageBox QLabel { background: transparent; color: #1e293b; }
QToolTip { background: #0f172a; color: #f8fafc; border: 1px solid #0f172a; border-radius: 8px; padding: 7px 11px; font-size: 12px; }

QLabel#title { color: #0f172a; font-size: 21px; font-weight: 800; letter-spacing: 4px; }

QWidget#sidebar { background: #ffffff; border-right: 1px solid #dce3ec; }
QWidget#content { background: #f1f4f8; }
QLabel#brand { color: #0f172a; font-size: 16px; font-weight: 800; letter-spacing: 3.2px; }
QLabel#brandsub { color: #0f766e; font-size: 9px; font-weight: 800; letter-spacing: 2.8px; }
QLabel#navsection { color: #64748b; font-size: 9px; font-weight: 800; letter-spacing: 1.9px; padding-left: 4px; }
QPushButton#navitem {
    text-align: left; background: transparent; color: #475569;
    border: 0; border-radius: 10px; padding: 9px 13px;
    font-weight: 600; font-size: 13px;
}
QPushButton#navitem:hover { background: #eef2f7; color: #0f172a; }
QPushButton#navitem:checked {
    background: #e6f7f4; color: #0f766e; font-weight: 700;
    border: 1px solid #b7e4dc;
}
QListWidget#navlist { background: transparent; border: 0; outline: 0; }
QListWidget#navlist::item {
    color: #475569; border-radius: 10px; padding: 10px 12px; margin: 3px 0;
    font-weight: 600; font-size: 13px;
}
QListWidget#navlist::item:hover { background: #eef2f7; color: #0f172a; }
QListWidget#navlist::item:selected { background: #e6f7f4; color: #0f766e; }
QLabel#dlgtitle { font-size: 18px; font-weight: 800; color: #0f172a; letter-spacing: 0.3px; }
QLabel#sectionlabel { color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: 1.8px; }
QLabel#hint { color: #64748b; font-size: 11px; }
QLabel#notekind { color: #0f766e; font-size: 10px; font-weight: 800; letter-spacing: 1.6px; }

QLabel#vpnpill {
    font-size: 12px; font-weight: 700; padding: 8px 14px; border-radius: 999px;
    background: #f8fafc; border: 1px solid #dce3ec; color: #64748b;
}
QLabel#vpnpill[state="up"] { color: #047857; border: 1px solid #bbf7d0; background: #ecfdf5; }
QLabel#vpnpill[state="down"] { color: #b91c1c; border: 1px solid #fecaca; background: #fef2f2; }

QLabel#countpill { color: #0f766e; background: #e6f7f4; border: 1px solid #b7e4dc; border-radius: 9px; padding: 3px 12px; font-weight: 800; font-size: 12px; }

QTabWidget::pane { border: 1px solid #dce3ec; border-radius: 14px; top: -1px; background: #ffffff; }
QTabBar { qproperty-drawBase: 0; }
QTabBar::tab { background: transparent; color: #64748b; padding: 8px 16px; margin: 0 2px; border: 1px solid transparent; border-radius: 9px; font-weight: 700; min-width: 60px; }
QTabBar::tab:hover { color: #0f172a; background: #eef2f7; }
QTabBar::tab:selected { background: #e6f7f4; color: #0f766e; border: 1px solid #b7e4dc; }

QTabWidget#termtabs::pane { border: 1px solid #dce3ec; border-radius: 12px; top: -1px; background: #0b1220; }
QTabWidget#termtabs QTabBar::tab {
    padding: 7px 14px; margin: 0 2px; font-size: 12px; font-weight: 600; color: #64748b;
    background: #ffffff; border: 1px solid #dce3ec;
    border-top-left-radius: 10px; border-top-right-radius: 10px;
    border-bottom-left-radius: 0; border-bottom-right-radius: 0;
}
QTabWidget#termtabs QTabBar::tab:selected { color: #0f766e; background: #e6f7f4; border-color: #b7e4dc; }

QGroupBox { border: 1px solid #dce3ec; border-radius: 16px; margin-top: 16px; padding: 20px 16px 16px 16px; font-weight: 700; color: #1e293b; background: #ffffff; }
QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 8px; color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: 1.6px; }

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
    background: #ffffff; border: 1px solid #d0d7e2; border-radius: 11px; padding: 9px 12px; color: #0f172a;
    selection-background-color: #0f766e; selection-color: #ffffff;
}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover, QPlainTextEdit:hover { border-color: #94a3b8; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus { border: 1px solid #0d9488; background: #ffffff; }
QLineEdit::placeholder, QPlainTextEdit::placeholder { color: #94a3b8; }
QLineEdit#preview { color: #0f766e; background: #e6f7f4; border: 1px solid #b7e4dc; font-family: "JetBrains Mono","Cascadia Code","Fira Code","DejaVu Sans Mono",monospace; font-size: 12px; padding: 10px 13px; }
QLineEdit#searchbox { padding: 8px 12px; border-radius: 999px; }
QComboBox::drop-down { border: 0; width: 24px; margin-right: 4px; }
QComboBox QAbstractItemView { background: #ffffff; color: #0f172a; padding: 6px; selection-background-color: #0f766e; selection-color: #ffffff; border: 1px solid #dce3ec; border-radius: 10px; outline: 0; }

QPlainTextEdit#console { background: #0b1220; color: #d7e0ea; border: 1px solid #dce3ec; border-radius: 0; padding: 12px; font-family: "JetBrains Mono","Cascadia Code","Fira Code","DejaVu Sans Mono",monospace; selection-background-color: #134e4a; selection-color: #ffffff; }
QPlainTextEdit#hostnotes, QPlainTextEdit#notesbody, QTextBrowser#notepreview {
    background: #ffffff; color: #0f172a; border: 1px solid #d0d7e2;
    border-radius: 12px; padding: 12px 14px; font-size: 13px;
}
QTextBrowser#notepreview { font-size: 15px; }
QLineEdit#notetitle {
    background: transparent; border: 0; border-bottom: 1px solid #d0d7e2;
    border-radius: 0; padding: 8px 2px 12px 2px;
    font-size: 22px; font-weight: 800; color: #0f172a;
}
QLineEdit#notetitle:focus { border-bottom: 1px solid #0d9488; }
QWidget#notesrail, QWidget#notesheet {
    background: #ffffff; border: 1px solid #dce3ec; border-radius: 16px;
}
QListWidget#noteslist { background: transparent; border: 0; padding: 2px; }
QListWidget#noteslist::item { padding: 10px 12px; border-radius: 10px; margin: 2px 0; }
QListWidget#noteslist::item:selected { background: #e6f7f4; color: #0f766e; }
QListWidget#noteslist::item:hover { background: #eef2f7; }

QWidget#termpane { border: 1px solid #dce3ec; border-radius: 12px; }
QWidget#termpane[active="1"] { border: 1px solid #0d9488; }
QWidget#termbar { background: #f8fafc; border-bottom: 1px solid #dce3ec; border-top-left-radius: 11px; border-top-right-radius: 11px; }
QLabel#termdot { color: #047857; font-size: 12px; }
QLabel#termtitle { color: #64748b; font-size: 11px; font-weight: 700; }
QPushButton#termmini { background: transparent; color: #64748b; border: 0; border-radius: 6px; font-size: 13px; padding: 0; }
QPushButton#termmini:hover { background: #eef2f7; color: #0f172a; }
QSplitter#termsplit::handle { background: #dce3ec; }

QPushButton { background: #ffffff; color: #1e293b; border: 1px solid #d0d7e2; border-radius: 10px; padding: 8px 14px; font-weight: 700; }
QPushButton:hover { background: #f8fafc; border-color: #94a3b8; }
QPushButton:pressed { background: #eef2f7; }
QPushButton:disabled { color: #94a3b8; background: #f8fafc; border-color: #e2e8f0; }
QPushButton#runbtn { background: #0f766e; color: #ffffff; border: 1px solid #0f766e; font-weight: 800; }
QPushButton#runbtn:hover { background: #0d9488; border-color: #0d9488; }
QPushButton#runbtn:pressed { background: #115e59; }
QPushButton#stopbtn { background: #dc2626; color: #fff5f2; border: 1px solid #dc2626; font-weight: 800; }
QPushButton#stopbtn:hover { background: #ef4444; }
QPushButton#ghostbtn { background: transparent; color: #475569; border: 1px solid #d0d7e2; border-radius: 10px; padding: 7px 12px; font-weight: 700; font-size: 12px; }
QPushButton#ghostbtn:hover { background: #f8fafc; color: #0f172a; border-color: #94a3b8; }
QPushButton#themebtn { background: #ffffff; color: #475569; border: 1px solid #d0d7e2; border-radius: 10px; padding: 9px 14px; font-size: 12px; font-weight: 700; text-align: center; }
QPushButton#themebtn:hover { color: #0f172a; border-color: #94a3b8; background: #f8fafc; }
QPushButton#sidebartoggle {
    background: #ffffff; color: #475569; border: 1px solid #d0d7e2;
    border-radius: 10px; font-size: 16px; font-weight: 700; padding: 0;
}
QPushButton#sidebartoggle:hover { color: #0f172a; border-color: #94a3b8; background: #f8fafc; }
QWidget#filterbar {
    background: #ffffff; border: 1px solid #dce3ec; border-radius: 10px;
}

QScrollArea#credscroll { border: 0; background: transparent; }
QFrame#credcard { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 14px; }
QFrame#credcard:hover { border: 1px solid #b7e4dc; background: #f8fffd; }
QLabel#hostchip { color: #0f766e; background: #e6f7f4; border: 1px solid #b7e4dc; border-radius: 8px; padding: 3px 10px; font-weight: 800; font-size: 12px; font-family: "JetBrains Mono","DejaVu Sans Mono",monospace; }
QLabel#svcchip { color: #047857; background: #ecfdf5; border: 1px solid #bbf7d0; border-radius: 8px; padding: 3px 10px; font-weight: 700; font-size: 11px; letter-spacing: 0.6px; }
QLabel#creduser { color: #0f172a; font-weight: 700; font-size: 13px; font-family: "JetBrains Mono","DejaVu Sans Mono",monospace; }
QLabel#credsep { color: #94a3b8; font-weight: 700; }
QLabel#credpass { color: #b45309; font-size: 13px; font-family: "JetBrains Mono","DejaVu Sans Mono",monospace; }
QLabel#seenchip { color: #b45309; background: #fffbeb; border: 1px solid #fde68a; border-radius: 7px; padding: 3px 10px; font-weight: 700; font-size: 11px; }
QLabel#crednotes { color: #64748b; font-size: 12px; }
QPushButton#credmini { background: #f8fafc; color: #475569; border: 1px solid #d0d7e2; border-radius: 7px; padding: 4px 10px; font-size: 11px; font-weight: 700; }
QPushButton#credmini:hover { background: #e6f7f4; color: #0f766e; border-color: #b7e4dc; }
QPushButton#credx { background: transparent; color: #94a3b8; border: 0; border-radius: 6px; font-size: 13px; }
QPushButton#credx:hover { background: #fef2f2; color: #b91c1c; }
QLabel#emptystate { color: #94a3b8; font-size: 13px; padding: 40px 10px; }

QListWidget { background: #ffffff; border: 1px solid #d0d7e2; border-radius: 12px; padding: 6px; }
QListWidget::item { padding: 8px 10px; border-radius: 8px; margin: 2px 0; }
QListWidget::item:selected { background: #e6f7f4; color: #0f766e; }
QListWidget::item:hover { background: #eef2f7; }

QGraphicsView#mapview { background: #e8eef5; border: 1px solid #dce3ec; border-radius: 16px; }

QCheckBox { color: #1e293b; spacing: 8px; padding: 2px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid #94a3b8; border-radius: 4px; background: #ffffff; }
QCheckBox::indicator:hover { border-color: #0f766e; }
QCheckBox::indicator:checked { background: #0f766e; border-color: #0f766e; }

QSpinBox::up-button, QSpinBox::down-button { width: 16px; border: 0; background: #eef2f7; }

QSplitter::handle { background: transparent; }
QSplitter::handle:horizontal { width: 8px; }
QSplitter::handle:vertical { height: 8px; }

QStatusBar { color: #64748b; background: #ffffff; border-top: 1px solid #dce3ec; }
QStatusBar::item { border: 0; }

QMenu { background: #ffffff; color: #0f172a; border: 1px solid #dce3ec; border-radius: 12px; padding: 6px; }
QMenu::item { padding: 7px 26px 7px 14px; border-radius: 7px; }
QMenu::item:selected { background: #0f766e; color: #ffffff; }
QMenu::separator { height: 1px; background: #e2e8f0; margin: 5px 8px; }

QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #cbd5e1; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #94a3b8; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: #cbd5e1; border-radius: 5px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #94a3b8; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QLabel#colorswatch { border-radius: 6px; border: 1px solid #d0d7e2; }
"""


class SettingsDialog(QDialog):
    def __init__(self, main):
        super().__init__(main)
        self.main = main
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)
        v = QVBoxLayout(self)
        v.setContentsMargins(26, 24, 26, 22)
        v.setSpacing(16)

        title = QLabel("Settings")
        title.setObjectName("dlgtitle")
        v.addWidget(title)

        appbox = QGroupBox("APPEARANCE")
        af = QFormLayout(appbox)
        af.setSpacing(12)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light"])
        self.theme_combo.setCurrentIndex(0 if main.dark else 1)
        self.theme_combo.currentIndexChanged.connect(lambda i: main.apply_theme(i == 0))
        af.addRow("Theme", self.theme_combo)
        v.addWidget(appbox)

        stbox = QGroupBox("STATUS BAR")
        sf = QVBoxLayout(stbox)
        sf.setSpacing(8)
        self.timer_chk = QCheckBox("Show engagement timer")
        self.timer_chk.setChecked(main.show_timer)
        self.timer_chk.toggled.connect(main.set_timer_visible)
        sf.addWidget(self.timer_chk)
        v.addWidget(stbox)

        v.addStretch(1)
        done = QPushButton("Done")
        done.setObjectName("runbtn")
        done.setMinimumHeight(38)
        done.setCursor(Qt.PointingHandCursor)
        done.clicked.connect(self.accept)
        v.addWidget(done)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LATVERIUX  ·  Core")
        self.setMinimumSize(860, 560)
        self.resize(1400, 860)
        self._fitted = False
        self.dark = True
        central = QWidget()
        self.setCentralWidget(central)
        outer = QHBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.sidebar = QWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(220)
        self.sidebar_visible = True
        sv = QVBoxLayout(self.sidebar)
        sv.setContentsMargins(18, 22, 18, 18)
        sv.setSpacing(6)

        brand = QLabel("LATVERIUX")
        brand.setObjectName("brand")
        sv.addWidget(brand)
        subtitle = QLabel("OFFENSIVE TOOLKIT")
        subtitle.setObjectName("brandsub")
        sv.addWidget(subtitle)
        sv.addSpacing(22)

        nav_lbl = QLabel("WORKSPACE")
        nav_lbl.setObjectName("navsection")
        sv.addWidget(nav_lbl)
        sv.addSpacing(4)

        self.map_panel = NetworkMapPanel()
        self.notes_panel = NotesPanel(self.map_panel)
        self.creds_panel = CredentialsPanel(self.map_panel)
        self.hosts_panel = HostsPanel(self.map_panel)
        self.term_panel = TerminalPanel()

        self.stack = QStackedWidget()
        nav_defs = [
            ("Network Map", "map", self.map_panel),
            ("Notes", "notes", self.notes_panel),
            ("Credentials", "creds", self.creds_panel),
            ("Terminal", "terminal", self.term_panel),
            ("Hosts", "hosts", self.hosts_panel),
        ]
        self.nav_btns = []
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for i, (label, kind, panel) in enumerate(nav_defs):
            self.stack.addWidget(panel)
            btn = QPushButton("  " + label)
            btn.setObjectName("navitem")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setMinimumHeight(42)
            btn.setIconSize(QSize(18, 18))
            btn.setProperty("nav_kind", kind)
            btn.setProperty("nav_index", i)
            btn.clicked.connect(lambda checked, idx=i: self._on_nav_clicked(idx))
            self.nav_group.addButton(btn, i)
            self.nav_btns.append(btn)
            sv.addWidget(btn)

        sv.addStretch(1)

        self.vpn_pill = QLabel()
        self.vpn_pill.setObjectName("vpnpill")
        self.vpn_pill.setCursor(Qt.PointingHandCursor)
        self.vpn_pill.setToolTip("VPN interface status — click to refresh")
        self.vpn_pill.mousePressEvent = lambda e: self._refresh_vpn()
        self.vpn_pill.setAlignment(Qt.AlignCenter)
        sv.addWidget(self.vpn_pill)

        self.settings_btn = QPushButton("  Settings")
        self.settings_btn.setObjectName("themebtn")
        self.settings_btn.setCursor(Qt.PointingHandCursor)
        self.settings_btn.setMinimumHeight(38)
        self.settings_btn.setIconSize(QSize(18, 18))
        self.settings_btn.clicked.connect(self.open_settings)
        sv.addWidget(self.settings_btn)

        outer.addWidget(self.sidebar)

        content = QWidget()
        content.setObjectName("content")
        cv = QVBoxLayout(content)
        cv.setContentsMargins(22, 16, 22, 12)
        cv.setSpacing(8)
        topbar = QHBoxLayout()
        topbar.setContentsMargins(0, 0, 0, 0)
        topbar.setSpacing(8)
        self.sidebar_btn = QPushButton("‹")
        self.sidebar_btn.setObjectName("sidebartoggle")
        self.sidebar_btn.setCursor(Qt.PointingHandCursor)
        self.sidebar_btn.setFixedSize(34, 34)
        self.sidebar_btn.setToolTip("Hide sidebar  (Ctrl+B)")
        self.sidebar_btn.clicked.connect(self.toggle_sidebar)
        topbar.addWidget(self.sidebar_btn)
        topbar.addStretch(1)
        cv.addLayout(topbar)
        cv.addWidget(self.stack, 1)
        outer.addWidget(content, 1)

        self.show_timer = True
        if self.nav_btns:
            self.nav_btns[0].setChecked(True)
            self.stack.setCurrentIndex(0)
        self._apply_nav_icons()
        sc_side = QShortcut(QKeySequence("Ctrl+B"), self)
        sc_side.setContext(Qt.ApplicationShortcut)
        sc_side.activated.connect(self.toggle_sidebar)

        sb = self.statusBar()
        self._start_time = __import__("time").time()
        self._sb_left = QLabel()
        sb.addWidget(self._sb_left, 1)

        self._clock = QTimer(self)
        self._clock.timeout.connect(self._tick)
        self._clock.start(1000)
        self._refresh_vpn()
        self._tick()

    def showEvent(self, event):
        super().showEvent(event)
        if not self._fitted:
            self._fitted = True
            self._fit_to_screen()

    def _fit_to_screen(self):
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        avail = screen.availableGeometry()
        margin = 20
        max_w = max(self.minimumWidth(), avail.width() - margin)
        max_h = max(self.minimumHeight(), avail.height() - margin)
        w = min(1400, int(avail.width() * 0.92), max_w)
        h = min(860, int(avail.height() * 0.90), max_h)
        w = max(self.minimumWidth(), w)
        h = max(self.minimumHeight(), h)
        self.resize(w, h)
        x = avail.x() + max(0, (avail.width() - w) // 2)
        y = avail.y() + max(0, (avail.height() - h) // 2)
        self.move(x, y)

    def _on_nav_clicked(self, idx):
        if idx < 0 or idx >= self.stack.count():
            return
        self.stack.setCurrentIndex(idx)
        for i, btn in enumerate(self.nav_btns):
            btn.setChecked(i == idx)
        self._apply_nav_icons()

    def _goto_panel(self, panel):
        idx = self.stack.indexOf(panel)
        if idx < 0:
            return
        self._on_nav_clicked(idx)

    def toggle_sidebar(self):
        self.sidebar_visible = not self.sidebar_visible
        self.sidebar.setVisible(self.sidebar_visible)
        if self.sidebar_visible:
            self.sidebar_btn.setText("‹")
            self.sidebar_btn.setToolTip("Hide sidebar  (Ctrl+B)")
        else:
            self.sidebar_btn.setText("☰")
            self.sidebar_btn.setToolTip("Show sidebar  (Ctrl+B)")

    def open_settings(self):
        SettingsDialog(self).exec_()

    def set_timer_visible(self, on):
        self.show_timer = on
        self._sb_left.setVisible(on)

    def _nav_colors(self):
        if self.dark:
            return "#5eead4", "#7d8b9e"
        return "#0f766e", "#64748b"

    def _apply_nav_icons(self):
        accent, muted = self._nav_colors()
        for btn in self.nav_btns:
            kind = btn.property("nav_kind")
            active = btn.isChecked()
            btn.setIcon(make_nav_icon(kind, accent if active else muted))
        if hasattr(self, "settings_btn"):
            self.settings_btn.setIcon(make_nav_icon("settings", muted))

    def _tick(self):
        import time
        el = int(time.time() - self._start_time)
        h, rem = divmod(el, 3600)
        m, s = divmod(rem, 60)
        self._sb_left.setText(f"   engagement time   {h:02d}:{m:02d}:{s:02d}")

    def _refresh_vpn(self):
        ip = detect_vpn_ip()
        if ip:
            self.vpn_pill.setText(f"●  VPN  {ip}")
            self.vpn_pill.setProperty("state", "up")
        else:
            self.vpn_pill.setText("●  VPN  down")
            self.vpn_pill.setProperty("state", "down")
        self.vpn_pill.style().unpolish(self.vpn_pill)
        self.vpn_pill.style().polish(self.vpn_pill)

    def apply_theme(self, dark):
        global IS_DARK
        app = QApplication.instance()
        self.dark = dark
        app.setStyleSheet(DARK_STYLE if dark else LIGHT_STYLE)
        IS_DARK = dark
        self._apply_nav_icons()
        if hasattr(self, "vpn_pill"):
            self.vpn_pill.style().unpolish(self.vpn_pill)
            self.vpn_pill.style().polish(self.vpn_pill)
        if hasattr(self, "map_panel") and self.map_panel.scene:
            self.map_panel.scene.update()
        if hasattr(self, "notes_panel"):
            self.notes_panel._refresh_preview()

def main():
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    icon = make_app_icon()
    app.setWindowIcon(icon)
    app.setStyleSheet(DARK_STYLE)
    win = MainWindow()
    win.setWindowIcon(icon)
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
