"""
PCAP Traffic Generator
Python rewrite of the original Delphi application.

Replays packets from .pcap / .pcapng files over a chosen network interface,
with configurable speed multiplier and optional looping.

Dependencies:
    pip install scapy

On Linux you may also need:
    sudo apt install libpcap-dev

Run with administrator/root privileges (required for raw packet injection).
"""

import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, scrolledtext, ttk

# ---------------------------------------------------------------------------
# Scapy import — optional graceful degradation for the import check
# ---------------------------------------------------------------------------
try:
    from scapy.all import get_if_list, get_working_ifaces, sendp, conf

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Fast raw pcap/pcapng parser  (no scapy packet construction overhead)
# ---------------------------------------------------------------------------

import struct

PCAP_MAGIC_LE = 0xA1B2C3D4  # microsecond, little-endian
PCAP_MAGIC_LE_NS = 0xA1B23C4D  # nanosecond,  little-endian
PCAP_MAGIC_BE = 0xD4C3B2A1  # microsecond, big-endian
PCAP_MAGIC_BE_NS = 0x4D3CB2A1  # nanosecond,  big-endian


def _parse_pcap(view: memoryview) -> list[dict]:
    """Parse a classic .pcap file."""
    magic = struct.unpack_from("<I", view, 0)[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_LE_NS):
        endian, ns = "<", magic == PCAP_MAGIC_LE_NS
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_BE_NS):
        endian, ns = ">", magic == PCAP_MAGIC_BE_NS
    else:
        raise ValueError(f"Unknown pcap magic: {magic:#010x}")

    global_hdr_size = struct.calcsize(endian + "IHHiIII")
    rec_fmt = endian + "IIII"
    rec_size = struct.calcsize(rec_fmt)

    offset = global_hdr_size
    total = len(view)
    packets = []

    while offset + rec_size <= total:
        ts_sec, ts_frac, caplen, _ = struct.unpack_from(rec_fmt, view, offset)
        offset += rec_size
        if offset + caplen > total:
            break  # truncated
        ts = ts_sec + (ts_frac / 1_000_000_000 if ns else ts_frac / 1_000_000)
        packets.append({"timestamp": ts, "data": bytes(view[offset : offset + caplen])})
        offset += caplen

    return packets


def _parse_pcapng(view: memoryview) -> list[dict]:
    """Parse a .pcapng file (SHB / IDB / EPB / SPB / OPB blocks)."""
    # Byte order from Section Header Block body
    endian = "<" if struct.unpack_from("<I", view, 8)[0] == 0x1A2B3C4D else ">"

    packets: list[dict] = []
    iface_tsresol: list[float] = []
    offset = 0
    total = len(view)

    while offset + 8 <= total:
        block_type, block_len = struct.unpack_from(endian + "II", view, offset)
        if block_len < 12 or offset + block_len > total:
            break

        body = view[offset + 8 : offset + block_len - 4]

        # --- Section Header Block ---
        if block_type == 0x0A0D0D0A:
            iface_tsresol.clear()

        # --- Interface Description Block ---
        elif block_type == 0x00000001:
            resol = 1e-6  # default: microseconds
            opt_off = 8  # skip LinkType(2)+Reserved(2)+SnapLen(4)
            while opt_off + 4 <= len(body):
                opt_code, opt_len = struct.unpack_from(endian + "HH", body, opt_off)
                opt_off += 4
                if opt_code == 0:
                    break
                if opt_code == 9 and opt_len >= 1:  # if_tsresol
                    raw = (
                        body[opt_off]
                        if isinstance(body[opt_off], int)
                        else body[opt_off : opt_off + 1].tobytes()[0]
                    )
                    resol = 2 ** -(raw & 0x7F) if raw & 0x80 else 10 ** -(raw & 0x7F)
                opt_off += opt_len + ((-opt_len) % 4)
            iface_tsresol.append(resol)

        # --- Enhanced Packet Block ---
        elif block_type == 0x00000006:
            iface_id = struct.unpack_from(endian + "I", body, 0)[0]
            ts_high, ts_low, caplen = struct.unpack_from(endian + "III", body, 4)
            ts_raw = (ts_high << 32) | ts_low
            resol = iface_tsresol[iface_id] if iface_id < len(iface_tsresol) else 1e-6
            packets.append(
                {"timestamp": ts_raw * resol, "data": bytes(body[20 : 20 + caplen])}
            )

        # --- Simple Packet Block ---
        elif block_type == 0x00000003:
            caplen = struct.unpack_from(endian + "I", body, 4)[0]
            packets.append({"timestamp": 0.0, "data": bytes(body[8 : 8 + caplen])})

        # --- Obsolete Packet Block ---
        elif block_type == 0x00000002:
            iface_id = struct.unpack_from(endian + "H", body, 0)[0]
            ts_high, ts_low = struct.unpack_from(endian + "HH", body, 2)
            caplen = struct.unpack_from(endian + "I", body, 12)[0]
            ts_raw = (ts_high << 32) | ts_low
            resol = iface_tsresol[iface_id] if iface_id < len(iface_tsresol) else 1e-6
            packets.append(
                {"timestamp": ts_raw * resol, "data": bytes(body[16 : 16 + caplen])}
            )

        offset += block_len

    return packets


def load_packets(filepath: str) -> list[dict]:
    """
    Read all packets from a pcap or pcapng file using a fast raw binary parser.
    Returns a list of dicts: {"timestamp": <float seconds>, "data": <bytes>}
    """
    with open(filepath, "rb") as f:
        raw = f.read()
    view = memoryview(raw)
    magic = struct.unpack_from("<I", view, 0)[0]
    return _parse_pcapng(view) if magic == 0x0A0D0D0A else _parse_pcap(view)


# ---------------------------------------------------------------------------
# Interface enumeration
# ---------------------------------------------------------------------------

import sys
import re


def _get_windows_friendly_names() -> dict[str, str]:
    """
    Call GetAdaptersAddresses (same approach as the C++ GetFriendlyNameFromPcapIf)
    and return a mapping of  "\\Device\\NPF_{GUID}" -> FriendlyName.
    Returns {} on non-Windows or any error.
    """
    if sys.platform != "win32":
        return {}

    import ctypes
    import ctypes.wintypes as wt

    # IP_ADAPTER_ADDRESSES is a variable-length linked-list node.
    # We only need the first few fields: Next ptr, AdapterName, and FriendlyName.
    # Using a raw buffer + manual pointer arithmetic is the safest cross-version approach.
    iphlpapi = ctypes.WinDLL("iphlpapi")
    GetAdaptersAddresses = iphlpapi.GetAdaptersAddresses
    GetAdaptersAddresses.restype = wt.DWORD
    GetAdaptersAddresses.argtypes = [
        wt.ULONG,  # Family
        wt.ULONG,  # Flags
        ctypes.c_void_p,  # Reserved
        ctypes.c_void_p,  # AdapterAddresses buffer
        ctypes.POINTER(wt.ULONG),  # SizePointer
    ]

    GAA_FLAG_INCLUDE_PREFIX = 0x0010
    AF_UNSPEC = 0
    NO_ERROR = 0
    ERROR_BUFFER_OVERFLOW = 111

    buf_size = wt.ULONG(15000)
    buf = (ctypes.c_byte * buf_size.value)()
    result = GetAdaptersAddresses(
        AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, None, buf, ctypes.byref(buf_size)
    )

    if result == ERROR_BUFFER_OVERFLOW:
        buf = (ctypes.c_byte * buf_size.value)()
        result = GetAdaptersAddresses(
            AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, None, buf, ctypes.byref(buf_size)
        )

    if result != NO_ERROR:
        return {}

    # Walk the linked list.
    # IP_ADAPTER_ADDRESSES layout (x64, relevant offsets):
    #   0   ULONG            Length
    #   4   DWORD            IfIndex
    #   8   struct*          Next
    #  16   PCHAR            AdapterName   (ASCII GUID string e.g. "{4C3A...}")
    #  24   ...
    #  (FriendlyName is a PWCHAR; its offset varies by Windows SDK version)
    #
    # Instead of hard-coding offsets we use a ctypes Structure that matches
    # the documented layout for both x86 and x64.

    is64 = ctypes.sizeof(ctypes.c_void_p) == 8

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass  # forward declaration for self-referential pointer

    # Offsets differ between 32-bit and 64-bit Windows due to pointer size and padding.
    # We replicate the documented SDK layout field by field.
    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", wt.ULONG),
        ("IfIndex", wt.DWORD),
        ("Next", ctypes.c_void_p),  # IP_ADAPTER_ADDRESSES*
        ("AdapterName", ctypes.c_char_p),  # PCHAR  — ASCII GUID
        ("FirstUnicastAddress", ctypes.c_void_p),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
    ]

    friendly: dict[str, str] = {}
    try:
        addr = IP_ADAPTER_ADDRESSES.from_buffer(buf)
        ptr = ctypes.addressof(buf)

        while ptr:
            adapter = IP_ADAPTER_ADDRESSES.from_address(ptr)
            if adapter.AdapterName and adapter.FriendlyName:
                # AdapterName is the bare GUID: "{4C3A1B2C-...}"
                # Npcap device name is:          "\Device\NPF_{4C3A1B2C-...}"
                npcap_name = r"\Device\NPF_" + adapter.AdapterName.decode()
                friendly[npcap_name] = adapter.FriendlyName
            ptr = adapter.Next
    except Exception:
        pass

    return friendly


def get_interfaces() -> list[dict]:
    """
    Return a list of dicts: {"display": <str>, "name": <str>}

    Display name priority on Windows:
      1. Windows friendly name via GetAdaptersAddresses (e.g. "Wi-Fi", "Ethernet")
         combined with scapy hardware description
      2. Scapy iface description alone
      3. Raw device name (last resort)

    On Linux/macOS the friendly-name lookup returns {} and only
    the scapy description / raw name is used.
    """
    friendly_names = _get_windows_friendly_names()

    ifaces = []
    try:
        for i, iface in enumerate(get_working_ifaces()):
            name = iface.name
            scapy_desc = getattr(iface, "description", None) or ""

            win_name = friendly_names.get(name)  # exact match on \Device\NPF_{...}

            if win_name and scapy_desc:
                display = f"[{i}] {win_name} — {scapy_desc}"
            elif win_name:
                display = f"[{i}] {win_name}"
            elif scapy_desc:
                display = f"[{i}] {scapy_desc}"
            else:
                display = f"[{i}] {name}"

            ifaces.append({"display": display, "name": name})

    except Exception:
        for i, name in enumerate(get_if_list()):
            ifaces.append({"display": f"[{i}] {name}", "name": name})

    return ifaces


# ---------------------------------------------------------------------------
# Replay thread
# ---------------------------------------------------------------------------


class ReplayThread(threading.Thread):
    """
    Sends packets on the chosen interface, honouring inter-packet timing
    scaled by a speed multiplier.
    """

    def __init__(
        self,
        packets: list[dict],
        iface: str,
        speed: float,
        loop: bool,
        on_progress,  # callback(current_index: int)
        on_log,  # callback(message: str)
        on_done,  # callback()
        stop_event: threading.Event,
    ):
        super().__init__(daemon=True)
        self._packets = packets
        self._iface = iface
        self._speed = max(speed, 0.01)
        self._loop = loop
        self._on_progress = on_progress
        self._on_log = on_log
        self._on_done = on_done
        self._stop = stop_event

    # ------------------------------------------------------------------
    def run(self):
        self._log("Replay thread started.")
        error_count = 0
        max_errors = 1000

        try:
            while True:
                prev_ts: float | None = None

                for i, pkt in enumerate(self._packets):
                    if self._stop.is_set():
                        self._log("Thread received termination signal.")
                        return

                    self._on_progress(i)

                    # Inter-packet delay
                    curr_ts = pkt["timestamp"]
                    if prev_ts is not None:
                        delay = (curr_ts - prev_ts) / self._speed
                        if delay > 0:
                            # Use small sleep slices so we can react to stop quickly
                            deadline = time.monotonic() + delay
                            while time.monotonic() < deadline:
                                if self._stop.is_set():
                                    self._log("Thread received termination signal.")
                                    return
                                time.sleep(min(0.01, deadline - time.monotonic()))
                    prev_ts = curr_ts

                    # Send
                    try:
                        sendp(
                            pkt["data"],
                            iface=self._iface,
                            verbose=False,
                        )
                    except Exception as exc:
                        error_count += 1
                        if error_count <= 5 or error_count % 100 == 0:
                            self._log(
                                f"Error sending packet {i} "
                                f"(size: {len(pkt['data'])}): {exc}"
                            )
                        if error_count > max_errors:
                            self._log("Too many send errors, aborting.")
                            return

                if not self._loop or self._stop.is_set():
                    break

        except Exception as exc:
            self._log(f"Error in replay thread: {exc}")
        finally:
            self._log("Replay thread finished.")
            self._on_done()

    # ------------------------------------------------------------------
    def _log(self, msg: str):
        self._on_log(msg)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PCAP Traffic Generator")
        self.resizable(True, True)
        self.minsize(620, 520)

        self._packets: list[dict] = []
        self._interfaces: list[dict] = []
        self._replay_thread: ReplayThread | None = None
        self._stop_event = threading.Event()
        self._current_packet = 0
        self._total_packets = 0

        self._build_ui()
        self._enumerate_interfaces()

        if not SCAPY_AVAILABLE:
            self._log("ERROR: scapy is not installed. Run: pip install scapy")
        else:
            self._log(
                f"Application started. Scapy {conf.version if hasattr(conf, 'version') else ''}"
            )

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}

        # ── File row ────────────────────────────────────────────────────
        file_frame = ttk.LabelFrame(self, text="PCAP File")
        file_frame.pack(fill="x", **pad)

        self._filepath_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self._filepath_var, state="readonly").pack(
            side="left", fill="x", expand=True, padx=4, pady=4
        )
        ttk.Button(file_frame, text="Browse…", command=self._browse).pack(
            side="right", padx=4, pady=4
        )

        # ── Interface ───────────────────────────────────────────────────
        iface_frame = ttk.LabelFrame(self, text="Network Interface")
        iface_frame.pack(fill="x", **pad)

        self._iface_var = tk.StringVar()
        self._iface_combo = ttk.Combobox(
            iface_frame, textvariable=self._iface_var, state="readonly"
        )
        self._iface_combo.pack(fill="x", padx=4, pady=4)

        # ── Options ─────────────────────────────────────────────────────
        opts_frame = ttk.LabelFrame(self, text="Options")
        opts_frame.pack(fill="x", **pad)

        # Speed
        spd_row = ttk.Frame(opts_frame)
        spd_row.pack(fill="x", padx=4, pady=2)
        ttk.Label(spd_row, text="Speed:").pack(side="left")
        self._speed_label = ttk.Label(spd_row, text="1.0×", width=6)
        self._speed_label.pack(side="right")
        self._speed_var = tk.DoubleVar(value=1.0)
        self._speed_slider = ttk.Scale(
            spd_row,
            from_=0.1,
            to=5.0,
            orient="horizontal",
            variable=self._speed_var,
            command=self._on_speed_change,
        )
        self._speed_slider.pack(fill="x", expand=True, padx=4)

        # Loop checkbox
        self._loop_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts_frame, text="Loop playback", variable=self._loop_var).pack(
            anchor="w", padx=4, pady=2
        )

        # ── Progress ────────────────────────────────────────────────────
        prog_frame = ttk.LabelFrame(self, text="Progress")
        prog_frame.pack(fill="x", **pad)

        self._progress = ttk.Progressbar(prog_frame, mode="determinate")
        self._progress.pack(fill="x", padx=4, pady=4)
        self._status_label = ttk.Label(prog_frame, text="Ready")
        self._status_label.pack(anchor="w", padx=4)

        # ── Buttons ─────────────────────────────────────────────────────
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", **pad)

        self._btn_start = ttk.Button(
            btn_frame, text="▶  Start Replay", command=self._start_replay
        )
        self._btn_start.pack(side="left", padx=4)

        self._btn_stop = ttk.Button(
            btn_frame, text="■  Stop", command=self._stop_replay, state="disabled"
        )
        self._btn_stop.pack(side="left", padx=4)

        # ── Log ─────────────────────────────────────────────────────────
        log_frame = ttk.LabelFrame(self, text="Log")
        log_frame.pack(fill="both", expand=True, **pad)

        self._log_box = scrolledtext.ScrolledText(
            log_frame, height=10, state="disabled", wrap="word"
        )
        self._log_box.pack(fill="both", expand=True, padx=4, pady=4)

    # ------------------------------------------------------------------
    # Interface enumeration
    # ------------------------------------------------------------------

    def _enumerate_interfaces(self):
        try:
            self._interfaces = get_interfaces()
        except Exception as exc:
            self._log(f"Failed to enumerate interfaces: {exc}")
            return

        names = [iface["display"] for iface in self._interfaces]
        self._iface_combo["values"] = names
        if names:
            self._iface_combo.current(0)
            for iface in self._interfaces:
                self._log(f"Found interface: {iface['display']} ({iface['name']})")
        else:
            self._log("No network interfaces found.")

    # ------------------------------------------------------------------
    # File browsing
    # ------------------------------------------------------------------

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[
                ("PCAP files", "*.pcap *.cap *.pcapng"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        self._filepath_var.set(path)
        self._log(f"Loading packets from: {path}")
        self._set_loading(True)

        def _load():
            try:
                packets = load_packets(path)
                self.after(0, self._on_load_done, packets, None)
            except Exception as exc:
                self.after(0, self._on_load_done, None, exc)

        threading.Thread(target=_load, daemon=True).start()

    def _on_load_done(self, packets, error):
        self._set_loading(False)
        if error:
            self._log(f"Error opening PCAP file: {error}")
            self._packets = []
            self._total_packets = 0
        else:
            self._packets = packets
            self._total_packets = len(packets)
            self._progress["maximum"] = self._total_packets
            self._progress["value"] = 0
            self._log(f"Loaded {self._total_packets} packets from file.")
        self._refresh_start_btn()

    def _set_loading(self, active: bool):
        self.config(cursor="watch" if active else "")
        state = "disabled" if active else "normal"
        # Disable browse button while loading
        for child in self.winfo_children():
            if isinstance(child, ttk.LabelFrame) and child.cget("text") == "PCAP File":
                for w in child.winfo_children():
                    if isinstance(w, ttk.Button):
                        w.config(state=state)
        if active:
            self._status_label.config(text="Loading file…")

    # ------------------------------------------------------------------
    # Speed slider
    # ------------------------------------------------------------------

    def _on_speed_change(self, _=None):
        val = round(self._speed_var.get(), 1)
        self._speed_label.config(text=f"{val:.1f}×")

    # ------------------------------------------------------------------
    # Replay control
    # ------------------------------------------------------------------

    def _start_replay(self):
        if not self._packets:
            self._log("No packets loaded. Please open a pcap file first.")
            return

        idx = self._iface_combo.current()
        if idx < 0:
            self._log("Please select a network interface.")
            return

        iface_name = self._interfaces[idx]["name"]
        speed = round(self._speed_var.get(), 2)
        loop = self._loop_var.get()

        self._log(f"Opening interface: {iface_name}")
        self._log(f"Starting packet replay at {speed:.1f}× speed…")

        self._stop_event.clear()
        self._current_packet = 0

        self._replay_thread = ReplayThread(
            packets=self._packets,
            iface=iface_name,
            speed=speed,
            loop=loop,
            on_progress=self._on_progress,
            on_log=self._log,
            on_done=self._on_replay_done,
            stop_event=self._stop_event,
        )
        self._replay_thread.start()

        self._set_replaying(True)
        self._poll_progress()

    def _stop_replay(self):
        self._log("Stopping packet replay. Please wait…")
        self._stop_event.set()
        self._set_replaying(False)

    # ------------------------------------------------------------------
    # Progress polling (runs on the main thread via after())
    # ------------------------------------------------------------------

    def _poll_progress(self):
        if self._stop_event.is_set():
            return
        if self._replay_thread and self._replay_thread.is_alive():
            cur = self._current_packet
            tot = self._total_packets
            self._progress["value"] = cur
            pct = int(cur / tot * 100) if tot else 0
            self._status_label.config(text=f"Sent {cur} of {tot} packets ({pct}%)")
            self.after(200, self._poll_progress)

    def _on_progress(self, index: int):
        # Called from the replay thread — just store, main thread reads it
        self._current_packet = index

    def _on_replay_done(self):
        # Called from the replay thread via a simple flag check
        self.after(0, self._replay_finished_ui)

    def _replay_finished_ui(self):
        self._set_replaying(False)

    # ------------------------------------------------------------------
    # UI state helpers
    # ------------------------------------------------------------------

    def _set_replaying(self, active: bool):
        state_off = "disabled" if active else "normal"
        state_on = "normal" if active else "disabled"

        self._btn_start.config(state=state_off)
        self._btn_stop.config(state=state_on)
        self._iface_combo.config(state="disabled" if active else "readonly")
        self._speed_slider.config(state=state_off)
        self._loop_var  # checkbox state managed via BooleanVar

        for child in self.winfo_children():
            if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Options":
                for w in child.winfo_children():
                    if isinstance(w, ttk.Checkbutton):
                        w.config(state=state_off)

        if not active:
            self._status_label.config(text="Ready")
            self._progress["value"] = 0

    def _refresh_start_btn(self):
        can_start = bool(self._packets) and self._iface_combo.current() >= 0
        self._btn_start.config(state="normal" if can_start else "disabled")

    # ------------------------------------------------------------------
    # Logging (thread-safe via after())
    # ------------------------------------------------------------------

    def _log(self, msg: str):
        ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        line = f"{ts} {msg}\n"
        # Schedule on main thread
        self.after(0, self._append_log, line)

    def _append_log(self, line: str):
        self._log_box.config(state="normal")
        self._log_box.insert("end", line)
        self._log_box.see("end")
        self._log_box.config(state="disabled")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = App()
    app.mainloop()
