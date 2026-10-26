from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


class MeasureError(Exception):
    pass


def ram_host() -> int:
    if hasattr(os, "sysconf"):
        try:
            pages = os.sysconf("SC_PHYS_PAGES")
            size = os.sysconf("SC_PAGE_SIZE")
        except (ValueError, OSError) as exc:
            raise MeasureError("ram") from exc
        if not isinstance(pages, int) or not isinstance(size, int) or pages < 1 or size < 1:
            raise MeasureError("ram")
        return pages * size
    return _ram_windows()


def _ram_windows() -> int:
    import ctypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    info = MEMORYSTATUSEX()
    info.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(info)) == 0:
        raise MeasureError("ram")
    total = int(info.ullTotalPhys)
    if total < 1:
        raise MeasureError("ram")
    return total


def gpu_devices() -> list[tuple[str, int]]:
    if os.name == "nt":
        found = _dxgi_vram()
        if found:
            return found
        return _nvidia_vram()
    if sys.platform == "darwin":
        found = _darwin_vram()
        if found:
            return found
        return _nvidia_vram()
    found = _nvidia_vram()
    if found:
        return found
    return _drm_vram()


def _run(cmd: list[str]) -> str | None:
    try:
        completed = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def _nvidia_vram() -> list[tuple[str, int]]:
    text = _run(
        [
            "nvidia-smi",
            "--query-gpu=memory.total,uuid",
            "--format=csv,noheader,nounits",
        ]
    )
    if text is None:
        return []
    devices = []
    for line in text.splitlines():
        if not line.strip():
            continue
        total, uuid = [part.strip() for part in line.split(",", 1)]
        devices.append((uuid, int(total) * 1024 * 1024))
    return devices


def _drm_vram() -> list[tuple[str, int]]:
    root = Path("/sys/class/drm")
    if not root.is_dir():
        return []
    devices = []
    for card in sorted(root.glob("card[0-9]*")):
        if "-" in card.name:
            continue
        total = card / "device" / "mem_info_vram_total"
        if not total.is_file():
            continue
        size = int(total.read_text().strip())
        if size < 1:
            continue
        devices.append((card.name, size))
    return devices


def _dxgi_vram() -> list[tuple[str, int]]:
    import ctypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_uint32),
            ("Data2", ctypes.c_uint16),
            ("Data3", ctypes.c_uint16),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

    class DXGI_ADAPTER_DESC(ctypes.Structure):
        _fields_ = [
            ("Description", ctypes.c_wchar * 128),
            ("VendorId", ctypes.c_uint32),
            ("DeviceId", ctypes.c_uint32),
            ("SubSysId", ctypes.c_uint32),
            ("Revision", ctypes.c_uint32),
            ("DedicatedVideoMemory", ctypes.c_size_t),
            ("DedicatedSystemMemory", ctypes.c_size_t),
            ("SharedSystemMemory", ctypes.c_size_t),
            ("AdapterLuid", LUID),
        ]

    iid = GUID(0x7B7166EC, 0x21C7, 0x44AE, (ctypes.c_ubyte * 8)(0xB2, 0x1A, 0xC9, 0xAE, 0x32, 0x1A, 0xE3, 0x69))
    factory = ctypes.c_void_p()
    try:
        dxgi = ctypes.windll.dxgi
    except OSError:
        return []
    if dxgi.CreateDXGIFactory(ctypes.byref(iid), ctypes.byref(factory)) != 0 or not factory.value:
        return []
    vtbl = ctypes.cast(factory, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    enum_adapters = ctypes.WINFUNCTYPE(
        ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)
    )(vtbl[7])
    release = ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)(vtbl[2])
    devices = []
    index = 0
    while True:
        adapter = ctypes.c_void_p()
        if enum_adapters(factory, index, ctypes.byref(adapter)) != 0 or not adapter.value:
            break
        avtbl = ctypes.cast(adapter, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        get_desc = ctypes.WINFUNCTYPE(
            ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(DXGI_ADAPTER_DESC)
        )(avtbl[8])
        release_adapter = ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)(avtbl[2])
        desc = DXGI_ADAPTER_DESC()
        if get_desc(adapter, ctypes.byref(desc)) == 0:
            size = int(desc.DedicatedVideoMemory)
            if size > 0 and desc.VendorId != 0x1414:
                ident = f"{desc.AdapterLuid.HighPart:08x}{desc.AdapterLuid.LowPart:08x}"
                devices.append((ident, size))
        release_adapter(adapter)
        index += 1
    release(factory)
    return devices


def _darwin_vram() -> list[tuple[str, int]]:
    text = _run(["system_profiler", "SPDisplaysDataType", "-json"])
    if text is None or not text.strip():
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    devices = []
    for item in payload.get("SPDisplaysDataType", []):
        if not isinstance(item, dict):
            continue
        raw = item.get("spdisplays_vram")
        if not isinstance(raw, str) or not raw:
            continue
        size = _darwin_octets(raw)
        if size < 1:
            continue
        ident = item.get("sppci_model") or item.get("_name")
        if not isinstance(ident, str) or not ident:
            continue
        devices.append((ident, size))
    return devices


def _darwin_octets(text: str) -> int:
    parts = text.strip().split()
    if len(parts) != 2:
        return 0
    try:
        amount = float(parts[0])
    except ValueError:
        return 0
    unit = parts[1].lower()
    if amount <= 0:
        return 0
    if unit == "gb":
        return int(amount * 1024 * 1024 * 1024)
    if unit == "mb":
        return int(amount * 1024 * 1024)
    if unit == "kb":
        return int(amount * 1024)
    return 0


def cap(quantity: int) -> int:
    return quantity // 100


def host_class() -> str:
    if gpu_devices():
        return "gpu"
    return "cpu"


def host_budget(device: str | None = None) -> int:
    if host_class() != "gpu":
        return cap(ram_host())
    devices = gpu_devices()
    if not devices:
        return cap(ram_host())
    if device is not None:
        match = [item for item in devices if item[0] == device]
        if len(match) == 1:
            return cap(match[0][1])
    return cap(min(item[1] for item in devices))
