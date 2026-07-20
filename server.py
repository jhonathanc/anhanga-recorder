#!/usr/bin/env python3
"""Local browser app for recording authorized camera streams."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse
import argparse
import base64
import ctypes
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import platform
import re
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
import uuid


APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
APP_NAME = "Anhangá Recorder"
DATA_DIR = Path(os.environ.get("CAMERA_RECORDER_DATA_DIR", APP_DIR / "data")).resolve()
CONFIG_PATH = DATA_DIR / "config.json"
VERSION = "0.4.0"
DEFAULT_T2U_DLL = "../Libt2u Win32 SDK/libt2u.dll" if os.name == "nt" else "./native/libt2u.so"
T2U_SETTING_KEYS = (
    "t2uDllPath",
    "t2uServer",
    "t2uServerPort",
    "t2uServerKey",
    "t2uDevicePassword",
    "t2uConnectTimeoutSeconds",
)
SOURCE_GROUP_KEYS = (
    "p2pUuid",
    "p2pPassword",
    "p2pRemoteIp",
    "p2pRemotePort",
    "p2pLocalPort",
    "rtspUser",
    "rtspPassword",
)
SETTINGS_SECRET_KEYS = ("t2uServerKey", "t2uDevicePassword")
T2U_CLOUD_SECRET_KEYS = ("t2uServerKey", "t2uDevicePassword")
SOURCE_GROUP_SECRET_KEYS = ("p2pPassword", "rtspPassword")
CAMERA_SECRET_KEYS = ("p2pPassword", "rtspPassword")
SERVER_MANAGED_SETTING_KEYS = ("outputDir", "ffmpegPath", "ffprobePath", "t2uDllPath")
SERVER_MANAGED_CLOUD_KEYS = ("t2uDllPath",)
ALLOWED_STREAM_SCHEMES = ("rtsp", "rtsps", "http", "https", "rtmp", "rtmps", "srt", "udp", "tcp")
AUTH_FAILURE_WINDOW_SECONDS = 5 * 60
AUTH_MAX_FAILURES = 10
AUTH_BLOCK_SECONDS = 15 * 60
DEFAULT_MAX_PREVIEWS = 8
DEFAULT_MAX_PREVIEWS_PER_CLIENT = 8
DEFAULT_PREVIEW_MAX_SECONDS = 30 * 60
DEFAULT_PREVIEW_START_TIMEOUT_SECONDS = 15
DEFAULT_PREVIEW_RTSP_ATTEMPTS = 3
DEFAULT_PREVIEW_RTSP_RETRY_SECONDS = 2
DEFAULT_MAX_DOWNLOADS = 4
RECORDING_EXTENSIONS = frozenset((".avi", ".m4v", ".mkv", ".mov", ".mp4", ".ts", ".webm"))
RECORDING_NAME_PATTERN = re.compile(r"_(\d{8})_(\d{6})(?:\.[^.]+)$")
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

DEFAULT_CONFIG = {
    "settings": {
        "outputDir": "./recordings",
        "segmentSeconds": 900,
        "rtspTransport": "tcp",
        "ffmpegPath": "ffmpeg",
        "ffprobePath": "ffprobe",
        "mapMode": "av",
        "autoRestart": True,
        "restartDelaySeconds": 10,
        "alignSegmentsToClock": True,
        "maxLogLines": 400,
        "webUser": "admin",
        "webPassword": "",
        "t2uDllPath": DEFAULT_T2U_DLL,
        "t2uServer": "",
        "t2uServerPort": 0,
        "t2uServerKey": "",
        "t2uDevicePassword": "",
        "t2uConnectTimeoutSeconds": 30,
    },
    "t2uClouds": [],
    "sourceGroups": [],
    "cameras": [],
}

CONFIG_LOCK = threading.RLock()
JOBS_LOCK = threading.RLock()
LOG_LOCK = threading.RLock()
AUTH_LOCK = threading.RLock()
PREVIEW_LOCK = threading.RLock()
JOBS = {}
LOGS = []
AUTH_FAILURES = {}
ACTIVE_PREVIEWS = {}
DOWNLOAD_SLOTS = threading.BoundedSemaphore(DEFAULT_MAX_DOWNLOADS)
PASSWORD_HASH_PREFIX = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 120000
PASSWORD_MAX_LENGTH = 50
RECONNECT_BASE_SECONDS = 5 * 60
RECONNECT_MAX_SECONDS = 60 * 60
RECONNECT_STABLE_SECONDS = 60


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def iso_from_epoch(value):
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(value))


def epoch_ms():
    return int(time.time() * 1000)


def deep_merge(defaults, current):
    result = dict(defaults)
    for key, value in (current or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def resolve_user_path(value):
    raw = str(value or "").strip()
    if not raw:
        raw = str(APP_DIR / "recordings")
    path = Path(os.path.expanduser(raw))
    if not path.is_absolute():
        path = APP_DIR / path
    return path.resolve()


def resolve_app_path(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    path = Path(os.path.expanduser(raw))
    if not path.is_absolute():
        path = APP_DIR / path
    return path.resolve()


def path_display_name(value, fallback="Configurado no servidor"):
    raw = str(value or "").strip()
    if not raw:
        return fallback
    return Path(raw.rstrip("/\\")).name or fallback


def bounded_int(value, default, minimum, maximum):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


def environment_int(name, default, minimum, maximum):
    return bounded_int(os.environ.get(name, default), default, minimum, maximum)


def is_loopback_host(host):
    text = str(host or "").strip().strip("[]")
    if text.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def environment_flag(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def reconnect_delay_for_failures(failures):
    failures = max(1, int(failures or 1))
    multiplier = 2 ** min(failures - 1, 8)
    return min(RECONNECT_MAX_SECONDS, RECONNECT_BASE_SECONDS * multiplier)


def format_duration(seconds):
    seconds = max(0, int(seconds or 0))
    if seconds >= 3600:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h{minutes:02d}" if minutes else f"{hours}h"
    if seconds >= 60:
        minutes = seconds // 60
        rest = seconds % 60
        return f"{minutes}min{rest:02d}s" if rest else f"{minutes}min"
    return f"{seconds}s"


class T2uBackoffError(RuntimeError):
    def __init__(self, message, retry_after):
        super().__init__(message)
        self.retry_after = max(1, int(retry_after or 1))


class T2uTunnelUnavailableError(RuntimeError):
    pass


def safe_name(value):
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._-")
    return name[:80] or "camera"


def unique_text_id(value, seen, fallback):
    base = safe_name(value).lower()
    if base == "camera":
        base = f"{fallback}-{uuid.uuid4().hex[:8]}"
    base = base[:48].strip("._-") or f"{fallback}-{uuid.uuid4().hex[:8]}"
    candidate = base
    suffix = 2
    while candidate in seen:
        tail = f"-{suffix}"
        candidate = f"{base[: max(1, 48 - len(tail))]}{tail}"
        suffix += 1
    seen.add(candidate)
    return candidate


URL_AUTH_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/@\s]+)@", re.IGNORECASE)
URL_AUTH_ANYWHERE_PATTERN = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)([^/@\s]+)@", re.IGNORECASE)


def redact_url(text):
    if not text:
        return text
    return URL_AUTH_ANYWHERE_PATTERN.sub(r"\1***@", str(text))


def strip_url_credentials(text):
    if not text:
        return text
    return URL_AUTH_PATTERN.sub(r"\1", str(text))


def url_has_credentials(text):
    return bool(text and URL_AUTH_PATTERN.search(str(text)))


def pe_machine(path):
    result = {"format": None, "machine": None, "label": None, "bits": None}
    try:
        data = Path(path).read_bytes()[:512]
        if len(data) < 0x40 or data[:2] != b"MZ":
            return result
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        data = Path(path).read_bytes()[pe_offset : pe_offset + 8]
        if len(data) < 6 or data[:4] != b"PE\0\0":
            return result
        machine = int.from_bytes(data[4:6], "little")
    except OSError:
        return result

    labels = {
        0x014C: ("x86 / PE32", 32),
        0x8664: ("x64 / PE32+", 64),
        0x01C0: ("ARM", 32),
        0xAA64: ("ARM64", 64),
    }
    label, bits = labels.get(machine, (f"0x{machine:04X}", None))
    return {"format": "PE", "machine": machine, "label": label, "bits": bits}


def elf_machine(path):
    result = {"format": None, "machine": None, "label": None, "bits": None}
    try:
        data = Path(path).read_bytes()[:64]
    except OSError:
        return result
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return result

    bits = 64 if data[4] == 2 else 32 if data[4] == 1 else None
    byteorder = "big" if data[5] == 2 else "little"
    machine = int.from_bytes(data[18:20], byteorder)
    labels = {
        0x03: ("x86 / ELF32", 32),
        0x08: (f"MIPS / ELF{bits or ''}", bits),
        0x28: ("ARM / ELF32", 32),
        0x3E: ("x86_64 / ELF64", 64),
        0xB7: ("AArch64 / ELF64", 64),
    }
    label, expected_bits = labels.get(machine, (f"ELF machine 0x{machine:04X}", bits))
    return {"format": "ELF", "machine": machine, "label": label, "bits": expected_bits}


def shared_library_machine(path):
    pe = pe_machine(path)
    if pe.get("format"):
        return pe
    elf = elf_machine(path)
    if elf.get("format"):
        return elf
    return {"format": None, "machine": None, "label": None, "bits": None}


def python_bits():
    return 64 if sys.maxsize > 2**32 else 32


def add_log(source_id, level, message):
    with LOG_LOCK:
        LOGS.append(
            {
                "ts": now_iso(),
                "sourceId": source_id,
                "level": level,
                "message": redact_url(str(message).rstrip()),
            }
        )
        max_lines = int(load_config()["settings"].get("maxLogLines", 400))
        if len(LOGS) > max_lines:
            del LOGS[: len(LOGS) - max_lines]


def load_config():
    with CONFIG_LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not CONFIG_PATH.exists():
            return save_config(DEFAULT_CONFIG)
        ensure_private_config_permissions()
        try:
            with CONFIG_PATH.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Arquivo de configuracao invalido: {CONFIG_PATH}: {exc}") from exc

        normalized = normalize_config(deep_merge(DEFAULT_CONFIG, loaded))
        if settings_needs_password_migration(loaded.get("settings", {}), normalized["settings"]):
            save_config(normalized)
        return normalized


def ensure_private_config_permissions():
    if os.name == "nt":
        return
    try:
        DATA_DIR.chmod(0o700)
        if CONFIG_PATH.exists():
            CONFIG_PATH.chmod(0o600)
    except OSError as exc:
        raise RuntimeError("Nao foi possivel restringir as permissoes da configuracao.") from exc


def save_config(config):
    with CONFIG_LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        normalized = normalize_config(config)
        tmp_path = CONFIG_PATH.with_suffix(".json.tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(normalized, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        if os.name != "nt":
            tmp_path.chmod(0o600)
        tmp_path.replace(CONFIG_PATH)
        ensure_private_config_permissions()
        return normalized


def hash_password(password):
    text = str(password or "")
    if len(text) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"A senha da pagina deve ter no maximo {PASSWORD_MAX_LENGTH} caracteres.")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        text.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_text = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{PASSWORD_HASH_PREFIX}${PASSWORD_HASH_ITERATIONS}${salt_text}${digest_text}"


def is_password_hash(value):
    text = str(value or "")
    if len(text) <= PASSWORD_MAX_LENGTH:
        return False
    parts = text.split("$")
    if len(parts) != 4 or parts[0] != PASSWORD_HASH_PREFIX:
        return False
    try:
        int(parts[1])
        return bool(parts[2] and parts[3])
    except ValueError:
        return False


def normalize_web_password(value):
    text = str(value or "")
    if not text:
        return ""
    if is_password_hash(text):
        return text
    if len(text) > PASSWORD_MAX_LENGTH:
        raise ValueError(
            f"Senha da pagina invalida: use ate {PASSWORD_MAX_LENGTH} caracteres ou um hash {PASSWORD_HASH_PREFIX}."
        )
    return hash_password(text)


def verify_web_password(password, stored):
    stored_text = str(stored or "")
    password_text = str(password or "")
    if not stored_text:
        return hmac.compare_digest(password_text, "")
    if not is_password_hash(stored_text):
        stored_text = normalize_web_password(stored_text)
    try:
        _prefix, iterations_text, salt_text, digest_text = stored_text.split("$", 3)
        padding = "=" * (-len(salt_text) % 4)
        salt = base64.urlsafe_b64decode((salt_text + padding).encode("ascii"))
        padding = "=" * (-len(digest_text) % 4)
        expected = base64.urlsafe_b64decode((digest_text + padding).encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password_text.encode("utf-8"),
            salt,
            int(iterations_text),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def settings_needs_password_migration(raw_settings, normalized_settings):
    if not isinstance(raw_settings, dict):
        return False
    if "webPassword" not in raw_settings and "webPasswordHash" not in raw_settings:
        return False
    raw_value = raw_settings.get("webPassword", raw_settings.get("webPasswordHash", ""))
    return str(raw_value or "") != str(normalized_settings.get("webPassword") or "")


def normalize_settings(settings):
    merged = deep_merge(DEFAULT_CONFIG["settings"], settings or {})
    merged["segmentSeconds"] = bounded_int(merged.get("segmentSeconds", 900), 900, 30, 86400)
    merged["restartDelaySeconds"] = bounded_int(merged.get("restartDelaySeconds", 10), 10, 1, 600)
    merged["rtspTransport"] = str(merged.get("rtspTransport", "tcp")).lower()
    if merged["rtspTransport"] not in ("tcp", "udp", "auto"):
        merged["rtspTransport"] = "tcp"
    merged["mapMode"] = str(merged.get("mapMode", "av")).lower()
    if merged["mapMode"] not in ("av", "all"):
        merged["mapMode"] = "av"
    merged["autoRestart"] = bool(merged.get("autoRestart", True))
    merged["alignSegmentsToClock"] = bool(merged.get("alignSegmentsToClock", True))
    merged["maxLogLines"] = bounded_int(merged.get("maxLogLines", 400), 400, 100, 5000)
    merged["outputDir"] = str(merged.get("outputDir") or "./recordings")
    merged["ffmpegPath"] = str(merged.get("ffmpegPath") or "ffmpeg")
    merged["ffprobePath"] = str(merged.get("ffprobePath") or "ffprobe")
    merged["webUser"] = str(merged.get("webUser") or "admin").strip() or "admin"
    merged["webPassword"] = normalize_web_password(
        merged.get("webPassword", merged.get("webPasswordHash", ""))
    )
    merged.pop("webPasswordHash", None)
    merged.pop("webPasswordConfigured", None)
    for key in (*SETTINGS_SECRET_KEYS, *SERVER_MANAGED_SETTING_KEYS):
        merged.pop(f"{key}Configured", None)
        merged.pop(f"{key}Display", None)
    merged["t2uDllPath"] = str(merged.get("t2uDllPath") or DEFAULT_T2U_DLL).strip()
    merged["t2uServer"] = str(merged.get("t2uServer") or "").strip()
    merged["t2uServerPort"] = bounded_int(merged.get("t2uServerPort", 0), 0, 0, 65535)
    merged["t2uServerKey"] = str(merged.get("t2uServerKey") or "").strip()
    merged["t2uDevicePassword"] = str(merged.get("t2uDevicePassword") or "")
    merged["t2uConnectTimeoutSeconds"] = bounded_int(
        merged.get("t2uConnectTimeoutSeconds", 30), 30, 3, 180
    )
    return merged


def t2u_cloud_from_settings(settings):
    return {
        "id": "t2u-default",
        "name": "T2U Cloud",
        **{key: settings.get(key, DEFAULT_CONFIG["settings"].get(key)) for key in T2U_SETTING_KEYS},
    }


def normalize_t2u_clouds(clouds, settings):
    normalized = []
    seen = set()
    source = clouds or [t2u_cloud_from_settings(settings)]
    for cloud in source:
        if not isinstance(cloud, dict):
            continue
        item = dict(cloud)
        item["name"] = str(item.get("name") or "T2U Cloud").strip()
        item["id"] = str(item.get("id") or "").strip()
        if not item["id"] or item["id"] in seen:
            item["id"] = unique_text_id(item["id"] or item["name"], seen, "cloud")
        else:
            seen.add(item["id"])
        item["t2uDllPath"] = str(item.get("t2uDllPath") or settings.get("t2uDllPath") or DEFAULT_T2U_DLL).strip()
        item["t2uServer"] = str(item.get("t2uServer") or settings.get("t2uServer") or "").strip()
        item["t2uServerPort"] = bounded_int(item.get("t2uServerPort", settings.get("t2uServerPort", 0)), 0, 0, 65535)
        item["t2uServerKey"] = str(item.get("t2uServerKey") or settings.get("t2uServerKey") or "").strip()
        item["t2uDevicePassword"] = str(
            item.get("t2uDevicePassword")
            if item.get("t2uDevicePassword") is not None
            else settings.get("t2uDevicePassword", "")
        )
        item["t2uConnectTimeoutSeconds"] = bounded_int(
            item.get("t2uConnectTimeoutSeconds", settings.get("t2uConnectTimeoutSeconds", 30)),
            30,
            3,
            180,
        )
        item["createdAt"] = str(item.get("createdAt") or now_iso())
        item["updatedAt"] = str(item.get("updatedAt") or now_iso())
        for key in (*T2U_CLOUD_SECRET_KEYS, *SERVER_MANAGED_CLOUD_KEYS):
            item.pop(f"{key}Configured", None)
            item.pop(f"{key}Display", None)
        normalized.append(item)
    return normalized or normalize_t2u_clouds([t2u_cloud_from_settings(settings)], settings)


def normalize_source_groups(groups, t2u_clouds):
    normalized = []
    seen = set()
    default_cloud_id = t2u_clouds[0]["id"] if t2u_clouds else ""
    valid_cloud_ids = {cloud["id"] for cloud in t2u_clouds}
    for group in groups or []:
        if not isinstance(group, dict):
            continue
        item = dict(group)
        item["name"] = str(item.get("name") or item.get("group") or "Grupo Cloud/P2P").strip()
        item["id"] = str(item.get("id") or item.get("groupId") or "").strip()
        if not item["id"] or item["id"] in seen:
            item["id"] = unique_text_id(item["id"] or item["name"], seen, "group")
        else:
            seen.add(item["id"])
        item["t2uCloudId"] = str(item.get("t2uCloudId") or item.get("cloudId") or default_cloud_id).strip()
        if item["t2uCloudId"] not in valid_cloud_ids and default_cloud_id:
            item["t2uCloudId"] = default_cloud_id
        item["p2pUuid"] = str(item.get("p2pUuid") or item.get("serial") or "").strip()
        item["p2pPassword"] = str(item.get("p2pPassword") or "")
        item["p2pRemoteIp"] = str(item.get("p2pRemoteIp") or "127.0.0.1").strip()
        item["p2pRemotePort"] = bounded_int(item.get("p2pRemotePort", 554), 554, 1, 65535)
        item["p2pLocalPort"] = bounded_int(item.get("p2pLocalPort", 0), 0, 0, 65535)
        item["rtspUser"] = str(item.get("rtspUser") or "").strip()
        item["rtspPassword"] = str(item.get("rtspPassword") or "")
        item["maxSources"] = bounded_int(item.get("maxSources", 0), 0, 0, 128)
        item["enabled"] = bool(item.get("enabled", True))
        item["createdAt"] = str(item.get("createdAt") or now_iso())
        item["updatedAt"] = str(item.get("updatedAt") or now_iso())
        for key in SOURCE_GROUP_SECRET_KEYS:
            item.pop(f"{key}Configured", None)
        normalized.append(item)
    return normalized


def normalize_cameras(cameras):
    normalized = []
    seen = set()
    for camera in cameras or []:
        if not isinstance(camera, dict):
            continue
        item = dict(camera)
        item["id"] = str(item.get("id") or uuid.uuid4().hex[:12])
        while item["id"] in seen:
            item["id"] = uuid.uuid4().hex[:12]
        seen.add(item["id"])
        item["name"] = str(item.get("name") or "Camera").strip()
        item["type"] = str(item.get("type") or "stream").lower()
        if item["type"] not in ("stream", "v4l2", "cloud-p2p"):
            item["type"] = "stream"
        item["url"] = str(item.get("url") or "").strip()
        item["videoDevice"] = str(item.get("videoDevice") or "/dev/video0").strip()
        item["audioDevice"] = str(item.get("audioDevice") or "").strip()
        item["resolution"] = str(item.get("resolution") or "").strip()
        item["frameRate"] = str(item.get("frameRate") or "").strip()
        item["inputFormat"] = str(item.get("inputFormat") or "").strip()
        item["stream"] = str(item.get("stream") or "main").lower()
        if item["stream"] not in ("main", "extra", "custom"):
            item["stream"] = "main"
        item["p2pUuid"] = str(item.get("p2pUuid") or item.get("serial") or "").strip()
        item["p2pPassword"] = str(item.get("p2pPassword") or "")
        item["p2pRemoteIp"] = str(item.get("p2pRemoteIp") or "127.0.0.1").strip()
        item["p2pRemotePort"] = bounded_int(item.get("p2pRemotePort", 554), 554, 1, 65535)
        item["p2pLocalPort"] = bounded_int(item.get("p2pLocalPort", 0), 0, 0, 65535)
        item["rtspUser"] = str(item.get("rtspUser") or "").strip()
        item["rtspPassword"] = str(item.get("rtspPassword") or "")
        item["rtspPath"] = str(item.get("rtspPath") or "/cam/realmonitor?channel=1&subtype=0").strip()
        item["groupId"] = str(item.get("groupId") or item.get("sourceGroupId") or "").strip()
        item["t2uCloudId"] = str(item.get("t2uCloudId") or "").strip()
        item["group"] = str(item.get("group") or "").strip()
        item["enabled"] = bool(item.get("enabled", True))
        item["createdAt"] = str(item.get("createdAt") or now_iso())
        item["updatedAt"] = str(item.get("updatedAt") or now_iso())
        for key in CAMERA_SECRET_KEYS:
            item.pop(f"{key}Configured", None)
        item.pop("urlConfigured", None)
        item.pop("urlCredentialsConfigured", None)
        normalized.append(item)
    return normalized


def migrate_source_groups(cameras, t2u_clouds):
    groups = []
    seen_ids = set()
    seen_keys = {}
    default_cloud_id = t2u_clouds[0]["id"] if t2u_clouds else ""
    for camera in cameras:
        if camera.get("type") != "cloud-p2p":
            continue
        raw_name = camera.get("group") or camera.get("p2pUuid") or camera.get("name") or "Cloud/P2P"
        key = str(raw_name).strip().lower() if camera.get("group") else "|".join(
            [
                str(camera.get("p2pUuid") or ""),
                str(camera.get("p2pRemoteIp") or "127.0.0.1"),
                str(camera.get("p2pRemotePort") or 554),
                str(camera.get("rtspUser") or ""),
            ]
        )
        group = seen_keys.get(key)
        if not group:
            group = {
                "id": unique_text_id(raw_name, seen_ids, "group"),
                "name": str(raw_name).strip() or "Cloud/P2P",
                "t2uCloudId": camera.get("t2uCloudId") or default_cloud_id,
                "p2pUuid": camera.get("p2pUuid") or "",
                "p2pPassword": camera.get("p2pPassword") or "",
                "p2pRemoteIp": camera.get("p2pRemoteIp") or "127.0.0.1",
                "p2pRemotePort": camera.get("p2pRemotePort") or 554,
                "p2pLocalPort": camera.get("p2pLocalPort") or 0,
                "rtspUser": camera.get("rtspUser") or "",
                "rtspPassword": camera.get("rtspPassword") or "",
                "maxSources": 0,
                "enabled": True,
                "createdAt": now_iso(),
                "updatedAt": now_iso(),
            }
            seen_keys[key] = group
            groups.append(group)
        camera["groupId"] = group["id"]
        camera["group"] = group["name"]
    return normalize_source_groups(groups, t2u_clouds)


def attach_group_ids_to_cameras(cameras, source_groups):
    by_id = {group["id"]: group for group in source_groups}
    by_name = {str(group["name"]).strip().lower(): group for group in source_groups}
    for camera in cameras:
        group = by_id.get(camera.get("groupId"))
        if not group and camera.get("group"):
            group = by_name.get(str(camera["group"]).strip().lower())
        if group:
            camera["groupId"] = group["id"]
            camera["group"] = group["name"]


def prune_grouped_camera_fields(cameras):
    for camera in cameras:
        if camera.get("type") == "cloud-p2p" and camera.get("groupId"):
            for key in (*SOURCE_GROUP_KEYS, "t2uCloudId"):
                camera.pop(key, None)


def normalize_config(config):
    settings = normalize_settings(config.get("settings", {}))
    t2u_clouds = normalize_t2u_clouds(config.get("t2uClouds"), settings)
    cameras = normalize_cameras(config.get("cameras", []))
    source_groups = normalize_source_groups(config.get("sourceGroups"), t2u_clouds)
    if not source_groups:
        source_groups = migrate_source_groups(cameras, t2u_clouds)
    attach_group_ids_to_cameras(cameras, source_groups)
    prune_grouped_camera_fields(cameras)
    return {
        "settings": settings,
        "t2uClouds": t2u_clouds,
        "sourceGroups": source_groups,
        "cameras": cameras,
    }


def public_config(config):
    visible = json.loads(json.dumps(config))
    settings = visible.get("settings", {})
    settings["webPasswordConfigured"] = bool(settings.get("webPassword"))
    settings.pop("webPassword", None)
    settings.pop("webPasswordHash", None)
    for key in SETTINGS_SECRET_KEYS:
        settings[f"{key}Configured"] = bool(settings.get(key))
        settings.pop(key, None)
    for key in SERVER_MANAGED_SETTING_KEYS:
        settings[f"{key}Display"] = path_display_name(settings.get(key))
        settings.pop(key, None)

    for cloud in visible.get("t2uClouds", []):
        for key in T2U_CLOUD_SECRET_KEYS:
            cloud[f"{key}Configured"] = bool(cloud.get(key))
            cloud.pop(key, None)
        for key in SERVER_MANAGED_CLOUD_KEYS:
            cloud[f"{key}Display"] = path_display_name(cloud.get(key))
            cloud.pop(key, None)

    for group in visible.get("sourceGroups", []):
        for key in SOURCE_GROUP_SECRET_KEYS:
            group[f"{key}Configured"] = bool(group.get(key))
            group.pop(key, None)

    for camera in visible.get("cameras", []):
        for key in CAMERA_SECRET_KEYS:
            camera[f"{key}Configured"] = bool(camera.get(key))
            camera.pop(key, None)
        camera["urlConfigured"] = bool(camera.get("url"))
        camera["urlCredentialsConfigured"] = url_has_credentials(camera.get("url"))
        if camera["urlConfigured"]:
            camera["url"] = ""
    return visible


def preserve_secret_fields(current, incoming, keys):
    current = current or {}
    for key in keys:
        if not str(incoming.get(key) or ""):
            incoming[key] = current.get(key, "")
        incoming.pop(f"{key}Configured", None)


def prepare_config_update(current, payload):
    incoming = dict(payload or {})
    current_settings = current.get("settings", {})
    settings = {**current_settings, **dict(incoming.get("settings") or {})}
    if not str(settings.get("webPassword", settings.get("webPasswordHash", "")) or ""):
        settings["webPassword"] = current_settings.get("webPassword", "")
    settings.pop("webPasswordConfigured", None)
    preserve_secret_fields(current_settings, settings, SETTINGS_SECRET_KEYS)
    for key in SERVER_MANAGED_SETTING_KEYS:
        settings[key] = current_settings.get(key, DEFAULT_CONFIG["settings"].get(key))
        settings.pop(f"{key}Display", None)
    incoming["settings"] = settings

    current_clouds = {item.get("id"): item for item in current.get("t2uClouds", [])}
    clouds = []
    for raw_cloud in incoming.get("t2uClouds", current.get("t2uClouds", [])):
        cloud = dict(raw_cloud or {})
        existing = current_clouds.get(cloud.get("id"), {})
        preserve_secret_fields(existing, cloud, T2U_CLOUD_SECRET_KEYS)
        for key in SERVER_MANAGED_CLOUD_KEYS:
            cloud[key] = existing.get(key, current_settings.get(key, DEFAULT_T2U_DLL))
            cloud.pop(f"{key}Display", None)
        clouds.append(cloud)
    incoming["t2uClouds"] = clouds

    current_groups = {item.get("id"): item for item in current.get("sourceGroups", [])}
    groups = []
    for raw_group in incoming.get("sourceGroups", current.get("sourceGroups", [])):
        group = dict(raw_group or {})
        preserve_secret_fields(current_groups.get(group.get("id"), {}), group, SOURCE_GROUP_SECRET_KEYS)
        groups.append(group)
    incoming["sourceGroups"] = groups

    current_cameras = {item.get("id"): item for item in current.get("cameras", [])}
    cameras = []
    for raw_camera in incoming.get("cameras", current.get("cameras", [])):
        camera = dict(raw_camera or {})
        existing = current_cameras.get(camera.get("id"), {})
        preserve_secret_fields(existing, camera, CAMERA_SECRET_KEYS)
        old_url = str(existing.get("url") or "")
        new_url = str(camera.get("url") or "")
        if old_url and (
            not new_url
            or (url_has_credentials(old_url) and new_url in (strip_url_credentials(old_url), redact_url(old_url)))
        ):
            camera["url"] = old_url
        camera.pop("urlCredentialsConfigured", None)
        camera.pop("urlConfigured", None)
        cameras.append(camera)
    incoming["cameras"] = cameras
    return incoming


def find_camera(config, camera_id):
    for camera in config.get("cameras", []):
        if camera.get("id") == camera_id:
            return camera
    return None


def find_source_group(config, group_id_or_name):
    needle = str(group_id_or_name or "").strip()
    if not needle:
        return None
    lower = needle.lower()
    for group in config.get("sourceGroups", []):
        if group.get("id") == needle or str(group.get("name") or "").strip().lower() == lower:
            return group
    return None


def find_t2u_cloud(config, cloud_id):
    needle = str(cloud_id or "").strip()
    clouds = config.get("t2uClouds", [])
    if needle:
        for cloud in clouds:
            if cloud.get("id") == needle:
                return cloud
    return clouds[0] if clouds else None


def settings_for_t2u_cloud(settings, cloud):
    merged = dict(settings or {})
    if cloud:
        for key in T2U_SETTING_KEYS:
            if key in cloud:
                merged[key] = cloud[key]
    return normalize_settings(merged)


def resolve_camera_runtime(camera, config):
    settings = normalize_settings((config or {}).get("settings", {}))
    effective = dict(camera)
    group = None
    if effective.get("type") == "cloud-p2p":
        group = find_source_group(config or {}, effective.get("groupId") or effective.get("group"))
        if group:
            effective["groupId"] = group["id"]
            effective["group"] = group["name"]
            effective["t2uCloudId"] = group.get("t2uCloudId") or ""
            for key in SOURCE_GROUP_KEYS:
                effective[key] = group.get(key)
        cloud = find_t2u_cloud(config or {}, effective.get("t2uCloudId"))
        settings = settings_for_t2u_cloud(settings, cloud)
    return effective, settings, group


def camera_cloud_group(camera, config):
    if camera.get("type") != "cloud-p2p":
        return None
    return find_source_group(config or {}, camera.get("groupId") or camera.get("group"))


def active_recording_group_counts(config):
    counts = {}
    for job in JOBS.values():
        if not job.is_active():
            continue
        group = camera_cloud_group(job.camera, config)
        if group:
            counts[group["id"]] = counts.get(group["id"], 0) + 1
    return counts


class ReconnectCoordinator:
    def __init__(self):
        self._lock = threading.RLock()
        self._group_states = {}

    def reset_group(self, group_id):
        if not group_id:
            return
        with self._lock:
            self._group_states.pop(group_id, None)

    def mark_success(self, job):
        self.reset_group(getattr(job, "cloud_group_id", None))

    def delay_for(self, job):
        group_id = getattr(job, "cloud_group_id", None)
        if not group_id:
            return RECONNECT_BASE_SECONDS, "falha isolada"

        with JOBS_LOCK:
            group_jobs = [
                candidate
                for candidate in JOBS.values()
                if getattr(candidate, "cloud_group_id", None) == group_id
                and candidate.wants_reconnect()
            ]

        if len(group_jobs) < 2:
            return RECONNECT_BASE_SECONDS, "falha isolada"

        all_failed = all(candidate.awaiting_reconnect() for candidate in group_jobs)
        if not all_failed:
            return RECONNECT_BASE_SECONDS, "falha isolada"

        signature = tuple(
            sorted((candidate.id, candidate.failure_epoch) for candidate in group_jobs)
        )
        with self._lock:
            state = self._group_states.setdefault(group_id, {"failures": 0, "signature": None})
            if signature != state["signature"]:
                state["failures"] += 1
                state["signature"] = signature
            failures = state["failures"]

        return reconnect_delay_for_failures(failures), "falha do grupo cloud"


RECONNECT = ReconnectCoordinator()


class T2uNetStat(ctypes.Structure):
    _fields_ = [
        ("ip", ctypes.c_char * 20),
        ("port", ctypes.c_int),
        ("proxy", ctypes.c_int),
        ("lost_rate", ctypes.c_float),
        ("bandwidth", ctypes.c_int),
        ("remote_nattype", ctypes.c_int),
        ("local_nattype", ctypes.c_int),
        ("ip6", ctypes.c_char * 40),
        ("remote_version", ctypes.c_int),
    ]


class T2uRuntime:
    def __init__(self):
        self._lock = threading.RLock()
        self._dll = None
        self._dll_path = None
        self._init_key = None
        self._server_backoff = {}

    def _server_key(self, settings):
        path = resolve_app_path(settings.get("t2uDllPath") or DEFAULT_T2U_DLL)
        server = settings.get("t2uServer")
        port = int(settings.get("t2uServerPort") or 0)
        key = settings.get("t2uServerKey") or ""
        return (str(path), str(server or ""), port, str(key or ""))

    def _server_backoff_state(self, init_key):
        state = self._server_backoff.get(init_key) or {}
        next_attempt = float(state.get("nextAttempt") or 0)
        retry_after = max(0, int(next_attempt - time.time()))
        return {
            "failures": int(state.get("failures") or 0),
            "retryAfterSeconds": retry_after,
            "nextAttemptAt": iso_from_epoch(next_attempt) if retry_after > 0 else None,
        }

    def _raise_if_server_backoff(self, init_key):
        state = self._server_backoff_state(init_key)
        retry_after = state["retryAfterSeconds"]
        if retry_after > 0:
            raise T2uBackoffError(
                f"T2U aguardando reconexao com o servidor em {format_duration(retry_after)}.",
                retry_after,
            )

    def _mark_server_success(self, init_key):
        self._server_backoff.pop(init_key, None)

    def _mark_server_failure(self, init_key, reason):
        state = self._server_backoff.setdefault(init_key, {"failures": 0, "nextAttempt": 0})
        state["failures"] += 1
        delay = reconnect_delay_for_failures(state["failures"])
        state["nextAttempt"] = time.time() + delay
        self._init_key = None
        add_log(
            None,
            "warning",
            f"Falha na conexao T2U ({reason}). Nova tentativa em {format_duration(delay)}.",
        )

    def status_info(self, settings):
        configured = settings.get("t2uDllPath") or DEFAULT_T2U_DLL
        path = resolve_app_path(configured)
        exists = bool(path and path.exists())
        machine = shared_library_machine(path) if exists else {"format": None, "label": None, "bits": None}
        py_bits = python_bits()
        loadable = exists and (machine.get("bits") in (None, py_bits))
        if os.name == "nt" and machine.get("format") == "ELF":
            loadable = False
        if os.name != "nt" and machine.get("format") == "PE":
            loadable = False
        message = "T2U pronto para carregar" if loadable else "T2U indisponivel"
        if not exists:
            message = "Biblioteca T2U nao encontrada"
        elif os.name == "nt" and machine.get("format") == "ELF":
            message = "Use DLL T2U no Windows; ELF .so e para Linux"
        elif os.name != "nt" and machine.get("format") == "PE":
            message = "Use libt2u.so Linux; DLL Windows nao carrega no Linux"
        elif machine.get("bits") and machine.get("bits") != py_bits:
            message = f"Biblioteca {machine.get('bits')}-bit exige Python {machine.get('bits')}-bit"
        return {
            "configured": configured,
            "path": str(path) if path else "",
            "found": exists,
            "format": machine.get("format"),
            "machine": machine.get("label"),
            "pythonBits": py_bits,
            "loadable": loadable,
            "message": message,
            "backoff": self._server_backoff_state(self._server_key(settings)),
        }

    def _load(self, settings):
        path = resolve_app_path(settings.get("t2uDllPath") or DEFAULT_T2U_DLL)
        if not path or not path.exists():
            raise RuntimeError(f"Biblioteca T2U nao encontrada: {path}")
        machine = shared_library_machine(path)
        if os.name == "nt" and machine.get("format") == "ELF":
            raise RuntimeError("Use uma DLL T2U no Windows; o arquivo configurado e ELF/Linux.")
        if os.name != "nt" and machine.get("format") == "PE":
            raise RuntimeError("Use uma libt2u.so Linux; DLL Windows nao carrega no Linux.")
        if machine.get("bits") and machine["bits"] != python_bits():
            raise RuntimeError(
                f"{path.name} e {machine['bits']}-bit, mas este Python e {python_bits()}-bit. "
                f"Use Python {machine['bits']}-bit ou uma biblioteca T2U {python_bits()}-bit."
            )
        if self._dll is not None and self._dll_path == str(path):
            return self._dll

        dll = ctypes.CDLL(str(path))
        dll.t2u_init.argtypes = [ctypes.c_char_p, ctypes.c_ushort, ctypes.c_char_p]
        dll.t2u_init.restype = None
        dll.t2u_add_port_v3.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_ushort,
            ctypes.c_ushort,
        ]
        dll.t2u_add_port_v3.restype = ctypes.c_int
        dll.t2u_del_port.argtypes = [ctypes.c_ushort]
        dll.t2u_del_port.restype = None
        dll.t2u_port_status.argtypes = [ctypes.c_ushort, ctypes.POINTER(T2uNetStat)]
        dll.t2u_port_status.restype = ctypes.c_int
        dll.t2u_status.argtypes = []
        dll.t2u_status.restype = ctypes.c_int

        self._dll = dll
        self._dll_path = str(path)
        self._init_key = None
        return dll

    def _bytes(self, value, field):
        text = str(value or "")
        if not text and field:
            raise RuntimeError(f"Configure {field} antes de usar Cloud/P2P.")
        return text.encode("utf-8")

    def ensure_initialized(self, settings):
        with self._lock:
            dll = self._load(settings)
            server = settings.get("t2uServer")
            port = int(settings.get("t2uServerPort") or 0)
            key = settings.get("t2uServerKey") or ""
            if not server:
                raise RuntimeError("Configure o servidor T2U em Gravacao > T2U.")
            if port <= 0:
                raise RuntimeError("Configure a porta do servidor T2U em Gravacao > T2U.")
            init_key = (self._dll_path, server, port, key)
            self._raise_if_server_backoff(init_key)
            if init_key != self._init_key:
                key_arg = self._bytes(key, None) if key else None
                dll.t2u_init(self._bytes(server, "servidor T2U"), port, key_arg)
                self._init_key = init_key
        return dll, init_key

    def wait_until_ready(self, settings):
        dll, init_key = self.ensure_initialized(settings)
        timeout = int(settings.get("t2uConnectTimeoutSeconds") or 30)
        deadline = time.time() + timeout
        last_status = None
        while time.time() < deadline:
            with self._lock:
                last_status = dll.t2u_status()
            if last_status > 0:
                self._mark_server_success(init_key)
                return
            if last_status < 0:
                self._mark_server_failure(init_key, f"status {last_status}")
                raise RuntimeError(f"T2U nao conectou ao servidor. Status: {last_status}")
            time.sleep(0.2)
        self._mark_server_failure(init_key, f"timeout {timeout}s; ultimo status {last_status}")
        raise RuntimeError(f"T2U nao ficou pronto em {timeout}s. Ultimo status: {last_status}")

    def open_tunnel(self, camera, settings):
        self.wait_until_ready(settings)
        dll = self._dll
        uuid_value = camera.get("p2pUuid")
        password = camera.get("p2pPassword") or settings.get("t2uDevicePassword")
        remote_ip = camera.get("p2pRemoteIp") or "127.0.0.1"
        remote_port = int(camera.get("p2pRemotePort") or 554)
        local_port = int(camera.get("p2pLocalPort") or 0)
        timeout = int(settings.get("t2uConnectTimeoutSeconds") or 30)
        attempts = 2
        overall_deadline = time.monotonic() + timeout
        last_status = None

        for attempt in range(1, attempts + 1):
            with self._lock:
                mapped_port = dll.t2u_add_port_v3(
                    self._bytes(uuid_value, "ID do dispositivo P2P"),
                    self._bytes(password, "senha T2U/P2P"),
                    self._bytes(remote_ip, "IP remoto T2U"),
                    remote_port,
                    local_port,
                )
            if mapped_port <= 0:
                raise T2uTunnelUnavailableError(f"T2U nao criou a porta local. Retorno: {mapped_port}")

            tunnel = T2uTunnel(self, mapped_port, remote_ip, remote_port)
            remaining = max(0.0, overall_deadline - time.monotonic())
            attempts_left = attempts - attempt + 1
            attempt_budget = max(3.0, remaining / attempts_left) if remaining else 0.0
            attempt_deadline = min(overall_deadline, time.monotonic() + attempt_budget)
            last_status = None
            while time.monotonic() < attempt_deadline:
                stat = T2uNetStat()
                with self._lock:
                    last_status = dll.t2u_port_status(mapped_port, ctypes.byref(stat))
                if last_status > 0:
                    tunnel.status = last_status
                    tunnel.stat = stat
                    return tunnel
                if last_status < 0:
                    tunnel.close()
                    raise T2uTunnelUnavailableError(
                        f"T2U falhou ao abrir tunel na porta {mapped_port}. Status: {last_status}"
                    )
                time.sleep(0.1)

            tunnel.close()
            if attempt < attempts and time.monotonic() < overall_deadline:
                time.sleep(0.25)

        raise T2uTunnelUnavailableError(
            f"T2U nao abriu tunel em {timeout}s apos {attempts} tentativas. Ultimo status: {last_status}"
        )

    def close_port(self, port):
        with self._lock:
            if self._dll is not None:
                self._dll.t2u_del_port(int(port))


class T2uTunnel:
    def __init__(self, runtime, local_port, remote_ip, remote_port):
        self.runtime = runtime
        self.local_port = int(local_port)
        self.remote_ip = str(remote_ip)
        self.remote_port = int(remote_port)
        self.status = None
        self.stat = None
        self.closed = False

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.runtime.close_port(self.local_port)
        except Exception:
            pass

    def snapshot(self):
        info = {
            "localPort": self.local_port,
            "remoteIp": self.remote_ip,
            "remotePort": self.remote_port,
            "status": self.status,
        }
        if self.stat is not None:
            info.update(
                {
                    "peerIp": self.stat.ip.split(b"\0", 1)[0].decode("utf-8", "replace"),
                    "peerPort": self.stat.port,
                    "proxy": self.stat.proxy,
                    "remoteNatType": self.stat.remote_nattype,
                    "localNatType": self.stat.local_nattype,
                }
            )
        return info


class SharedT2uTunnel:
    def __init__(self, key, tunnel):
        self.key = key
        self.tunnel = tunnel
        self.refs = 0


class T2uTunnelLease:
    def __init__(self, pool, shared, reused, use_count):
        self._pool = pool
        self._shared = shared
        self.reused = reused
        self.use_count = use_count
        self.closed = False

    @property
    def local_port(self):
        return self._shared.tunnel.local_port

    def close(self):
        if self.closed:
            return None
        self.closed = True
        return self._pool.release(self)

    def snapshot(self):
        info = self._shared.tunnel.snapshot()
        info["shared"] = True
        info["useCount"] = self._pool.ref_count(self)
        return info


class T2uTunnelPool:
    def __init__(self, runtime):
        self.runtime = runtime
        self._lock = threading.RLock()
        self._items = {}

    def key_for(self, camera, settings):
        p2p_password = camera.get("p2pPassword") or settings.get("t2uDevicePassword")
        identity = camera.get("groupId") or camera.get("id") or ""
        return (
            str(identity),
            str(camera.get("p2pUuid") or ""),
            str(p2p_password or ""),
            str(camera.get("p2pRemoteIp") or "127.0.0.1"),
            int(camera.get("p2pRemotePort") or 554),
            int(camera.get("p2pLocalPort") or 0),
            str(settings.get("t2uDllPath") or DEFAULT_T2U_DLL),
            str(settings.get("t2uServer") or ""),
            int(settings.get("t2uServerPort") or 0),
            str(settings.get("t2uServerKey") or ""),
        )

    def _active_count_for_group_locked(self, group_id):
        return sum(shared.refs for key, shared in self._items.items() if key[0] == group_id and not shared.tunnel.closed)

    def active_count_for_group(self, group_id):
        with self._lock:
            return self._active_count_for_group_locked(str(group_id or ""))

    def acquire(self, camera, settings, group=None):
        key = self.key_for(camera, settings)
        group_id = str((group or {}).get("id") or camera.get("groupId") or camera.get("id") or "")
        group_name = str((group or {}).get("name") or group_id or "Cloud/P2P")
        group_limit = int((group or {}).get("maxSources") or 0)
        with self._lock:
            if group_limit > 0:
                active = self._active_count_for_group_locked(group_id)
                if active >= group_limit:
                    raise RuntimeError(f"Limite do grupo {group_name} atingido ({active}/{group_limit}).")

            shared = self._items.get(key)
            if shared and not shared.tunnel.closed:
                shared.refs += 1
                return T2uTunnelLease(self, shared, True, shared.refs)

            tunnel = self.runtime.open_tunnel(camera, settings)
            shared = SharedT2uTunnel(key, tunnel)
            shared.refs = 1
            self._items[key] = shared
            return T2uTunnelLease(self, shared, False, shared.refs)

    def release(self, lease):
        with self._lock:
            shared = lease._shared
            current = self._items.get(shared.key)
            if current is not shared:
                return {"localPort": shared.tunnel.local_port, "closed": False, "remainingRefs": 0}

            shared.refs = max(0, shared.refs - 1)
            remaining = shared.refs
            if remaining == 0:
                self._items.pop(shared.key, None)
                shared.tunnel.close()
                return {"localPort": shared.tunnel.local_port, "closed": True, "remainingRefs": 0}

            return {"localPort": shared.tunnel.local_port, "closed": False, "remainingRefs": remaining}

    def ref_count(self, lease):
        with self._lock:
            shared = self._items.get(lease._shared.key)
            return shared.refs if shared is lease._shared else 0


T2U = T2uRuntime()
T2U_TUNNELS = T2uTunnelPool(T2U)


def cloud_rtsp_url(camera, local_port):
    user = quote(str(camera.get("rtspUser") or ""), safe="")
    password = quote(str(camera.get("rtspPassword") or ""), safe="")
    auth = f"{user}{':' + password if password else ''}@" if user else ""
    path = str(camera.get("rtspPath") or "/cam/realmonitor?channel=1&subtype=0").strip()
    if not path.startswith("/"):
        path = "/" + path
    return f"rtsp://{auth}127.0.0.1:{int(local_port)}{path}"


def prepare_camera_input(camera, config):
    effective, settings, group = resolve_camera_runtime(camera, config)
    if effective.get("type") != "cloud-p2p":
        return dict(effective), settings, None

    tunnel = T2U_TUNNELS.acquire(effective, settings, group)
    prepared = dict(effective)
    prepared["type"] = "stream"
    prepared["url"] = cloud_rtsp_url(effective, tunnel.local_port)
    return prepared, settings, tunnel


def log_tunnel_release(source_id, result, prefix="Tunel P2P"):
    if not result:
        return
    port = result.get("localPort")
    if result.get("closed"):
        add_log(source_id, "info", f"{prefix} fechado na porta local {port}")
    else:
        refs = result.get("remainingRefs", 0)
        add_log(source_id, "info", f"{prefix} liberado na porta local {port}; {refs} uso(s) ativo(s)")


def build_input_args(camera, settings):
    if camera.get("type") == "v4l2":
        args = ["-thread_queue_size", "1024"]
        if camera.get("inputFormat"):
            args += ["-input_format", camera["inputFormat"]]
        if camera.get("resolution"):
            args += ["-video_size", camera["resolution"]]
        if camera.get("frameRate"):
            args += ["-framerate", camera["frameRate"]]
        args += ["-f", "v4l2", "-i", camera.get("videoDevice") or "/dev/video0"]
        if camera.get("audioDevice"):
            args += ["-thread_queue_size", "1024", "-f", "alsa", "-i", camera["audioDevice"]]
        return args

    url = camera.get("url", "")
    args = ["-thread_queue_size", "1024"]
    if url.lower().startswith(("rtsp://", "rtsps://")) and settings.get("rtspTransport") != "auto":
        args += ["-rtsp_transport", settings.get("rtspTransport", "tcp")]
    args += ["-i", url]
    return args


def build_map_args(camera, settings):
    map_mode = settings.get("mapMode", "av")
    has_audio_input = camera.get("type") == "v4l2" and bool(camera.get("audioDevice"))
    if map_mode == "all":
        if camera.get("type") == "v4l2" and has_audio_input:
            return ["-map", "0", "-map", "1", "-c", "copy"]
        return ["-map", "0", "-c", "copy"]

    args = ["-map", "0:v?"]
    if camera.get("type") == "v4l2" and has_audio_input:
        args += ["-map", "1:a?"]
    else:
        args += ["-map", "0:a?"]
    return args + ["-c:v", "copy", "-c:a", "copy"]


def output_pattern(camera, settings):
    output_root = resolve_user_path(settings.get("outputDir"))
    day = time.strftime("%Y-%m-%d")
    target_dir = output_root / safe_name(camera.get("name")) / day
    target_dir.mkdir(parents=True, exist_ok=True)
    return str(target_dir / f"{safe_name(camera.get('name'))}_%Y%m%d_%H%M%S.mkv")


def build_ffmpeg_command(camera, settings):
    ffmpeg = settings.get("ffmpegPath") or "ffmpeg"
    args = [ffmpeg, "-hide_banner", "-loglevel", "info", "-fflags", "+genpts"]
    args += build_input_args(camera, settings)
    args += build_map_args(camera, settings)
    args += [
        "-f",
        "segment",
        "-segment_time",
        str(settings.get("segmentSeconds", 900)),
        "-segment_format",
        "matroska",
        "-reset_timestamps",
        "1",
        "-strftime",
        "1",
    ]
    if settings.get("alignSegmentsToClock", True):
        args += ["-segment_atclocktime", "1"]
    args.append(output_pattern(camera, settings))
    return args


def build_preview_command(camera, settings):
    ffmpeg = settings.get("ffmpegPath") or "ffmpeg"
    args = [ffmpeg, "-hide_banner", "-nostdin", "-loglevel", "warning", "-fflags", "+genpts"]
    args += build_input_args(camera, settings)
    args += [
        "-an",
        "-sn",
        "-dn",
        "-vf",
        "scale=960:-2:force_original_aspect_ratio=decrease",
        "-r",
        "8",
        "-q:v",
        "5",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "-",
    ]
    return args


def is_rtsp_service_unavailable(line):
    return bool(re.search(r"\bmethod\s+OPTIONS\s+failed:\s*503\b", str(line or ""), re.IGNORECASE))


def preview_log_reader(camera_id, pipe, state=None):
    if not pipe:
        return
    try:
        for raw in iter(pipe.readline, b""):
            line = raw.decode("utf-8", "replace").strip()
            if line:
                if state is not None and is_rtsp_service_unavailable(line):
                    state["rtspServiceUnavailable"] = True
                level = "error" if "error" in line.lower() or "failed" in line.lower() else "ffmpeg"
                add_log(camera_id, level, line)
    except Exception:
        return
    finally:
        if state is not None:
            state["done"].set()


def terminate_preview_process(proc):
    if not proc or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def send_preview_headers(handler, max_seconds):
    handler.send_response(200)
    handler.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
    handler.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
    handler.send_header("Pragma", "no-cache")
    handler.send_header("X-Preview-Max-Seconds", str(max_seconds))
    send_security_headers(handler)
    handler.end_headers()


def write_mjpeg_frames(handler, proc, on_first_frame=None):
    buffer = bytearray()
    frame_count = 0
    while True:
        chunk = proc.stdout.read(8192) if proc.stdout else b""
        if not chunk:
            break
        buffer.extend(chunk)
        while True:
            start = buffer.find(b"\xff\xd8")
            if start < 0:
                if len(buffer) > 2:
                    del buffer[:-2]
                break
            end = buffer.find(b"\xff\xd9", start + 2)
            if end < 0:
                if start:
                    del buffer[:start]
                break
            frame = bytes(buffer[start : end + 2])
            del buffer[: end + 2]
            if frame_count == 0 and on_first_frame:
                on_first_frame()
            header = (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n"
                + f"Content-Length: {len(frame)}\r\n\r\n".encode("ascii")
            )
            handler.wfile.write(header)
            handler.wfile.write(frame)
            handler.wfile.write(b"\r\n")
            handler.wfile.flush()
            frame_count += 1
    return frame_count


class PreviewLimitError(RuntimeError):
    pass


class PreviewSourceUnavailableError(RuntimeError):
    pass


def acquire_preview_slot(client_ip, camera_id):
    global_limit = environment_int("CAMERA_RECORDER_MAX_PREVIEWS", DEFAULT_MAX_PREVIEWS, 1, 64)
    client_limit = environment_int(
        "CAMERA_RECORDER_MAX_PREVIEWS_PER_CLIENT",
        DEFAULT_MAX_PREVIEWS_PER_CLIENT,
        1,
        global_limit,
    )
    with PREVIEW_LOCK:
        active_for_client = sum(1 for item in ACTIVE_PREVIEWS.values() if item["clientIp"] == client_ip)
        if len(ACTIVE_PREVIEWS) >= global_limit or active_for_client >= client_limit:
            raise PreviewLimitError("Limite de previews simultaneos atingido.")
        token = uuid.uuid4().hex
        ACTIVE_PREVIEWS[token] = {
            "clientIp": client_ip,
            "cameraId": camera_id,
            "startedAt": time.time(),
        }
    max_seconds = environment_int(
        "CAMERA_RECORDER_PREVIEW_MAX_SECONDS",
        DEFAULT_PREVIEW_MAX_SECONDS,
        30,
        24 * 60 * 60,
    )
    return token, max_seconds


def release_preview_slot(token):
    if not token:
        return
    with PREVIEW_LOCK:
        ACTIVE_PREVIEWS.pop(token, None)


def stream_preview(handler, camera_id):
    config = load_config()
    camera = find_camera(config, camera_id)
    if not camera:
        send_error_json(handler, 404, "Camera nao encontrada.")
        return

    slot = None
    tunnel = None
    proc = None
    timer = None
    response_started = False
    try:
        slot, max_seconds = acquire_preview_slot(handler.client_ip(), camera_id)
        validate_camera(camera, config)
        effective_camera, effective_settings, tunnel = prepare_camera_input(camera, config)
        if tunnel:
            action = "reutilizado" if tunnel.reused else "aberto"
            add_log(
                camera_id,
                "info",
                f"Tunel P2P de preview {action} em 127.0.0.1:{tunnel.local_port}; "
                f"{tunnel.use_count} uso(s) ativo(s)",
            )
        command = build_preview_command(effective_camera, effective_settings)
        add_log(camera_id, "info", f"Preview iniciado: {camera.get('name')}")
        add_log(camera_id, "debug", " ".join(redact_url(part) for part in command))
        attempts = environment_int(
            "CAMERA_RECORDER_PREVIEW_RTSP_ATTEMPTS",
            DEFAULT_PREVIEW_RTSP_ATTEMPTS,
            1,
            5,
        )
        retry_seconds = environment_int(
            "CAMERA_RECORDER_PREVIEW_RTSP_RETRY_SECONDS",
            DEFAULT_PREVIEW_RTSP_RETRY_SECONDS,
            1,
            10,
        )
        start_timeout = environment_int(
            "CAMERA_RECORDER_PREVIEW_START_TIMEOUT_SECONDS",
            DEFAULT_PREVIEW_START_TIMEOUT_SECONDS,
            3,
            60,
        )
        preview_deadline = time.monotonic() + max_seconds
        last_rtsp_unavailable = False

        for attempt in range(1, attempts + 1):
            proc = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
            log_state = {"rtspServiceUnavailable": False, "done": threading.Event()}
            log_thread = None
            if proc.stderr:
                log_thread = threading.Thread(
                    target=preview_log_reader,
                    args=(camera_id, proc.stderr, log_state),
                    daemon=True,
                )
                log_thread.start()

            timer = threading.Timer(start_timeout, terminate_preview_process, args=(proc,))
            timer.daemon = True
            timer.start()

            def begin_response():
                nonlocal response_started, timer
                if response_started:
                    return
                timer.cancel()
                send_preview_headers(handler, max_seconds)
                response_started = True
                remaining = max(0.1, preview_deadline - time.monotonic())
                timer = threading.Timer(remaining, terminate_preview_process, args=(proc,))
                timer.daemon = True
                timer.start()

            frame_count = write_mjpeg_frames(handler, proc, begin_response)
            timer.cancel()
            terminate_preview_process(proc)
            if log_thread:
                log_thread.join(timeout=1)
            last_rtsp_unavailable = bool(log_state["rtspServiceUnavailable"])

            if frame_count > 0 or response_started:
                break
            if not last_rtsp_unavailable or attempt >= attempts:
                break
            add_log(
                camera_id,
                "warning",
                f"RTSP respondeu 503; nova tentativa no mesmo tunel em {retry_seconds}s "
                f"({attempt}/{attempts}).",
            )
            time.sleep(retry_seconds)

        if not response_started:
            if last_rtsp_unavailable:
                raise PreviewSourceUnavailableError("RTSP respondeu 503 apos tentativas limitadas.")
            raise PreviewSourceUnavailableError("FFmpeg nao produziu imagens para o preview.")
    except PreviewLimitError as exc:
        send_error_json(handler, 429, str(exc), {"Retry-After": "5"})
    except T2uBackoffError as exc:
        send_error_json(handler, 503, str(exc), {"Retry-After": str(exc.retry_after)})
    except T2uTunnelUnavailableError as exc:
        add_log(camera_id, "warning", f"Tunel P2P temporariamente indisponivel: {exc}")
        send_error_json(handler, 503, "Tunel P2P temporariamente indisponivel.", {"Retry-After": "5"})
    except PreviewSourceUnavailableError as exc:
        add_log(camera_id, "warning", f"Fonte do preview temporariamente indisponivel: {exc}")
        if not response_started:
            send_error_json(handler, 503, "Fonte RTSP temporariamente indisponivel.", {"Retry-After": "5"})
    except ValueError as exc:
        send_error_json(handler, 400, str(exc))
    except FileNotFoundError as exc:
        add_log(camera_id, "error", f"FFmpeg de preview nao encontrado: {exc}")
        if not response_started:
            send_error_json(handler, 500, "FFmpeg nao encontrado no servidor.")
    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
        pass
    except Exception as exc:
        add_log(camera_id, "error", f"Falha ao iniciar preview: {exc}")
        if not response_started:
            send_error_json(handler, 500, "Nao foi possivel iniciar o preview.")
    finally:
        if timer:
            timer.cancel()
        terminate_preview_process(proc)
        if tunnel:
            log_tunnel_release(camera_id, tunnel.close(), "Tunel P2P de preview")
        release_preview_slot(slot)
        if proc:
            add_log(camera_id, "info", f"Preview encerrado: {camera.get('name')}")


class RecordingJob:
    def __init__(self, camera, config):
        self.camera = dict(camera)
        self.config = json.loads(json.dumps(config))
        self.settings = dict(self.config.get("settings", {}))
        group = camera_cloud_group(self.camera, self.config)
        self.cloud_group_id = group.get("id") if group else None
        self.cloud_group_name = group.get("name") if group else None
        self.id = camera["id"]
        self.proc = None
        self.tunnel = None
        self.state = "idle"
        self.started_at = None
        self.ended_at = None
        self.exit_code = None
        self.output = None
        self.command = None
        self.stop_requested = False
        self.restart_count = 0
        self.failure_epoch = 0
        self.last_error = None
        self.next_restart_at = None
        self._restart_thread = None
        self._lock = threading.RLock()

    def is_active(self):
        with self._lock:
            return self.proc is not None and self.proc.poll() is None

    def is_managed(self):
        with self._lock:
            if self.stop_requested:
                return False
            if self.proc is not None and self.proc.poll() is None:
                return True
            return self.state in ("starting", "running", "restarting", "error") and self.settings.get("autoRestart", True)

    def wants_reconnect(self):
        with self._lock:
            return not self.stop_requested and bool(self.settings.get("autoRestart", True))

    def awaiting_reconnect(self):
        with self._lock:
            proc_active = self.proc is not None and self.proc.poll() is None
            return (
                not self.stop_requested
                and bool(self.settings.get("autoRestart", True))
                and not proc_active
                and self.state in ("error", "restarting")
                and self.failure_epoch > 0
            )

    def _record_failure(self, error):
        with self._lock:
            self.failure_epoch += 1
            self.last_error = str(error)
            self.state = "error"
            self.ended_at = now_iso()
            self.next_restart_at = None

    def _set_restarting(self, delay, reason):
        next_time = time.time() + max(1, int(delay))
        with self._lock:
            self.state = "restarting"
            self.next_restart_at = iso_from_epoch(next_time)
        add_log(
            self.id,
            "warning",
            f"Reconexao em {format_duration(delay)} ({reason}): {self.camera.get('name')}",
        )
        return next_time

    def _still_current(self):
        with JOBS_LOCK:
            return JOBS.get(self.id) is self

    def _should_retry(self):
        if not self._still_current():
            return False
        with self._lock:
            return (
                not self.stop_requested
                and bool(self.settings.get("autoRestart", True))
            )

    def _sleep_until(self, deadline):
        while time.time() < deadline:
            if not self._should_retry():
                return False
            time.sleep(min(1, max(0.1, deadline - time.time())))
        return self._should_retry()

    def _group_limit_allows_restart(self):
        if not self.cloud_group_id:
            return True, 0, 0
        config = load_config()
        group = find_source_group(config, self.cloud_group_id)
        limit = int((group or {}).get("maxSources") or 0)
        if limit <= 0:
            return True, limit, 0
        active = 0
        with JOBS_LOCK:
            for job in JOBS.values():
                if job is self:
                    continue
                if getattr(job, "cloud_group_id", None) == self.cloud_group_id and job.is_active():
                    active += 1
        return active < limit, limit, active

    def schedule_restart(self, error):
        self._record_failure(error)
        if not self.settings.get("autoRestart", True):
            return False
        with self._lock:
            if self._restart_thread and self._restart_thread.is_alive():
                return True
            self._restart_thread = threading.Thread(target=self._restart_until_running, daemon=True)
            self._restart_thread.start()
        return True

    def _restart_until_running(self):
        current_thread = threading.current_thread()
        forced_delay = None
        forced_reason = None
        try:
            while self._should_retry():
                if forced_delay is not None:
                    delay = forced_delay
                    reason = forced_reason or "aguardando T2U"
                    forced_delay = None
                    forced_reason = None
                else:
                    delay, reason = RECONNECT.delay_for(self)

                deadline = self._set_restarting(delay, reason)
                if not self._sleep_until(deadline):
                    return

                allowed, limit, active = self._group_limit_allows_restart()
                if not allowed:
                    add_log(
                        self.id,
                        "warning",
                        f"Limite do grupo {self.cloud_group_name or self.cloud_group_id} atingido "
                        f"({active}/{limit}). Reconexao adiada.",
                    )
                    forced_delay = RECONNECT_BASE_SECONDS
                    forced_reason = "limite do grupo cloud"
                    continue

                with self._lock:
                    self.restart_count += 1
                    if self._restart_thread is current_thread:
                        self._restart_thread = None
                try:
                    self.start()
                    return
                except T2uBackoffError as exc:
                    with self._lock:
                        if self._restart_thread is None:
                            self._restart_thread = current_thread
                        self.last_error = str(exc)
                        self.state = "restarting"
                    forced_delay = exc.retry_after
                    forced_reason = "servidor T2U"
                    add_log(self.id, "warning", str(exc))
                except Exception as exc:
                    with self._lock:
                        if self._restart_thread is None:
                            self._restart_thread = current_thread
                    self._record_failure(exc)
                    add_log(self.id, "error", f"Falha na reconexao: {exc}")
        finally:
            with self._lock:
                if self._restart_thread is current_thread:
                    self._restart_thread = None

    def _mark_stable_after_delay(self, proc):
        time.sleep(RECONNECT_STABLE_SECONDS)
        with self._lock:
            if self.proc is not proc or proc.poll() is not None or self.stop_requested:
                return
            self.failure_epoch = 0
            self.last_error = None
            self.next_restart_at = None
        RECONNECT.mark_success(self)
        add_log(self.id, "info", f"Conexao estavel: {self.camera.get('name')}")

    def _close_tunnel(self):
        tunnel = self.tunnel
        self.tunnel = None
        if tunnel:
            log_tunnel_release(self.id, tunnel.close(), "Tunel P2P da gravacao")

    def start(self):
        with self._lock:
            if self.is_active():
                return
            self._close_tunnel()
            self.stop_requested = False
            self.state = "starting"
            self.started_at = now_iso()
            self.ended_at = None
            self.exit_code = None
            self.output = output_pattern(self.camera, self.settings)
            add_log(self.id, "info", f"Iniciando gravacao: {self.camera.get('name')}")
            try:
                effective_camera, self.settings, self.tunnel = prepare_camera_input(self.camera, self.config)
                if self.tunnel:
                    action = "reutilizado" if self.tunnel.reused else "aberto"
                    add_log(
                        self.id,
                        "info",
                        f"Tunel P2P {action} em 127.0.0.1:{self.tunnel.local_port}; "
                        f"{self.tunnel.use_count} uso(s) ativo(s)",
                    )
                self.command = build_ffmpeg_command(effective_camera, self.settings)
            except Exception:
                self._close_tunnel()
                self.state = "error"
                raise
            add_log(self.id, "debug", " ".join(redact_url(part) for part in self.command))
            try:
                self.proc = subprocess.Popen(
                    self.command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
            except FileNotFoundError as exc:
                self.state = "error"
                self.exit_code = -1
                self._close_tunnel()
                add_log(self.id, "error", f"FFmpeg nao encontrado: {exc}")
                raise
            except Exception as exc:
                self.state = "error"
                self.exit_code = -1
                self._close_tunnel()
                add_log(self.id, "error", f"Falha ao iniciar FFmpeg: {exc}")
                raise
            self.state = "running"
            self.last_error = None
            self.next_restart_at = None
            threading.Thread(target=self._read_output, daemon=True).start()
            threading.Thread(target=self._watch, daemon=True).start()
            threading.Thread(target=self._mark_stable_after_delay, args=(self.proc,), daemon=True).start()

    def _read_output(self):
        proc = self.proc
        if not proc or not proc.stdout:
            return
        for line in proc.stdout:
            level = "error" if "error" in line.lower() or "failed" in line.lower() else "ffmpeg"
            add_log(self.id, level, line)

    def _watch(self):
        proc = self.proc
        if not proc:
            return
        code = proc.wait()
        with self._lock:
            self.exit_code = code
            self.ended_at = now_iso()
            self._close_tunnel()
            if self.stop_requested:
                self.state = "stopped"
                add_log(self.id, "info", f"Gravacao encerrada: {self.camera.get('name')}")
                return
            self.state = "stopped" if code == 0 else "error"
            message = f"FFmpeg saiu com codigo {code}: {self.camera.get('name')}"
            add_log(self.id, "warning" if code else "info", message)

        if self.settings.get("autoRestart", True):
            self.schedule_restart(RuntimeError(message))

    def stop(self, timeout=12):
        with self._lock:
            self.stop_requested = True
            self.next_restart_at = None
            proc = self.proc
            if not proc or proc.poll() is not None:
                self.state = "stopped"
                return
            self.state = "stopping"
            add_log(self.id, "info", f"Encerrando gravacao: {self.camera.get('name')}")
            try:
                if proc.stdin:
                    proc.stdin.write("q\n")
                    proc.stdin.flush()
            except Exception:
                pass

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        with self._lock:
            if not self.is_active():
                self._close_tunnel()

    def snapshot(self):
        with self._lock:
            pid = self.proc.pid if self.proc and self.proc.poll() is None else None
            return {
                "id": self.id,
                "name": self.camera.get("name"),
                "state": self.state,
                "pid": pid,
                "startedAt": self.started_at,
                "endedAt": self.ended_at,
                "exitCode": self.exit_code,
                "lastError": self.last_error,
                "nextRestartAt": self.next_restart_at,
                "cloudGroupId": self.cloud_group_id,
                "cloudGroupName": self.cloud_group_name,
                "outputPattern": self.output,
                "command": [redact_url(part) for part in (self.command or [])],
                "restartCount": self.restart_count,
                "tunnel": self.tunnel.snapshot() if self.tunnel else None,
            }


def start_recording(camera_ids, all_enabled=False):
    config = load_config()
    cameras = config["cameras"]
    if all_enabled:
        selected = [camera for camera in cameras if camera.get("enabled", True)]
    else:
        ids = set(camera_ids or [])
        selected = [camera for camera in cameras if camera.get("id") in ids and camera.get("enabled", True)]
    if not selected:
        return {"started": [], "skipped": [], "errors": [{"message": "Nenhuma fonte habilitada selecionada."}]}

    started, skipped, errors = [], [], []
    with JOBS_LOCK:
        planned_group_counts = active_recording_group_counts(config)
    for camera in selected:
        job = None
        group = camera_cloud_group(camera, config)
        group_limit = int(group.get("maxSources") or 0) if group else 0
        group_id = group.get("id") if group else None
        try:
            with JOBS_LOCK:
                existing = JOBS.get(camera["id"])
                if existing and existing.is_managed():
                    skipped.append({"id": camera["id"], "name": camera.get("name"), "reason": "already_running"})
                    continue
                if group_limit > 0 and planned_group_counts.get(group_id, 0) >= group_limit:
                    skipped.append(
                        {
                            "id": camera["id"],
                            "name": camera.get("name"),
                            "reason": "group_limit",
                            "groupId": group_id,
                            "groupName": group.get("name"),
                            "limit": group_limit,
                        }
                    )
                    add_log(
                        camera["id"],
                        "warning",
                        f"Limite do grupo {group.get('name')} atingido: {group_limit} fonte(s).",
                    )
                    continue
                job = RecordingJob(camera, config)
                JOBS[camera["id"]] = job
                if group_limit > 0:
                    planned_group_counts[group_id] = planned_group_counts.get(group_id, 0) + 1
            job.start()
            started.append({"id": camera["id"], "name": camera.get("name")})
        except Exception as exc:
            retry_scheduled = False
            with JOBS_LOCK:
                if job is not None and JOBS.get(camera["id"]) is job and job.settings.get("autoRestart", True):
                    retry_scheduled = True
                elif job is not None and JOBS.get(camera["id"]) is job:
                    JOBS.pop(camera["id"], None)
                if group_limit > 0 and group_id:
                    planned_group_counts[group_id] = max(0, planned_group_counts.get(group_id, 0) - 1)
            if retry_scheduled and job.schedule_restart(exc):
                errors.append(
                    {
                        "id": camera.get("id"),
                        "name": camera.get("name"),
                        "message": f"{redact_config_paths(str(exc), config)}; reconexao automatica agendada.",
                    }
                )
            else:
                errors.append(
                    {
                        "id": camera.get("id"),
                        "name": camera.get("name"),
                        "message": redact_config_paths(str(exc), config),
                    }
                )
    return {"started": started, "skipped": skipped, "errors": errors}


def stop_recording(camera_ids=None, all_active=False):
    with JOBS_LOCK:
        if all_active:
            ids = list(JOBS.keys())
        else:
            ids = list(camera_ids or [])
        jobs = [(camera_id, JOBS.pop(camera_id, None)) for camera_id in ids]

    stopped, skipped = [], []
    for camera_id, job in jobs:
        if not job:
            skipped.append({"id": camera_id, "reason": "not_running"})
            continue
        job.stop()
        stopped.append({"id": camera_id, "name": job.camera.get("name")})
    return {"stopped": stopped, "skipped": skipped}


def ff_tool_status(path_value):
    resolved = shutil.which(path_value)
    if resolved:
        return {"configured": path_value, "found": True, "path": resolved}
    explicit = Path(str(path_value))
    try:
        found = explicit.exists()
    except OSError as exc:
        return {"configured": path_value, "found": False, "path": str(explicit), "error": str(exc)}
    return {"configured": path_value, "found": found, "path": str(explicit) if found else None}


def redact_config_paths(text, config):
    redacted = str(text or "")
    settings = (config or {}).get("settings", {})
    secret_values = [settings.get("webPassword")]
    secret_values.extend(settings.get(key) for key in SETTINGS_SECRET_KEYS)
    for cloud in (config or {}).get("t2uClouds", []):
        secret_values.extend(cloud.get(key) for key in T2U_CLOUD_SECRET_KEYS)
    for group in (config or {}).get("sourceGroups", []):
        secret_values.extend(group.get(key) for key in SOURCE_GROUP_SECRET_KEYS)
    for camera in (config or {}).get("cameras", []):
        secret_values.extend(camera.get(key) for key in CAMERA_SECRET_KEYS)
        url = str(camera.get("url") or "")
        for variant in (url, redact_url(url), strip_url_credentials(url)):
            if len(variant) >= 4:
                redacted = re.sub(re.escape(variant), "<stream>", redacted, flags=re.IGNORECASE)
    for secret in secret_values:
        value = str(secret or "")
        if value:
            redacted = redacted.replace(value, "***")
    redacted = redact_url(redacted)
    candidates = [APP_DIR, DATA_DIR, CONFIG_PATH]
    for key in SERVER_MANAGED_SETTING_KEYS:
        value = settings.get(key)
        if not value:
            continue
        try:
            candidates.append(resolve_user_path(value) if key == "outputDir" else resolve_app_path(value))
        except OSError:
            continue
    for cloud in (config or {}).get("t2uClouds", []):
        try:
            candidates.append(resolve_app_path(cloud.get("t2uDllPath")))
        except OSError:
            continue
    for candidate in candidates:
        value = str(candidate or "")
        if len(value) < 4:
            continue
        for variant in {value, value.replace("\\", "/")}:
            redacted = re.sub(
                re.escape(variant),
                "<caminho>",
                redacted,
                flags=re.IGNORECASE if os.name == "nt" else 0,
            )
    return redacted


def sanitize_public_value(value, config):
    if isinstance(value, dict):
        return {key: sanitize_public_value(item, config) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_public_value(item, config) for item in value]
    if isinstance(value, str):
        return redact_config_paths(value, config)
    return value


def public_log_rows(rows, config):
    return [
        {
            **row,
            "message": redact_config_paths(row.get("message"), config),
        }
        for row in rows
    ]


def public_job_snapshot(snapshot, config):
    return {
        "id": snapshot.get("id"),
        "name": snapshot.get("name"),
        "state": snapshot.get("state"),
        "startedAt": snapshot.get("startedAt"),
        "endedAt": snapshot.get("endedAt"),
        "exitCode": snapshot.get("exitCode"),
        "lastError": redact_config_paths(snapshot.get("lastError"), config) if snapshot.get("lastError") else None,
        "nextRestartAt": snapshot.get("nextRestartAt"),
        "cloudGroupId": snapshot.get("cloudGroupId"),
        "cloudGroupName": snapshot.get("cloudGroupName"),
        "restartCount": snapshot.get("restartCount", 0),
    }


def public_t2u_status(status):
    return {
        key: status.get(key)
        for key in ("found", "format", "machine", "pythonBits", "loadable", "message", "backoff")
    }


def public_disk_status(status):
    return {
        "total": status.get("total"),
        "used": status.get("used"),
        "free": status.get("free"),
        "available": not bool(status.get("error")),
    }


def disk_status(settings):
    output = resolve_user_path(settings.get("outputDir"))
    candidate = output if output.exists() else output.parent
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(candidate)
        return {
            "path": str(output),
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
        }
    except Exception as exc:
        return {"path": str(output), "error": str(exc)}


def path_is_within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def recording_timestamp(path, stat):
    match = RECORDING_NAME_PATTERN.search(path.name)
    if match:
        compact_date, compact_time = match.groups()
        try:
            time.strptime(compact_date + compact_time, "%Y%m%d%H%M%S")
            return (
                f"{compact_date[:4]}-{compact_date[4:6]}-{compact_date[6:]}",
                f"{compact_time[:2]}:{compact_time[2:4]}:{compact_time[4:]}",
            )
        except ValueError:
            pass
    try:
        time.strptime(path.parent.name, "%Y-%m-%d")
        day = path.parent.name
    except ValueError:
        day = time.strftime("%Y-%m-%d", time.localtime(stat.st_mtime))
    return day, time.strftime("%H:%M:%S", time.localtime(stat.st_mtime))


def recording_camera_names(config):
    names = {}
    for camera in (config or {}).get("cameras", []):
        folder = safe_name(camera.get("name"))
        names.setdefault(folder, {"id": camera.get("id"), "name": camera.get("name") or folder})
    return names


def iter_recordings(config=None):
    config = config or load_config()
    output = resolve_user_path(config["settings"].get("outputDir"))
    if not output.exists():
        return
    output = output.resolve()
    camera_names = recording_camera_names(config)
    for path in output.rglob("*"):
        try:
            relative = path.relative_to(output)
            if (
                not path.is_file()
                or path.suffix.lower() not in RECORDING_EXTENSIONS
                or any(not part or part.startswith(".") for part in relative.parts)
            ):
                continue
            resolved = path.resolve()
            if not path_is_within(resolved, output):
                continue
            stat = path.stat()
            day, recorded_time = recording_timestamp(path, stat)
            camera_key = relative.parts[0] if len(relative.parts) > 1 else "recordings"
            camera = camera_names.get(camera_key, {})
            yield {
                "name": path.name,
                "relativePath": relative.as_posix(),
                "size": stat.st_size,
                "modified": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(stat.st_mtime)),
                "date": day,
                "time": recorded_time,
                "cameraKey": camera_key,
                "cameraId": camera.get("id"),
                "cameraName": camera.get("name") or camera_key,
            }
        except OSError:
            continue


def list_recordings(limit=500):
    files = list(iter_recordings())
    files.sort(key=lambda item: item["modified"], reverse=True)
    return files[:limit]


def validate_recording_date(value):
    value = str(value or "").strip()
    if not value:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Data de gravacao invalida.")
    try:
        time.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("Data de gravacao invalida.") from exc
    return value


def validate_recording_camera_key(value):
    value = str(value or "").strip()
    if not value:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", value):
        raise ValueError("Camera de gravacao invalida.")
    return value


def recording_catalog(selected_date=None, selected_camera=None, file_limit=2000):
    selected_date = validate_recording_date(selected_date)
    selected_camera = validate_recording_camera_key(selected_camera)
    date_stats = {}
    camera_stats = {}
    selected_day_files = []
    latest_date = None

    for item in iter_recordings():
        day = item["date"]
        camera_key = item["cameraKey"]
        day_stat = date_stats.setdefault(day, {"fileCount": 0, "totalSize": 0, "cameras": set()})
        day_stat["fileCount"] += 1
        day_stat["totalSize"] += item["size"]
        day_stat["cameras"].add(camera_key)

        camera_stat = camera_stats.setdefault(
            (day, camera_key),
            {
                "key": camera_key,
                "id": item.get("cameraId"),
                "name": item.get("cameraName") or camera_key,
                "fileCount": 0,
                "totalSize": 0,
            },
        )
        camera_stat["fileCount"] += 1
        camera_stat["totalSize"] += item["size"]

        if selected_date:
            if day == selected_date:
                selected_day_files.append(item)
        elif latest_date is None or day > latest_date:
            latest_date = day
            selected_day_files = [item]
        elif day == latest_date:
            selected_day_files.append(item)

    if selected_date is None:
        selected_date = latest_date

    dates = [
        {
            "date": day,
            "fileCount": stats["fileCount"],
            "cameraCount": len(stats["cameras"]),
            "totalSize": stats["totalSize"],
        }
        for day, stats in date_stats.items()
    ]
    dates.sort(key=lambda item: item["date"], reverse=True)

    cameras = [dict(stats) for (day, _key), stats in camera_stats.items() if day == selected_date]
    cameras.sort(key=lambda item: (str(item["name"]).casefold(), item["key"]))
    if selected_camera is None and cameras:
        selected_camera = cameras[0]["key"]

    files = [item for item in selected_day_files if item["cameraKey"] == selected_camera]
    files.sort(key=lambda item: (item["date"], item["time"], item["modified"]), reverse=True)
    limit = max(1, min(5000, int(file_limit or 2000)))
    return {
        "dates": dates,
        "cameras": cameras,
        "recordings": files[:limit],
        "selectedDate": selected_date,
        "selectedCamera": selected_camera,
        "truncated": len(files) > limit,
    }


def resolve_recording_file(relative_value):
    raw = str(relative_value or "").strip()
    if not raw or len(raw) > 1024 or "\0" in raw:
        raise FileNotFoundError("Gravacao nao encontrada.")
    parts = raw.replace("\\", "/").split("/")
    if any(not part or part in (".", "..") or part.startswith(".") for part in parts):
        raise FileNotFoundError("Gravacao nao encontrada.")

    output = resolve_user_path(load_config()["settings"].get("outputDir")).resolve(strict=True)
    candidate = output.joinpath(*parts).resolve(strict=True)
    if (
        not path_is_within(candidate, output)
        or not candidate.is_file()
        or candidate.suffix.lower() not in RECORDING_EXTENSIONS
    ):
        raise FileNotFoundError("Gravacao nao encontrada.")
    return candidate


def parse_byte_range(value, size):
    value = str(value or "").strip()
    if not value:
        return 0, max(-1, size - 1), False
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
    if not match or size <= 0:
        raise ValueError("Faixa de bytes invalida.")
    start_text, end_text = match.groups()
    if not start_text and not end_text:
        raise ValueError("Faixa de bytes invalida.")
    if not start_text:
        suffix = int(end_text)
        if suffix <= 0:
            raise ValueError("Faixa de bytes invalida.")
        start = max(0, size - suffix)
        end = size - 1
    else:
        start = int(start_text)
        end = int(end_text) if end_text else size - 1
        if start >= size or end < start:
            raise ValueError("Faixa de bytes invalida.")
        end = min(end, size - 1)
    return start, end, True


def send_recording_file(handler, relative_value):
    try:
        path = resolve_recording_file(relative_value)
    except (FileNotFoundError, OSError):
        send_error_json(handler, 404, "Gravacao nao encontrada.")
        return

    try:
        size = path.stat().st_size
    except OSError:
        send_error_json(handler, 404, "Gravacao nao encontrada.")
        return

    if not DOWNLOAD_SLOTS.acquire(blocking=False):
        send_error_json(handler, 503, "Limite de downloads simultaneos atingido.", {"Retry-After": "5"})
        return
    try:
        try:
            start, end, partial = parse_byte_range(handler.headers.get("Range"), size)
        except ValueError:
            send_error_json(
                handler,
                416,
                "Faixa de bytes invalida.",
                {"Content-Range": f"bytes */{size}", "Accept-Ranges": "bytes"},
            )
            return

        length = max(0, end - start + 1)
        fallback = safe_name(path.stem) + path.suffix.lower()
        disposition = f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(path.name, safe='')}"
        handler.send_response(206 if partial else 200)
        handler.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        handler.send_header("Content-Length", str(length))
        handler.send_header("Content-Disposition", disposition)
        handler.send_header("Accept-Ranges", "bytes")
        handler.send_header("Cache-Control", "private, no-cache")
        if partial:
            handler.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        send_security_headers(handler)
        handler.end_headers()

        with path.open("rb") as handle:
            handle.seek(start)
            remaining = length
            while remaining > 0:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                handler.wfile.write(chunk)
                remaining -= len(chunk)
    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
        pass
    finally:
        DOWNLOAD_SLOTS.release()


def recent_logs(source_id=None, limit=160):
    limit = max(10, min(1000, int(limit or 160)))
    with LOG_LOCK:
        rows = [row for row in LOGS if not source_id or row.get("sourceId") == source_id]
        return rows[-limit:]


def state_payload():
    config = load_config()
    t2u_status_settings = settings_for_t2u_cloud(config["settings"], find_t2u_cloud(config, None))
    with JOBS_LOCK:
        jobs = {
            camera_id: public_job_snapshot(job.snapshot(), config)
            for camera_id, job in JOBS.items()
        }
    ffmpeg_status = ff_tool_status(config["settings"].get("ffmpegPath", "ffmpeg"))
    ffprobe_status = ff_tool_status(config["settings"].get("ffprobePath", "ffprobe"))
    return {
        "version": VERSION,
        "config": public_config(config),
        "jobs": jobs,
        "logs": public_log_rows(recent_logs(limit=120), config),
        "system": {
            "ffmpeg": {"found": ffmpeg_status.get("found", False)},
            "ffprobe": {"found": ffprobe_status.get("found", False)},
            "t2u": public_t2u_status(T2U.status_info(t2u_status_settings)),
            "disk": public_disk_status(disk_status(config["settings"])),
            "time": now_iso(),
        },
    }


def probe_source(payload):
    config = load_config()
    settings = config["settings"]
    camera = None
    if payload.get("id"):
        camera = find_camera(config, str(payload.get("id")))
    if not camera:
        camera = normalize_cameras([payload.get("camera") or payload])[0]

    ffprobe = settings.get("ffprobePath") or "ffprobe"
    tunnel = None
    args = [ffprobe, "-v", "error", "-show_streams", "-show_format", "-print_format", "json"]
    try:
        validate_camera(camera, config)
        camera, settings, tunnel = prepare_camera_input(camera, config)
        args[0] = settings.get("ffprobePath") or "ffprobe"
        if camera.get("type") == "stream":
            url = camera.get("url", "")
            if url.lower().startswith(("rtsp://", "rtsps://")) and settings.get("rtspTransport") != "auto":
                args[1:1] = ["-rtsp_transport", settings.get("rtspTransport", "tcp")]
            args.append(url)
        else:
            if camera.get("inputFormat"):
                args += ["-input_format", camera["inputFormat"]]
            if camera.get("resolution"):
                args += ["-video_size", camera["resolution"]]
            if camera.get("frameRate"):
                args += ["-framerate", camera["frameRate"]]
            args += ["-f", "v4l2", camera.get("videoDevice") or "/dev/video0"]
    except T2uBackoffError as exc:
        if tunnel:
            log_tunnel_release(camera.get("id"), tunnel.close(), "Tunel P2P do teste")
        return {"ok": False, "message": str(exc)}
    except ValueError as exc:
        if tunnel:
            log_tunnel_release(camera.get("id"), tunnel.close(), "Tunel P2P do teste")
        return {"ok": False, "message": str(exc)}
    except Exception as exc:
        if tunnel:
            log_tunnel_release(camera.get("id"), tunnel.close(), "Tunel P2P do teste")
        add_log(camera.get("id"), "error", f"Falha ao preparar teste: {exc}")
        return {"ok": False, "message": "Nao foi possivel preparar o teste da fonte."}

    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        add_log(camera.get("id"), "error", f"ffprobe nao encontrado: {exc}")
        return {"ok": False, "message": "ffprobe nao encontrado no servidor."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "ffprobe excedeu 15s."}
    finally:
        if tunnel:
            log_tunnel_release(camera.get("id"), tunnel.close(), "Tunel P2P do teste")

    if completed.returncode != 0:
        return {
            "ok": False,
            "message": redact_config_paths(
                completed.stderr.strip() or f"ffprobe saiu com codigo {completed.returncode}",
                config,
            ),
        }
    try:
        data = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        data = {"raw": completed.stdout}
    return {"ok": True, "data": sanitize_public_value(data, config)}


def local_devices():
    video = sorted(str(path) for path in Path("/dev").glob("video*")) if Path("/dev").exists() else []
    snd = sorted(str(path) for path in Path("/dev/snd").glob("*")) if Path("/dev/snd").exists() else []
    return {"video": video, "sound": snd}


def read_json(handler):
    content_type = str(handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if content_type and content_type != "application/json":
        raise ValueError("Content-Type deve ser application/json.")
    try:
        length = int(handler.headers.get("Content-Length") or 0)
    except ValueError as exc:
        raise ValueError("Content-Length invalido.") from exc
    if length < 0 or length > 1024 * 1024:
        raise ValueError("Payload muito grande.")
    if not length:
        return {}
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def send_security_headers(handler):
    for name, value in SECURITY_HEADERS.items():
        handler.send_header(name, value)
    if getattr(handler.server, "is_tls", False):
        handler.send_header("Strict-Transport-Security", "max-age=31536000")


def send_json(handler, status, payload, headers=None):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    for name, value in (headers or {}).items():
        handler.send_header(name, value)
    send_security_headers(handler)
    handler.end_headers()
    handler.wfile.write(body)


def send_error_json(handler, status, message, headers=None):
    send_json(handler, status, {"error": message}, headers)


def expected_web_credentials():
    settings = load_config()["settings"]
    return settings.get("webUser") or "admin", settings.get("webPassword") or ""


def parse_basic_auth(value):
    if not value:
        return None, None
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "basic" or not token.strip():
        return None, None
    try:
        decoded = base64.b64decode(token.strip(), validate=True).decode("utf-8")
    except Exception:
        return None, None
    user, sep, password = decoded.partition(":")
    if not sep:
        return None, None
    return user, password


def authentication_retry_after(client_ip):
    now = time.time()
    with AUTH_LOCK:
        state = AUTH_FAILURES.get(client_ip)
        if not state:
            return 0
        blocked_until = float(state.get("blockedUntil") or 0)
        if blocked_until > now:
            return max(1, int(blocked_until - now))
        failures = [stamp for stamp in state.get("failures", []) if now - stamp <= AUTH_FAILURE_WINDOW_SECONDS]
        if failures:
            state["failures"] = failures
            state["blockedUntil"] = 0
        else:
            AUTH_FAILURES.pop(client_ip, None)
        return 0


def record_authentication_failure(client_ip):
    now = time.time()
    with AUTH_LOCK:
        state = AUTH_FAILURES.setdefault(client_ip, {"failures": [], "blockedUntil": 0})
        state["failures"] = [
            stamp for stamp in state.get("failures", []) if now - stamp <= AUTH_FAILURE_WINDOW_SECONDS
        ]
        state["failures"].append(now)
        if len(state["failures"]) >= AUTH_MAX_FAILURES:
            state["blockedUntil"] = now + AUTH_BLOCK_SECONDS
            return AUTH_BLOCK_SECONDS
    return 0


def clear_authentication_failures(client_ip):
    with AUTH_LOCK:
        AUTH_FAILURES.pop(client_ip, None)


def origin_matches_host(origin_value, host_value):
    try:
        origin = urlparse(str(origin_value or ""))
        if origin.scheme not in ("http", "https") or not origin.hostname or origin.username or origin.password:
            return False
        host = urlparse(f"//{host_value}")
        if not host.hostname or host.username or host.password:
            return False
        default_port = 443 if origin.scheme == "https" else 80
        return (
            origin.hostname.lower(),
            origin.port or default_port,
        ) == (
            host.hostname.lower(),
            host.port or default_port,
        )
    except ValueError:
        return False


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "Recorder"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, fmt, *args):
        add_log(None, "http", "%s - %s" % (self.address_string(), fmt % args))

    def client_ip(self):
        peer = str(self.client_address[0] or "")
        if is_loopback_host(peer):
            forwarded = str(self.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
            try:
                if forwarded:
                    return str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
        return peer

    def is_authenticated(self):
        expected_user, stored_password = expected_web_credentials()
        user, password = parse_basic_auth(self.headers.get("Authorization"))
        user_matches = hmac.compare_digest(user or "", expected_user)
        password_matches = verify_web_password(password or "", stored_password)
        return user_matches and password_matches

    def request_authentication(self, retry_after=0):
        blocked = retry_after > 0
        body = ("Muitas tentativas. Tente novamente mais tarde.\n" if blocked else "Autenticacao requerida.\n").encode("utf-8")
        self.send_response(429 if blocked else 401)
        if not blocked:
            self.send_header("WWW-Authenticate", f'Basic realm="{APP_NAME}", charset="UTF-8"')
        else:
            self.send_header("Retry-After", str(retry_after))
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        send_security_headers(self)
        self.end_headers()
        self.wfile.write(body)

    def require_authentication(self):
        client_ip = self.client_ip()
        retry_after = authentication_retry_after(client_ip)
        if retry_after:
            self.request_authentication(retry_after)
            return False
        if self.is_authenticated():
            clear_authentication_failures(client_ip)
            return True
        self.request_authentication(record_authentication_failure(client_ip))
        return False

    def require_same_origin(self, mutation=False):
        fetch_site = str(self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        origin = self.headers.get("Origin")
        rejected = fetch_site in ("cross-site", "same-site")
        if mutation and fetch_site and fetch_site not in ("same-origin", "none"):
            rejected = True
        if origin and not origin_matches_host(origin, self.headers.get("Host")):
            rejected = True
        if rejected:
            send_error_json(self, 403, "Origem da requisicao nao permitida.")
            return False
        return True

    def require_mutation_marker(self):
        if hmac.compare_digest(str(self.headers.get("X-Recorder-Request") or ""), "1"):
            return True
        send_error_json(self, 403, "Cabecalho de seguranca ausente.")
        return False

    def do_GET(self):
        if not self.require_authentication():
            return
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            if not self.require_same_origin():
                return
            self.handle_api_get(parsed)
            return
        self.serve_static(parsed.path)

    def do_POST(self):
        if not self.require_authentication():
            return
        if not self.require_mutation_marker():
            return
        if not self.require_same_origin(mutation=True):
            return
        self.handle_json_mutation("POST")

    def do_PUT(self):
        if not self.require_authentication():
            return
        if not self.require_mutation_marker():
            return
        if not self.require_same_origin(mutation=True):
            return
        self.handle_json_mutation("PUT")

    def do_DELETE(self):
        if not self.require_authentication():
            return
        if not self.require_mutation_marker():
            return
        if not self.require_same_origin(mutation=True):
            return
        self.handle_json_mutation("DELETE")

    def handle_api_get(self, parsed):
        try:
            query = parse_qs(parsed.query)
            preview_match = re.fullmatch(r"/api/preview/([A-Za-z0-9_-]+)\.mjpg", parsed.path)
            if parsed.path == "/api/state":
                send_json(self, 200, state_payload())
            elif parsed.path == "/api/recordings/download":
                send_recording_file(self, (query.get("path") or [""])[0])
            elif parsed.path == "/api/recordings":
                try:
                    payload = recording_catalog(
                        (query.get("date") or [None])[0],
                        (query.get("camera") or [None])[0],
                    )
                except ValueError as exc:
                    send_error_json(self, 400, str(exc))
                    return
                send_json(self, 200, payload)
            elif parsed.path == "/api/logs":
                config = load_config()
                rows = recent_logs((query.get("sourceId") or [None])[0], (query.get("limit") or [160])[0])
                send_json(self, 200, {"logs": public_log_rows(rows, config)})
            elif parsed.path == "/api/local-devices":
                send_json(self, 200, local_devices())
            elif preview_match:
                stream_preview(self, preview_match.group(1))
            else:
                send_error_json(self, 404, "Rota nao encontrada.")
        except Exception as exc:
            add_log(None, "error", f"Falha na API GET: {exc}")
            send_error_json(self, 500, "Erro interno do servidor.")

    def handle_json_mutation(self, method):
        parsed = urlparse(self.path)
        try:
            payload = read_json(self) if method in ("POST", "PUT") else {}
            if parsed.path == "/api/config" and method == "POST":
                current = load_config()
                incoming = prepare_config_update(current, payload)
                candidate = normalize_config(incoming)
                validate_web_access_config(
                    candidate,
                    self.server.server_address[0],
                    getattr(self.server, "is_tls", False),
                    getattr(self.server, "allow_insecure_http", False),
                )
                config = save_config(candidate)
                send_json(self, 200, {"config": public_config(config)})
                return

            if parsed.path == "/api/cameras" and method == "POST":
                config = load_config()
                camera = normalize_cameras([payload])[0]
                camera["id"] = uuid.uuid4().hex[:12]
                camera["createdAt"] = now_iso()
                camera["updatedAt"] = now_iso()
                validate_camera(camera, config)
                config["cameras"].append(camera)
                saved = save_config(config)
                visible = public_config(saved)
                send_json(self, 201, {"camera": find_camera(visible, camera["id"]), "config": visible})
                return

            camera_match = re.fullmatch(r"/api/cameras/([A-Za-z0-9_-]+)", parsed.path)
            if camera_match and method == "PUT":
                camera_id = camera_match.group(1)
                config = load_config()
                camera = find_camera(config, camera_id)
                if not camera:
                    send_error_json(self, 404, "Camera nao encontrada.")
                    return
                incoming_camera = dict(payload or {})
                preserve_secret_fields(camera, incoming_camera, CAMERA_SECRET_KEYS)
                old_url = str(camera.get("url") or "")
                new_url = str(incoming_camera.get("url") or "")
                if old_url and (
                    not new_url
                    or (url_has_credentials(old_url) and new_url in (strip_url_credentials(old_url), redact_url(old_url)))
                ):
                    incoming_camera["url"] = old_url
                incoming_camera.pop("urlCredentialsConfigured", None)
                incoming_camera.pop("urlConfigured", None)
                updated = normalize_cameras([{**camera, **incoming_camera, "id": camera_id, "updatedAt": now_iso()}])[0]
                validate_camera(updated, config)
                config["cameras"] = [updated if item["id"] == camera_id else item for item in config["cameras"]]
                saved = save_config(config)
                visible = public_config(saved)
                send_json(self, 200, {"camera": find_camera(visible, camera_id), "config": visible})
                return

            if camera_match and method == "DELETE":
                camera_id = camera_match.group(1)
                stop_recording([camera_id])
                config = load_config()
                before = len(config["cameras"])
                config["cameras"] = [item for item in config["cameras"] if item["id"] != camera_id]
                if len(config["cameras"]) == before:
                    send_error_json(self, 404, "Camera nao encontrada.")
                    return
                send_json(self, 200, {"config": public_config(save_config(config))})
                return

            if parsed.path == "/api/record/start" and method == "POST":
                send_json(self, 200, start_recording(payload.get("ids"), bool(payload.get("all"))))
                return

            if parsed.path == "/api/record/stop" and method == "POST":
                send_json(self, 200, stop_recording(payload.get("ids"), bool(payload.get("all"))))
                return

            if parsed.path == "/api/probe" and method == "POST":
                send_json(self, 200, probe_source(payload))
                return

            send_error_json(self, 404, "Rota nao encontrada.")
        except ValueError as exc:
            send_error_json(self, 400, str(exc))
        except json.JSONDecodeError as exc:
            send_error_json(self, 400, f"JSON invalido: {exc}")
        except Exception as exc:
            add_log(None, "error", f"Falha na API mutavel: {exc}")
            send_error_json(self, 500, "Erro interno do servidor.")

    def serve_static(self, raw_path):
        path = unquote(raw_path).split("?", 1)[0]
        if path in ("", "/"):
            path = "/index.html"
        relative = Path(path.lstrip("/"))
        target = (WEB_DIR / relative).resolve()
        if WEB_DIR.resolve() not in target.parents and target != WEB_DIR.resolve():
            send_error_json(self, 403, "Acesso negado.")
            return
        if not target.exists() or not target.is_file():
            target = WEB_DIR / "index.html"
        content = target.read_bytes()
        mime = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        send_security_headers(self)
        self.end_headers()
        self.wfile.write(content)


def validate_camera(camera, config=None):
    if not camera.get("name"):
        raise ValueError("Informe um nome para a fonte.")
    if camera.get("type") == "stream":
        if not camera.get("url"):
            raise ValueError("Informe a URL do stream.")
        if "\r" in camera["url"] or "\n" in camera["url"]:
            raise ValueError("A URL do stream contem caracteres invalidos.")
        try:
            parsed = urlparse(camera["url"])
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname
        except ValueError as exc:
            raise ValueError("A URL do stream e invalida.") from exc
        if not scheme:
            raise ValueError("A URL precisa incluir o protocolo, por exemplo rtsp://.")
        if scheme not in ALLOWED_STREAM_SCHEMES:
            raise ValueError(f"Protocolo de stream nao permitido: {scheme}.")
        if not hostname:
            raise ValueError("A URL do stream precisa informar um host de rede.")
    elif camera.get("type") == "cloud-p2p":
        effective, _settings, group = resolve_camera_runtime(camera, config or {})
        if camera.get("groupId") and not group:
            raise ValueError("Grupo Cloud/P2P nao encontrado.")
        if not group and not effective.get("p2pUuid"):
            raise ValueError("Selecione um grupo Cloud/P2P ou informe o ID do dispositivo P2P.")
        if group and not effective.get("p2pUuid"):
            raise ValueError("Informe o ID do dispositivo P2P no grupo Cloud/P2P.")
        if not effective.get("rtspPath"):
            raise ValueError("Informe o caminho RTSP.")
        if not str(effective.get("rtspPath")).startswith("/") or "://" in str(effective.get("rtspPath")):
            raise ValueError("O caminho RTSP deve iniciar com / e nao pode conter outra URL.")
        if "\r" in str(effective.get("rtspPath")) or "\n" in str(effective.get("rtspPath")):
            raise ValueError("O caminho RTSP contem caracteres invalidos.")
    elif not camera.get("videoDevice"):
        raise ValueError("Informe o dispositivo de video Linux.")


class RecorderServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    is_tls = False
    allow_insecure_http = False


def validate_web_access_config(config, host, is_tls=False, allow_insecure_http=False):
    if is_loopback_host(host):
        return
    if not config.get("settings", {}).get("webPassword"):
        raise ValueError("Defina uma senha web antes de escutar em um endereco nao local.")
    if not is_tls and not allow_insecure_http:
        raise ValueError(
            "HTTP sem TLS em endereco nao local foi bloqueado. Use um proxy HTTPS em 127.0.0.1, "
            "configure --tls-cert/--tls-key ou confirme o risco com --allow-insecure-http."
        )


def stop_all_jobs():
    with JOBS_LOCK:
        jobs = list(JOBS.values())
        JOBS.clear()
    for job in jobs:
        job.stop(timeout=6)


def main(argv=None):
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--host", default=os.environ.get("CAMERA_RECORDER_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CAMERA_RECORDER_PORT", "8088")))
    parser.add_argument("--tls-cert", default=os.environ.get("CAMERA_RECORDER_TLS_CERT", ""))
    parser.add_argument("--tls-key", default=os.environ.get("CAMERA_RECORDER_TLS_KEY", ""))
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        default=environment_flag("CAMERA_RECORDER_ALLOW_INSECURE_HTTP"),
        help="permite HTTP sem TLS fora do loopback (nao recomendado)",
    )
    args = parser.parse_args(argv)

    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert e --tls-key devem ser informados juntos.")
    config = load_config()
    try:
        validate_web_access_config(config, args.host, bool(args.tls_cert), args.allow_insecure_http)
    except ValueError as exc:
        parser.error(str(exc))
    server = RecorderServer((args.host, args.port), RequestHandler)
    server.allow_insecure_http = args.allow_insecure_http
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.is_tls = True
    scheme = "https" if server.is_tls else "http"
    add_log(None, "info", f"Servidor iniciado em {scheme}://{args.host}:{args.port}")
    print(f"{APP_NAME} {VERSION} em {scheme}://{args.host}:{args.port}")
    print(f"Configuracao: {CONFIG_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando...")
    finally:
        server.shutdown()
        server.server_close()
        stop_all_jobs()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit(0))
    main()
