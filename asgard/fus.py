# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import queue
import re
import secrets
import struct
import sys
import tarfile
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator

import requests
from Cryptodome.Cipher import AES

from .constants import (
    _AES_BLOCK_SIZE,
    _AUTH_AES_KEY,
    _AUTH_NONCE_COUNT,
    _AUTH_SIGNATURE_ALPHABET,
    _DOWNLOAD_RECOVERY_INTERVAL,
    _DOWNLOAD_RETRIES,
    _FUS_BASE_URL,
    _FUS_DOWNLOAD_URL,
    _FUS_PLACEHOLDER,
    _FUS_USER_AGENT,
    _LATEST_HISTORY_IGNORED_INDEXES,
    _PROGRESS_REFRESH_S,
    _RANGE_CHUNK_SIZE,
    _RATE_LIMIT_COOLDOWN_S,
    _RESUME_META_SAVE_INTERVAL_S,
    _RETRY_BACKOFF_S,
    _THREAD_STAGGER_S,
)


def _available_worker_count() -> int:
    try:
        affinity = os.sched_getaffinity(0)
    except (AttributeError, OSError):
        affinity = None
    if affinity:
        return max(1, len(affinity))
    return max(1, os.cpu_count() or 1)


_DOWNLOAD_THREADS = _available_worker_count()
_DECRYPT_THREADS = _available_worker_count()
_ARCHIVE_TAIL_CACHE_SIZE = 128 * 1024
_ARCHIVE_COPY_CHUNK_SIZE = 1024 * 1024
_TAR_INDEX_SPACING = 8 * 1024 * 1024
_TAR_INDEX_SCAN_BUFFER_SIZE = 1024 * 1024
_TAR_INDEX_MEMBER_BUFFER_SIZE = 32 * 1024 * 1024
_TAR_INDEX_VERSION = 1
_CONTENT_RANGE_RE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", re.IGNORECASE)
_ZIP_LOCAL_FILE_HEADER = struct.Struct("<I5H3I2H")
_ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50
_GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
_SPARSE_HEADER = struct.Struct("<I4H4I")
_SPARSE_CHUNK_HEADER = struct.Struct("<2H2I")
_SPARSE_MAGIC = 0xED26FF3A
_SPARSE_RAW = 0xCAC1
_SPARSE_FILL = 0xCAC2
_SPARSE_DONT_CARE = 0xCAC3
_SPARSE_CRC32 = 0xCAC4


def _md5_digest(text: str) -> bytes:
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).digest()


def _md5_hexdigest(text: str) -> str:
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).hexdigest()


class FUSError(RuntimeError):
    pass


class RetryableDownloadError(FUSError):
    pass


def _upper_code(value: str) -> str:
    return str(value or "").strip().upper()


def _device_codes(model: str, region: str) -> tuple[str, str]:
    model_code = _upper_code(model)
    region_code = _upper_code(region)
    if not model_code or not region_code:
        raise ValueError("model and region are required")
    return model_code, region_code


@dataclass(frozen=True)
class BinaryInfo:
    model_path: str
    filename: str
    size: int
    latest_version: str | None = None
    logic_value_factory: str | None = None
    logic_value_home: str | None = None
    firmware_version: str | None = None
    model_type: str | None = None

    @property
    def logic_value(self) -> str | None:
        return self.logic_value_factory or self.logic_value_home

    @property
    def binary_version(self) -> str | None:
        return self.firmware_version or self.latest_version


@dataclass(frozen=True)
class DownloadResult:
    encrypted_path: Path
    decrypted_path: Path | None
    firmware_version: str
    filename: str
    size: int


@dataclass(frozen=True)
class FirmwareArchiveEntry:
    name: str
    size: int
    compressed_size: int


@dataclass(frozen=True)
class FirmwareArchiveListing:
    firmware_version: str
    filename: str
    size: int
    entries: tuple[FirmwareArchiveEntry, ...]


@dataclass(frozen=True)
class FirmwareTarEntry:
    name: str
    size: int


@dataclass(frozen=True)
class _IndexedTarMember:
    name: str
    size: int
    offset_data: int


@dataclass(frozen=True)
class _TarIndexCache:
    complete: bool
    members: tuple[_IndexedTarMember, ...]
    index_path: Path


@dataclass(frozen=True)
class FirmwareHistoryEntry:
    firmware_version: str
    index: str
    sequence: str
    natures: tuple[str, ...]
    open_date: str
    android_version: str = ""
    os_name: str = ""
    display_version: str = ""
    sw_display_version: str = ""
    model_name: str = ""
    display_name: str = ""
    local_code: str = ""
    fields: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "firmware_version": self.firmware_version,
            "index": self.index,
            "sequence": self.sequence,
            "natures": list(self.natures),
            "open_date": self.open_date,
            "android_version": self.android_version,
            "os_name": self.os_name,
            "display_version": self.display_version,
            "sw_display_version": self.sw_display_version,
            "model_name": self.model_name,
            "display_name": self.display_name,
            "local_code": self.local_code,
            "fields": {tag: list(values) for tag, values in self.fields.items()},
        }


def _print_info(message: str) -> None:
    print(message, flush=True)


def _format_bytes(size: float) -> str:
    value = float(size)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TiB"


_PROGRESS_LINE_WIDTH = 0


def _render_progress(
    label: str,
    done: int,
    total: int,
    started_at: float,
    *,
    speed_done: int | None = None,
    complete: bool = False,
) -> None:
    elapsed = max(time.monotonic() - started_at, 0.001)
    speed = (done if speed_done is None else speed_done) / elapsed
    if total > 0:
        percent = min(100.0, (done / total) * 100.0)
        total_text = _format_bytes(total)
        progress_text = f"{percent:6.2f}% {_format_bytes(done)}/{total_text}"
    else:
        progress_text = _format_bytes(done)
    line = f"{label}: {progress_text} {_format_bytes(speed)}/s"
    if os.name == "nt":
        global _PROGRESS_LINE_WIDTH
        padding = " " * max(0, _PROGRESS_LINE_WIDTH - len(line))
        sys.stdout.write(f"\r{line}{padding}")
        _PROGRESS_LINE_WIDTH = 0 if complete else len(line)
    else:
        sys.stdout.write(f"\r\033[2K{line}")
    if complete:
        sys.stdout.write("\n")
    sys.stdout.flush()


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise FUSError("invalid PKCS#7 payload")
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > _AES_BLOCK_SIZE or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise FUSError("invalid PKCS#7 padding")
    return data[:-pad_len]


def _authenticate_block(in_block: bytes) -> bytes:
    if len(in_block) != _AES_BLOCK_SIZE:
        raise FUSError("nonce block is too short")
    return AES.new(_AUTH_AES_KEY, AES.MODE_ECB).encrypt(in_block)


def decrypt_nonce(enc_nonce: str) -> str:
    seed = enc_nonce[:_AES_BLOCK_SIZE].ljust(_AES_BLOCK_SIZE, "0").encode("utf-8")
    return _authenticate_block(seed).hex()


def normalize_version_code(version_code: str) -> str:
    parts = [part.strip() for part in str(version_code or "").split("/")]
    if len(parts) == 3:
        parts.append(parts[0])
    if len(parts) >= 3 and not parts[2]:
        parts[2] = parts[0]
    return "/".join(parts)


def get_logic_check(value: str, nonce: str) -> str:
    if len(value) < _AES_BLOCK_SIZE:
        raise FUSError("logic check input too short")
    return "".join(value[ord(ch) & 0xF] for ch in nonce)


def _xml_text(root: ET.Element, path: str) -> str | None:
    node = root.find(path)
    if node is None or node.text is None:
        return None
    text = node.text.strip()
    return text or None


def _first_xml_text(root: ET.Element, *paths: str) -> str | None:
    for path in paths:
        text = _xml_text(root, path)
        if text is not None:
            return text
    return None


def _parse_xml_response(response_text: str, source: str) -> ET.Element:
    try:
        return ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise FUSError(f"{source} returned invalid XML") from exc


def _build_xml_request(*, proto_ver: str = "1") -> tuple[ET.Element, ET.Element]:
    fus_msg = ET.Element("FUSMsg")
    fus_hdr = ET.SubElement(fus_msg, "FUSHdr")
    ET.SubElement(fus_hdr, "ProtoVer").text = proto_ver
    ET.SubElement(fus_hdr, "SessionID").text = "0"
    ET.SubElement(fus_hdr, "MsgID").text = "1"
    fus_body = ET.SubElement(fus_msg, "FUSBody")
    put = ET.SubElement(fus_body, "Put")
    return fus_msg, put


def _append_data_node(parent: ET.Element, tag: str, value: str | int) -> None:
    elem = ET.SubElement(parent, tag)
    ET.SubElement(elem, "Data").text = str(value)


def build_binaryinform_request(
    model: str,
    region: str,
    *,
    firmware_version: str | None = None,
    nonce: str | None = None,
) -> bytes:
    version = normalize_version_code(firmware_version) if str(firmware_version or "").strip() else _FUS_PLACEHOLDER
    logic_check = get_logic_check(version, nonce or "") if firmware_version and nonce else _FUS_PLACEHOLDER
    fus_msg, put = _build_xml_request(proto_ver="1")
    fus_body = fus_msg.find("./FUSBody")
    ET.SubElement(put, "CmdID").text = "1"
    for tag, value in (
        ("ACCESS_MODE", "1"),
        ("BINARY_NATURE", "1"),
        ("REQUEST_TYPE", "2"),
        ("LOGIC_CHECK", logic_check),
        ("BINARY_SW_VERSION", version),
        ("DEVICE_SN_NUMBER", ""),
        ("BINARY_LOCAL_CODE", _upper_code(region)),
        ("BINARY_MODEL_NAME", _upper_code(model)),
    ):
        _append_data_node(put, tag, value)
    get = ET.SubElement(fus_body, "Get")
    ET.SubElement(get, "CmdID").text = "2"
    ET.SubElement(get, "BINARY_SW_VERSION")
    return ET.tostring(fus_msg, encoding="utf-8")


def build_smart_history_request(model: str, region: str) -> bytes:
    fus_msg, put = _build_xml_request(proto_ver="1")
    ET.SubElement(put, "CmdID").text = "1"
    for tag, value in (
        ("ACCESS_MODE", "1"),
        ("BINARY_LOCAL_CODE", _upper_code(region)),
        ("BINARY_MODEL_NAME", _upper_code(model)),
    ):
        _append_data_node(put, tag, value)
    return ET.tostring(fus_msg, encoding="utf-8")


def _binary_init_logic_input(filename: str) -> str:
    name = str(filename or "")
    if len(name) >= 25:
        return name[-25:-9]
    return name.split(".")[0][-_AES_BLOCK_SIZE:]


def build_binaryinit_request(
    filename: str,
    nonce: str,
    *,
    firmware_version: str | None = None,
    model_type: str | None = None,
    region: str | None = None,
) -> bytes:
    fus_msg, put = _build_xml_request(proto_ver="1")
    _append_data_node(put, "BINARY_NAME", filename)
    if firmware_version:
        _append_data_node(put, "BINARY_SW_VERSION", normalize_version_code(firmware_version))
    if region:
        _append_data_node(put, "DEVICE_LOCAL_CODE", _upper_code(region))
    if model_type:
        _append_data_node(put, "DEVICE_MODEL_TYPE", model_type)
    _append_data_node(put, "LOGIC_CHECK", get_logic_check(_binary_init_logic_input(filename), nonce))
    return ET.tostring(fus_msg, encoding="utf-8")


def decrypted_output_path(path: str | os.PathLike[str]) -> Path:
    in_path = Path(path).expanduser()
    if in_path.suffix.lower() in {".enc2", ".enc4"}:
        return in_path.with_suffix("")
    return in_path.with_name(f"{in_path.name}.dec")


def _partial_output_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.part")


def _resume_state_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.resume.json")


def _build_range_parts(total_size: int, part_count: int = _DOWNLOAD_THREADS) -> list[dict[str, int]]:
    if total_size <= 0:
        return []
    block_size = _AES_BLOCK_SIZE
    max_parts = max(1, total_size // block_size)
    parts = max(1, min(int(part_count), max_parts))
    ranges: list[dict[str, int]] = []
    start = 0
    for idx in range(parts):
        if idx == parts - 1:
            end = total_size - 1
        else:
            remaining_parts = parts - idx
            remaining_bytes = total_size - start
            seg_len = max(block_size, (remaining_bytes // remaining_parts) // block_size * block_size)
            max_len = remaining_bytes - (remaining_parts - 1) * block_size
            seg_len = min(seg_len, max_len)
            end = start + seg_len - 1
        ranges.append({"start": start, "end": end, "offset": start})
        start = end + 1
    return ranges


def _save_range_resume_state(meta_path: Path, total_size: int, ranges: list[dict[str, int]]) -> None:
    tmp_path = meta_path.with_name(f"{meta_path.name}.tmp")
    tmp_path.write_text(json.dumps({"size": total_size, "ranges": ranges}), encoding="utf-8")
    tmp_path.replace(meta_path)


def _resume_done_bytes(ranges: list[dict[str, int]]) -> int:
    return sum(max(0, int(item["offset"]) - int(item["start"])) for item in ranges)


def _prepare_range_resume_state(data_path: Path, total_size: int, resume: bool) -> tuple[list[dict[str, int]], Path]:
    meta_path = _resume_state_path(data_path)
    default_ranges = _build_range_parts(total_size)
    ranges = default_ranges
    if resume and meta_path.is_file():
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
            raw_ranges = payload.get("ranges")
            if (
                isinstance(raw_ranges, list)
                and int(payload.get("size", -1)) == total_size
                and len(raw_ranges) == len(default_ranges)
            ):
                loaded: list[dict[str, int]] = []
                valid = True
                for raw, default in zip(raw_ranges, default_ranges):
                    start = int(raw.get("start", -1))
                    end = int(raw.get("end", -1))
                    offset = int(raw.get("offset", start))
                    if start != default["start"] or end != default["end"]:
                        valid = False
                        break
                    loaded.append({"start": start, "end": end, "offset": max(start, min(end + 1, offset))})
                if valid:
                    ranges = loaded
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            ranges = default_ranges

    data_path.parent.mkdir(parents=True, exist_ok=True)
    if resume and data_path.exists():
        with data_path.open("r+b") as fh:
            fh.truncate(total_size)
    else:
        with data_path.open("wb") as fh:
            fh.truncate(total_size)
    return (ranges if resume else default_ranges), meta_path


class FUSClient:
    GENERATE_NONCE_PATH = "NF_SmartDownloadGenerateNonce.do"
    SMART_HISTORY_PATH = "SmartHistory.do"
    BINARY_INFORM_PATH = "NF_SmartDownloadBinaryInform.do"
    BINARY_INIT_PATH = "NF_SmartDownloadBinaryInitForMass.do"

    def __init__(self, *, timeout_s: int = 30, session: requests.Session | None = None):
        self.timeout_s = int(timeout_s)
        self.session = session or requests.Session()
        self.auth = ""
        self.server_cookies: dict[str, str] = {}
        self.encnonce = ""
        self.nonce = ""
        self._auth_lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self.make_request(self.GENERATE_NONCE_PATH)

    def _make_interface_signature_hash(self, nonce: str, signature: str) -> str:
        auth_hash = _md5_hexdigest(f"auth:{nonce}:{_AUTH_NONCE_COUNT}")
        interface_hash = _md5_hexdigest(f"interface:{signature}")
        return _md5_hexdigest(f"{auth_hash}:FUS:{interface_hash}")

    def _build_auth_header_unlocked(self, *, cloud: bool = False) -> str:
        header_nonce = self.encnonce if cloud else ""
        auth = self.auth
        return f'FUS nonce="{header_nonce}", signature="{auth}", nc="", type="", realm=""'

    def _cookie_header_unlocked(self) -> str | None:
        if not self.server_cookies:
            return None
        cookies = tuple(self.server_cookies.items())
        return "; ".join(f"{name}={value}" for name, value in cookies)

    def _headers_unlocked(self, authorization: str, *, no_cache: bool = False) -> dict[str, str]:
        headers = {"Authorization": authorization, "User-Agent": _FUS_USER_AGENT}
        if no_cache:
            headers["Cache-Control"] = "no-cache"
        cookie = self._cookie_header_unlocked()
        if cookie:
            headers["Cookie"] = cookie
        return headers

    def _has_nonce(self) -> bool:
        with self._auth_lock:
            return bool(self.nonce)

    def _headers(self, authorization: str, *, no_cache: bool = False) -> dict[str, str]:
        with self._auth_lock:
            return self._headers_unlocked(authorization, no_cache=no_cache)

    def _post_headers(self) -> dict[str, str]:
        with self._auth_lock:
            return self._headers_unlocked(self._build_auth_header_unlocked(cloud=False))

    def _signed_post_headers(self, signature: str) -> dict[str, str]:
        nonce = "".join(secrets.choice(_AUTH_SIGNATURE_ALPHABET) for _ in range(_AES_BLOCK_SIZE))
        authorization = (
            f'FUS nonce="{nonce}", signature="{self._make_interface_signature_hash(nonce, signature)}", '
            f'nc="{_AUTH_NONCE_COUNT}", type="auth", realm="interface"'
        )
        return self._headers(authorization, no_cache=True)

    def _download_headers(self) -> dict[str, str]:
        with self._auth_lock:
            headers = self._headers_unlocked(self._build_auth_header_unlocked(cloud=True), no_cache=True)
            headers["Accept-Encoding"] = "identity"
            return headers

    def _response_is_401(self, response: requests.Response, body: str) -> bool:
        if response.status_code == 401:
            return True
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return False
        return _xml_text(root, "./FUSBody/Results/Status") == "401"

    def _response_cookies(self, response: requests.Response) -> dict[str, str]:
        parsed_cookies: dict[str, str] = {}
        for cookie_value in self._set_cookie_headers(response):
            cookies = SimpleCookie()
            try:
                cookies.load(cookie_value)
            except CookieError:
                continue
            for name, morsel in cookies.items():
                if morsel.value:
                    parsed_cookies[name] = morsel.value
        for name, value in response.cookies.items():
            if value:
                parsed_cookies.setdefault(name, value)
        return parsed_cookies

    def _set_cookie_headers(self, response: requests.Response) -> list[str]:
        set_cookie_values: list[str] = []
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "get_all"):
            try:
                set_cookie_values = list(raw_headers.get_all("Set-Cookie") or [])
            except (AttributeError, TypeError, ValueError):
                set_cookie_values = []
        if not set_cookie_values:
            header = response.headers.get("Set-Cookie")
            if header:
                set_cookie_values = [header]
        return set_cookie_values

    def _update_identity_state(self, response: requests.Response) -> None:
        enc_nonce = response.headers.get("NONCE") or response.headers.get("nonce")
        auth = None
        if enc_nonce:
            try:
                auth = decrypt_nonce(enc_nonce)
            except FUSError:
                auth = ""
        parsed_cookies = self._response_cookies(response)
        with self._auth_lock:
            if enc_nonce:
                self.encnonce = enc_nonce
                self.nonce = enc_nonce
                self.auth = auth or ""
            if parsed_cookies:
                self.server_cookies.update(parsed_cookies)

    def refresh_auth(self) -> str:
        with self._refresh_lock:
            response = self.session.post(
                f"{_FUS_BASE_URL}{self.GENERATE_NONCE_PATH}",
                data=b"",
                headers=self._post_headers(),
                timeout=self.timeout_s,
            )
            body = response.text
            response.raise_for_status()
            self._update_identity_state(response)
            return body

    def make_request(self, path: str, data: bytes | str = b"") -> str:
        if path == self.GENERATE_NONCE_PATH:
            return self.refresh_auth()
        for attempt in range(2):
            if not self._has_nonce():
                self.refresh_auth()
            response = self.session.post(
                f"{_FUS_BASE_URL}{path}",
                data=data,
                headers=self._post_headers(),
                timeout=self.timeout_s,
            )
            body = response.text
            if self._response_is_401(response, body) and attempt == 0:
                self.refresh_auth()
                continue
            response.raise_for_status()
            self._update_identity_state(response)
            return body
        raise FUSError("FUS authorization failed after nonce refresh")

    def make_signed_request(self, path: str, data: bytes | str = b"", *, signature: str) -> str:
        response = self.session.post(
            f"{_FUS_BASE_URL}{path}",
            data=data,
            headers=self._signed_post_headers(signature),
            timeout=self.timeout_s,
        )
        response.raise_for_status()
        self._update_identity_state(response)
        return response.text

    def download_file(
        self,
        remote_path: str,
        *,
        start: int = 0,
        end: int | None = None,
    ) -> requests.Response:
        url = f"{_FUS_DOWNLOAD_URL}?file={remote_path}"
        for attempt in range(2):
            headers = self._download_headers()
            if end is not None:
                headers["Range"] = f"bytes={start}-{end}"
            elif start > 0:
                headers["Range"] = f"bytes={start}-"
            response = self.session.get(url, headers=headers, stream=True, timeout=self.timeout_s)
            if response.status_code == 401 and attempt == 0:
                response.close()
                self.refresh_auth()
                time.sleep(_RETRY_BACKOFF_S)
                continue
            if "Range" in headers and response.status_code != requests.codes.partial_content:
                status = response.status_code
                response.close()
                raise RetryableDownloadError(
                    f"download server ignored requested byte range ({status}): {headers['Range']}"
                )
            response.raise_for_status()
            self._update_identity_state(response)
            return response
        raise FUSError("FUS download authorization failed after nonce refresh")


def _validate_content_range(
    response: requests.Response,
    *,
    start: int,
    end: int,
    total_size: int,
) -> None:
    value = response.headers.get("Content-Range", "").strip()
    match = _CONTENT_RANGE_RE.fullmatch(value)
    if match is None:
        raise RetryableDownloadError(f"download server returned an invalid Content-Range: {value or 'missing'}")
    response_start, response_end = int(match.group(1)), int(match.group(2))
    response_total = match.group(3)
    if response_start != start or response_end != end:
        raise RetryableDownloadError(
            "download server returned the wrong byte range: "
            f"expected {start}-{end}, got {response_start}-{response_end}"
        )
    if response_total == "*" or int(response_total) != total_size:
        raise RetryableDownloadError(
            f"download server returned the wrong file size: expected {total_size}, got {response_total}"
        )


def _read_download_range(
    *,
    client: FUSClient,
    remote_path: str,
    start: int,
    end: int,
    total_size: int,
    recover_download: Callable[[], None] | None = None,
) -> bytes:
    expected_size = end - start + 1
    for attempt in range(1, _DOWNLOAD_RETRIES + 2):
        response: requests.Response | None = None
        try:
            response = client.download_file(remote_path, start=start, end=end)
            _validate_content_range(response, start=start, end=end, total_size=total_size)
            chunks: list[bytes] = []
            received = 0
            for chunk in response.iter_content(chunk_size=_RANGE_CHUNK_SIZE):
                if not chunk:
                    continue
                received += len(chunk)
                if received > expected_size:
                    raise RetryableDownloadError(
                        f"download server returned more data than requested for range {start}-{end}"
                    )
                chunks.append(chunk)
            if received != expected_size:
                raise RetryableDownloadError(
                    f"download server returned {received} bytes for range {start}-{end}, expected {expected_size}"
                )
            return b"".join(chunks)
        except (requests.RequestException, OSError, RetryableDownloadError) as exc:
            if attempt > _DOWNLOAD_RETRIES:
                raise FUSError(f"range {start}-{end} failed after retries: {exc}") from exc
            if recover_download is not None and attempt % _DOWNLOAD_RECOVERY_INTERVAL == 0:
                try:
                    recover_download()
                except Exception as recovery_exc:
                    raise FUSError(f"download recovery failed: {recovery_exc}") from recovery_exc
                time.sleep(_RATE_LIMIT_COOLDOWN_S)
            time.sleep(_RETRY_BACKOFF_S * attempt)
        finally:
            if response is not None:
                response.close()
    raise FUSError(f"range {start}-{end} failed")


class _FUSDecryptingReader(io.RawIOBase):
    def __init__(
        self,
        *,
        client: FUSClient,
        remote_path: str,
        encrypted_size: int,
        key: bytes,
        recover_download: Callable[[], None] | None = None,
    ):
        super().__init__()
        if encrypted_size <= 0 or encrypted_size % _AES_BLOCK_SIZE:
            raise FUSError("invalid encrypted firmware size")
        self._client = client
        self._remote_path = remote_path
        self._encrypted_size = int(encrypted_size)
        self._key = key
        self._recover_download = recover_download
        self._position = 0
        self._response: requests.Response | None = None
        self._response_iter: Iterator[bytes] | None = None
        self._cipher: AES | None = None
        self._cipher_buffer = bytearray()
        self._plain_buffer = bytearray()
        self._stream_discard = 0
        self._stream_failures = 0
        self._stream_failure_position: int | None = None

        tail_start = max(0, self._encrypted_size - _ARCHIVE_TAIL_CACHE_SIZE)
        tail_start -= tail_start % _AES_BLOCK_SIZE
        encrypted_tail = _read_download_range(
            client=self._client,
            remote_path=self._remote_path,
            start=tail_start,
            end=self._encrypted_size - 1,
            total_size=self._encrypted_size,
            recover_download=self._recover_download,
        )
        decrypted_tail = AES.new(self._key, AES.MODE_ECB).decrypt(encrypted_tail)
        unpadded_last_block = _pkcs7_unpad(decrypted_tail[-_AES_BLOCK_SIZE:])
        padding_size = _AES_BLOCK_SIZE - len(unpadded_last_block)
        self._size = self._encrypted_size - padding_size
        self._tail_start = min(tail_start, self._size)
        self._tail = decrypted_tail[: self._size - tail_start]

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        self._checkClosed()
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        if whence == os.SEEK_SET:
            target = int(offset)
        elif whence == os.SEEK_CUR:
            target = self._position + int(offset)
        elif whence == os.SEEK_END:
            target = self._size + int(offset)
        else:
            raise ValueError(f"invalid whence: {whence}")
        if target < 0:
            raise ValueError("negative seek position")
        if target == self._position:
            return target

        buffered_end = self._position + len(self._plain_buffer)
        if self._position < target <= buffered_end:
            del self._plain_buffer[: target - self._position]
            self._position = target
            return target

        self._close_stream()
        self._plain_buffer.clear()
        self._position = target
        return target

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        if size == 0 or self._position >= self._size:
            return b""
        if size is None or size < 0:
            remaining = self._size - self._position
        else:
            remaining = min(int(size), self._size - self._position)
        chunks: list[bytes] = []

        while remaining > 0:
            if self._position >= self._tail_start:
                self._close_stream()
                tail_offset = self._position - self._tail_start
                take = min(remaining, len(self._tail) - tail_offset)
                if take <= 0:
                    break
                chunks.append(self._tail[tail_offset : tail_offset + take])
                self._position += take
                remaining -= take
                continue

            if not self._plain_buffer:
                self._fill_stream_buffer()
            if not self._plain_buffer:
                raise FUSError(f"unexpected end of firmware data at byte {self._position}")
            take = min(remaining, len(self._plain_buffer))
            chunks.append(bytes(self._plain_buffer[:take]))
            del self._plain_buffer[:take]
            self._position += take
            remaining -= take

        return b"".join(chunks)

    def close(self) -> None:
        if not self.closed:
            self._close_stream()
        super().close()

    def _open_stream(self) -> None:
        request_start = self._position - (self._position % _AES_BLOCK_SIZE)
        response = self._client.download_file(
            self._remote_path,
            start=request_start,
            end=self._encrypted_size - 1,
        )
        try:
            _validate_content_range(
                response,
                start=request_start,
                end=self._encrypted_size - 1,
                total_size=self._encrypted_size,
            )
        except Exception:
            response.close()
            raise
        self._response = response
        self._response_iter = response.iter_content(chunk_size=_RANGE_CHUNK_SIZE)
        self._cipher = AES.new(self._key, AES.MODE_ECB)
        self._cipher_buffer.clear()
        self._stream_discard = self._position - request_start

    def _close_stream(self) -> None:
        response = self._response
        self._response = None
        self._response_iter = None
        self._cipher = None
        self._cipher_buffer.clear()
        self._stream_discard = 0
        if response is not None:
            response.close()

    def _retry_stream(self, exc: Exception) -> None:
        self._close_stream()
        if self._stream_failure_position == self._position:
            self._stream_failures += 1
        else:
            self._stream_failure_position = self._position
            self._stream_failures = 1
        if self._stream_failures > _DOWNLOAD_RETRIES:
            raise FUSError(f"firmware stream failed after retries at byte {self._position}: {exc}") from exc
        if self._recover_download is not None and self._stream_failures % _DOWNLOAD_RECOVERY_INTERVAL == 0:
            try:
                self._recover_download()
            except Exception as recovery_exc:
                raise FUSError(f"download recovery failed: {recovery_exc}") from recovery_exc
            time.sleep(_RATE_LIMIT_COOLDOWN_S)
        time.sleep(_RETRY_BACKOFF_S * self._stream_failures)

    def _fill_stream_buffer(self) -> None:
        stream_limit = min(self._size, self._tail_start)
        while not self._plain_buffer and self._position < stream_limit:
            try:
                if self._response_iter is None:
                    self._open_stream()
                if self._response_iter is None:
                    raise RetryableDownloadError("download stream did not start")
                chunk = next(self._response_iter)
                if not chunk:
                    continue
                self._cipher_buffer.extend(chunk)
                block_size = (len(self._cipher_buffer) // _AES_BLOCK_SIZE) * _AES_BLOCK_SIZE
                if block_size == 0:
                    continue
                encrypted = bytes(self._cipher_buffer[:block_size])
                del self._cipher_buffer[:block_size]
                if self._cipher is None:
                    raise RetryableDownloadError("download stream lost its decryptor")
                plain = self._cipher.decrypt(encrypted)
                if self._stream_discard:
                    discarded = min(self._stream_discard, len(plain))
                    plain = plain[discarded:]
                    self._stream_discard -= discarded
                remaining = stream_limit - self._position
                if len(plain) > remaining:
                    plain = plain[:remaining]
                self._plain_buffer.extend(plain)
            except StopIteration:
                if self._cipher_buffer:
                    error = RetryableDownloadError("download stream ended with a partial encrypted block")
                else:
                    error = RetryableDownloadError("download stream ended before the requested data")
                self._retry_stream(error)
            except (requests.RequestException, OSError, RetryableDownloadError) as exc:
                self._retry_stream(exc)


def _parse_binary_info(response_text: str) -> BinaryInfo:
    root = _parse_xml_response(response_text, "DownloadBinaryInform")
    status = _xml_text(root, "./FUSBody/Results/Status")
    if status not in {"200", "S00"}:
        raise FUSError(f"DownloadBinaryInform returned {status or 'unknown'}")
    filename = _first_xml_text(root, "./FUSBody/Put/BINARY_NAME/Data", "./FUSBody/Put/BINARY_FILE_NAME/Data")
    size_text = _xml_text(root, "./FUSBody/Put/BINARY_BYTE_SIZE/Data")
    model_path = _xml_text(root, "./FUSBody/Put/MODEL_PATH/Data")
    if not filename or not size_text or model_path is None:
        raise FUSError("FUS response did not include a downloadable firmware bundle")
    try:
        size = int(size_text)
    except ValueError as exc:
        raise FUSError(f"FUS returned an invalid firmware size: {size_text}") from exc
    return BinaryInfo(
        model_path=model_path,
        filename=filename,
        size=size,
        latest_version=_first_xml_text(
            root, "./FUSBody/Results/LATEST_FW_VERSION/Data", "./FUSBody/Results/BINARY_SW_VERSION/Data"
        ),
        logic_value_factory=_xml_text(root, "./FUSBody/Put/LOGIC_VALUE_FACTORY/Data"),
        logic_value_home=_xml_text(root, "./FUSBody/Put/LOGIC_VALUE_HOME/Data"),
        firmware_version=_xml_text(root, "./FUSBody/Put/BINARY_SW_VERSION/Data"),
        model_type=_xml_text(root, "./FUSBody/Put/DEVICE_MODEL_TYPE/Data"),
    )


def _element_data_text(element: ET.Element) -> str:
    data_node = element.find("Data")
    if data_node is not None and data_node.text is not None:
        return data_node.text.strip()
    return "".join(element.itertext()).strip()


def _add_history_field(fields: dict[str, list[str]], tag: str, value: str) -> None:
    values = fields.setdefault(tag, [])
    if value not in values:
        values.append(value)


@dataclass
class _HistoryRow:
    firmware_version: str
    index: str
    sequence: str
    open_date: str
    natures: set[str] = field(default_factory=set)
    fields: dict[str, list[str]] = field(default_factory=dict)

    def merge(self, fields: dict[str, list[str]], *, natures: set[str], open_date: str) -> None:
        self.natures.update(natures)
        if open_date > self.open_date:
            self.open_date = open_date
        for tag, values in fields.items():
            for value in values:
                _add_history_field(self.fields, tag, value)


def _first_history_field(fields: dict[str, tuple[str, ...]], *tags: str) -> str:
    for tag in tags:
        for value in fields.get(tag, ()):
            if value:
                return value
    return ""


def _android_version_from_text(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    open_idx = text.find("(")
    close_idx = text.find(")", open_idx + 1)
    if open_idx >= 0 and close_idx > open_idx:
        inner = text[open_idx + 1 : close_idx].strip()
        if inner:
            return inner
    if text.lower().startswith("android"):
        return text
    if text.isdecimal():
        return f"Android {text}"
    return ""


def _history_android_version(fields: dict[str, tuple[str, ...]], os_name: str) -> str:
    for tag in ("BINARY_ANDROID_VERSION", "ANDROID_VERSION", "BINARY_OS_VERSION", "OS_VERSION"):
        for value in fields.get(tag, ()):
            android_version = _android_version_from_text(value)
            if android_version:
                return android_version
    return _android_version_from_text(os_name)


def _freeze_history_fields(fields: dict[str, list[str]]) -> dict[str, tuple[str, ...]]:
    return {tag: tuple(values) for tag, values in fields.items()}


def _history_fields(binary_info: ET.Element) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for field_node in binary_info:
        _add_history_field(fields, field_node.tag, _element_data_text(field_node))
    return fields


def _history_row_from_fields(fields: dict[str, list[str]]) -> _HistoryRow | None:
    frozen_fields = _freeze_history_fields(fields)
    firmware_version = _first_history_field(frozen_fields, "BINARY_SW_VERSION")
    if not firmware_version:
        return None
    return _HistoryRow(
        firmware_version=firmware_version,
        index=_first_history_field(frozen_fields, "BINARY_INDEX"),
        sequence=_first_history_field(frozen_fields, "BINARY_SEQUENCE"),
        open_date=_first_history_field(frozen_fields, "BINARY_OPEN_DATE"),
        natures=set(value for value in frozen_fields.get("BINARY_NATURE", ()) if value),
        fields=fields,
    )


def _history_entry_from_row(row: _HistoryRow) -> FirmwareHistoryEntry:
    fields = _freeze_history_fields(row.fields)
    os_name = _first_history_field(fields, "BINARY_OS_NAME", "OS_NAME", "BINARY_OS_VERSION", "OS_VERSION")
    return FirmwareHistoryEntry(
        firmware_version=row.firmware_version,
        index=row.index,
        sequence=row.sequence,
        natures=tuple(sorted(row.natures)),
        open_date=row.open_date,
        android_version=_history_android_version(fields, os_name),
        os_name=os_name,
        display_version=_first_history_field(fields, "BINARY_DISPLAY_VERSION", "DISPLAY_VERSION"),
        sw_display_version=_first_history_field(fields, "BINARY_SW_DISPLAYVERSION", "SW_DISPLAYVERSION"),
        model_name=_first_history_field(fields, "BINARY_MODEL_NAME", "DEVICE_MODEL_NAME", "MODEL_NAME"),
        display_name=_first_history_field(
            fields,
            "BINARY_MODEL_DISPLAYNAME",
            "BINARY_DISPLAY_NAME",
            "DEVICE_DISPLAY_NAME",
            "DISPLAY_NAME",
        ),
        local_code=_first_history_field(fields, "BINARY_LOCAL_CODE", "DEVICE_LOCAL_CODE", "LOCAL_CODE"),
        fields=fields,
    )


def _sequence_sort_value(entry: FirmwareHistoryEntry) -> tuple[int, str]:
    try:
        return int(entry.sequence), entry.open_date
    except ValueError:
        return -1, entry.open_date


def _latest_history_candidates(rows: list[FirmwareHistoryEntry]) -> list[FirmwareHistoryEntry]:
    return [row for row in rows if str(row.index).strip() not in _LATEST_HISTORY_IGNORED_INDEXES]


def _parse_smart_history(response_text: str) -> list[FirmwareHistoryEntry]:
    root = _parse_xml_response(response_text, "SmartHistory")
    merged: dict[tuple[str, str, str], _HistoryRow] = {}
    for binary_info in root.iter("BINARY_INFO"):
        row = _history_row_from_fields(_history_fields(binary_info))
        if row is None:
            continue
        key = (row.firmware_version, row.index, row.sequence)
        if key in merged:
            merged[key].merge(row.fields, natures=row.natures, open_date=row.open_date)
        else:
            merged[key] = row

    rows = [_history_entry_from_row(row) for row in merged.values()]
    rows.sort(key=_sequence_sort_value)
    return rows


def get_firmware_history_with_client(client: FUSClient, model: str, region: str) -> list[FirmwareHistoryEntry]:
    model_u, region_u = _device_codes(model, region)
    response_text = client.make_signed_request(
        FUSClient.SMART_HISTORY_PATH,
        build_smart_history_request(model_u, region_u),
        signature=model_u,
    )
    return _parse_smart_history(response_text)


def get_firmware_history(model: str, region: str, *, timeout_s: int = 15) -> list[FirmwareHistoryEntry]:
    client = FUSClient(timeout_s=timeout_s)
    return get_firmware_history_with_client(client, model, region)


def get_latest_history_version(client: FUSClient, model: str, region: str) -> str:
    rows = get_firmware_history_with_client(client, model, region)
    if not rows:
        raise FUSError("SmartHistory did not return firmware history")
    latest_candidates = _latest_history_candidates(rows)
    if not latest_candidates:
        raise FUSError("SmartHistory did not return non-index-90 firmware history")
    return latest_candidates[-1].firmware_version


def get_latest_version(model: str, region: str, *, timeout_s: int = 15) -> str:
    client = FUSClient(timeout_s=timeout_s)
    return get_latest_history_version(client, model, region)


def get_binary_info_for_version(client: FUSClient, model: str, region: str, firmware_version: str) -> BinaryInfo:
    response_text = client.make_request(
        FUSClient.BINARY_INFORM_PATH,
        build_binaryinform_request(model, region, firmware_version=firmware_version, nonce=client.nonce),
    )
    return _parse_binary_info(response_text)


def _resolve_versioned_info(client: FUSClient, model: str, region: str, firmware_version: str | None) -> BinaryInfo:
    if str(firmware_version or "").strip():
        return get_binary_info_for_version(client, model, region, str(firmware_version))
    resolved_version = get_latest_history_version(client, model, region)
    return get_binary_info_for_version(client, model, region, resolved_version)


def initialize_download(client: FUSClient, info: BinaryInfo, region: str) -> None:
    client.make_request(
        FUSClient.BINARY_INIT_PATH,
        build_binaryinit_request(
            info.filename,
            client.nonce,
            firmware_version=info.binary_version,
            model_type=info.model_type,
            region=region,
        ),
    )


def get_v4_key(model: str, region: str, *, firmware_version: str | None = None, force_firmware: bool = False) -> bytes:
    client = FUSClient()
    info = _resolve_versioned_info(client, model, region, firmware_version if force_firmware else None)
    binary_version = info.binary_version
    logic_value = info.logic_value
    if not binary_version or not logic_value:
        raise FUSError("FUS did not return the logic value required for v4 decryption")
    return _md5_digest(get_logic_check(binary_version, logic_value))


def get_v2_key(version: str, model: str, region: str) -> bytes:
    deckey = f"{_upper_code(region)}:{_upper_code(model)}:{normalize_version_code(version)}"
    return _md5_digest(deckey)


def _decryption_key_from_info(info: BinaryInfo, model: str, region: str) -> bytes:
    firmware = info.binary_version
    if not firmware:
        raise FUSError("FUS did not return a firmware version")
    if info.filename.lower().endswith(".enc2"):
        return get_v2_key(firmware, model, region)
    if not info.logic_value:
        raise FUSError("FUS did not return the logic value required for v4 decryption")
    return _md5_digest(get_logic_check(firmware, info.logic_value))


@dataclass
class _RemoteFirmwareArchive:
    model: str
    region: str
    info: BinaryInfo
    firmware_version: str
    reader: _FUSDecryptingReader
    archive: zipfile.ZipFile


@contextmanager
def _open_remote_firmware_archive(
    *,
    model: str,
    region: str,
    firmware_version: str | None = None,
    force_firmware: bool = False,
) -> Iterator[_RemoteFirmwareArchive]:
    model_u, region_u = _device_codes(model, region)
    client = FUSClient()
    try:
        info = _resolve_versioned_info(client, model_u, region_u, str(firmware_version) if force_firmware else None)
        firmware = info.binary_version or ""
        if not firmware:
            raise FUSError("FUS did not return a firmware version")

        initialize_download(client, info, region_u)
        remote_path = f"{info.model_path}{info.filename}"

        def recover_download() -> None:
            client.refresh_auth()
            initialize_download(client, info, region_u)

        reader = _FUSDecryptingReader(
            client=client,
            remote_path=remote_path,
            encrypted_size=info.size,
            key=_decryption_key_from_info(info, model_u, region_u),
            recover_download=recover_download,
        )
    except Exception:
        client.session.close()
        raise
    try:
        archive = zipfile.ZipFile(reader)
    except zipfile.BadZipFile as exc:
        reader.close()
        client.session.close()
        raise FUSError(f"decrypted firmware is not a valid ZIP archive: {exc}") from exc
    except Exception:
        reader.close()
        client.session.close()
        raise

    try:
        yield _RemoteFirmwareArchive(
            model=model_u,
            region=region_u,
            info=info,
            firmware_version=firmware,
            reader=reader,
            archive=archive,
        )
    finally:
        try:
            archive.close()
        finally:
            try:
                reader.close()
            finally:
                client.session.close()


def list_firmware_entries(
    *,
    model: str,
    region: str,
    firmware_version: str | None = None,
    force_firmware: bool = False,
) -> FirmwareArchiveListing:
    with _open_remote_firmware_archive(
        model=model,
        region=region,
        firmware_version=firmware_version,
        force_firmware=force_firmware,
    ) as remote:
        entries = tuple(
            FirmwareArchiveEntry(
                name=entry.filename,
                size=entry.file_size,
                compressed_size=entry.compress_size,
            )
            for entry in remote.archive.infolist()
            if not entry.is_dir()
        )
        return FirmwareArchiveListing(
            firmware_version=remote.firmware_version,
            filename=remote.info.filename,
            size=remote.info.size,
            entries=entries,
        )


def _entry_matches_selector(entry: zipfile.ZipInfo, selector: str) -> bool:
    normalized_selector = str(selector or "").strip().replace("\\", "/")
    if not normalized_selector:
        raise ValueError("entry selector cannot be empty")
    name = entry.filename.replace("\\", "/")
    basename = PurePosixPath(name).name
    selector_lower = normalized_selector.casefold()
    name_lower = name.casefold()
    basename_lower = basename.casefold()
    if name_lower == selector_lower or basename_lower == selector_lower:
        return True
    if any(character in normalized_selector for character in "*?["):
        return fnmatch.fnmatchcase(name_lower, selector_lower) or fnmatch.fnmatchcase(basename_lower, selector_lower)
    return name_lower.startswith(f"{selector_lower}_") or basename_lower.startswith(f"{selector_lower}_")


def _select_firmware_entries(
    entries: list[zipfile.ZipInfo],
    selectors: tuple[str, ...],
) -> list[zipfile.ZipInfo]:
    files = [entry for entry in entries if not entry.is_dir()]
    selected_offsets: set[int] = set()
    selected: list[zipfile.ZipInfo] = []
    unmatched: list[str] = []
    for selector in selectors:
        matches = [entry for entry in files if _entry_matches_selector(entry, selector)]
        if not matches:
            unmatched.append(selector)
            continue
        for entry in matches:
            if entry.header_offset in selected_offsets:
                continue
            selected_offsets.add(entry.header_offset)
            selected.append(entry)
    if unmatched:
        available = ", ".join(entry.filename for entry in files)
        raise FUSError(
            f"no archive entry matched {', '.join(repr(selector) for selector in unmatched)}"
            + (f"; available entries: {available}" if available else "")
        )
    return selected


def _select_single_firmware_entry(entries: list[zipfile.ZipInfo], selector: str) -> zipfile.ZipInfo:
    selected = _select_firmware_entries(entries, (selector,))
    if len(selected) != 1:
        names = ", ".join(entry.filename for entry in selected)
        raise FUSError(f"archive selector {selector!r} matched multiple entries: {names}")
    return selected[0]


class _TarIndexUnavailable(Exception):
    pass


class _VirtualGzipReader(io.RawIOBase):
    def __init__(
        self,
        source: _FUSDecryptingReader,
        *,
        data_offset: int,
        compressed_size: int,
        crc: int,
        uncompressed_size: int,
    ):
        super().__init__()
        self._source = source
        self._data_offset = data_offset
        self._compressed_size = compressed_size
        self._footer = struct.pack("<II", crc, uncompressed_size & 0xFFFFFFFF)
        self._size = len(_GZIP_HEADER) + compressed_size + len(self._footer)
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        self._checkClosed()
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        if whence == os.SEEK_SET:
            target = int(offset)
        elif whence == os.SEEK_CUR:
            target = self._position + int(offset)
        elif whence == os.SEEK_END:
            target = self._size + int(offset)
        else:
            raise ValueError(f"invalid whence: {whence}")
        if target < 0:
            raise ValueError("negative seek position")
        self._position = min(target, self._size)
        return self._position

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        if self._position >= self._size or size == 0:
            return b""
        remaining = self._size - self._position
        amount = remaining if size is None or size < 0 else min(int(size), remaining)
        chunks: list[bytes] = []

        header_end = len(_GZIP_HEADER)
        data_end = header_end + self._compressed_size
        while amount:
            if self._position < header_end:
                take = min(amount, header_end - self._position)
                chunks.append(_GZIP_HEADER[self._position : self._position + take])
            elif self._position < data_end:
                take = min(amount, data_end - self._position)
                source_offset = self._data_offset + self._position - header_end
                self._source.seek(source_offset)
                chunk = self._source.read(take)
                if len(chunk) != take:
                    raise FUSError("unexpected end of compressed firmware entry")
                chunks.append(chunk)
            else:
                footer_offset = self._position - data_end
                take = min(amount, len(self._footer) - footer_offset)
                chunks.append(self._footer[footer_offset : footer_offset + take])
            self._position += take
            amount -= take

        return b"".join(chunks)


class _BoundedReader(io.RawIOBase):
    def __init__(self, source: io.BufferedIOBase, size: int):
        super().__init__()
        self._source = source
        self._remaining = size

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:
        self._checkClosed()
        if self._remaining <= 0:
            return 0
        view = memoryview(buffer)
        amount = min(len(view), self._remaining)
        try:
            data = self._source.read(amount)
        except Exception as exc:
            if exc.__class__.__module__.partition(".")[0] == "indexed_gzip" or isinstance(
                exc,
                (EOFError, ValueError, zlib.error),
            ):
                raise _TarIndexUnavailable from exc
            raise
        if not data:
            raise _TarIndexUnavailable
        view[: len(data)] = data
        self._remaining -= len(data)
        return len(data)


class _PrefetchReader(io.RawIOBase):
    def __init__(self, source: io.BufferedIOBase):
        super().__init__()
        self._source = source
        self._queue: queue.Queue[bytes | BaseException | None] = queue.Queue(maxsize=2)
        self._stop = threading.Event()
        self._buffer = b""
        self._buffer_offset = 0
        self._eof = False
        self._thread = threading.Thread(target=self._produce, name="asgard-prefetch", daemon=True)
        self._thread.start()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:
        self._checkClosed()
        if not buffer:
            return 0
        if self._eof:
            return 0
        if self._buffer_offset >= len(self._buffer):
            item = self._queue.get()
            if item is None:
                self._eof = True
                return 0
            if isinstance(item, BaseException):
                raise item
            self._buffer = item
            self._buffer_offset = 0

        view = memoryview(buffer)
        amount = min(len(view), len(self._buffer) - self._buffer_offset)
        view[:amount] = self._buffer[self._buffer_offset : self._buffer_offset + amount]
        self._buffer_offset += amount
        return amount

    def close(self) -> None:
        if not self.closed:
            self._stop.set()
            while True:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break
            self._thread.join()
        super().close()

    def _put(self, item: bytes | BaseException | None) -> bool:
        while not self._stop.is_set():
            try:
                self._queue.put(item, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def _produce(self) -> None:
        try:
            while not self._stop.is_set():
                chunk = self._source.read(_ARCHIVE_COPY_CHUNK_SIZE)
                if not chunk:
                    self._put(None)
                    return
                if not self._put(chunk):
                    return
        except BaseException as exc:
            self._put(exc)


@contextmanager
def _open_prefetched_stream(source: io.BufferedIOBase) -> Iterator[io.BufferedReader]:
    prefetched = _PrefetchReader(source)
    buffered = io.BufferedReader(prefetched, buffer_size=64 * 1024)
    try:
        yield buffered
    finally:
        buffered.close()


def _zip_entry_data_offset(remote: _RemoteFirmwareArchive, entry: zipfile.ZipInfo) -> int:
    remote.reader.seek(entry.header_offset)
    header = remote.reader.read(_ZIP_LOCAL_FILE_HEADER.size)
    if len(header) != _ZIP_LOCAL_FILE_HEADER.size:
        raise FUSError(f"could not read ZIP header for {entry.filename!r}")
    (
        signature,
        _extract_version,
        flags,
        compression,
        _modified_time,
        _modified_date,
        _crc,
        _compressed_size,
        _uncompressed_size,
        filename_size,
        extra_size,
    ) = _ZIP_LOCAL_FILE_HEADER.unpack(header)
    if signature != _ZIP_LOCAL_FILE_HEADER_SIGNATURE:
        raise FUSError(f"invalid ZIP header for {entry.filename!r}")
    if flags & 1:
        raise FUSError(f"encrypted ZIP entry is not supported: {entry.filename!r}")
    if compression != entry.compress_type:
        raise FUSError(f"ZIP compression metadata does not match for {entry.filename!r}")
    return entry.header_offset + _ZIP_LOCAL_FILE_HEADER.size + filename_size + extra_size


def _tar_index_identity(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
) -> dict[str, int | str]:
    return {
        "firmware": remote.firmware_version,
        "firmware_file": remote.info.filename,
        "entry": outer_entry.filename,
        "header_offset": outer_entry.header_offset,
        "crc": outer_entry.CRC,
        "compressed_size": outer_entry.compress_size,
        "size": outer_entry.file_size,
    }


def _tar_index_paths(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
) -> tuple[Path, Path, dict[str, int | str]]:
    identity = _tar_index_identity(remote, outer_entry)
    cache_key = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    cache_home = os.environ.get("XDG_CACHE_HOME")
    cache_root = Path(cache_home).expanduser() if cache_home else Path.home() / ".cache"
    cache_dir = cache_root / "asgard" / "tar-index"
    return cache_dir / f"{cache_key}.json", cache_dir / f"{cache_key}.gzidx", identity


def _load_tar_index(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
) -> _TarIndexCache | None:
    metadata_path, index_path, identity = _tar_index_paths(remote, outer_entry)
    if not metadata_path.is_file() or not index_path.is_file():
        return None
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        if (
            payload.get("version") != _TAR_INDEX_VERSION
            or payload.get("identity") != identity
            or not isinstance(payload.get("complete"), bool)
            or not isinstance(payload.get("members"), list)
            or index_path.stat().st_size <= 0
        ):
            return None
        members: list[_IndexedTarMember] = []
        for raw_member in payload["members"]:
            if not isinstance(raw_member, dict):
                return None
            name = raw_member.get("name")
            size = raw_member.get("size")
            offset_data = raw_member.get("offset_data")
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(size, int)
                or size < 0
                or not isinstance(offset_data, int)
                or offset_data < 0
                or offset_data + size > outer_entry.file_size
            ):
                return None
            members.append(_IndexedTarMember(name=name, size=size, offset_data=offset_data))
        return _TarIndexCache(
            complete=payload["complete"],
            members=tuple(members),
            index_path=index_path,
        )
    except (OSError, TypeError, ValueError):
        return None


def _indexed_progress(members: tuple[_IndexedTarMember, ...] | list[_IndexedTarMember]) -> int:
    return max((member.offset_data + member.size for member in members), default=0)


def _prefer_indexed_member(member: _IndexedTarMember) -> bool:
    buffer_size = min(
        _TAR_INDEX_MEMBER_BUFFER_SIZE,
        max(_ARCHIVE_COPY_CHUNK_SIZE, member.size),
    )
    buffer_count = max(1, (member.size + buffer_size - 1) // buffer_size)
    return member.offset_data > buffer_count * _TAR_INDEX_SPACING


def _discard_tar_index(remote: _RemoteFirmwareArchive, outer_entry: zipfile.ZipInfo) -> None:
    metadata_path, index_path, _identity = _tar_index_paths(remote, outer_entry)
    for path in (metadata_path, index_path):
        with suppress(OSError):
            path.unlink(missing_ok=True)


def _save_tar_index(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
    indexed_source: object,
    members: list[_IndexedTarMember],
    *,
    complete: bool,
) -> None:
    if not complete and not members:
        return
    metadata_path, index_path, identity = _tar_index_paths(remote, outer_entry)
    existing = _load_tar_index(remote, outer_entry)
    if existing is not None and (
        existing.complete or (not complete and _indexed_progress(existing.members) >= _indexed_progress(members))
    ):
        return

    suffix = f".{secrets.token_hex(8)}.tmp"
    metadata_tmp = metadata_path.with_name(f"{metadata_path.name}{suffix}")
    index_tmp = index_path.with_name(f"{index_path.name}{suffix}")
    try:
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        indexed_source.export_index(filename=str(index_tmp))
        index_tmp.replace(index_path)
        payload = {
            "version": _TAR_INDEX_VERSION,
            "identity": identity,
            "complete": complete,
            "members": [
                {
                    "name": member.name,
                    "size": member.size,
                    "offset_data": member.offset_data,
                }
                for member in members
            ],
        }
        metadata_tmp.write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        metadata_tmp.replace(metadata_path)
    except Exception:
        pass
    finally:
        for path in (metadata_tmp, index_tmp):
            with suppress(OSError):
                path.unlink(missing_ok=True)


@contextmanager
def _open_indexed_firmware_entry(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
    *,
    index_path: Path | None = None,
    buffer_size: int | None = None,
) -> Iterator[io.BufferedIOBase]:
    try:
        import indexed_gzip
    except ImportError as exc:
        raise FUSError("indexed DEFLATE support is not installed; reinstall asgard") from exc

    virtual_source = _VirtualGzipReader(
        remote.reader,
        data_offset=_zip_entry_data_offset(remote, outer_entry),
        compressed_size=outer_entry.compress_size,
        crc=outer_entry.CRC,
        uncompressed_size=outer_entry.file_size,
    )
    indexed_source = indexed_gzip.IndexedGzipFile(
        fileobj=virtual_source,
        spacing=_TAR_INDEX_SPACING,
        readbuf_size=_ARCHIVE_COPY_CHUNK_SIZE,
        readall_buf_size=_ARCHIVE_COPY_CHUNK_SIZE,
        buffer_size=buffer_size or _TAR_INDEX_SCAN_BUFFER_SIZE,
    )
    try:
        if index_path is not None:
            try:
                indexed_source.import_index(filename=str(index_path))
            except Exception as exc:
                raise _TarIndexUnavailable from exc
        yield indexed_source
    finally:
        indexed_source.close()
        virtual_source.close()


@contextmanager
def _open_cached_tar_member(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
    cached_member: _IndexedTarMember,
    index_path: Path,
) -> Iterator[io.BufferedReader]:
    buffer_size = min(
        _TAR_INDEX_MEMBER_BUFFER_SIZE,
        max(_ARCHIVE_COPY_CHUNK_SIZE, cached_member.size),
    )
    with _open_indexed_firmware_entry(
        remote,
        outer_entry,
        index_path=index_path,
        buffer_size=buffer_size,
    ) as indexed_source:
        try:
            header_offset = cached_member.offset_data - tarfile.BLOCKSIZE
            if header_offset < 0 or cached_member.offset_data % tarfile.BLOCKSIZE:
                raise _TarIndexUnavailable
            indexed_source.seek(header_offset)
            header = indexed_source.read(tarfile.BLOCKSIZE)
            if len(header) != tarfile.BLOCKSIZE:
                raise _TarIndexUnavailable
            tar_info = tarfile.TarInfo.frombuf(header, encoding="utf-8", errors="surrogateescape")
            if tar_info.name != cached_member.name or tar_info.size != cached_member.size or not tar_info.isfile():
                raise _TarIndexUnavailable
        except _TarIndexUnavailable:
            raise
        except Exception as exc:
            raise _TarIndexUnavailable from exc
        bounded = _BoundedReader(indexed_source, cached_member.size)
        source = io.BufferedReader(bounded, buffer_size=64 * 1024)
        try:
            yield source
        finally:
            source.close()


@contextmanager
def _open_firmware_tar(
    remote: _RemoteFirmwareArchive,
    outer_entry: zipfile.ZipInfo,
) -> Iterator[tarfile.TarFile]:
    with remote.archive.open(outer_entry, "r") as source:
        mode = "r:" if outer_entry.compress_type == zipfile.ZIP_STORED else "r|"
        try:
            archive = tarfile.open(fileobj=source, mode=mode)
        except tarfile.TarError as exc:
            raise FUSError(f"archive entry {outer_entry.filename!r} is not a readable TAR: {exc}") from exc
        try:
            yield archive
        finally:
            archive.close()


def iter_firmware_tar_entries(
    *,
    model: str,
    region: str,
    outer_selector: str,
    firmware_version: str | None = None,
    force_firmware: bool = False,
) -> Iterator[FirmwareTarEntry]:
    with _open_remote_firmware_archive(
        model=model,
        region=region,
        firmware_version=firmware_version,
        force_firmware=force_firmware,
    ) as remote:
        outer_entry = _select_single_firmware_entry(remote.archive.infolist(), outer_selector)
        if outer_entry.compress_type == zipfile.ZIP_DEFLATED:
            cached = _load_tar_index(remote, outer_entry)
            if cached is not None and cached.complete:
                for member in cached.members:
                    yield FirmwareTarEntry(name=member.name, size=member.size)
                return

            small_archive = outer_entry.file_size <= _TAR_INDEX_MEMBER_BUFFER_SIZE
            scan_buffer_size = (
                max(_ARCHIVE_COPY_CHUNK_SIZE, outer_entry.file_size) if small_archive else _TAR_INDEX_SCAN_BUFFER_SIZE
            )
            cache_attempt = cached
            while True:
                indexed_members: list[_IndexedTarMember] = []
                scan_complete = False
                try:
                    with _open_indexed_firmware_entry(
                        remote,
                        outer_entry,
                        index_path=cache_attempt.index_path if cache_attempt is not None else None,
                        buffer_size=scan_buffer_size,
                    ) as indexed_source:
                        tar_mode = "r|" if small_archive and cache_attempt is None else "r:"
                        try:
                            archive = tarfile.open(fileobj=indexed_source, mode=tar_mode)
                        except tarfile.TarError as exc:
                            if cache_attempt is not None:
                                raise _TarIndexUnavailable from exc
                            raise FUSError(
                                f"archive entry {outer_entry.filename!r} is not a readable TAR: {exc}"
                            ) from exc
                        try:
                            for member in archive:
                                if not member.isfile():
                                    continue
                                indexed_member = _IndexedTarMember(
                                    name=member.name,
                                    size=member.size,
                                    offset_data=member.offset_data,
                                )
                                indexed_members.append(indexed_member)
                                yield FirmwareTarEntry(name=member.name, size=member.size)
                            while indexed_source.read(_ARCHIVE_COPY_CHUNK_SIZE):
                                pass
                            scan_complete = True
                        finally:
                            archive.close()
                            _save_tar_index(
                                remote,
                                outer_entry,
                                indexed_source,
                                indexed_members,
                                complete=scan_complete,
                            )
                    return
                except _TarIndexUnavailable:
                    if cache_attempt is None:
                        raise FUSError(f"cached TAR index for {outer_entry.filename!r} could not be read")
                    _discard_tar_index(remote, outer_entry)
                    cache_attempt = None
                except FUSError:
                    raise
                except Exception as exc:
                    raise FUSError(f"could not read TAR entry {outer_entry.filename!r}: {exc}") from exc

        try:
            with _open_firmware_tar(remote, outer_entry) as archive:
                for member in archive:
                    if member.isfile():
                        yield FirmwareTarEntry(name=member.name, size=member.size)
        except FUSError:
            raise
        except Exception as exc:
            raise FUSError(f"could not read TAR entry {outer_entry.filename!r}: {exc}") from exc


def _entry_output_path(output_dir: Path, entry_name: str) -> Path:
    filename = PurePosixPath(str(entry_name or "").replace("\\", "/")).name
    if not filename or filename in {".", ".."}:
        raise FUSError(f"invalid archive entry name: {entry_name!r}")
    return output_dir / filename


def _copy_stream_with_progress(
    source: io.BufferedIOBase,
    output: io.BufferedWriter,
    *,
    label: str,
    total_size: int,
    initial: bytes = b"",
) -> int:
    started_at = time.monotonic()
    last_render = 0.0
    done = len(initial)
    if initial:
        output.write(initial)
    while True:
        chunk = source.read(_ARCHIVE_COPY_CHUNK_SIZE)
        if not chunk:
            break
        output.write(chunk)
        done += len(chunk)
        now = time.monotonic()
        if now - last_render >= _PROGRESS_REFRESH_S and (not total_size or done < total_size):
            _render_progress(label, done, total_size, started_at)
            last_render = now
    _render_progress(label, done, total_size, started_at, complete=True)
    return done


def _read_exact_stream(source: io.BufferedIOBase, size: int, description: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            raise FUSError(f"unexpected end of {description}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _copy_sparse_stream(
    source: io.BufferedIOBase,
    output: io.BufferedWriter,
    *,
    header_prefix: bytes,
    label: str,
) -> int:
    header = header_prefix + _read_exact_stream(
        source,
        _SPARSE_HEADER.size - len(header_prefix),
        "sparse image header",
    )
    (
        _magic,
        major_version,
        _minor_version,
        file_header_size,
        chunk_header_size,
        block_size,
        total_blocks,
        total_chunks,
        image_checksum,
    ) = _SPARSE_HEADER.unpack(header)
    if major_version != 1:
        raise FUSError(f"unsupported sparse image version: {major_version}")
    if file_header_size < _SPARSE_HEADER.size:
        raise FUSError(f"invalid sparse file header size: {file_header_size}")
    if chunk_header_size < _SPARSE_CHUNK_HEADER.size:
        raise FUSError(f"invalid sparse chunk header size: {chunk_header_size}")
    if block_size <= 0 or block_size % 4:
        raise FUSError(f"invalid sparse block size: {block_size}")
    raw_size = block_size * total_blocks
    if raw_size > (1 << 63) - 1:
        raise FUSError(f"sparse image is too large: {raw_size} bytes")
    if file_header_size > _SPARSE_HEADER.size:
        _read_exact_stream(source, file_header_size - _SPARSE_HEADER.size, "extended sparse header")

    zero_buffer = bytes(_ARCHIVE_COPY_CHUNK_SIZE)
    blocks_written = 0
    logical_done = 0
    checksum = 0
    started_at = time.monotonic()
    last_render = 0.0

    def update_progress(size: int) -> None:
        nonlocal logical_done, last_render
        logical_done += size
        now = time.monotonic()
        if now - last_render >= _PROGRESS_REFRESH_S and logical_done < raw_size:
            _render_progress(label, logical_done, raw_size, started_at)
            last_render = now

    def process_repeated(pattern: bytes, size: int, *, write: bool) -> None:
        nonlocal checksum
        repeat_buffer = zero_buffer if pattern == b"\0\0\0\0" else pattern * (_ARCHIVE_COPY_CHUNK_SIZE // 4)
        remaining = size
        if not write:
            output.seek(size, os.SEEK_CUR)
        while remaining:
            amount = min(remaining, len(repeat_buffer))
            chunk = repeat_buffer[:amount]
            if write:
                output.write(chunk)
            checksum = zlib.crc32(chunk, checksum)
            update_progress(amount)
            remaining -= amount

    for chunk_index in range(total_chunks):
        raw_chunk_header = _read_exact_stream(source, chunk_header_size, f"sparse chunk {chunk_index + 1} header")
        chunk_type, _reserved, chunk_blocks, total_size = _SPARSE_CHUNK_HEADER.unpack_from(raw_chunk_header)
        if total_size < chunk_header_size:
            raise FUSError(f"invalid sparse chunk {chunk_index + 1} size: {total_size}")
        data_size = total_size - chunk_header_size

        if chunk_type == _SPARSE_CRC32:
            if chunk_blocks != 0 or data_size != 4:
                raise FUSError(f"invalid sparse CRC chunk {chunk_index + 1}")
            expected_checksum = struct.unpack("<I", _read_exact_stream(source, 4, "sparse CRC32"))[0]
            if expected_checksum != checksum:
                raise FUSError(f"sparse CRC mismatch: expected {expected_checksum:08x}, got {checksum:08x}")
            continue

        if chunk_blocks > total_blocks - blocks_written:
            raise FUSError(f"sparse chunk {chunk_index + 1} exceeds the output size")
        chunk_size = chunk_blocks * block_size
        blocks_written += chunk_blocks

        if chunk_type == _SPARSE_RAW:
            if data_size != chunk_size:
                raise FUSError(f"invalid sparse RAW chunk {chunk_index + 1}")
            remaining = chunk_size
            while remaining:
                amount = min(remaining, _ARCHIVE_COPY_CHUNK_SIZE)
                data = _read_exact_stream(source, amount, "sparse RAW data")
                output.write(data)
                checksum = zlib.crc32(data, checksum)
                update_progress(len(data))
                remaining -= len(data)
        elif chunk_type == _SPARSE_FILL:
            if data_size != 4:
                raise FUSError(f"invalid sparse FILL chunk {chunk_index + 1}")
            pattern = _read_exact_stream(source, 4, "sparse fill pattern")
            process_repeated(pattern, chunk_size, write=pattern != b"\0\0\0\0")
        elif chunk_type == _SPARSE_DONT_CARE:
            if data_size != 0:
                raise FUSError(f"invalid sparse DONT_CARE chunk {chunk_index + 1}")
            process_repeated(b"\0\0\0\0", chunk_size, write=False)
        else:
            raise FUSError(f"unknown sparse chunk type: 0x{chunk_type:04x}")

    if blocks_written != total_blocks:
        raise FUSError(f"incomplete sparse image: expected {total_blocks} blocks, got {blocks_written}")
    if image_checksum and image_checksum != checksum:
        raise FUSError(f"sparse image checksum mismatch: expected {image_checksum:08x}, got {checksum:08x}")
    if source.read(1):
        raise FUSError("sparse image contains trailing data")
    output.truncate(raw_size)
    _render_progress(label, raw_size, raw_size, started_at, complete=True)
    return raw_size


def _copy_image_stream(
    source: io.BufferedIOBase,
    output: io.BufferedWriter,
    *,
    label: str,
    total_size: int,
) -> int:
    prefix = source.read(4)
    if prefix == struct.pack("<I", _SPARSE_MAGIC):
        return _copy_sparse_stream(source, output, header_prefix=prefix, label=label)
    done = _copy_stream_with_progress(
        source,
        output,
        label=label,
        total_size=total_size,
        initial=prefix,
    )
    if total_size and done != total_size:
        raise FUSError(f"incomplete output: expected {total_size} bytes, got {done}")
    return done


def _copy_lz4_stream(source: io.BufferedIOBase, output: io.BufferedWriter, *, label: str) -> int:
    try:
        from lz4 import frame as lz4_frame
    except ImportError as exc:
        raise FUSError("LZ4 support is not installed; reinstall asgard") from exc

    try:
        frame_info = lz4_frame.get_frame_info(source.peek(19)[:19])
        total_size = int(frame_info.get("content_size") or 0)
        with (
            lz4_frame.LZ4FrameFile(source, mode="rb") as decoded,
            _open_prefetched_stream(decoded) as prefetched,
        ):
            done = _copy_image_stream(prefetched, output, label=label, total_size=total_size)
    except (_TarIndexUnavailable, FUSError, OSError):
        raise
    except Exception as exc:
        raise FUSError(f"could not decompress LZ4 member: {exc}") from exc
    return done


def _write_firmware_tar_member(
    source: io.BufferedIOBase,
    part_path: Path,
    *,
    requested_name: str,
    output_name: str,
    member_size: int,
) -> None:
    with part_path.open("xb") as output:
        label = f"Extracting {PurePosixPath(output_name).name}"
        if requested_name.lower().endswith(".lz4"):
            _copy_lz4_stream(source, output, label=label)
        else:
            with _open_prefetched_stream(source) as prefetched:
                _copy_image_stream(
                    prefetched,
                    output,
                    label=label,
                    total_size=member_size,
                )


def download_firmware_tar_member(
    *,
    model: str,
    region: str,
    outer_selector: str,
    member_name: str,
    out_dir: str | os.PathLike[str],
    firmware_version: str | None = None,
    force_firmware: bool = False,
) -> Path:
    requested_name = str(member_name or "").strip().replace("\\", "/")
    if not requested_name:
        raise ValueError("TAR member name is required")
    output_name = requested_name[:-4] if requested_name.lower().endswith(".lz4") else requested_name
    output_dir = Path(out_dir).expanduser()
    if output_dir.exists() and not output_dir.is_dir():
        raise FUSError(f"member output must be a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = _entry_output_path(output_dir.resolve(), output_name)
    part_path = _partial_output_path(destination)
    if destination.exists():
        raise FUSError(f"{destination} already exists")
    if part_path.exists():
        raise FUSError(f"{part_path} already exists")

    with _open_remote_firmware_archive(
        model=model,
        region=region,
        firmware_version=firmware_version,
        force_firmware=force_firmware,
    ) as remote:
        outer_entry = _select_single_firmware_entry(remote.archive.infolist(), outer_selector)
        _print_info(f"model: {remote.model}")
        _print_info(f"region: {remote.region}")
        _print_info(f"firmware: {remote.firmware_version}")
        _print_info(f"archive: {outer_entry.filename}")
        _print_info(f"member: {requested_name}")
        _print_info(f"output: {destination}")

        output_complete = False
        try:
            member_copied = False
            cached: _TarIndexCache | None = None
            cached_member: _IndexedTarMember | None = None
            if outer_entry.compress_type == zipfile.ZIP_DEFLATED:
                cached = _load_tar_index(remote, outer_entry)
                cached_member = (
                    next(
                        (member for member in cached.members if member.name == requested_name),
                        None,
                    )
                    if cached is not None
                    else None
                )
                if cached_member is not None and _prefer_indexed_member(cached_member):
                    try:
                        with _open_cached_tar_member(
                            remote,
                            outer_entry,
                            cached_member,
                            cached.index_path,
                        ) as member_source:
                            _write_firmware_tar_member(
                                member_source,
                                part_path,
                                requested_name=requested_name,
                                output_name=output_name,
                                member_size=cached_member.size,
                            )
                        member_copied = True
                    except (_TarIndexUnavailable, FUSError):
                        part_path.unlink(missing_ok=True)
                        _discard_tar_index(remote, outer_entry)

            if not member_copied:
                if cached is not None and cached.complete and cached_member is None:
                    raise FUSError(f"TAR member not found: {requested_name}")

                with _open_firmware_tar(remote, outer_entry) as archive:
                    for member in archive:
                        if member.name != requested_name:
                            continue
                        if not member.isfile():
                            raise FUSError(f"TAR member is not a regular file: {requested_name}")
                        member_source = archive.extractfile(member)
                        if member_source is None:
                            raise FUSError(f"could not open TAR member: {requested_name}")
                        with member_source:
                            _write_firmware_tar_member(
                                member_source,
                                part_path,
                                requested_name=requested_name,
                                output_name=output_name,
                                member_size=member.size,
                            )
                        member_copied = True
                        break

            if not member_copied:
                raise FUSError(f"TAR member not found: {requested_name}")
            if destination.exists():
                raise FUSError(f"{destination} already exists")
            part_path.replace(destination)
            output_complete = True
            return destination
        except FUSError:
            raise
        except Exception as exc:
            raise FUSError(f"could not extract TAR member {requested_name!r}: {exc}") from exc
        finally:
            if not output_complete:
                part_path.unlink(missing_ok=True)


def download_firmware_entries(
    *,
    model: str,
    region: str,
    selectors: tuple[str, ...] | list[str],
    out_dir: str | os.PathLike[str],
    firmware_version: str | None = None,
    force_firmware: bool = False,
) -> tuple[Path, ...]:
    selector_values = tuple(str(selector) for selector in selectors)
    if not selector_values:
        raise ValueError("at least one entry selector is required")
    output_dir = Path(out_dir).expanduser()
    if output_dir.exists() and not output_dir.is_dir():
        raise FUSError(f"entry output must be a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_root = output_dir.resolve()

    with _open_remote_firmware_archive(
        model=model,
        region=region,
        firmware_version=firmware_version,
        force_firmware=force_firmware,
    ) as remote:
        selected = _select_firmware_entries(remote.archive.infolist(), selector_values)
        destinations: list[tuple[zipfile.ZipInfo, Path]] = []
        destination_keys: set[str] = set()
        for entry in selected:
            destination = _entry_output_path(output_root, entry.filename)
            destination_key = os.path.normcase(str(destination))
            if destination_key in destination_keys:
                raise FUSError(f"multiple archive entries map to the same output path: {destination}")
            destination_keys.add(destination_key)
            if destination.exists():
                raise FUSError(f"{destination} already exists")
            destinations.append((entry, destination))

        _print_info(f"model: {remote.model}")
        _print_info(f"region: {remote.region}")
        _print_info(f"firmware: {remote.firmware_version}")
        _print_info(f"filename: {remote.info.filename}")
        _print_info(f"size: {_format_bytes(remote.info.size)}")
        _print_info(f"entries: {len(destinations)}")
        _print_info(f"output: {output_dir}")

        completed_paths: list[Path] = []
        for entry, destination in destinations:
            complete = False
            part_path = _partial_output_path(destination)
            try:
                with (
                    part_path.open("xb") as output,
                    remote.archive.open(entry, "r") as source,
                    _open_prefetched_stream(source) as prefetched,
                ):
                    done = _copy_stream_with_progress(
                        prefetched,
                        output,
                        label=f"Downloading {PurePosixPath(entry.filename).name}",
                        total_size=entry.file_size,
                    )
                    if done != entry.file_size:
                        raise FUSError(
                            f"incomplete archive entry {entry.filename!r}: expected {entry.file_size} bytes, got {done}"
                        )
                if destination.exists():
                    raise FUSError(f"{destination} already exists")
                part_path.replace(destination)
                complete = True
                completed_paths.append(destination)
            except FUSError:
                raise
            except Exception as exc:
                raise FUSError(f"could not extract archive entry {entry.filename!r}: {exc}") from exc
            finally:
                if not complete:
                    part_path.unlink(missing_ok=True)

        return tuple(completed_paths)


def _decrypt_range(
    in_path: Path,
    out_path: Path,
    key: bytes,
    start: int,
    end: int,
    progress: Callable[[int], None] | None = None,
) -> None:
    cipher = AES.new(key, AES.MODE_ECB)
    with in_path.open("rb") as inf, out_path.open("r+b") as outf:
        inf.seek(start)
        outf.seek(start)
        remaining = end - start + 1
        while remaining > 0:
            chunk_size = min(1024 * 1024, remaining)
            chunk_size -= chunk_size % _AES_BLOCK_SIZE
            if chunk_size == 0:
                chunk_size = remaining
            data = inf.read(chunk_size)
            if len(data) != chunk_size:
                raise FUSError("unexpected end of encrypted input")
            outf.write(cipher.decrypt(data))
            remaining -= chunk_size
            if progress is not None:
                progress(chunk_size)


def _finalize_decrypted_file(path: Path) -> None:
    with path.open("r+b") as fh:
        if fh.seek(0, os.SEEK_END) <= 0:
            raise FUSError("decrypted file is empty")
        fh.seek(-_AES_BLOCK_SIZE, os.SEEK_END)
        tail = fh.read(_AES_BLOCK_SIZE)
        final_size = fh.tell() - len(tail) + len(_pkcs7_unpad(tail))
        fh.truncate(final_size)


def decrypt_firmware(
    *,
    version: str | None,
    model: str,
    region: str,
    in_file: str | os.PathLike[str],
    out_file: str | os.PathLike[str],
    enc_ver: int = 4,
    force_firmware: bool = False,
) -> Path:
    in_path = Path(in_file).expanduser()
    out_path = Path(out_file).expanduser()
    if not in_path.is_file():
        raise FileNotFoundError(in_path)
    length = in_path.stat().st_size
    if length % _AES_BLOCK_SIZE != 0:
        raise FUSError("invalid encrypted input size")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if int(enc_ver) == 4:
        key = get_v4_key(model, region, firmware_version=version, force_firmware=force_firmware)
    else:
        if not str(version or "").strip():
            raise ValueError("firmware version is required for enc2 decrypt")
        key = get_v2_key(str(version), model, region)

    ranges = _build_range_parts(length, part_count=_DECRYPT_THREADS)
    with out_path.open("wb") as fh:
        fh.truncate(length)

    done = 0
    done_lock = threading.Lock()
    started_at = time.monotonic()

    def worker(item: dict[str, int]) -> None:
        def update_progress(size: int) -> None:
            nonlocal done
            with done_lock:
                done += size

        _decrypt_range(in_path, out_path, key, int(item["start"]), int(item["end"]), progress=update_progress)

    with ThreadPoolExecutor(max_workers=len(ranges) or 1) as executor:
        futures = [executor.submit(worker, item) for item in ranges]
        while True:
            completed = all(future.done() for future in futures)
            with done_lock:
                current_done = done
            _render_progress(
                "Decrypting", current_done, length, started_at, complete=completed and current_done >= length
            )
            if completed:
                for future in futures:
                    future.result()
                break
            time.sleep(_PROGRESS_REFRESH_S)

    _finalize_decrypted_file(out_path)
    return out_path


def _download_output_path(
    *,
    filename: str,
    out_dir: str | os.PathLike[str] | None,
    out_file: str | os.PathLike[str] | None,
    auto_decrypt: bool,
) -> Path:
    if out_file:
        path = Path(out_file).expanduser()
    else:
        path = Path(out_dir or ".").expanduser() / filename
    return decrypted_output_path(path) if auto_decrypt else path


def _encrypted_target_path(
    *,
    filename: str,
    out_dir: str | os.PathLike[str] | None,
    out_file: str | os.PathLike[str] | None,
) -> Path:
    if out_file:
        out_path = Path(out_file).expanduser()
        if out_path.suffix.lower() in {".enc2", ".enc4"}:
            return out_path
        return out_path.with_name(f"{out_path.name}.enc4")
    return Path(out_dir or ".").expanduser() / filename


def _finalize_stream_decrypted_file(part_path: Path, final_path: Path) -> Path:
    if not part_path.is_file():
        raise FileNotFoundError(part_path)
    with part_path.open("r+b") as fh:
        if fh.seek(0, os.SEEK_END) <= 0:
            raise FUSError(f"partial file is empty: {part_path}")
        fh.seek(-_AES_BLOCK_SIZE, os.SEEK_END)
        tail = fh.read(_AES_BLOCK_SIZE)
        final_size = fh.tell() - len(tail) + len(_pkcs7_unpad(tail))
        fh.truncate(final_size)
    if final_path.exists():
        final_path.unlink()
    part_path.replace(final_path)
    return final_path


def _download_ranges_parallel(
    *,
    client: FUSClient,
    remote_path: str,
    out_path: Path,
    total_size: int,
    ranges: list[dict[str, int]],
    decrypt_key: bytes | None = None,
    recover_download: Callable[[], None] | None = None,
) -> None:
    state_lock = threading.Lock()
    stop_event = threading.Event()
    errors: list[Exception] = []
    started_at = time.monotonic()
    last_meta_save = 0.0
    meta_path = _resume_state_path(out_path)
    initial_done = _resume_done_bytes(ranges)
    recovery_lock = threading.Lock()

    def worker(range_idx: int) -> None:
        segment = ranges[range_idx]
        seg_end = int(segment["end"])
        cipher = AES.new(decrypt_key, AES.MODE_ECB) if decrypt_key is not None else None
        pending = b""
        with out_path.open("r+b", buffering=0) as fh:
            while not stop_event.is_set():
                with state_lock:
                    write_offset = int(segment["offset"])
                request_start = write_offset + len(pending)
                if request_start > seg_end:
                    if pending:
                        stop_event.set()
                        with state_lock:
                            errors.append(FUSError(f"range {range_idx + 1} ended with a partial encrypted block"))
                    return
                response: requests.Response | None = None
                try:
                    response = client.download_file(remote_path, start=request_start, end=seg_end)
                    fh.seek(write_offset)
                    for chunk in response.iter_content(chunk_size=_RANGE_CHUNK_SIZE):
                        if stop_event.is_set():
                            return
                        if not chunk:
                            continue
                        remaining = seg_end + 1 - write_offset
                        if cipher is None:
                            if len(chunk) > remaining:
                                raise FUSError(f"range {range_idx + 1} received more data than requested")
                            fh.write(chunk)
                            write_offset += len(chunk)
                        else:
                            pending += chunk
                            block_size = (len(pending) // _AES_BLOCK_SIZE) * _AES_BLOCK_SIZE
                            if block_size:
                                if block_size > remaining:
                                    raise FUSError(f"range {range_idx + 1} received more data than requested")
                                block = pending[:block_size]
                                pending = pending[block_size:]
                                plain = cipher.decrypt(block)
                                fh.write(plain)
                                write_offset += len(plain)
                        with state_lock:
                            segment["offset"] = write_offset
                    if pending:
                        raise FUSError(f"range {range_idx + 1} ended with a partial encrypted block")
                    if write_offset != seg_end + 1:
                        raise FUSError(f"range {range_idx + 1} incomplete: expected {seg_end + 1}, got {write_offset}")
                    return
                except (requests.RequestException, OSError, RetryableDownloadError) as exc:
                    attempt = int(segment.get("attempts", 0)) + 1
                    segment["attempts"] = attempt
                    if attempt > _DOWNLOAD_RETRIES:
                        stop_event.set()
                        with state_lock:
                            errors.append(FUSError(f"range {range_idx + 1} failed after retries: {exc}"))
                        return
                    if recover_download is not None and attempt % _DOWNLOAD_RECOVERY_INTERVAL == 0:
                        try:
                            with recovery_lock:
                                recover_download()
                            with state_lock:
                                segment["attempts"] = 0
                        except Exception as recovery_exc:
                            stop_event.set()
                            with state_lock:
                                errors.append(FUSError(f"download recovery failed: {recovery_exc}"))
                            return
                        time.sleep(_RATE_LIMIT_COOLDOWN_S)
                    time.sleep(_RETRY_BACKOFF_S * attempt)
                except Exception as exc:
                    stop_event.set()
                    with state_lock:
                        errors.append(exc)
                    return
                finally:
                    if response is not None:
                        response.close()

    threads = [threading.Thread(target=worker, args=(idx,), daemon=True) for idx in range(len(ranges))]
    for thread in threads:
        thread.start()
        time.sleep(_THREAD_STAGGER_S)

    try:
        while any(thread.is_alive() for thread in threads):
            now = time.monotonic()
            with state_lock:
                done = _resume_done_bytes(ranges)
                err = errors[0] if errors else None
                snapshot = [dict(item) for item in ranges]
            _render_progress(
                "Downloading",
                done,
                total_size,
                started_at,
                speed_done=max(0, done - initial_done),
                complete=False,
            )
            if now - last_meta_save >= _RESUME_META_SAVE_INTERVAL_S:
                _save_range_resume_state(meta_path, total_size, snapshot)
                last_meta_save = now
            if err is not None:
                break
            time.sleep(_PROGRESS_REFRESH_S)
    finally:
        stop_event.set()
        for thread in threads:
            thread.join()

    with state_lock:
        done = _resume_done_bytes(ranges)
        err = errors[0] if errors else None
        snapshot = [dict(item) for item in ranges]
    _save_range_resume_state(meta_path, total_size, snapshot)
    _render_progress(
        "Downloading",
        done,
        total_size,
        started_at,
        speed_done=max(0, done - initial_done),
        complete=err is None and done >= total_size,
    )
    if err is not None:
        raise err
    if done != total_size:
        raise FUSError(f"incomplete download: expected {total_size} bytes, received {done}")


def download_firmware(
    *,
    model: str,
    region: str,
    firmware_version: str | None = None,
    force_firmware: bool = False,
    out_dir: str | os.PathLike[str] | None = None,
    out_file: str | os.PathLike[str] | None = None,
    resume: bool = False,
    auto_decrypt: bool = False,
) -> DownloadResult:
    model_u, region_u = _device_codes(model, region)

    client = FUSClient()
    info = _resolve_versioned_info(client, model_u, region_u, str(firmware_version) if force_firmware else None)
    firmware = info.binary_version or ""
    if not firmware:
        raise FUSError("FUS did not return a firmware version")

    final_path = _download_output_path(
        filename=info.filename,
        out_dir=out_dir,
        out_file=out_file,
        auto_decrypt=auto_decrypt,
    )
    encrypted_path = _encrypted_target_path(filename=info.filename, out_dir=out_dir, out_file=out_file)
    temp_path = _partial_output_path(final_path) if auto_decrypt else encrypted_path
    final_path.parent.mkdir(parents=True, exist_ok=True)

    if final_path.exists() and auto_decrypt:
        raise FUSError(f"{final_path} already exists")
    if encrypted_path.exists() and not auto_decrypt and not resume:
        raise FUSError(f"{encrypted_path} already exists, use --resume or choose another output")

    ranges, meta_path = _prepare_range_resume_state(temp_path, info.size, resume)
    done_before = _resume_done_bytes(ranges)

    initialize_download(client, info, region_u)
    remote_path = f"{info.model_path}{info.filename}"

    def recover_download() -> None:
        client.refresh_auth()
        initialize_download(client, info, region_u)

    _print_info(f"model: {model_u}")
    _print_info(f"region: {region_u}")
    _print_info(f"firmware: {firmware}")
    _print_info(f"filename: {info.filename}")
    _print_info(f"size: {_format_bytes(info.size)}")
    _print_info(f"output: {final_path if auto_decrypt else temp_path}")
    if done_before:
        _print_info(f"resume: {_format_bytes(done_before)}")

    if not auto_decrypt:
        if done_before < info.size:
            _download_ranges_parallel(
                client=client,
                remote_path=remote_path,
                out_path=temp_path,
                total_size=info.size,
                ranges=ranges,
                recover_download=recover_download,
            )
        meta_path.unlink(missing_ok=True)
        return DownloadResult(temp_path, None, firmware, info.filename, info.size)

    decrypt_key = _decryption_key_from_info(info, model_u, region_u)
    if done_before < info.size:
        _download_ranges_parallel(
            client=client,
            remote_path=remote_path,
            out_path=temp_path,
            total_size=info.size,
            ranges=ranges,
            decrypt_key=decrypt_key,
            recover_download=recover_download,
        )
    meta_path.unlink(missing_ok=True)
    final_stream_path = _finalize_stream_decrypted_file(temp_path, final_path)
    return DownloadResult(encrypted_path, final_stream_path, firmware, info.filename, info.size)
