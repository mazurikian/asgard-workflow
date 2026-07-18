# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

import requests

from . import __version__, archive, fus
from .errors import FUSError
from .progress import format_bytes

_HISTORY_WRAP_WIDTH = 100
_FIRMWARE_HELP = "Firmware version to use, for example S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2Z"
_HISTORY_DETAIL_SKIP_TAGS = {
    "ANDROID_VERSION",
    "BINARY_ANDROID_VERSION",
    "BINARY_DISPLAY_NAME",
    "BINARY_DISPLAY_VERSION",
    "BINARY_INDEX",
    "BINARY_LOCAL_CODE",
    "BINARY_MODEL_DISPLAYNAME",
    "BINARY_MODEL_NAME",
    "BINARY_NATURE",
    "BINARY_OPEN_DATE",
    "BINARY_OS_NAME",
    "BINARY_OS_VERSION",
    "BINARY_SEQUENCE",
    "BINARY_SW_DISPLAYVERSION",
    "BINARY_SW_VERSION",
    "DEVICE_DISPLAY_NAME",
    "DEVICE_LOCAL_CODE",
    "DEVICE_MODEL_NAME",
    "DISPLAY_NAME",
    "DISPLAY_VERSION",
    "LOCAL_CODE",
    "MODEL_NAME",
    "OS_NAME",
    "OS_VERSION",
    "SW_DISPLAYVERSION",
}


def _join_history_values(values: tuple[str, ...]) -> str:
    return " | ".join(value for value in values if value)


def _format_labeled_value(label: str, value: str, *, indent: str = "  ", label_width: int = 12) -> list[str]:
    text = str(value or "")
    prefix = f"{indent}{label:<{label_width}}: "
    continuation = " " * len(prefix)
    wrap_width = max(24, _HISTORY_WRAP_WIDTH - len(prefix))
    wrapped = textwrap.wrap(
        text,
        width=wrap_width,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    return [prefix + wrapped[0], *(continuation + line for line in wrapped[1:])]


def _format_history_entry(row: fus.FirmwareHistoryEntry) -> str:
    title_parts = [f"sequence {row.sequence or '?'}", f"index {row.index or '?'}"]
    if row.open_date:
        title_parts.append(row.open_date)
    lines = [", ".join(title_parts)]

    fields = [
        ("Firmware", row.firmware_version),
        ("Android", row.android_version),
        ("Nature", _join_history_values(row.natures)),
        ("OS", row.os_name),
        ("Model", row.model_name),
        ("Name", row.display_name),
        ("Region", row.local_code),
        ("Display", row.display_version),
    ]
    if row.sw_display_version and row.sw_display_version != row.firmware_version:
        fields.append(("SW display", row.sw_display_version))
    for label, value in fields:
        if value:
            lines.extend(_format_labeled_value(label, value))

    extra_fields = []
    for tag, values in row.fields.items():
        if tag in _HISTORY_DETAIL_SKIP_TAGS:
            continue
        value = _join_history_values(values)
        if value:
            extra_fields.append((tag, value))
    if extra_fields:
        lines.append("  Extra")
        for tag, value in extra_fields:
            lines.extend(_format_labeled_value(tag, value, indent="    ", label_width=24))

    return "\n".join(lines)


def _add_device_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("model")
    parser.add_argument("region")


def _add_firmware_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--firmware", help=_FIRMWARE_HELP)


def _download_output_args(output: str) -> tuple[Path | None, Path | None]:
    path = Path(output).expanduser()
    if path.is_dir() or path.suffix == "":
        return path, None
    return None, path


def _print_error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="asgard", description=f"asgard {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("checkupdate", help="Get the latest firmware version")
    _add_device_args(check_parser)

    history_parser = subparsers.add_parser("history", help="Show firmware history for a device and CSC")
    _add_device_args(history_parser)
    history_parser.add_argument("--json", action="store_true", help="Output all SmartHistory fields as JSON")

    download_parser = subparsers.add_parser("download", help="Download firmware from FUS")
    _add_device_args(download_parser)
    _add_firmware_arg(download_parser)
    download_parser.add_argument(
        "-o",
        "--output",
        help="Output file or directory; --archive and --file use a directory",
    )
    download_parser.add_argument("--resume", action="store_true")
    download_parser.add_argument("--decrypt", action="store_true", help="Decrypt while downloading")
    content_mode = download_parser.add_mutually_exclusive_group()
    content_mode.add_argument(
        "--list-entries",
        action="store_true",
        help="List archives in the firmware ZIP, or files inside --archive when combined",
    )
    content_mode.add_argument(
        "--file",
        metavar="NAME",
        help="Stream one file from --archive; LZ4 and sparse images are decoded automatically",
    )
    content_mode.add_argument(
        "--list-partitions",
        action="store_true",
        help="List partitions in the super image inside --archive",
    )
    content_mode.add_argument(
        "--partition",
        action="append",
        metavar="NAME",
        help="Stream a partition from the super image; repeat to extract multiple partitions",
    )
    content_mode.add_argument(
        "--unpack-super",
        action="store_true",
        help="Stream every partition from the super image",
    )
    download_parser.add_argument(
        "--archive",
        action="append",
        metavar="SELECTOR",
        help="Select an archive in the firmware ZIP; repeat or use a glob such as '*.zip'",
    )
    download_parser.add_argument(
        "--keep-sparse",
        action="store_true",
        help="Keep an Android sparse image instead of converting it to raw",
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt an encrypted FUS package")
    _add_device_args(decrypt_parser)
    decrypt_parser.add_argument("input")
    decrypt_parser.add_argument("-o", "--output")
    _add_firmware_arg(decrypt_parser)
    decrypt_parser.add_argument("--enc-ver", type=int, choices=[2, 4], default=4)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "checkupdate":
            version = fus.get_latest_version(args.model, args.region)
            print(version)
            return 0

        if args.command == "history":
            rows = fus.get_firmware_history(args.model, args.region)
            if not rows:
                print("No history found.")
                return 0
            if args.json:
                print(json.dumps([row.to_dict() for row in rows], indent=2, sort_keys=True))
                return 0
            for idx, row in enumerate(rows):
                if idx:
                    print()
                print(_format_history_entry(row))
            return 0

        if args.command == "download":
            if args.keep_sparse and not args.file:
                parser.error("--keep-sparse requires --file")

            if args.list_entries:
                if args.resume:
                    parser.error("--resume cannot be used with --list-entries")
                if args.decrypt:
                    parser.error("--decrypt cannot be used with --list-entries")
                if args.output:
                    parser.error("--output cannot be used with --list-entries")
                if args.archive:
                    if len(args.archive) != 1:
                        parser.error("listing files requires exactly one --archive selector")
                    print(f"{'Size':>12}  Name")
                    for entry in archive.iter_firmware_tar_entries(
                        model=args.model,
                        region=args.region,
                        firmware_version=args.firmware,
                        outer_selector=args.archive[0],
                    ):
                        print(f"{format_bytes(entry.size):>12}  {entry.name}")
                    return 0
                listing = archive.list_firmware_entries(
                    model=args.model,
                    region=args.region,
                    firmware_version=args.firmware,
                )
                print(f"firmware: {listing.firmware_version}")
                print(f"filename: {listing.filename}")
                print(f"size: {format_bytes(listing.size)}")
                print()
                print(f"{'Size':>12} {'Compressed':>12}  Name")
                for entry in listing.entries:
                    print(f"{format_bytes(entry.size):>12} {format_bytes(entry.compressed_size):>12}  {entry.name}")
                return 0

            if args.list_partitions:
                if not args.archive or len(args.archive) != 1:
                    parser.error("--list-partitions requires exactly one --archive selector")
                if args.resume:
                    parser.error("--resume cannot be used with --list-partitions")
                if args.decrypt:
                    parser.error("--decrypt cannot be used with --list-partitions")
                if args.output:
                    parser.error("--output cannot be used with --list-partitions")
                print(f"{'Size':>12}  Name")
                for partition in archive.iter_firmware_super_partitions(
                    model=args.model,
                    region=args.region,
                    firmware_version=args.firmware,
                    outer_selector=args.archive[0],
                ):
                    print(f"{format_bytes(partition.size):>12}  {partition.name}")
                return 0

            if args.file:
                if not args.archive or len(args.archive) != 1:
                    parser.error("--file requires exactly one --archive selector")
                if args.resume:
                    parser.error("--resume is not supported with --file")
                if args.decrypt:
                    parser.error("--decrypt is not needed with --file")
                if not args.output:
                    parser.error("--output is required with --file")
                path = archive.download_firmware_tar_member(
                    model=args.model,
                    region=args.region,
                    firmware_version=args.firmware,
                    outer_selector=args.archive[0],
                    member_name=args.file,
                    out_dir=args.output,
                    keep_sparse=args.keep_sparse,
                )
                print(path)
                return 0

            if args.partition is not None or args.unpack_super:
                option = "--partition" if args.partition is not None else "--unpack-super"
                if not args.archive or len(args.archive) != 1:
                    parser.error(f"{option} requires exactly one --archive selector")
                if args.resume:
                    parser.error(f"--resume is not supported with {option}")
                if args.decrypt:
                    parser.error(f"--decrypt is not needed with {option}")
                if not args.output:
                    parser.error(f"--output is required with {option}")
                paths = archive.download_firmware_super_partitions(
                    model=args.model,
                    region=args.region,
                    firmware_version=args.firmware,
                    outer_selector=args.archive[0],
                    partitions=tuple(args.partition) if args.partition is not None else None,
                    output=args.output,
                )
                for path in paths:
                    print(path)
                return 0

            if not args.output:
                parser.error("--output is required unless a listing option is used")

            if args.archive:
                if args.resume:
                    parser.error("--resume is not supported with --archive")
                if args.decrypt:
                    parser.error("--decrypt is not needed with --archive; archives are decrypted automatically")
                paths = archive.download_firmware_entries(
                    model=args.model,
                    region=args.region,
                    firmware_version=args.firmware,
                    selectors=args.archive,
                    out_dir=args.output,
                )
                for path in paths:
                    print(path)
                return 0

            out_dir, out_file = _download_output_args(args.output)
            result = fus.download_firmware(
                model=args.model,
                region=args.region,
                firmware_version=args.firmware,
                out_dir=out_dir,
                out_file=out_file,
                resume=args.resume,
                auto_decrypt=args.decrypt,
            )
            print(result.decrypted_path or result.encrypted_path)
            return 0

        out_path = Path(args.output).expanduser() if args.output else fus.decrypted_output_path(args.input)
        final_path = fus.decrypt_firmware(
            version=args.firmware,
            model=args.model,
            region=args.region,
            in_file=args.input,
            out_file=out_path,
            enc_ver=args.enc_ver,
        )
        print(final_path)
        return 0
    except ValueError as exc:
        parser.error(str(exc))
    except FileNotFoundError as exc:
        _print_error(f"file not found: {exc}")
        return 2
    except FUSError as exc:
        _print_error(str(exc))
        return 1
    except requests.RequestException as exc:
        _print_error(f"request failed: {exc}")
        return 1

    return 1
