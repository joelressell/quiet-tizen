#!/usr/bin/env python3
"""Profile-specific TV diagnostics and access. See docs/02-access.md."""
import argparse
import asyncio
import base64
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor"))
from samsung_tv_root.archive_root import probe, _capture
from samsung_tv_root.sdb import SdbClient, find_sdb
from device_profiles import DEFAULT_PROFILE_PATH, load_profile, check_profile_identity, require_operation
from diagnostics import collect_diagnostics

PROFILE = load_profile()
STAGE = "/home/owner/share/tmp/sdk_tools/quiet-tizen"


def private_path(path):
    path = Path(path).expanduser().resolve()
    private = (ROOT / ".local").resolve()
    if path == private or private not in path.parents:
        raise ValueError("Private files must be inside this checkout's .local/ directory.")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def save_private(path, data):
    path = private_path(path)
    path.write_bytes(data)
    path.chmod(0o600)


def observed_model(client):
    client.connect()
    client.require_device()
    rows = [line.split() for line in client.run(("devices",), check=True).stdout.splitlines()]
    rows = [row for row in rows if row and row[0] == client.serial]
    if len(rows) != 1 or len(rows[0]) < 3:
        raise ValueError("Cannot identify the explicitly selected device from SDB.")
    return rows[0][-1]


def check_identity(model, firmware, profile=None):
    check_profile_identity(PROFILE if profile is None else profile, model, firmware)


def pull_command(remote):
    if not remote.startswith("/") or "\0" in remote or "\n" in remote:
        raise ValueError("Use an absolute, single-line TV file path.")
    # The upstream command channel captures at most 1 MiB per stream.
    # A compressed transfer is bounded before emitting any base64.
    return f"""set -eu
test -f {shlex.quote(remote)}
test "$(stat -c %s {shlex.quote(remote)})" -le 33554432
t=$(mktemp /run/quiet-tizen-pull.XXXXXX)
trap 'rm -f "$t"' EXIT HUP INT TERM
gzip -c {shlex.quote(remote)} > "$t"
test "$(wc -c < "$t")" -le 760000 || {{ echo 'File too large; split a snapshot into smaller files first.' >&2; exit 1; }}
sha256sum {shlex.quote(remote)} | cut -d ' ' -f 1
base64 "$t"
"""


def decode_pull(stdout):
    digest, encoded = stdout.split("\n", 1)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Missing transfer digest.")
    compressed = base64.b64decode("".join(encoded.split()), validate=True)
    data = gzip.decompress(compressed)
    if len(data) > 33554432 or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Transfer size or digest mismatch; file was not saved.")
    return data


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="The owner's TV IPv4 address; never auto-discovered")
    parser.add_argument("--profile", type=Path, help="Exact model/firmware profile JSON; default is the U8000F case study")
    parser.add_argument("--firmware", help="Operator-verified version from the TV's About screen")
    parser.add_argument("--sdb", help="Path to Samsung's separately installed SDB")
    parser.add_argument("--callback-host", help="This computer's LAN IPv4 if route detection is wrong")
    sub = parser.add_subparsers(dest="action", required=True)
    doctor = sub.add_parser("doctor", help="Collect fixed non-root compatibility observations")
    doctor.add_argument("--report", type=Path, help="Save a diagnostic JSON report below .local/")
    sub.add_parser("root-check", help="Temporarily obtain root and run id; no configuration changes")
    run = sub.add_parser("exec", help="Execute one reviewed command or short script using temporary root")
    source = run.add_mutually_exclusive_group(required=True)
    source.add_argument("--command")
    source.add_argument("--script", type=Path)
    run.add_argument("--arg", action="append", default=[], help="Positional argument passed to --script")
    pull = sub.add_parser("pull", help="Read and verify one bounded file into ignored .local/")
    pull.add_argument("remote")
    pull.add_argument("local", type=Path)
    push = sub.add_parser("push", help="Upload one file to the SDK staging directory, not to system paths")
    push.add_argument("local", type=Path)
    push.add_argument("name", help="Simple staging filename")
    args = parser.parse_args(argv)
    profile = load_profile(args.profile or DEFAULT_PROFILE_PATH)
    # A model name alone never enables operations on an inventory-only profile.
    # Reject unsupported operations before locating SDB or connecting to the TV.
    require_operation(profile, args.action)
    if args.action != "doctor" or args.profile is not None:
        check_identity(profile["model"], args.firmware, profile)
    if args.action == "doctor" and args.report:
        private_path(args.report)
    ipaddress.IPv4Address(args.host)
    if args.callback_host:
        ipaddress.IPv4Address(args.callback_host)
    if args.sdb:
        os.environ["SDB"] = str(Path(args.sdb).expanduser().resolve())
    transport = profile.get("diagnostic_transport", {}) if args.action == "doctor" else {}
    client = SdbClient(find_sdb(), args.host, timeout=15,
                       max_appinstall_bytes=transport.get("max_inline_bytes", 510))
    model = observed_model(client)
    print("SDB model:", model)
    if args.action == "doctor":
        if args.profile is not None:
            check_identity(model, args.firmware, profile)
        report = collect_diagnostics(client, profile, model, args.firmware, args.callback_host)
        print("Profile status:", profile["support_status"])
        print("Archive prerequisites:", report["archive_prerequisites"])
        for name, result in report["checks"].items():
            print(f"  {name}: {result['status']}" +
                  (f" ({result['reason']})" if "reason" in result else ""))
        if args.report:
            save_private(args.report, (json.dumps(report, indent=2) + "\n").encode())
            print(f"Diagnostic report: {args.report.resolve().relative_to(ROOT)}")
        else:
            print(json.dumps(report, indent=2))
        print("Diagnostic observations only. Root, launcher and cleanup have not been tested by this command.")
        return 0 if report["archive_prerequisites"] == "observed_not_root_proof" else 2
    check_identity(model, args.firmware, profile)
    if args.action == "push":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", args.name):
            raise ValueError("Use a simple staging filename without directory components.")
        if not args.local.is_file():
            raise ValueError("Upload source must be a file.")
        _capture(client, f"mkdir -p {STAGE}")
        remote = PurePosixPath(STAGE) / args.name
        client.push(args.local.resolve(), remote)
        digest = hashlib.sha256(args.local.read_bytes()).hexdigest()
        actual = _capture(client, f"sha256sum {shlex.quote(str(remote))}").split()[0]
        if digest != actual:
            raise ValueError("Uploaded file digest mismatch.")
        print(f"Verified staging file: {remote}. Remove it after deployment.")
        return
    if args.action == "root-check":
        command = "id"
    elif args.action == "pull":
        private_path(args.local)
        command = pull_command(args.remote)
    elif args.script:
        script = args.script.read_bytes()
        if len(script) > 45000:
            raise ValueError("Script too large for the bounded command channel; split into phases.")
        encoded = base64.b64encode(script).decode()
        command = f"printf '%s' {shlex.quote(encoded)} | /bin/sh -s -- " + shlex.join(args.arg)
    else:
        if args.arg:
            raise ValueError("--arg requires --script.")
        command = args.command
    result = asyncio.run(probe(
        args.host, model=model, callback_host=args.callback_host,
        payloads=ROOT / ".local/build/payloads", commands=(command,), command_timeout=30,
    ))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    log = ROOT / ".local/sessions" / f"{stamp}.json"
    save_private(log, (json.dumps(result, indent=2) + "\n").encode())
    if result.get("uid") != 0 or result.get("euid") != 0:
        raise ValueError("The callback did not prove UID/EUID 0.")
    if not result.get("system_files_unchanged") or not result.get("staging_cleaned"):
        raise ValueError("Root session cleanup checks failed; inspect the private session log.")
    response = result["commands"][0]
    if response["stderr"]:
        print(response["stderr"], file=sys.stderr, end="")
    if response["exit_code"] or response["timed_out"]:
        raise RuntimeError(f"Command failed ({response['exit_code']}, timeout={response['timed_out']}). "
                           f"Private log: {log.relative_to(ROOT)}")
    if args.action == "pull":
        save_private(args.local, decode_pull(response["stdout"]))
        print("Verified file saved inside .local/.")
    else:
        print(response["stdout"], end="")
    print("UID/EUID 0 verified; root staging cleaned; passwd and SDB key hashes unchanged.")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as error:
        print(f"Stopped: {error}", file=sys.stderr)
        sys.exit(1)
