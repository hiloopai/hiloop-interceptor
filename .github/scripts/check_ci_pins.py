#!/usr/bin/env python3
"""Reject unpinned CI actions and external tool bootstraps."""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses:\s*([^@\s#]+)@([^ \t#]+)")
TOOL_COMMAND = re.compile(r"\b(cargo|go|npm|pnpm|yarn|pipx)\s+")
SCOPED_NPM_PACKAGE_AT_COUNT = 2
MOVING_GO_REFS = {"HEAD", "latest", "main", "master"}


def _has_flag(args: list[str], *flags: str) -> bool:
    return any(arg in flags or any(arg.startswith(f"{flag}=") for flag in flags) for arg in args)


def _npm_package_is_pinned(package: str) -> bool:
    if package.startswith("@"):
        return package.count("@") >= SCOPED_NPM_PACKAGE_AT_COUNT and not package.endswith("@latest")
    return "@" in package and not package.endswith("@latest")


def _packages(args: list[str]) -> list[str]:
    return [value for value in args if not value.startswith("-")]


def _check_cargo(path: Path, line_no: int, args: list[str], index: int) -> list[str]:
    if args[index + 1 : index + 2] != ["install"]:
        return []

    install_args = args[index + 2 :]
    pinned_registry_install = _has_flag(install_args, "--version", "--path")
    pinned_git_install = _has_flag(install_args, "--git") and _has_flag(
        install_args,
        "--rev",
        "--tag",
    )
    if pinned_registry_install or pinned_git_install:
        return []
    return [
        f"{path}:{line_no}: cargo install must pin with --version, --path, "
        "or --git plus --rev/--tag",
    ]


def _check_go(path: Path, line_no: int, args: list[str], index: int) -> list[str]:
    if args[index + 1 : index + 2] != ["install"]:
        return []

    def unpinned(package: str) -> bool:
        return "@" not in package or package.rsplit("@", 1)[1] in MOVING_GO_REFS

    return [
        f"{path}:{line_no}: go install target must use a fixed version or commit"
        for package in _packages(args[index + 2 :])
        if unpinned(package)
    ]


def _check_node(path: Path, line_no: int, args: list[str], index: int) -> list[str]:
    if "install" not in args[index + 1 : index + 3] or "-g" not in args[index + 1 :]:
        return []

    return [
        f"{path}:{line_no}: global {args[index]} install must pin package versions"
        for package in _packages(args[index + 2 :])
        if package != "install" and not _npm_package_is_pinned(package)
    ]


def _check_pipx(path: Path, line_no: int, args: list[str], index: int) -> list[str]:
    if args[index + 1 : index + 2] != ["install"]:
        return []

    return [
        f"{path}:{line_no}: pipx install must pin with == or a direct URL"
        for package in _packages(args[index + 2 :])[:1]
        if "==" not in package and "@" not in package
    ]


def _check_run_line(path: Path, line_no: int, line: str) -> list[str]:
    if not TOOL_COMMAND.search(line):
        return []

    try:
        args = shlex.split(line)
    except ValueError:
        return []

    errors: list[str] = []
    for index, arg in enumerate(args):
        if arg == "cargo":
            errors.extend(_check_cargo(path, line_no, args, index))
        if arg == "go":
            errors.extend(_check_go(path, line_no, args, index))
        if arg in {"npm", "pnpm", "yarn"}:
            errors.extend(_check_node(path, line_no, args, index))
        if arg == "pipx":
            errors.extend(_check_pipx(path, line_no, args, index))
    return errors


def _workflow_files() -> list[Path]:
    workflow_dir = Path(".github/workflows")
    return sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml"))


def _main() -> int:
    errors: list[str] = []
    for path in _workflow_files():
        for line_no, line in enumerate(path.read_text().splitlines(), start=1):
            match = USES.match(line)
            if match:
                action, ref = match.groups()
                if not action.startswith(("./", "../", "docker://")) and not SHA.fullmatch(ref):
                    errors.append(
                        f"{path}:{line_no}: pin external GitHub Action to a full commit SHA"
                    )
            errors.extend(_check_run_line(path, line_no, line))

    if errors:
        sys.stderr.write("CI pin policy violations:\n")
        for error in errors:
            sys.stderr.write(f"- {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
