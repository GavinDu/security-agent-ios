#!/usr/bin/env bash
set -euo pipefail
cd "${FOUNDATION_ROOT:-$(dirname "$0")/..}"
revision="2fec12a6e1f6e3460b6ee483aa00ad29cddadab1"
grep -Fq "$revision" scripts/bootstrap-wireguard.sh
grep -Fq 'https://github.com/WireGuard/wireguard-apple' scripts/bootstrap-wireguard.sh
grep -Fq '.package(path: "../Vendor/wireguard-apple")' Tuist/Package.swift
grep -Fq 'tools-version:5.5' scripts/patch-wireguard-manifest.py
grep -Fq "$revision" scripts/build-wireguard-go.sh
grep -Fq 'go = "1.19.13"' .mise.toml
grep -Fq 'tuist = "4.218.1"' .mise.toml
grep -Fxq '16.4' .xcode-version
grep -Fq "xcode-version: '16.4'" .github/workflows/validate.yml
grep -Fq 'runs-on: ubuntu-24.04' .github/workflows/validate.yml
grep -Fq '["WireGuardKit": .staticFramework]' Tuist/Package.swift
grep -Fq 'LIBRARY_SEARCH_PATHS' Project.swift
grep -Fq 'Build pinned WireGuard Go bridge' Project.swift
printf 'Pinned toolchain and source invariants OK\n'
