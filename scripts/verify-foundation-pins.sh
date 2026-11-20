#!/usr/bin/env bash
set -euo pipefail
cd "${FOUNDATION_ROOT:-$(dirname "$0")/..}"
revision="253f7afb2b3df9e952065d10bf2af19913cb176b"
grep -Fq "$revision" scripts/bootstrap-boringtun.sh
grep -Fq "$revision" scripts/build-boringtun.sh
grep -Fq 'https://github.com/cloudflare/boringtun.git' scripts/bootstrap-boringtun.sh
grep -Fq 'Cargo.lock' scripts/bootstrap-boringtun.sh
grep -Fq -- '--locked --target "$triple"' scripts/build-boringtun.sh
grep -Fq -- '--features ffi-bindings' scripts/build-boringtun.sh
grep -Fq 'aarch64-apple-ios-sim' scripts/build-boringtun.sh
grep -Fq 'rustc 1.90.0' scripts/build-boringtun.sh
grep -Fq 'channel = "1.90.0"' rust-toolchain.toml
grep -Fq 'tuist = "4.218.1"' .mise.toml
! grep -Fq 'go =' .mise.toml
grep -Fxq '16.4' .xcode-version
grep -Fq "xcode-version: '16.4'" .github/workflows/validate.yml
grep -Fq 'runs-on: ubuntu-24.04' .github/workflows/validate.yml
grep -Fq 'LIBRARY_SEARCH_PATHS' Project.swift
grep -Fq 'Build pinned Rust BoringTun' Project.swift
! grep -Eq 'WireGuardKit|libwg-go|build-wireguard-go' Tuist/Package.swift Project.swift
echo 'Pinned Rust BoringTun source/toolchain invariants OK'
