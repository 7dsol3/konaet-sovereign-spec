#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/setup.sh"
config="$(konaet_apt_config)"
[[ "$config" == *'Acquire::Retries "1";'* ]]
[[ "$config" == *'Acquire::http::Timeout "15";'* ]]
[[ "$config" == *'Acquire::https::Timeout "15";'* ]]
[[ "$config" != *'AllowInsecure'* && "$config" != *'Verify-Peer'* ]]
mapfile -t archives < <(konaet_archive_candidates)
[[ ${#archives[@]} == 2 && ${archives[0]} == https://archive.ubuntu.com/ubuntu/ ]]
for archive in "${archives[@]}"; do [[ "$archive" == https://*/ubuntu/ ]]; done
konaet_probe_archive() { [[ "$1" == https://mirrors.edge.kernel.org/ubuntu/ ]]; }
[[ "$(konaet_reachable_archives)" == https://mirrors.edge.kernel.org/ubuntu/ ]]
konaet_probe_archive() { return 1; }
if konaet_reachable_archives; then echo 'Unreachable archive accepted' >&2; exit 1; fi
konaet_probe_archive() { return 0; }
[[ "$(konaet_reachable_archives)" == "$(konaet_archive_candidates)" ]]
printf 'Ubuntu transport configuration: 9 fixture checks passed; no host mutation.\n'
