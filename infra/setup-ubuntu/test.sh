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
printf 'Ubuntu transport configuration: 6 fixture checks passed; no host mutation.\n'
