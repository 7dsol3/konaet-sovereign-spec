#!/usr/bin/env bash
set -euo pipefail
konaet_apt_config() {
  # Same effective keys as actions/runner-images configure-apt.sh. Filename
  # sorts last because later files otherwise silently override these values.
  printf '%s\n' 'Acquire::Retries "1";' 'Acquire::http::Timeout "15";' 'Acquire::https::Timeout "15";'
}
konaet_archive_candidates() {
  printf '%s\n' 'https://archive.ubuntu.com/ubuntu/' 'https://mirrors.edge.kernel.org/ubuntu/'
}
konaet_probe_archive() {
  curl --fail --silent --show-error --location --head --connect-timeout 5 --max-time 12 "${1}dists/noble/InRelease" >/dev/null
}
konaet_reachable_archives() {
  local archive found=false
  while IFS= read -r archive; do
    if konaet_probe_archive "$archive"; then printf '%s\n' "$archive"; found=true; fi
  done < <(konaet_archive_candidates)
  [[ "$found" == true ]]
}
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 && "$(dpkg --print-architecture)" == amd64 ]]
konaet_apt_config | sudo tee /etc/apt/apt.conf.d/zzzz-konaet-network >/dev/null
# Only update the runner's existing mirror list. Keep its signed-by archive
# keyring, suites and components; never disable package signatures or TLS.
if [[ -f /etc/apt/apt-mirrors.txt ]] && grep -q 'mirror+file:/etc/apt/apt-mirrors.txt' /etc/apt/sources.list.d/ubuntu.sources; then
  selected="$(konaet_reachable_archives)" || { echo 'No authenticated Ubuntu archive endpoint is reachable' >&2; exit 69; }
  [[ -n "$selected" ]] || { echo 'No authenticated Ubuntu archive endpoint is reachable' >&2; exit 69; }
  # APT may select any entry again for every package. Do not reintroduce an
  # endpoint that already failed its probe; that repeats DNS delays per file.
  printf '%s\n' "$selected" | sudo tee /etc/apt/apt-mirrors.txt >/dev/null
fi
apt-config dump Acquire::Retries Acquire::http::Timeout Acquire::https::Timeout
sudo apt-get update -qq --error-on=any
