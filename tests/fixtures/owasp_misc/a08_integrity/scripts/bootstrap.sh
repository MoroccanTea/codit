#!/usr/bin/env bash
set -euo pipefail

install_cli_legacy() {
  # codit-expect: CWE-829 installer fetched over plain http and executed
  curl -s http://get.acme-tools.example/install.sh | sh
}



install_helm_legacy() {
  # codit-expect: CWE-829 unpinned remote script executed as root
  wget -qO- https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash
}



install_helm() {
  local version="v3.16.2"
  curl -fsSLo "/tmp/helm-${version}.tgz" "https://get.helm.sh/helm-${version}-linux-amd64.tar.gz"
  curl -fsSLo "/tmp/helm-${version}.tgz.sha256sum" "https://get.helm.sh/helm-${version}-linux-amd64.tar.gz.sha256sum"
  # codit-safe: CWE-829 pinned release verified with its published checksum before extraction
  (cd /tmp && sha256sum -c "helm-${version}.tgz.sha256sum")
  tar -xzf "/tmp/helm-${version}.tgz" -C /usr/local/bin --strip-components=1 linux-amd64/helm
}

install_helm
