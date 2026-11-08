#!/usr/bin/env bash
# Aplica reglas reales en un namespace nuevo; nunca en la red del equipo anfitrión.
# shellcheck disable=SC1090,SC2034 # Funciones y variables compartidas con el script cargado.
set -euo pipefail
if [[ ${1:-} != inside ]]; then
  exec unshare --net bash "$0" inside
fi
cd "$(dirname "$0")/.."
source <(sed '/^COMMAND=/,$d' nexo-dns.sh)
set -euo pipefail
task_dir=$(mktemp -d)
client_pid=""; echo_pid=""
cleanup() {
  [[ -z "$echo_pid" ]] || kill "$echo_pid" 2>/dev/null || true
  [[ -z "$client_pid" ]] || kill "$client_pid" 2>/dev/null || true
  rm -rf -- "$task_dir"
}
trap cleanup EXIT
FW_NFT="$task_dir/firewall.nft"
FW_UNIT="$task_dir/firewall.service"
FW_NFTABLES_CONF="$task_dir/nftables.conf"
FW_NFTABLES_LOAD="$task_dir/nftables-nexo.conf"
FW_NFTABLES_DROPIN="$task_dir/nftables.service.d/90-nexo-dns.conf"
FW_TRUST_CONF="$task_dir/trusted"
BACKUP_ROOT="$task_dir/backups"
printf 'IPV4=192.168.1.0/24\nIPV6=fe80::/10,fd42::/64\n' > "$FW_TRUST_CONF"
printf 'flush ruleset\ntable inet unrelated { }\n' > "$FW_NFTABLES_CONF"
ENGINE=pihole
WEB_TEST='80o,443os,[::]:80o,[::]:443os'
ph_get() { printf '%s\n' "$WEB_TEST"; }
SYSTEMD_TEST=ok
SERVICE_ACTIVE=no
SERVICE_ENABLED=no
STOP_CALLS=0
NATIVE_TEST=ok
STATE_TEST=ok
systemctl() {
  if [[ "$1" == show && "${*: -1}" == nexo-dns-firewall.service ]]; then
    [[ "$STATE_TEST" == ok ]] || return 1
    if [[ "$SERVICE_ACTIVE" == yes ]]; then
      printf 'ActiveState=active\n'
    else
      printf 'ActiveState=inactive\n'
    fi
    if [[ "$SERVICE_ENABLED" == yes ]]; then
      printf 'UnitFileState=enabled\n'
    elif [[ -f "$FW_UNIT" ]]; then
      printf 'UnitFileState=disabled\n'
    else
      printf 'UnitFileState=\n'
    fi
    return
  fi
  if [[ "$1" == show && "${*: -1}" == nftables.service ]]; then
    local nftbin config
    nftbin=$(command -v nft)
    config="$FW_NFTABLES_CONF"
    [[ "$NATIVE_TEST" == ok ]] || config="$task_dir/custom.conf"
    if [[ -f "$FW_NFTABLES_DROPIN" ]]; then
      config="$FW_NFTABLES_LOAD"
    else
      printf 'ExecStop={ path=%s ; argv[]=%s flush ruleset ; ignore_errors=no ; }\n' "$nftbin" "$nftbin"
    fi
    printf 'ExecStart={ path=%s ; argv[]=%s -f %s ; ignore_errors=no ; }\n' "$nftbin" "$nftbin" "$config"
    printf 'ExecReload={ path=%s ; argv[]=%s -f %s ; ignore_errors=no ; }\n' "$nftbin" "$nftbin" "$config"
    return
  fi
  if [[ "$1" == is-enabled ]]; then [[ "$SERVICE_ENABLED" == yes ]]; return; fi
  if [[ "$1" == is-active ]]; then [[ "$SERVICE_ACTIVE" == yes ]]; return; fi
  if [[ "$1" == stop ]]; then STOP_CALLS=$((STOP_CALLS+1)); SERVICE_ACTIVE=no; fi
  if [[ "$1" == start ]]; then SERVICE_ACTIVE=yes; fi
  if [[ "$1" == disable ]]; then SERVICE_ENABLED=no; fi
  if [[ "$1" == enable && "$SYSTEMD_TEST" == ok ]]; then SERVICE_ACTIVE=yes; SERVICE_ENABLED=yes; fi
  [[ "$SYSTEMD_TEST" != fail || "$1" != enable ]]
}
sshd() { printf 'port 22\n'; }
DNS_TEST=ok
DNS_CALLS=0
dns_healthy() {
  DNS_CALLS=$((DNS_CALLS+1))
  [[ "$DNS_TEST" == ok || "$DNS_CALLS" -eq 1 ]]
}
nft add table inet unrelated
NATIVE_TEST=fail
if install_firewall_quiet; then echo 'ERROR: reemplazó un nftables.service personalizado'; exit 1; fi
if fw_active; then echo 'ERROR: aplicó reglas con nftables.service personalizado'; exit 1; fi
NATIVE_TEST=ok
install_firewall_quiet
old_saved=$(sha256sum "$FW_NFT")
old_live=$(nft -s list table inet nexo_dns)
WEB_TEST='9443s'
STATE_TEST=fail
if install_firewall_quiet; then echo 'ERROR: aceptó respaldo sin estado de servicio'; exit 1; fi
STATE_TEST=ok
WEB_TEST='80o,443os,[::]:80o,[::]:443os'
[[ $(sha256sum "$FW_NFT") == "$old_saved" ]]
[[ $(nft -s list table inet nexo_dns) == "$old_live" ]]
systemd-analyze verify "$FW_UNIT"
nft list table inet nexo_dns | grep -q '443'
nft list table inet nexo_dns | grep -q 'tailscale0'
nft list table inet unrelated >/dev/null
ip link set lo up
ip link add probe-s type veth peer name probe-c
unshare --net sh -c 'echo "$$" > "$1"; exec sleep 120' probe "$task_dir/client.pid" &
for ((attempt=0; attempt<50; attempt++)); do
  [[ -s "$task_dir/client.pid" ]] && break
  sleep 0.02
done
client_pid=$(cat "$task_dir/client.pid")
ip link set probe-c netns "$client_pid"
ip address add 192.168.1.10/24 dev probe-s
ip address add 198.51.100.1/24 dev probe-s
ip address add 100.64.0.1/24 dev probe-s
ip -6 address add fd42::10/64 dev probe-s nodad
ip -6 address add 2001:db8::10/64 dev probe-s nodad
ip link set probe-s up
nsenter -t "$client_pid" -n ip link set lo up
nsenter -t "$client_pid" -n ip address add 192.168.1.49/24 dev probe-c
nsenter -t "$client_pid" -n ip address add 198.51.100.2/24 dev probe-c
nsenter -t "$client_pid" -n ip address add 100.64.0.2/24 dev probe-c
nsenter -t "$client_pid" -n ip -6 address add fd42::49/64 dev probe-c nodad
nsenter -t "$client_pid" -n ip -6 address add 2001:db8::49/64 dev probe-c nodad
nsenter -t "$client_pid" -n ip link set probe-c up
python3 tests/firewall_probe.py serve &
echo_pid=$!
sleep 0.2
nsenter -t "$client_pid" -n python3 tests/firewall_probe.py client 192.168.1.49 open
nsenter -t "$client_pid" -n python3 tests/firewall_probe.py client 198.51.100.2 blocked
nsenter -t "$client_pid" -n python3 tests/firewall_probe.py client 100.64.0.2 blocked
nsenter -t "$client_pid" -n python3 tests/firewall_probe.py client fd42::49 open
nsenter -t "$client_pid" -n python3 tests/firewall_probe.py client 2001:db8::49 blocked
# La interfaz Tailscale es la frontera de confianza, no cualquier IP CGNAT.
ip link set probe-s name tailscale0
nsenter -t "$client_pid" -n python3 tests/firewall_probe.py client 100.64.0.2 open
ip link set tailscale0 name probe-s
# Aplica las órdenes generadas, con nft real y la configuración nativa que
# contiene flush ruleset. El caso de reinicio ejecuta también la fase Stop.
apply_native() {
  local operation="$1" command
  while IFS= read -r command; do
    [[ -z "$command" ]] || $command || return 1
    fw_active || return 1
    nft list table inet unrelated >/dev/null || return 1
  done < <(sed -n "s/^Exec$operation=//p" "$FW_NFTABLES_DROPIN")
}
[[ -s "$FW_NFTABLES_DROPIN" ]]
apply_native Reload
apply_native Stop
apply_native Start
nsenter -t "$client_pid" -n python3 tests/firewall_probe.py client 198.51.100.2 blocked
# Esta tabla existe solo en ejecución, fuera de la configuración de nftables.
nft add table inet runtime_only

# Cambia a las reglas de AdGuard para probar el puerto HTTP/3 en UDP real.
ENGINE=adguard
AGH_YAML="$task_dir/AdGuardHome.yaml"
AGH_READY=1
printf 'dns:\n  serve_http3: true # DoH3\ntls:\n  enabled: true # TLS\n  port_https: 443\n' > "$AGH_YAML"
install_firewall_quiet
nsenter -t "$client_pid" -n python3 tests/firewall_probe.py client 192.168.1.49 open http3
nsenter -t "$client_pid" -n python3 tests/firewall_probe.py client 198.51.100.2 blocked http3
ENGINE=pihole
install_firewall_quiet
[[ $(nft list table inet nexo_dns | grep -c 'tcp dport') == 1 ]]
fw_prepare_port_change 9443 tcp
nft list table inet nexo_dns | grep -q '9443'
[[ -z "$FW_PENDING_TCP" && -z "$FW_PENDING_UDP" ]]
old_saved=$(sha256sum "$FW_NFT")
old_live=$(nft -s list table inet nexo_dns)
WEB_TEST='9443s'
# Los respaldos se leen y verifican antes de mutar archivos o reglas.
if (cp() { return 1; }; install_firewall_quiet); then
  echo 'ERROR: aceptó copia previa fallida'
  exit 1
fi
[[ $(sha256sum "$FW_NFT") == "$old_saved" ]]
[[ $(nft -s list table inet nexo_dns) == "$old_live" ]]
DNS_TEST=fail
DNS_CALLS=0
if install_firewall_quiet; then echo 'ERROR: aceptó DNS fallido'; exit 1; fi
[[ $(sha256sum "$FW_NFT") == "$old_saved" ]]
[[ $(nft -s list table inet nexo_dns) == "$old_live" ]]
nft list table inet unrelated >/dev/null
DNS_TEST=ok
SYSTEMD_TEST=fail
WEB_TEST='9444s'
if install_firewall_quiet; then echo 'ERROR: aceptó persistencia fallida'; exit 1; fi
[[ $(sha256sum "$FW_NFT") == "$old_saved" ]]
[[ $(nft -s list table inet nexo_dns) == "$old_live" ]]
SYSTEMD_TEST=ok
SERVICE_ACTIVE=no
SYSTEMD_TEST=fail
if install_firewall_quiet; then echo 'ERROR: aceptó nueva instalación fallida'; exit 1; fi
[[ "$STOP_CALLS" -eq 1 && "$SERVICE_ACTIVE" == no ]]
[[ $(nft -s list table inet nexo_dns) == "$old_live" ]]
SYSTEMD_TEST=ok
WEB_TEST='22'
if install_firewall_quiet; then echo 'ERROR: aceptó conflicto con SSH'; exit 1; fi
[[ $(nft -s list table inet nexo_dns) == "$old_live" ]]
nft list table inet runtime_only >/dev/null
echo 'PASS: carga real, HTTPS, Tailscale, idempotencia, rollback, SSH y tablas ajenas'
