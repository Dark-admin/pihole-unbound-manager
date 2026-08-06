#!/usr/bin/env bash
#
#  nexo-dns.sh — Instalador y panel de DNS privado
#  Pi-hole + Unbound + Tailscale
#
#  Autor: nexo (Dᵃʳᵏ- ᵃᵈᵐᶤᶰ)   ·   v3.2
#  Compatible: Raspberry Pi OS · Debian 11+ · Ubuntu 20.04+
#
#  Uso:
#     sudo bash nexo-dns.sh              → panel
#     sudo bash nexo-dns.sh install      → instalación completa
#     sudo bash nexo-dns.sh status       → estado
#     sudo bash nexo-dns.sh health       → chequeo con pruebas reales
#     sudo bash nexo-dns.sh optimize     → reaplica la optimización
#
#  Todo cambio hace copia previa y se revierte solo si la verificación falla.
#
set -uo pipefail

# Los bordes del cuadro se calculan con ${#cadena}. Sin una locale UTF-8, bash
# cuenta BYTES en vez de caracteres y cada acento o símbolo descuadra la caja.
# C.UTF-8 viene de serie en Debian y Ubuntu, no hace falta generarla.
if [[ -z "${LC_ALL:-}" ]] && locale -a 2>/dev/null | grep -qiE '^C\.utf-?8$'; then
  export LC_ALL=C.UTF-8
fi

# OJO: no llamarla VERSION. /etc/os-release define VERSION y al leerlo
# machacaría la nuestra ("nexo-dns v13 (trixie)").
NEXO_VERSION="3.2"
CONF=/etc/nexo-dns.conf
UNBOUND_CONF=/etc/unbound/unbound.conf.d/pi-hole.conf
PIHOLE_TOML=/etc/pihole/pihole.toml
FTL_DB=/etc/pihole/pihole-FTL.db
BACKUP_ROOT=/var/backups/nexo-dns

# ══════════════════════════════════════════════════════════ presentación ═══════
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[1;33m'; BLU=$'\033[0;34m'
  CYN=$'\033[0;36m'; MAG=$'\033[0;35m'; DIM=$'\033[2m'; BLD=$'\033[1m'; NC=$'\033[0m'
else
  RED=''; GRN=''; YEL=''; BLU=''; CYN=''; MAG=''; DIM=''; BLD=''; NC=''
fi

# Bordes: Unicode si la terminal lo soporta, ASCII si no.
# Se consulta la codificación EFECTIVA, no las variables de entorno sueltas:
# `locale charmap` respeta la precedencia LC_ALL > LC_CTYPE > LANG, que es
# exactamente la que usa bash para contar caracteres en ${#cadena}. Mirando
# solo las variables se elegían bordes Unicode con LC_ALL=C y se descuadraba.
if [[ "$(locale charmap 2>/dev/null)" == "UTF-8" ]]; then
  TL='┌'; TR='┐'; BL='└'; BR='┘'; HZ='─'; VT='│'; LT='├'; RT='┤'
  I_EST='◆'; I_CFG='▣'; I_TS='▲'; I_SYS='■'; DOT='●'
  LOGO1='   .~.  '; LOGO2='  ( o ) '; LOGO3="   \`~'  "
else
  TL='+'; TR='+'; BL='+'; BR='+'; HZ='-'; VT='|'; LT='+'; RT='+'
  I_EST='*'; I_CFG='#'; I_TS='^'; I_SYS='='; DOT='o'
  LOGO1='   ___  '; LOGO2='  ( o ) '; LOGO3="   ---  "
fi

BOXW=54   # ancho interior del cuadro

# Longitud visible de una cadena, sin depender de la locale:
#   1) quita los códigos de color ANSI (ocupan bytes pero no se ven)
#   2) borra los bytes de continuación UTF-8 (10xxxxxx), así de cada carácter
#      multibyte queda solo su primer byte
#   3) cuenta los bytes restantes = número real de caracteres
# Hacerlo con ${#cadena} fallaba: con LC_ALL=C bash cuenta bytes y cualquier
# acento o '·' descuadraba el borde.
vislen() {
  printf '%s' "$1" \
    | sed $'s/\033\\[[0-9;]*m//g' \
    | LC_ALL=C tr -d '\200-\277' \
    | LC_ALL=C wc -c | tr -d ' '
}
# La línea se construye repitiendo la cadena: `tr` trabaja por bytes y
# convertiría un '─' de 3 bytes en tres caracteres rotos.
HLINE=''
for ((_i=0; _i<BOXW+2; _i++)); do HLINE+="$HZ"; done
hline()  { printf '%s' "$HLINE"; }
btop()   { printf '  %s%s%s\n' "$TL" "$(hline)" "$TR"; }
bsep()   { printf '  %s%s%s\n' "$LT" "$(hline)" "$RT"; }
bbot()   { printf '  %s%s%s\n' "$BL" "$(hline)" "$BR"; }
# Si el contenido excede el ancho, el relleno saldría negativo y printf fallaría
# rompiendo el cuadro. Con nombres de host o de distro largos pasa de verdad,
# así que se recorta y se marca con '…'.
brow() {
  local t="${1:-}" l pad
  l=$(vislen "$t")
  if (( l > BOXW )); then
    # Recorte a ciegas sobre la cadena con color: se corta por caracteres y se
    # recalcula, para no partir una secuencia ANSI por la mitad.
    while (( l > BOXW - 1 )) && [[ -n "$t" ]]; do t="${t%?}"; l=$(vislen "$t"); done
    t="${t}…${NC}"; l=$(( $(vislen "$t") ))
  fi
  pad=$(( BOXW - l )); (( pad < 0 )) && pad=0
  printf '  %s %s%*s %s\n' "$VT" "$t" "$pad" '' "$VT"
}

info() { echo "${BLU}[i]${NC} $*"; }
ok()   { echo "${GRN}[✓]${NC} $*"; }
warn() { echo "${YEL}[!]${NC} $*"; }
err()  { echo "${RED}[✗]${NC} $*"; }
step() { echo; echo "${BLD}── $* ${NC}"; }
pause(){ [[ -t 0 ]] || return 0; echo; read -rp "  ${DIM}Enter para continuar...${NC} " _ || true; }
ask()  { local p="$1" d="${2:-}" r; read -rp "  $p " r || true; echo "${r:-$d}"; }
yes_no(){ local r; r=$(ask "$1 [s/N]"); [[ "$r" =~ ^[sSyY]$ ]]; }

clear_screen() { clear 2>/dev/null || printf '\033[2J\033[H'; }

# ══════════════════════════════════════════════════════════ requisitos ═════════
[[ $EUID -eq 0 ]] || { err "Hace falta root. Ejecuta: sudo bash $0 ${*:-}"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1; }

# `dig +short` escribe ";; communications error ..." por STDOUT (BIND 9.20), no
# por stderr, así que 2>/dev/null no basta: hay que descartar las líneas ';;'.
# Sin esto, el estado mostraba el error crudo donde debía ir la IP.
dig_short() { dig +short "$@" 2>/dev/null | grep -v '^;;' | head -1; }

# ══════════════════════════════════════════════════════ detección de SO ════════
OS_ID=""; OS_NAME=""; MODEL=""
detect_os() {
  # Se lee en subshells a propósito: /etc/os-release define VERSION, NAME e ID,
  # y un `source` directo pisaría variables nuestras.
  if [[ -r /etc/os-release ]]; then
    OS_ID=$(   . /etc/os-release 2>/dev/null; printf '%s' "${ID:-desconocido}" )
    OS_NAME=$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-${NAME:-desconocido}}" )
  else
    OS_ID=desconocido; OS_NAME=desconocido
  fi
  if [[ -r /proc/device-tree/model ]]; then
    MODEL=$(tr -d '\0' < /proc/device-tree/model)
  elif [[ -r /sys/devices/virtual/dmi/id/product_name ]]; then
    MODEL=$(cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null)
  fi
  [[ -z "$MODEL" ]] && MODEL="genérico"
  case "$OS_ID" in
    raspbian|debian|ubuntu|linuxmint|pop) : ;;
    *) warn "SO no probado ($OS_NAME). Está pensado para Debian, Ubuntu y Raspberry Pi OS." ;;
  esac
}

cpu_temp() {
  if need vcgencmd; then vcgencmd measure_temp 2>/dev/null | cut -d= -f2
  elif [[ -r /sys/class/thermal/thermal_zone0/temp ]]; then
    awk '{printf "%.1f°C\n", $1/1000}' /sys/class/thermal/thermal_zone0/temp
  fi
}

# ══════════════════════════════════════ systemd-resolved: el choque de Ubuntu ══
# En Ubuntu, systemd-resolved abre un stub en 127.0.0.53:53 y Pi-hole no puede
# arrancar. Hay que desactivar solo el stub, no el servicio entero.
resolved_conflicts() {
  systemctl is-active --quiet systemd-resolved 2>/dev/null || return 1
  ss -tulpnH 2>/dev/null | grep -q '127.0.0.53:53' || return 1
  return 0
}

fix_resolved() {
  step "Liberando el puerto 53 de systemd-resolved"
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/no-stub.conf <<'EOF'
# Cede el puerto 53 a Pi-hole. systemd-resolved sigue funcionando como
# resolvedor local para el propio sistema, solo deja de abrir el stub.
[Resolve]
DNSStubListener=no
EOF
  # /etc/resolv.conf apunta al stub; hay que llevarlo al fichero real.
  if [[ -L /etc/resolv.conf ]] && [[ "$(readlink -f /etc/resolv.conf)" == *stub-resolv.conf ]]; then
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    ok "/etc/resolv.conf reapuntado fuera del stub"
  fi
  systemctl restart systemd-resolved
  sleep 2
  if resolved_conflicts; then
    err "El puerto 53 sigue ocupado por systemd-resolved"
    return 1
  fi
  ok "Puerto 53 libre"
}

# ═════════════════════════════════════════════════ Pi-hole v5 / v6 ═════════════
PH_MAJOR=0
detect_pihole() {
  need pihole || { PH_MAJOR=0; return; }
  if [[ -f "$PIHOLE_TOML" ]] && pihole-FTL --config dns.port >/dev/null 2>&1; then
    PH_MAJOR=6
  elif [[ -f /etc/pihole/setupVars.conf ]]; then
    PH_MAJOR=5
  else
    PH_MAJOR=6
  fi
}

ph_get() { [[ $PH_MAJOR -ge 6 ]] && pihole-FTL --config "$1" 2>/dev/null; }
ph_set() {
  local k="$1" v="$2"
  if [[ $PH_MAJOR -lt 6 ]]; then warn "Pi-hole v5: '$k' hay que cambiarlo desde el panel web"; return 1; fi
  if pihole-FTL --config "$k" "$v" >/dev/null 2>&1; then
    ok "$k = $(pihole-FTL --config "$k" 2>/dev/null)"
  else
    warn "No se pudo fijar $k"; return 1
  fi
}

# ══════════════════════════════════════════════════ config persistente ═════════
LISTEN_IP=""; PIHOLE_PORT=53; UNBOUND_PORT=5335; WEB_PORT=80

load_conf() {
  # shellcheck disable=SC1090
  [[ -f "$CONF" ]] && source "$CONF"
  [[ -z "$LISTEN_IP" ]] && LISTEN_IP=$(ip -4 -br addr show scope global 2>/dev/null | awk 'NR==1{sub(/\/.*/,"",$3); print $3}')
  if [[ -f "$UNBOUND_CONF" ]]; then
    local p; p=$(grep -oP '^\s*port:\s*\K[0-9]+' "$UNBOUND_CONF" 2>/dev/null | head -1)
    [[ -n "$p" ]] && UNBOUND_PORT="$p"
  fi
  detect_pihole
  if [[ $PH_MAJOR -ge 6 ]]; then
    local q w
    q=$(ph_get dns.port);        [[ "$q" =~ ^[0-9]+$ ]] && PIHOLE_PORT="$q"
    w=$(ph_get webserver.port | grep -oE '^[0-9]+' | head -1); [[ "$w" =~ ^[0-9]+$ ]] && WEB_PORT="$w"
  fi
}

save_conf() {
  cat > "$CONF" <<EOF
# Generado por nexo-dns.sh v$NEXO_VERSION — $(date '+%Y-%m-%d %H:%M')
LISTEN_IP=$LISTEN_IP
PIHOLE_PORT=$PIHOLE_PORT
UNBOUND_PORT=$UNBOUND_PORT
WEB_PORT=$WEB_PORT
EOF
  chmod 644 "$CONF"
}

backup_now() {
  local d
  d="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$d"
  [[ -f "$UNBOUND_CONF" ]] && cp -a "$UNBOUND_CONF" "$d/"
  [[ -f "$PIHOLE_TOML"  ]] && cp -a "$PIHOLE_TOML"  "$d/"
  [[ -f "$CONF"         ]] && cp -a "$CONF"         "$d/"
  echo "$d"
}

# ══════════════════════════════════════════════════════════ validaciones ═══════
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
valid_ip() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  awk -F. '{for(i=1;i<=4;i++) if($i>255) exit 1}' <<<"$1"
}
# ¿Hay alguien escuchando en ese puerto que no sea el proceso que esperamos?
# Se compara el último campo tras los ':' en lugar de usar una regex: la
# dirección local puede ser 0.0.0.0:53, [::]:53 o 127.0.0.53%lo:53, y un
# patrón como ":53$" con anclaje pasado por -v a awk no es portable.
port_taken_by_other() {
  local port="$1" allow="$2"
  ss -tulpnH 2>/dev/null \
    | awk -v p="$port" '{ n = split($5, a, ":"); if (a[n] == p) print }' \
    | grep -qv "$allow"
}

RAM_MB=0; CORES=1; THREADS=1; MSG=32m; RRSET=64m; KEYC=8m; NEG=2m; SLABS=1
detect_hw() {
  RAM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  CORES=$(nproc --all)
  if   (( RAM_MB <= 1100 )); then THREADS=2; MSG=32m;  RRSET=64m;  KEYC=8m;  NEG=2m
  elif (( RAM_MB <= 2200 )); then THREADS=2; MSG=48m;  RRSET=96m;  KEYC=16m; NEG=4m
  elif (( RAM_MB <= 4400 )); then THREADS=4; MSG=64m;  RRSET=128m; KEYC=32m; NEG=4m
  else                            THREADS=4; MSG=128m; RRSET=256m; KEYC=64m; NEG=8m
  fi
  (( THREADS > CORES )) && THREADS=$CORES
  SLABS=1; while (( SLABS < THREADS )); do SLABS=$(( SLABS * 2 )); done
}

# ═════════════════════════════════════════════════════ CONFIG DE UNBOUND ═══════
find_root_hints() {
  local f
  for f in /usr/share/dns/root.hints /var/lib/unbound/root.hints /etc/unbound/root.hints; do
    [[ -s "$f" ]] && { echo "$f"; return; }
  done
  mkdir -p /var/lib/unbound
  if curl -fsSL --retry 3 -o /var/lib/unbound/root.hints.new https://www.internic.net/domain/named.root 2>/dev/null \
     && grep -q 'A.ROOT-SERVERS.NET' /var/lib/unbound/root.hints.new; then
    mv /var/lib/unbound/root.hints.new /var/lib/unbound/root.hints
    chown unbound:unbound /var/lib/unbound/root.hints 2>/dev/null || true
  fi
  echo /var/lib/unbound/root.hints
}

write_unbound_conf() {
  detect_hw
  local hints; hints=$(find_root_hints)
  local anchor_line='    auto-trust-anchor-file: "/var/lib/unbound/root.key"'
  if grep -rqs 'auto-trust-anchor-file' /etc/unbound/unbound.conf.d/ \
       --exclude="$(basename "$UNBOUND_CONF")" 2>/dev/null; then
    anchor_line='    # auto-trust-anchor-file ya lo declara otro fichero de unbound.conf.d/'
  fi

  cat > "$UNBOUND_CONF" <<EOF
###############################################################################
#  Unbound como resolver recursivo para Pi-hole
#  Generado por nexo-dns.sh v$NEXO_VERSION el $(date '+%Y-%m-%d %H:%M')
#  $MODEL · $OS_NAME · ${RAM_MB} MB RAM · ${CORES} núcleos
#  NO editar a mano: usa  sudo bash nexo-dns.sh  → Reoptimizar
###############################################################################
server:
    ### Escucha ###############################################################
    # Solo localhost: quien pregunta es Pi-hole, en la misma máquina. Fijarlo
    # evita acabar exponiendo un resolver recursivo abierto sin querer.
    interface: 127.0.0.1
    port: $UNBOUND_PORT
    do-ip4: yes
    do-ip6: no
    prefer-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow

    ### Identidad #############################################################
    verbosity: 0
    hide-identity: yes
    hide-version: yes
    # Con chroot activo, root.key y root.hints quedarían fuera de la jaula.
    chroot: ""

    ### Endurecimiento ########################################################
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    harden-algo-downgrade: no
    unwanted-reply-threshold: 10000000
    # Responde NXDOMAIN desde caché con NSEC ya validados: menos tráfico fuera.
    aggressive-nsec: yes
    # 0x20 encoding DESACTIVADO a propósito: bastantes autoritativos y CDNs no
    # preservan mayúsculas y devuelven SERVFAIL intermitentes. Con DNSSEC
    # validando, el anti-spoofing extra no compensa la rotura.
    use-caps-for-id: no

    ### Anti DNS-rebinding ####################################################
    # Un dominio público jamás debe resolver a una IP de tu red interna.
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    private-address: ::ffff:0:0/96
    # 100.64.0.0/10 (CGNAT/Tailscale) NO se bloquea: rompería el split-DNS de
    # quien apunte un dominio público a una IP del tailnet.

    ### Privacidad ############################################################
    qname-minimisation: yes
    qname-minimisation-strict: no
    rrset-roundrobin: yes
    minimal-responses: yes
    # Sin subnetcache: ECS filtra tu subred a los autoritativos y además
    # desactiva prefetch y serve-expired para ese tráfico.
    module-config: "validator iterator"

    ### Rendimiento ###########################################################
    num-threads: $THREADS
    so-reuseport: yes
    msg-cache-size: $MSG
    rrset-cache-size: $RRSET
    key-cache-size: $KEYC
    neg-cache-size: $NEG
    msg-cache-slabs: $SLABS
    rrset-cache-slabs: $SLABS
    infra-cache-slabs: $SLABS
    key-cache-slabs: $SLABS
    so-rcvbuf: 1m
    so-sndbuf: 1m
    edns-buffer-size: 1232
    prefetch: yes
    prefetch-key: yes
    # Guarda a quién preguntar y cuánto tarda: acelera las consultas frías.
    infra-host-ttl: 900
    infra-cache-numhosts: 10000

    ### TTLs ##################################################################
    # 120 y no más: los CDN usan TTLs de 30-60 s para balancear y hacer
    # failover. Forzarlos a una hora te deja clavado en una IP muerta.
    cache-min-ttl: 120
    cache-max-ttl: 86400
    serve-expired: yes
    serve-expired-ttl: 3600
    serve-expired-client-timeout: 1800
    serve-expired-reply-ttl: 30

    ### Raíz y DNSSEC #########################################################
    root-hints: "$hints"
$anchor_line

remote-control:
    control-enable: yes
    control-interface: /run/unbound.ctl
EOF
  chmod 644 "$UNBOUND_CONF"
  prune_unsupported
}

prune_unsupported() {
  local tries=0 out bad
  while ! unbound-checkconf >/dev/null 2>&1; do
    (( ++tries > 15 )) && { err "No consigo dejar la config válida"; return 1; }
    out=$(unbound-checkconf 2>&1 || true)
    bad=$(grep -oE "unknown keyword '[^']+'" <<<"$out" | head -1 | sed "s/unknown keyword '//;s/'//")
    if [[ -z "$bad" ]] || ! grep -qE "^[[:space:]]*${bad}:" "$UNBOUND_CONF"; then
      err "unbound-checkconf falla por algo ajeno a este fichero:"
      sed 's/^/    /' <<<"$out"; return 1
    fi
    warn "Tu Unbound no soporta '$bad' — se elimina"
    sed -i "/^[[:space:]]*${bad}:/d" "$UNBOUND_CONF"
  done
  return 0
}

restore_unbound() {
  local d="$1"
  [[ -f "$d/pi-hole.conf" ]] && cp -a "$d/pi-hole.conf" "$UNBOUND_CONF"
  systemctl restart unbound 2>/dev/null || true
  warn "Revertido desde $d"
}

apply_unbound() {
  local bkdir="$1"
  if ! unbound-checkconf >/dev/null 2>&1; then
    err "Configuración inválida:"; unbound-checkconf 2>&1 | sed 's/^/    /'
    restore_unbound "$bkdir"; return 1
  fi
  systemctl restart unbound || { restore_unbound "$bkdir"; return 1; }
  sleep 3
  systemctl is-active --quiet unbound || { err "Unbound no arranca"; restore_unbound "$bkdir"; return 1; }
  dig +short +time=5 +tries=2 google.com @127.0.0.1 -p "$UNBOUND_PORT" >/dev/null 2>&1 \
    || { err "Unbound no resuelve en el puerto $UNBOUND_PORT"; restore_unbound "$bkdir"; return 1; }

  local ad bad
  ad=$(dig +dnssec cloudflare.com @127.0.0.1 -p "$UNBOUND_PORT" +time=5 2>/dev/null | grep -c ' ad;')
  bad=$(dig dnssec-failed.org @127.0.0.1 -p "$UNBOUND_PORT" +time=5 2>/dev/null | grep -c 'status: SERVFAIL')
  if [[ "$ad" == "1" && "$bad" == "1" ]]; then
    ok "DNSSEC valida (firma buena → ad, firma rota → SERVFAIL)"
  else
    warn "DNSSEC no valida como debería (ad=$ad servfail=$bad)"
    warn "Revisa el trust anchor: /var/lib/unbound/root.key"
  fi
  ok "Unbound activo en 127.0.0.1#$UNBOUND_PORT"
}

configure_pihole() {
  detect_pihole
  [[ $PH_MAJOR -eq 0 ]] && { warn "Pi-hole no instalado"; return 1; }
  if [[ $PH_MAJOR -lt 6 ]]; then
    warn "Detectado Pi-hole v$PH_MAJOR. Este script está hecho para v6."
    warn "En el panel web pon como DNS upstream:  127.0.0.1#$UNBOUND_PORT"
    return 1
  fi
  ph_set dns.upstreams "[ \"127.0.0.1#$UNBOUND_PORT\" ]"
  ph_set dns.dnssec false        # Unbound ya valida; hacerlo dos veces gasta CPU
  ph_set dns.domainNeeded true   # no mandar fuera nombres sin dominio
  ph_set dns.bogusPriv true      # ni PTR de rangos privados
  ph_set dns.EDNS0ECS false      # ECS filtraría tu subred a los autoritativos
  systemctl restart pihole-FTL 2>/dev/null || true
  sleep 2
}

apply_sysctl_dns() {
  cat > /etc/sysctl.d/99-nexo-dns.conf <<'EOF'
# Buffers UDP: sin esto Unbound no puede aplicar so-rcvbuf/so-sndbuf y lo
# registra como error en cada arranque. Esto SÍ afecta al DNS (que es UDP).
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.core.netdev_max_backlog = 2048
EOF
  sysctl -q --system 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════ INSTALACIÓN ════════
do_install() {
  clear_screen; step "Instalación de Pi-hole + Unbound"
  detect_os; detect_hw
  echo "  Sistema : $OS_NAME"
  echo "  Equipo  : $MODEL · ${RAM_MB} MB · $CORES núcleos"
  echo "  IP      : $LISTEN_IP"
  echo "  Puertos : Pi-hole $PIHOLE_PORT · Unbound $UNBOUND_PORT · Web $WEB_PORT"
  echo
  yes_no "¿Continuar?" || { info "Cancelado"; pause; return; }

  step "1/6 · Paquetes"
  apt-get update -y || warn "apt-get update falló, sigo"
  apt-get install -y unbound dnsutils curl ca-certificates ethtool \
    || { err "No se pudieron instalar los paquetes"; pause; return 1; }
  ok "Paquetes listos"

  step "2/6 · Puerto 53"
  if resolved_conflicts; then
    warn "systemd-resolved está ocupando el puerto 53 (típico de Ubuntu)."
    warn "Sin liberarlo, Pi-hole no puede arrancar."
    if yes_no "¿Desactivo solo el stub de systemd-resolved?"; then
      fix_resolved || { err "No se pudo liberar el 53"; pause; return 1; }
    else
      err "Sin el puerto 53 libre no se puede seguir"; pause; return 1
    fi
  else
    ok "Puerto 53 disponible"
  fi

  step "3/6 · Pi-hole"
  if need pihole; then
    ok "Pi-hole ya está instalado, no lo toco"
  else
    warn "El instalador de Pi-hole es interactivo y pide su propia configuración."
    warn "Se lanza tal cual; cuando termine, este script sigue."
    pause
    curl -sSL https://install.pi-hole.net | bash || { err "Falló la instalación de Pi-hole"; pause; return 1; }
  fi
  detect_pihole

  step "4/6 · Ajustes del kernel"
  apply_sysctl_dns; ok "Buffers UDP ampliados"

  step "5/6 · Unbound"
  local bk; bk=$(backup_now)
  write_unbound_conf
  apply_unbound "$bk" || { pause; return 1; }

  step "6/6 · Enlazar Pi-hole con Unbound"
  configure_pihole
  save_conf
  echo
  ok "Instalación terminada"
  echo "  Panel web : http://$LISTEN_IP:$WEB_PORT/admin"
  echo "  DNS       : $LISTEN_IP:$PIHOLE_PORT → Unbound 127.0.0.1#$UNBOUND_PORT"
  echo "  Copia     : $bk"
  echo
  warn "Falta lo más importante: que tus equipos lo usen. En el DHCP de tu"
  warn "router pon $LISTEN_IP como ÚNICO servidor DNS. Si dejas uno público"
  warn "de secundario, el filtrado se salta de forma intermitente."
  pause
}

# ═══════════════════════════════════════════════════════ CAMBIO DE PUERTOS ═════
change_unbound_port() {
  clear_screen; step "Puerto de Unbound"
  echo "  Actual: ${BLD}$UNBOUND_PORT${NC}   ·   Pi-hole usa el $PIHOLE_PORT"
  local np; np=$(ask "Nuevo puerto para Unbound:")
  valid_port "$np" || { err "Puerto inválido"; pause; return; }
  [[ "$np" == "$PIHOLE_PORT" ]] && { err "Chocaría con Pi-hole (puerto $PIHOLE_PORT)"; pause; return; }
  if port_taken_by_other "$np" unbound; then
    err "El puerto $np ya lo usa otro proceso:"; ss -tulpn 2>/dev/null | grep ":$np " | sed 's/^/    /'
    pause; return
  fi
  local bk; bk=$(backup_now); info "Copia en $bk"
  sed -i "s/^\(\s*\)port:.*/\1port: $np/" "$UNBOUND_CONF"
  local old="$UNBOUND_PORT"; UNBOUND_PORT="$np"
  if apply_unbound "$bk"; then
    if [[ $PH_MAJOR -lt 6 ]]; then
      # Sin Pi-hole no hay nada que reapuntar, y sobre todo: no se puede
      # condicionar el cambio a que Pi-hole resuelva. Antes se revertía un
      # cambio correcto solo porque Pi-hole no estaba instalado.
      save_conf; ok "Unbound movido del $old al $np"
      warn "Pi-hole no está instalado: cuando lo instales, apunta su upstream"
      warn "a 127.0.0.1#$np"
    else
      ph_set dns.upstreams "[ \"127.0.0.1#$np\" ]"
      systemctl restart pihole-FTL 2>/dev/null || true; sleep 2
      if dig +short +time=5 google.com @127.0.0.1 -p "$PIHOLE_PORT" >/dev/null 2>&1; then
        save_conf; ok "Unbound movido del $old al $np y Pi-hole apuntando ahí"
      else
        err "Pi-hole dejó de resolver; revirtiendo"
        UNBOUND_PORT="$old"; restore_unbound "$bk"
        ph_set dns.upstreams "[ \"127.0.0.1#$old\" ]"; systemctl restart pihole-FTL
      fi
    fi
  else
    UNBOUND_PORT="$old"
  fi
  pause
}

change_pihole_port() {
  clear_screen; step "Puerto DNS de Pi-hole"
  [[ $PH_MAJOR -ge 6 ]] || { err "Pi-hole v6 no está instalado"; pause; return; }
  echo "  Actual: ${BLD}$PIHOLE_PORT${NC}   ·   Unbound usa el $UNBOUND_PORT"
  echo
  warn "Fuera del 53, los clientes NO lo encontrarán solos: casi ningún router"
  warn "ni sistema operativo deja indicar un puerto DNS distinto del 53."
  local np; np=$(ask "Nuevo puerto DNS para Pi-hole:")
  valid_port "$np" || { err "Puerto inválido"; pause; return; }
  [[ "$np" == "$UNBOUND_PORT" ]] && { err "Chocaría con Unbound (puerto $UNBOUND_PORT)"; pause; return; }
  if port_taken_by_other "$np" pihole-FTL; then
    err "El puerto $np ya está ocupado:"; ss -tulpn 2>/dev/null | grep ":$np " | sed 's/^/    /'
    pause; return
  fi
  local old="$PIHOLE_PORT"; backup_now >/dev/null
  ph_set dns.port "$np"; systemctl restart pihole-FTL; sleep 3
  if dig +short +time=5 google.com @127.0.0.1 -p "$np" >/dev/null 2>&1; then
    PIHOLE_PORT="$np"; save_conf; ok "Pi-hole escuchando en el $np"
  else
    err "No responde en el $np; volviendo al $old"
    ph_set dns.port "$old"; systemctl restart pihole-FTL
  fi
  pause
}

change_web_port() {
  clear_screen; step "Puerto del panel web"
  [[ $PH_MAJOR -ge 6 ]] || { err "Pi-hole v6 no está instalado"; pause; return; }
  echo "  Actual: ${BLD}$WEB_PORT${NC}"
  local np; np=$(ask "Nuevo puerto web:")
  valid_port "$np" || { err "Puerto inválido"; pause; return; }
  backup_now >/dev/null
  ph_set webserver.port "$np,[::]:$np"
  systemctl restart pihole-FTL; sleep 2
  WEB_PORT="$np"; save_conf
  ok "Panel en http://$LISTEN_IP:$np/admin"
  pause
}

# ═════════════════════════════════════════════════════════ CAMBIO DE IP ════════
detect_net_stack() {
  if need nmcli && systemctl is-active --quiet NetworkManager 2>/dev/null; then echo nm
  elif [[ -d /etc/netplan ]] && systemctl is-active --quiet systemd-networkd 2>/dev/null; then echo netplan
  elif [[ -f /etc/network/interfaces ]]; then echo ifupdown
  else echo desconocido; fi
}

change_ip() {
  clear_screen; step "IP del servidor"
  local stack; stack=$(detect_net_stack)
  echo "  IP actual : ${BLD}$LISTEN_IP${NC}"
  echo "  Gestor de red detectado: ${BLD}$stack${NC}"
  ip -4 -br addr show scope global | sed 's/^/    /'
  echo
  if [[ "$stack" != "nm" ]]; then
    err "Solo sé cambiar la IP con NetworkManager, y aquí hay '$stack'."
    echo
    case "$stack" in
      netplan)
        info "Edita /etc/netplan/*.yaml y aplica con:  sudo netplan apply" ;;
      ifupdown)
        info "Edita /etc/network/interfaces y reinicia la red" ;;
      *) info "No reconozco el gestor de red de este sistema" ;;
    esac
    warn "No lo toco a ciegas: un error aquí te deja sin acceso a la máquina."
    pause; return
  fi

  err "AVISO: si estás por SSH, cambiar la IP CORTA la sesión."
  warn "Reconectarás a la IP nueva. Si te equivocas de máscara o de gateway,"
  warn "te quedas sin acceso remoto hasta enchufar un teclado a la máquina."
  echo
  local c; c=$(ask "Escribe SI en mayúsculas para seguir:")
  [[ "$c" == "SI" ]] || { info "Cancelado"; pause; return; }

  local nip cidr gw gw_def dev con
  nip=$(ask "Nueva IP (ej. 192.168.1.10):")
  valid_ip "$nip" || { err "IP inválida"; pause; return; }
  cidr=$(ask "Máscara en bits [24]:" 24)
  # 10# obliga a base decimal: sin él, "08" es un error de sintaxis octal y
  # "024" valdría 20.
  [[ "$cidr" =~ ^[0-9]+$ ]] && (( 10#$cidr >= 8 && 10#$cidr <= 32 )) \
    || { err "Máscara inválida"; pause; return; }
  cidr=$(( 10#$cidr ))
  gw_def=$(ip route show default | awk '/default/{print $3; exit}')
  gw=$(ask "Puerta de enlace [$gw_def]:" "$gw_def")
  valid_ip "$gw" || { err "Gateway inválido"; pause; return; }

  dev=$(ip route show default | awk '/default/{print $5; exit}')
  con=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: -v d="$dev" '$2==d{print $1; exit}')
  [[ -z "$con" ]] && { err "No encuentro la conexión de NetworkManager para $dev"; pause; return; }

  info "Conexión '$con' sobre $dev → $nip/$cidr, gw $gw"
  warn "Se aplica en 5 segundos. Aquí se corta la sesión."
  sleep 5
  # Desacoplado del SSH: el cambio termina aunque el terminal muera a mitad.
  setsid nohup bash -c "
    nmcli con mod '$con' ipv4.method manual ipv4.addresses '$nip/$cidr' ipv4.gateway '$gw'
    nmcli con up '$con'
  " >/var/log/nexo-dns-ipchange.log 2>&1 &
  LISTEN_IP="$nip"; save_conf
  echo; ok "Lanzado. Reconecta con:  ssh usuario@$nip"
  echo "  Registro: /var/log/nexo-dns-ipchange.log"
  exit 0
}

# ══════════════════════════════════════════════════════════ TAILSCALE ══════════
install_tailscale() {
  clear_screen; step "Instalar Tailscale"
  if need tailscale; then
    ok "Ya instalado: $(tailscale version 2>/dev/null | head -1)"
  else
    info "Descargando el instalador oficial de tailscale.com..."
    curl -fsSL https://tailscale.com/install.sh | sh || { err "Falló la instalación"; pause; return; }
    ok "Tailscale instalado"
  fi
  echo
  info "Vincular esta máquina requiere abrir una URL e iniciar sesión."
  info "Ejecútalo tú cuando quieras:"
  echo "    ${BLD}sudo tailscale up${NC}"
  echo "  o, si quieres que además sirva de salida a internet:"
  echo "    ${BLD}sudo tailscale up --advertise-exit-node${NC}"
  pause
}

# Compara versiones tipo 1.98.8 >= 1.54
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

optimize_tailscale() {
  clear_screen; step "Optimizar Tailscale"
  need tailscale || { err "Tailscale no está instalado"; pause; return; }
  tailscale status >/dev/null 2>&1 || { warn "Instalado pero sin sesión. Ejecuta: sudo tailscale up"; pause; return; }

  local tsip tsver kver
  tsip=$(tailscale ip -4 2>/dev/null | head -1)
  tsver=$(tailscale version 2>/dev/null | head -1 | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
  kver=$(uname -r | grep -oE '^[0-9]+\.[0-9]+')
  echo "  IP en el tailnet : ${BLD}${tsip:-?}${NC}"
  echo "  Tailscale        : ${tsver:-?}     Kernel: ${kver:-?}"
  echo

  # ── 1. Evitar el bucle de DNS ──
  if tailscale debug prefs 2>/dev/null | grep -q '"CorpDNS": true'; then
    info "Desactivando accept-dns (si esta máquina es el DNS del tailnet, se"
    info "resolvería a sí misma en bucle)"
    tailscale set --accept-dns=false 2>/dev/null && ok "accept-dns = false" || warn "No se pudo cambiar"
  else
    ok "accept-dns ya estaba desactivado"
  fi

  # ── 2. UDP GRO forwarding ──
  # Optimización documentada por Tailscale para exit nodes y subnet routers.
  # Requiere Tailscale >= 1.54 y kernel >= 6.2; por debajo puede empeorarlo.
  echo
  if ! ver_ge "${tsver:-0}" 1.54; then
    warn "UDP GRO necesita Tailscale >= 1.54 (tienes ${tsver:-?}). Se omite."
  elif ! ver_ge "${kver:-0}" 6.2; then
    warn "UDP GRO necesita kernel >= 6.2 (tienes ${kver:-?}). Se omite."
  elif ! need ethtool; then
    warn "Falta ethtool. Instálalo con: apt-get install -y ethtool"
  else
    local dev; dev=$(ip route show default | awk '/default/{print $5; exit}')
    if [[ -z "$dev" ]]; then
      warn "No encuentro la interfaz de salida"
    else
      info "Activando UDP GRO forwarding en $dev"
      if ethtool -K "$dev" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null; then
        ok "UDP GRO activado"
        local ethbin; ethbin=$(command -v ethtool)
        cat > /etc/systemd/system/tailscale-udp-gro.service <<EOF
[Unit]
Description=UDP GRO forwarding para Tailscale (exit node / subnet router)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ethbin -K $dev rx-udp-gro-forwarding on rx-gro-list off

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now tailscale-udp-gro.service >/dev/null 2>&1 \
          && ok "Se reaplica en cada arranque"
      else
        warn "Tu tarjeta o su driver no soporta estos ajustes"
      fi
    fi
  fi

  # ── 3. Reenvío IP para exit node / subnet router ──
  if tailscale status 2>/dev/null | grep -q 'offers exit node' \
     || tailscale debug prefs 2>/dev/null | grep -qE '"AdvertiseRoutes": \[[^]]'; then
    cat > /etc/sysctl.d/99-tailscale.conf <<'EOF'
# Necesario para hacer de exit node o subnet router
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -q --system 2>/dev/null || true
    ok "Reenvío IP activado (ip_forward=$(sysctl -n net.ipv4.ip_forward))"
  fi

  # ── 4. Que Pi-hole atienda al tailnet ──
  echo
  local lm; lm=$(ph_get dns.listeningMode)
  if [[ "$lm" == "ALL" ]]; then
    ok "Pi-hole escucha en todas las interfaces: el tailnet llega"
  elif [[ -n "$lm" ]]; then
    warn "Pi-hole en listeningMode=$lm: los equipos del tailnet NO podrán usarlo"
    yes_no "¿Lo pongo en ALL?" && { ph_set dns.listeningMode ALL; systemctl restart pihole-FTL; }
  fi

  echo
  info "Para usar este Pi-hole fuera de casa, en login.tailscale.com/admin/dns:"
  echo "    · Nameserver global: ${tsip:-<IP del tailnet>}"
  echo "    · Marca «Override local DNS»"
  warn "Eso hace que tus equipos dependan de esta máquina SIEMPRE, también con"
  warn "datos móviles. Si se apaga, se quedan sin DNS en cualquier sitio."
  pause
}

# ═══════════════════════════════════════════════════════ AJUSTES DE RED ════════
network_tuning() {
  clear_screen; step "Ajustes de red (TCP)"
  echo
  echo "  ${BLD}BBR y el DNS${NC}"
  echo "  BBR es control de congestión de ${BLD}TCP${NC}. El DNS va prácticamente todo"
  echo "  por ${BLD}UDP${NC}, así que ${RED}BBR no acelera las consultas DNS${NC}."
  echo
  echo "  Sí mejora: descargas, streaming y el tráfico que pase por esta máquina"
  echo "  si hace de exit node de Tailscale."
  echo
  echo "  Lo que sí acelera el DNS ya está puesto: caché dimensionada, prefetch,"
  echo "  serve-expired y los buffers UDP del kernel."
  echo
  echo "  Congestión actual: ${BLD}$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)${NC}"
  echo "  Disponibles: $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)"
  echo
  echo "    1) Activar BBR + fq"
  echo "    2) Volver a cubic"
  echo "    0) Volver"
  local o; o=$(ask "Opción:")
  case "$o" in
    1)
      grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || modprobe tcp_bbr 2>/dev/null || true
      if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        cat > /etc/sysctl.d/99-nexo-bbr.conf <<'EOF'
# BBR mejora el rendimiento TCP (descargas, streaming, exit node).
# NO afecta al DNS, que es UDP.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
        # Que sobreviva al reinicio si va como módulo
        echo tcp_bbr > /etc/modules-load.d/bbr.conf
        sysctl -q --system 2>/dev/null || true
        ok "BBR activo: $(sysctl -n net.ipv4.tcp_congestion_control)"
      else
        err "Tu kernel no trae BBR"
      fi ;;
    2) rm -f /etc/sysctl.d/99-nexo-bbr.conf /etc/modules-load.d/bbr.conf
       sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1
       ok "Vuelto a cubic" ;;
  esac
  pause
}

# ════════════════════════════════════════════════ PRECALENTADO DE CACHÉ ════════
install_prewarm() {
  clear_screen; step "Precalentado de caché"
  echo
  echo "  El resolver recursivo paga un peaje la primera vez que ve un dominio:"
  echo "  tiene que preguntar a los servidores raíz, al TLD y al autoritativo."
  echo "  Eso son 200-500 ms. Después queda en caché y baja a 2-5 ms."
  echo
  echo "  Esto coge los dominios que TÚ más usas (del historial de Pi-hole) y"
  echo "  los resuelve cada media hora, y 3 min después de cada arranque — que"
  echo "  es cuando la caché está vacía y más duele."
  echo
  [[ $PH_MAJOR -lt 6 ]] && { warn "Necesita Pi-hole v6"; pause; return; }
  yes_no "¿Instalar?" || return

  cat > /usr/local/bin/dns-prewarm.sh <<'SCRIPT'
#!/usr/bin/env bash
# Precalienta la caché de Unbound con los dominios más usados de esta red.
# Consulta al puerto de Unbound para no ensuciar las estadísticas de Pi-hole.
set -uo pipefail
DB=/etc/pihole/pihole-FTL.db
TOP=${1:-250}; DIAS=${2:-7}
PORT=$(grep -oP '^\s*port:\s*\K[0-9]+' /etc/unbound/unbound.conf.d/pi-hole.conf 2>/dev/null | head -1)
PORT=${PORT:-5335}
[[ -r "$DB" ]] || { echo "No puedo leer $DB"; exit 1; }
# status 2 = reenviada, 3 = de caché. Los bloqueados no interesa resolverlos.
mapfile -t DOMS < <(pihole-FTL sqlite3 "$DB" "
  SELECT d.domain FROM query_storage q JOIN domain_by_id d ON q.domain = d.id
  WHERE q.timestamp > strftime('%s','now','-$DIAS days') AND q.status IN (2,3)
  GROUP BY d.domain ORDER BY COUNT(*) DESC LIMIT $TOP;" 2>/dev/null)
[[ ${#DOMS[@]} -eq 0 ]] && { echo "Sin historial todavía"; exit 0; }
OK=0; ERR=0
for d in "${DOMS[@]}"; do
  [[ -z "$d" ]] && continue
  if dig +short +tries=1 +time=3 "$d" @127.0.0.1 -p "$PORT" >/dev/null 2>&1; then OK=$((OK+1)); else ERR=$((ERR+1)); fi
  sleep 0.15
done
echo "precalentados: $OK  fallidos: $ERR  (top $TOP de $DIAS días, puerto $PORT)"
SCRIPT
  chmod +x /usr/local/bin/dns-prewarm.sh

  cat > /etc/systemd/system/dns-prewarm.service <<'EOF'
[Unit]
Description=Precalienta la cache de Unbound con los dominios mas usados
After=unbound.service pihole-FTL.service
Wants=unbound.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dns-prewarm.sh 250 7
Nice=15
IOSchedulingClass=idle
EOF
  cat > /etc/systemd/system/dns-prewarm.timer <<'EOF'
[Unit]
Description=Precalentado periodico de la cache DNS

[Timer]
OnBootSec=3min
OnUnitActiveSec=30min
RandomizedDelaySec=2min

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now dns-prewarm.timer >/dev/null 2>&1
  ok "Instalado y activado"
  info "Primera pasada en marcha (tarda un par de minutos)..."
  systemctl start dns-prewarm.service &
  pause
}

# ═══════════════════════════════════════════════════════ LISTAS DE BLOQUEO ═════
manage_lists() {
  clear_screen; step "Listas de bloqueo"
  [[ -r /etc/pihole/gravity.db ]] || { err "Pi-hole no está instalado (falta gravity.db)"; pause; return; }
  local n; n=$(pihole-FTL sqlite3 /etc/pihole/gravity.db 'SELECT COUNT(*) FROM gravity;' 2>/dev/null)
  echo "  Dominios bloqueados ahora mismo: ${BLD}${n:-?}${NC}"
  echo
  pihole-FTL sqlite3 /etc/pihole/gravity.db \
    "SELECT '  ' || CASE enabled WHEN 1 THEN '[on] ' ELSE '[off]' END || ' ' || COALESCE(comment,address) FROM adlist;" 2>/dev/null
  echo
  echo "    1) Añadir listas recomendadas"
  echo "    2) Actualizar gravity ahora"
  echo "    0) Volver"
  local o; o=$(ask "Opción:")
  case "$o" in
    1)
      local e a c
      for e in \
        "https://big.oisd.nl/|OISD Big - equilibrada, pocos falsos positivos" \
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt|HaGeZi Multi - muy buena calidad" \
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt|HaGeZi Threat Intelligence - malware y phishing" \
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt|AdGuard DNS filter"; do
        a="${e%%|*}"; c="${e##*|}"
        pihole-FTL sqlite3 /etc/pihole/gravity.db \
          "INSERT OR IGNORE INTO adlist (address, comment) VALUES ('$a','$c');" 2>/dev/null && ok "$c"
      done
      echo
      yes_no "¿Actualizar gravity ahora? (tarda unos minutos)" && pihole updateGravity
      ;;
    2) pihole updateGravity ;;
  esac
  pause
}

# ══════════════════════════════════════════════════════════════ ESTADO ═════════
show_status() {
  clear_screen; step "Estado"
  detect_os; detect_hw
  echo "  Sistema  : $OS_NAME"
  echo "  Equipo   : $MODEL · ${RAM_MB} MB · $CORES núcleos"
  echo "  IP       : $LISTEN_IP     Pi-hole v${PH_MAJOR}"
  echo "  Puertos  : Pi-hole $PIHOLE_PORT · Unbound $UNBOUND_PORT · Web $WEB_PORT"
  echo
  local s
  for s in unbound pihole-FTL tailscaled; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then echo "  ${GRN}${DOT}${NC} $s"
    elif systemctl cat "$s" >/dev/null 2>&1;        then echo "  ${RED}${DOT}${NC} $s (parado)"
    else echo "  ${DIM}o $s (no instalado)${NC}"; fi
  done
  echo
  echo "  ${BLD}Resolución${NC}"
  local r1 r2 bl
  r2=$(dig_short +time=3 google.com @127.0.0.1 -p "$UNBOUND_PORT")
  r1=$(dig_short +time=3 google.com @127.0.0.1 -p "$PIHOLE_PORT")
  bl=$(dig_short doubleclick.net @127.0.0.1 -p "$PIHOLE_PORT")
  echo "    Unbound :$UNBOUND_PORT → ${r2:-${RED}sin respuesta${NC}}"
  echo "    Pi-hole :$PIHOLE_PORT → ${r1:-${RED}sin respuesta${NC}}"
  echo "    Bloqueo       → ${bl:-(vacío)}"
  if need unbound-control; then
    local st q h
    st=$(unbound-control stats_noreset 2>/dev/null)
    q=$(awk -F= '/^total.num.queries=/{print $2}' <<<"$st")
    h=$(awk -F= '/^total.num.cachehits=/{print $2}' <<<"$st")
    if [[ -n "${q:-}" && "${q:-0}" -gt 0 ]]; then
      echo
      echo "  ${BLD}Caché de Unbound${NC}"
      awk -v h="${h:-0}" -v q="$q" 'BEGIN{printf "    %d consultas · %d aciertos (%.1f%%)\n", q, h, (h/q)*100}'
      echo "    recursión media: $(awk -F= '/^total.recursion.time.avg=/{print $2}' <<<"$st")s"
    fi
  fi
  if need tailscale && tailscale status >/dev/null 2>&1; then
    echo; echo "  ${BLD}Tailscale${NC}  $(tailscale ip -4 2>/dev/null | head -1)"
    tailscale status 2>/dev/null | head -4 | sed 's/^/    /'
  fi
  echo; echo "  ${BLD}Recursos${NC}"
  free -m | awk 'NR==2{printf "    RAM: %d/%d MB · %d disponibles\n", $3, $2, $7}'
  echo "    Carga: $(cut -d' ' -f1-3 /proc/loadavg)"
  local t; t=$(cpu_temp); [[ -n "$t" ]] && echo "    Temp : $t"
  pause
}

health_check() {
  clear_screen; step "Chequeo con pruebas reales"
  local fails=0 d o s t
  echo "  ${BLD}Resolución${NC}"
  for d in wikipedia.org github.com amazon.es unam.mx; do
    o=$(dig "$d" @127.0.0.1 -p "$PIHOLE_PORT" +time=5 2>/dev/null)
    s=$(grep -oE 'status: [A-Z]+' <<<"$o" | head -1 | awk '{print $2}')
    t=$(grep -oE 'Query time: [0-9]+' <<<"$o" | head -1 | awk '{print $3}')
    if [[ "$s" == "NOERROR" ]]; then printf "    ${GRN}✓${NC} %-18s %s ms\n" "$d" "${t:-?}"
    else printf "    ${RED}✗${NC} %-18s %s\n" "$d" "${s:-sin respuesta}"; fails=$((fails+1)); fi
  done
  echo; echo "  ${BLD}DNSSEC${NC}"
  local ad; ad=$(dig +dnssec cloudflare.com @127.0.0.1 -p "$UNBOUND_PORT" +time=5 2>/dev/null | grep -c ' ad;')
  [[ "$ad" == "1" ]] && echo "    ${GRN}✓${NC} firma válida aceptada (flag ad)" \
                     || { echo "    ${RED}✗${NC} sin flag ad consultando a Unbound"; fails=$((fails+1)); }
  for d in dnssec-failed.org brokendnssec.net; do
    s=$(dig "$d" @127.0.0.1 -p "$UNBOUND_PORT" +time=5 2>/dev/null | grep -oE 'status: [A-Z]+' | head -1 | awk '{print $2}')
    [[ "$s" == "SERVFAIL" ]] && echo "    ${GRN}✓${NC} $d rechazado" \
                             || { echo "    ${RED}✗${NC} $d dio $s (debería ser SERVFAIL)"; fails=$((fails+1)); }
  done
  echo; echo "  ${BLD}Filtrado${NC}"
  for d in doubleclick.net googleadservices.com; do
    local ip; ip=$(dig_short "$d" @127.0.0.1 -p "$PIHOLE_PORT")
    [[ "$ip" == "0.0.0.0" || -z "$ip" ]] && echo "    ${GRN}✓${NC} $d bloqueado" || echo "    ${YEL}!${NC} $d → $ip"
  done
  local gh; gh=$(dig_short github.com @127.0.0.1 -p "$PIHOLE_PORT")
  [[ -n "$gh" ]] && echo "    ${GRN}✓${NC} github.com resuelve normal ($gh)" \
                 || { echo "    ${RED}✗${NC} falso positivo: github.com no resuelve"; fails=$((fails+1)); }

  # ── ¿Lo está usando alguien? ──
  # El fallo más común no es la config: es que el router siga repartiendo
  # su propio DNS y este servidor esté de adorno.
  if [[ -r "$FTL_DB" ]]; then
    echo; echo "  ${BLD}¿Lo usa alguien?${NC}"
    local qn cl
    qn=$(pihole-FTL sqlite3 "$FTL_DB" "SELECT COUNT(*) FROM query_storage WHERE timestamp > strftime('%s','now','-1 day');" 2>/dev/null)
    cl=$(pihole-FTL sqlite3 "$FTL_DB" "SELECT COUNT(DISTINCT client) FROM query_storage WHERE timestamp > strftime('%s','now','-1 day');" 2>/dev/null)
    echo "    ${qn:-0} consultas de ${cl:-0} cliente(s) en 24 h"
    if [[ "${cl:-0}" -le 2 ]]; then
      echo "    ${YEL}!${NC} Muy pocos clientes. Una casa normal tiene 5-20 aparatos."
      echo "      ${DIM}Revisa el DHCP del router: debe repartir $LISTEN_IP como${NC}"
      echo "      ${DIM}ÚNICO DNS. Un secundario público salta el filtrado.${NC}"
    else
      echo "    ${GRN}✓${NC} La red lo está usando"
    fi
  fi
  echo
  (( fails == 0 )) && ok "Todo correcto" || err "$fails prueba(s) fallidas"
  pause
}

do_optimize() {
  clear_screen; step "Reoptimizar Unbound"
  detect_os; detect_hw
  echo "  Se dimensiona para: $MODEL · ${RAM_MB} MB · $CORES núcleos"
  echo "  → num-threads=$THREADS · msg-cache=$MSG · rrset-cache=$RRSET"
  echo
  yes_no "¿Continuar?" || return
  local bk; bk=$(backup_now); info "Copia en $bk"
  apply_sysctl_dns
  write_unbound_conf
  apply_unbound "$bk" && configure_pihole && { save_conf; ok "Optimización aplicada"; }
  pause
}

backups_menu() {
  clear_screen; step "Copias de seguridad"
  local list; mapfile -t list < <(ls -1t "$BACKUP_ROOT" 2>/dev/null | head -10)
  if [[ ${#list[@]} -eq 0 ]]; then info "Todavía no hay copias"; pause; return; fi
  local i=1 b
  for b in "${list[@]}"; do printf '    %2d) %s\n' "$i" "$b"; i=$((i+1)); done
  echo "     0) Volver"
  echo
  local o; o=$(ask "Restaurar la config de Unbound de cuál:")
  [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 1 && o <= ${#list[@]} )) || return
  local src="$BACKUP_ROOT/${list[$((o-1))]}/pi-hole.conf"
  [[ -f "$src" ]] || { err "Esa copia no tiene pi-hole.conf"; pause; return; }
  echo
  yes_no "¿Restaurar ${list[$((o-1))]}?" || return
  local bk; bk=$(backup_now)
  cp -a "$src" "$UNBOUND_CONF"
  if apply_unbound "$bk"; then
    load_conf; save_conf; ok "Restaurado"
  fi
  pause
}

# ══════════════════════════════════════════════════════════════ PANEL ══════════
panel() {
  while true; do
    load_conf; detect_os
    clear_screen
    local up ph
    systemctl is-active --quiet unbound 2>/dev/null    && up="${GRN}${DOT}${NC}" || up="${RED}${DOT}${NC}"
    systemctl is-active --quiet pihole-FTL 2>/dev/null && ph="${GRN}${DOT}${NC}" || ph="${RED}${DOT}${NC}"

    echo
    btop
    brow "${MAG}${LOGO1}${NC}"
    brow "${MAG}${LOGO2}${NC} ${BLD}nexo-dns${NC} ${DIM}v$NEXO_VERSION${NC}"
    brow "${MAG}${LOGO3}${NC} ${DIM}Pi-hole · Unbound · Tailscale${NC}"
    bsep
    brow "$ph Pi-hole :$PIHOLE_PORT     $up Unbound :$UNBOUND_PORT"
    brow "${DIM}$(hostname) · $LISTEN_IP · ${OS_NAME:0:28}${NC}"
    bsep
    brow "${CYN}${I_EST}${NC} ${BLD}ESTADO${NC}"
    brow "   1 Ver estado            2 Chequeo real"
    bsep
    brow "${CYN}${I_CFG}${NC} ${BLD}CONFIGURACIÓN${NC}"
    brow "   3 Puerto Unbound        4 Puerto Pi-hole"
    brow "   5 Puerto web            6 IP del servidor"
    brow "   7 Reoptimizar           8 Listas de bloqueo"
    brow "   9 Precalentar caché"
    bsep
    brow "${CYN}${I_TS}${NC} ${BLD}TAILSCALE${NC}"
    brow "  10 Instalar             11 Optimizar"
    bsep
    brow "${CYN}${I_SYS}${NC} ${BLD}SISTEMA${NC}"
    brow "  12 Red / BBR            13 Reiniciar servicios"
    brow "  14 Copias / restaurar   15 Instalar todo"
    bsep
    brow "   0 Salir"
    bbot
    echo
    local c; c=$(ask "${YEL}Opción:${NC}")
    case "$c" in
      1)  show_status ;;
      2)  health_check ;;
      3)  change_unbound_port ;;
      4)  change_pihole_port ;;
      5)  change_web_port ;;
      6)  change_ip ;;
      7)  do_optimize ;;
      8)  manage_lists ;;
      9)  install_prewarm ;;
      10) install_tailscale ;;
      11) optimize_tailscale ;;
      12) network_tuning ;;
      13) clear_screen; step "Reiniciando"
          systemctl restart unbound    && ok "Unbound" || err "Unbound"
          sleep 1
          systemctl restart pihole-FTL && ok "Pi-hole" || err "Pi-hole"
          pause ;;
      14) backups_menu ;;
      15) do_install ;;
      0)  echo; ok "Hasta luego"; exit 0 ;;
      *)  ;;
    esac
  done
}

# ═══════════════════════════════════════════════════════════════ MAIN ═════════
detect_os
load_conf
case "${1:-panel}" in
  install)   do_install ;;
  status)    show_status ;;
  health)    health_check ;;
  optimize)  do_optimize ;;
  panel|"")  panel ;;
  -h|--help) sed -n '2,20p' "$0" ;;
  *) err "Orden desconocida: $1"; sed -n '2,20p' "$0"; exit 1 ;;
esac
