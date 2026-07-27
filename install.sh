#!/usr/bin/env bash
#
# install.sh — Instalador automático de Pi-hole + Unbound en Raspberry Pi
# Autor: nexo (Dᵃʳᵏ- ᵃᵈᵐᶤᶰ)
# v2.0 — Mejorado: quotes, validaciones, manejo de pihole.toml robusto
#
# Qué hace:
#   1. Instala Pi-hole en modo unattended
#   2. Instala Unbound (resolver recursivo privado)
#   3. Aplica el FIX de puerto 53 (comenta interface/port en unbound.conf)
#   4. Descarga root hints
#   5. Conecta Pi-hole → Unbound (127.0.0.1#5335)
#   6. Configura memoria para Pi 3B (1GB RAM)
#   7. Activa el bloqueo y añade listas élite
#
set -euo pipefail

PIHOLE_PASS="${1:-admin123}"
LOG="/tmp/pihole-unbound-install.log"

# Colores
RED='\033[0;31m'; GREEN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info() { echo -e "${BLU}[i]${NC} $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YEL}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG"; }

echo -e "${GREEN}"
echo "=================================================="
echo "  Pi-hole + Unbound Installer for Raspberry Pi"
echo "=================================================="
echo -e "${NC}"

# --- Comprobaciones previas ---
if [[ $EUID -ne 0 ]] && ! command -v sudo >/dev/null; then
  err "Este script necesita sudo. Ejecuta: sudo bash install.sh"
  exit 1
fi
SUDO=""
if [[ $EUID -ne 0 ]]; then SUDO="sudo"; fi

info "Registrando todo en $LOG"
exec > >(tee -a "$LOG") 2>&1

# --- 1. Actualizar sistema ---
info "Actualizando paquetes..."
$SUDO apt-get update -y && $SUDO apt-get upgrade -y

# --- 2. Instalar Pi-hole (unattended) ---
info "Instalando Pi-hole (modo unattended)..."
if ! command -v pihole >/dev/null 2>&1; then
  curl -sSL https://install.pi-hole.net | $SUDO bash /dev/stdin --unattended
  $SUDO pihole -a -p "$PIHOLE_PASS"
  ok "Pi-hole instalado"
else
  warn "Pi-hole ya está instalado, omitiendo"
fi

# --- 3. Instalar Unbound + dnsutils ---
info "Instalando Unbound..."
$SUDO apt-get install -y unbound dnsutils

# --- 4. FIX de puerto 53 ---
info "Aplicando FIX de puerto: comentando interface/port en unbound.conf..."
$SUDO sed -i 's/^interface:/#interface:/g' /etc/unbound/unbound.conf
$SUDO sed -i 's/^port:/#port:/g' /etc/unbound/unbound.conf

# --- 5. Configuración de Unbound para Pi 3B ---
info "Escribiendo configuración de Unbound (Pi 3B, 1GB RAM)..."
cat <<'EOF' | $SUDO tee /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    # Puerto diferente al de Pi-hole (evita conflicto en 53)
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no

    # Privacidad
    qname-minimisation: yes
    prefetch: yes
    serve-expired: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no

    # Rendimiento Pi 3B (1GB RAM)
    num-threads: 4
    rrset-cache-size: 128m
    msg-cache-size: 64m
    so-rcvbuf: 1m
    so-sndbuf: 1m
    edns-buffer-size: 1232

    # Root hints
    root-hints: "/usr/share/dns/root.hints"

    # Logs mínimos
    verbosity: 0
    hide-identity: yes
    hide-version: yes

    # Control para recargar sin reiniciar
    remote-control:
        control-enable: yes
        control-interface: 127.0.0.1
EOF

# --- 6. Root hints ---
info "Descargando root hints..."
$SUDO wget -q -O /usr/share/dns/root.hints https://www.internic.net/domain/named.root

# --- 7. Reiniciar Unbound ---
info "Reiniciando Unbound..."
$SUDO systemctl restart unbound
$SUDO systemctl enable unbound

# --- 8. Conectar Pi-hole → Unbound ---
info "Conectando Pi-hole a Unbound (127.0.0.1#5335)..."

# Configurar upstream DNS en pihole.toml
PIHOLE_TOML="/etc/pihole/pihole.toml"
if [[ -f "$PIHOLE_TOML" ]]; then
  # Reemplazar upstreams existente o agregar al final
  if grep -q 'upstreams' "$PIHOLE_TOML" 2>/dev/null; then
    $SUDO python3 -c "
import re
with open('$PIHOLE_TOML', 'r') as f:
    content = f.read()
content = re.sub(r'upstreams\s*=\s*\[.*?\]', 'upstreams = [\"127.0.0.1#5335\"]', content, flags=re.DOTALL)
with open('$PIHOLE_TOML', 'w') as f:
    f.write(content)
" 2>/dev/null || {
    # Fallback: borrar lineas de upstreams y agregar
    $SUDO sed -i '/upstreams/d' "$PIHOLE_TOML"
    echo '' | $SUDO tee -a "$PIHOLE_TOML" >/dev/null
    echo 'upstreams = ["127.0.0.1#5335"]' | $SUDO tee -a "$PIHOLE_TOML" >/dev/null
  }
  else
    echo 'upstreams = ["127.0.0.1#5335"]' | $SUDO tee -a "$PIHOLE_TOML" >/dev/null
  fi
  $SUDO sed -i 's/listeningMode = "LOCAL"/listeningMode = "ALL"/' "$PIHOLE_TOML"
else
  warn "No se encontró $PIHOLE_TOML, configura manualmente el upstream DNS"
fi

# --- 9. Añadir listas élite ---
info "Añadiendo listas de bloqueo élite..."
for entry in \
  "https://big.oisd.nl/|OISD Full - balanced, few false positives" \
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt|HaGeZi Multi NORMAL - excellent quality" \
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt|HaGeZi Threat Intelligence Feeds" \
  "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt|AdGuard DNS filter" \
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt|HaGeZi Light - fallback for 1Hosts"; do
  addr="${entry%%|*}"
  cmt="${entry##*|}"
  $SUDO pihole-FTL sqlite3 /etc/pihole/gravity.db \
    "INSERT OR IGNORE INTO adlist (address, comment) VALUES ('$addr', '$cmt');" 2>/dev/null || true
done

# --- 10. Reiniciar y actualizar gravedad ---
info "Reiniciando Pi-hole y actualizando listas..."
$SUDO systemctl restart pihole-FTL || true
sleep 2
$SUDO pihole updateGravity || true

# --- 11. Verificación ---
info "Verificando instalación..."
UP=$(dig +short google.com @127.0.0.1 -p 5335 2>/dev/null | head -1)
if [[ -n "$UP" ]]; then
  ok "Unbound resuelve: $UP"
else
  warn "Unbound no responde en 5335"
fi

BLOCKED=$(dig +short doubleclick.net @127.0.0.1 2>/dev/null | head -1)
if [[ -z "$BLOCKED" ]]; then
  ok "Pi-hole bloqueando anuncios correctamente"
else
  warn "Revisar bloqueo: $BLOCKED"
fi

COUNT=$($SUDO pihole-FTL sqlite3 /etc/pihole/gravity.db 'SELECT COUNT(*) FROM gravity;' 2>/dev/null)
ok "Dominios en gravedad: ${COUNT:-0}"

echo -e "${GREEN}"
echo "=================================================="
echo "  Instalación completada"
echo "  Panel web: http://$(hostname -I | awk '{print $1}')/admin"
echo "  Password : $PIHOLE_PASS"
echo "  DNS      : 127.0.0.1#5335 (Unbound)"
echo "=================================================="
echo -e "${NC}"