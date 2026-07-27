#!/usr/bin/env bash
#
# manage.sh — Panel de gestión TUI para Pi-hole + Unbound
# Autor: nexo (Dᵃʳᵏ- ᵃᵈᵐᶤᶰ)
# v2.0 — Mejorado: validación de vw_gravity, quotes, timeouts DNS
#
set -euo pipefail

SUDO=""
if [[ $EUID -ne 0 ]]; then SUDO="sudo"; fi

# Colores
RED='\033[0;31m'; GREEN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'
CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

clear_screen() { clear 2>/dev/null || printf '\033[2J\033[H'; }

header() {
  clear_screen
  echo -e "${BOLD}${CYN}"
  echo "╔══════════════════════════════════════════════╗"
  echo "║      Pi-hole + Unbound  ·  Panel TUI        ║"
  echo "╚══════════════════════════════════════════════╝"
  echo -e "${NC}"
}

status_line() {
  local name="$1" check="$2"
  if [[ "$check" == "0" ]]; then
    echo -e "  ${GREEN}●${NC} $name"
  else
    echo -e "  ${RED}●${NC} $name"
  fi
}

# Helper: consulta segura a SQLite
sql_query() {
  $SUDO pihole-FTL sqlite3 /etc/pihole/gravity.db "$1" 2>/dev/null || echo ""
}

show_status() {
  header
  echo -e "${BOLD}Estado de servicios:${NC}"
  echo ""

  # Pi-hole FTL
  if systemctl is-active --quiet pihole-FTL 2>/dev/null; then
    status_line "Pi-hole FTL (port 53)" "0"
  else
    status_line "Pi-hole FTL (port 53)" "1"
  fi

  # Unbound
  if systemctl is-active --quiet unbound 2>/dev/null; then
    status_line "Unbound (port 5335)" "0"
  else
    status_line "Unbound (port 5335)" "1"
  fi

  # Bloqueo activo (probar con y sin vista)
  local blocking=""
  blocking=$(sql_query "SELECT enabled FROM vw_gravity LIMIT 1;")
  if [[ -z "$blocking" ]]; then
    blocking=$(sql_query "SELECT 1 FROM gravity LIMIT 1;")
    if [[ -n "$blocking" ]]; then blocking="1"; else blocking="0"; fi
  fi
  if [[ "$blocking" == "1" ]]; then
    status_line "Bloqueo de anuncios" "0"
  else
    status_line "Bloqueo de anuncios" "1"
  fi

  # DNS test
  echo ""
  echo -e "${BOLD}Test de resolución:${NC}"
  local r1 r2
  r1=$(dig +short +time=2 google.com @127.0.0.1 2>/dev/null | head -1)
  r2=$(dig +short +time=2 google.com @127.0.0.1 -p 5335 2>/dev/null | head -1)
  echo -e "  Pi-hole (53):   ${GREEN}${r1:-SIN RESPUESTA}${NC}"
  echo -e "  Unbound (5335): ${GREEN}${r2:-SIN RESPUESTA}${NC}"

  # Dominios
  local n
  n=$(sql_query "SELECT COUNT(*) FROM gravity;")
  echo -e "  Dominios bloqueados: ${YEL}${n:-?}${NC}"
  echo ""
  read -rp "  Presiona Enter para volver..."
}

verify_install() {
  header
  echo -e "${BOLD}Verificación de instalación:${NC}"
  echo ""

  # Verificar que ss existe
  if ! command -v ss >/dev/null 2>&1; then
    echo -e "  ${RED}ss no encontrado. Instala iproute2.${NC}"
    read -rp "  Presiona Enter para volver..."
    return
  fi

  # Puerto 53
  echo -n "  Puerto 53 (Pi-hole): "
  if ss -tlnp 2>/dev/null | grep -qE ':53\s'; then
    echo -e "${GREEN}OK${NC}"
  else
    echo -e "${RED}FALTA${NC}"
  fi

  # Puerto 5335
  echo -n "  Puerto 5335 (Unbound): "
  if ss -tlnp 2>/dev/null | grep -qE ':5335\s'; then
    echo -e "${GREEN}OK${NC}"
  else
    echo -e "${RED}FALTA${NC}"
  fi

  # Fix puerto Unbound
  echo -n "  Fix puerto Unbound: "
  if grep -qE '^#interface:' /etc/unbound/unbound.conf 2>/dev/null; then
    echo -e "${GREEN}Aplicado${NC}"
  else
    echo -e "${YEL}No encontrado${NC}"
  fi

  # Upstream
  echo -n "  Upstream = Unbound: "
  if grep -q '127.0.0.1#5335' /etc/pihole/pihole.toml 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
  else
    echo -e "${RED}No${NC}"
  fi

  # Root hints
  echo -n "  Root hints: "
  if [[ -s /usr/share/dns/root.hints ]]; then
    echo -e "${GREEN}OK${NC}"
  else
    echo -e "${RED}FALTA${NC}"
  fi

  # Listas
  local l
  l=$(sql_query "SELECT COUNT(*) FROM adlist;")
  echo -e "  Listas activas: ${YEL}${l:-?}${NC}"
  echo ""
  read -rp "  Presiona Enter para volver..."
}

restart_services() {
  header
  echo -e "${YEL}Reiniciando servicios...${NC}"
  $SUDO systemctl restart unbound && echo -e "  ${GREEN}Unbound reiniciado${NC}" || echo -e "  ${RED}Error Unbound${NC}"
  sleep 1
  $SUDO systemctl restart pihole-FTL && echo -e "  ${GREEN}Pi-hole reiniciado${NC}" || echo -e "  ${RED}Error Pi-hole${NC}"
  echo -e "${GREEN}Listo.${NC}"
  sleep 2
}

open_port() {
  header
  # Verificar si ufw está instalado
  if ! command -v ufw >/dev/null 2>&1; then
    echo -e "${RED}ufw no está instalado. Instala con: sudo apt-get install ufw${NC}"
    read -rp "  Presiona Enter para volver..."
    return
  fi

  echo -e "${BOLD}Gestión de puerto 53 (firewall):${NC}"
  echo ""
  echo -e "  1) Abrir puerto 53 (ufw allow 53)"
  echo -e "  2) Cerrar puerto 53 (ufw deny 53)"
  echo -e "  3) Estado de ufw"
  echo -e "  0) Volver"
  echo ""
  read -rp "  Opción: " opt
  case "$opt" in
    1) $SUDO ufw allow 53/tcp 2>/dev/null; $SUDO ufw allow 53/udp 2>/dev/null; echo -e "${GREEN}Puerto 53 abierto${NC}";;
    2) $SUDO ufw deny 53/tcp 2>/dev/null; $SUDO ufw deny 53/udp 2>/dev/null; echo -e "${YEL}Puerto 53 cerrado${NC}";;
    3) $SUDO ufw status verbose 2>/dev/null || echo "ufw no habilitado";;
    0) return;;
    *) echo -e "${RED}Opción inválida${NC}";;
  esac
  sleep 2
}

show_lists() {
  header
  echo -e "${BOLD}Listas de bloqueo activas:${NC}"
  echo ""
  local lists
  lists=$(sql_query "SELECT ' - ' || COALESCE(comment, 'sin nombre') || ' (' || COALESCE(address, '?') || ')' FROM adlist;")
  if [[ -n "$lists" ]]; then
    echo "$lists"
  else
    echo "  No hay listas configuradas"
  fi
  echo ""
  read -rp "  Presiona Enter para volver..."
}

# --- Bucle principal ---
while true; do
  header
  echo -e "  ${BOLD}1)${NC} Ver estado"
  echo -e "  ${BOLD}2)${NC} Verificar instalación"
  echo -e "  ${BOLD}3)${NC} Reiniciar servicios"
  echo -e "  ${BOLD}4)${NC} Gestionar puerto 53 (firewall)"
  echo -e "  ${BOLD}5)${NC} Ver listas activas"
  echo -e "  ${BOLD}0)${NC} Salir"
  echo ""
  read -rp "  ${YEL}Selecciona:${NC} " choice
  case "$choice" in
    1) show_status;;
    2) verify_install;;
    3) restart_services;;
    4) open_port;;
    5) show_lists;;
    0) echo -e "${GREEN}Adiós.${NC}"; exit 0;;
    *) echo -e "${RED}Opción inválida${NC}"; sleep 1;;
  esac
done