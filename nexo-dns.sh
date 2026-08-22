#!/usr/bin/env bash
#
#  nexo-dns.sh — Instalador y panel de DNS privado
#  Pi-hole o AdGuard Home + Unbound + Tailscale
#
#  Autor: nexo (Dᵃʳᵏ- ᵃᵈᵐᶤᶰ)   ·   v4.2
#  Compatible: Raspberry Pi OS · Debian 11+ · Ubuntu 20.04+ · VPS
#
#  Uso:
#     sudo bash nexo-dns.sh              → panel
#     sudo bash nexo-dns.sh install      → instalación completa
#     sudo bash nexo-dns.sh status       → estado
#     sudo bash nexo-dns.sh health       → chequeo con pruebas reales
#     sudo bash nexo-dns.sh optimize     → reaplica la optimización
#     sudo bash nexo-dns.sh security     → qué hay expuesto a internet
#     sudo bash nexo-dns.sh firewall     → cierra el DNS al mundo
#     sudo bash nexo-dns.sh engine       → cambia entre Pi-hole y AdGuard Home
#     sudo bash nexo-dns.sh banner       → portada
#
#  El filtro se elige al instalar: Pi-hole o AdGuard Home. Unbound va detrás de
#  cualquiera de los dos. Pueden convivir instalados, pero solo uno tiene el 53.
#
#  Todo cambio hace copia previa y se revierte solo si la verificación falla.
#
#  Detecta si corre en una máquina doméstica o en una VPS pública y cambia
#  en consecuencia los consejos y las comprobaciones de seguridad: en una VPS
#  el riesgo no es quedarse sin internet, es dejar un resolver DNS abierto.
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
NEXO_VERSION="4.2"
CONF=/etc/nexo-dns.conf
UNBOUND_CONF=/etc/unbound/unbound.conf.d/pi-hole.conf
PIHOLE_TOML=/etc/pihole/pihole.toml
FTL_DB=/etc/pihole/pihole-FTL.db
BACKUP_ROOT=/var/backups/nexo-dns
# AdGuard Home no tiene paquete en Debian ni en Ubuntu: su instalador oficial
# deja un binario Go en /opt con su propio servicio systemd.
AGH_DIR=/opt/AdGuardHome
AGH_BIN=$AGH_DIR/AdGuardHome
AGH_YAML=$AGH_DIR/AdGuardHome.yaml
AGH_LOG=$AGH_DIR/data/querylog.json
AGH_SVC=AdGuardHome

# ══════════════════════════════════════════════════════════ presentación ═══════
# Paleta inspirada en ambas marcas y equilibrada para fondo oscuro:
#   Pi-hole   coral + granate + verde de las hojas
#   Unbound   cian + índigo
# Se usa la mayor profundidad de color que soporte el terminal y se degrada
# hasta ANSI de 8 colores sin perder legibilidad. NO_COLOR=1 lo desactiva todo.
COLOR_DEPTH=0
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
  case "${COLORTERM:-}" in
    truecolor|24bit) COLOR_DEPTH=24 ;;
    *)
      _nc=$(tput colors 2>/dev/null) || _nc=8
      [[ "$_nc" =~ ^[0-9]+$ ]] || _nc=8
      if   (( _nc >= 256 )); then COLOR_DEPTH=8
      elif (( _nc >= 8   )); then COLOR_DEPTH=4
      fi ;;
  esac
fi

# fg R G B N256 ANSI → la secuencia que toque según lo que soporte el terminal.
fg() {
  case $COLOR_DEPTH in
    24) printf '\033[38;2;%s;%s;%sm' "$1" "$2" "$3" ;;
    8)  printf '\033[38;5;%sm' "$4" ;;
    4)  printf '\033[%sm' "$5" ;;
  esac
}
# Lo mismo para el color de FONDO. Hace falta para los logotipos: pintando el
# fondo de una celda y el texto de otra se meten dos píxeles en cada carácter.
bg() {
  case $COLOR_DEPTH in
    24) printf '\033[48;2;%s;%s;%sm' "$1" "$2" "$3" ;;
    8)  printf '\033[48;5;%sm' "$4" ;;
    4)  printf '\033[%sm' "$5" ;;
  esac
}

if (( COLOR_DEPTH )); then
  # ── Paleta ───────────────────────────────────────────────────────────
  # Tomada de los dos logotipos. El panel NO usa el color por defecto del
  # terminal: si lo hiciera, heredaria el verde, el ambar o lo que tenga el
  # tema de cada uno y no habria tematica que valga. Aqui todo va explicito.
  PH=$(fg  244  63  94 204 '1;31')   # Pi-hole  rojo coral #F43F5E
  PHD=$(fg 190  24  93 161 '0;31')   # Pi-hole  granate   #BE185D
  PHG=$(fg  74 222 128  84 '1;32')   # Pi-hole  hoja      #4ADE80
  UB=$(fg   34 211 238  45 '1;36')   # Unbound  cian      #22D3EE
  UBN=$(fg  99 102 241  63 '1;34')   # Unbound  índigo    #6366F1
  UBC=$(fg 103 232 249  87 '0;36')   # Unbound  cian claro
  # AdGuard Home entra con su verde de marca. NO se usa para la cabecera de su
  # sección: ESTADO ya lleva verde y dos verdes en la misma columna no se
  # distinguen. La sección del motor va en índigo, que estaba libre.
  AG=$(fg  103 178 121  71 '1;32')   # AdGuard  verde      #67B279
  TS=$(fg  203 213 225 252 '0;37')   # Tailscale, gris frío
  # ── Interfaz ─────────────────────────────────────────────────────────
  TXT=$(fg 241 245 249 255 '0;37')   # texto principal, blanco frío
  MUT=$(fg 148 163 184 246 '0;37')   # texto secundario y valores
  LIN=$(fg  71  85 105 240 '1;30')   # bordes pizarra
  NUM=$(fg 255 255 255 231 '1;37')   # números: máxima legibilidad
  VAL=$(fg 165 243 252 159 '0;36')   # valores configurados
  # ── Estado ───────────────────────────────────────────────────────────
  GRN=$(fg  34 197  94  77 '0;32')   # bien
  YEL=$(fg 250 204  21 220 '1;33')   # ojo
  RED=$(fg 239  68  68 203 '0;31')   # mal
  BLU="$UB"
  DIM=$'\033[2m'; BLD=$'\033[1m'; NC=$'\033[0m'
else
  PH=''; PHD=''; PHG=''; UB=''; UBN=''; UBC=''; AG=''; TS=''
  TXT=''; MUT=''; LIN=''; NUM=''; VAL=''
  GRN=''; YEL=''; RED=''; BLU=''
  RED=''; GRN=''; YEL=''; BLU=''; DIM=''; BLD=''; NC=''
fi

# Bordes: Unicode si la terminal lo soporta, ASCII si no.
# Se consulta la codificación EFECTIVA, no las variables de entorno sueltas:
# `locale charmap` respeta la precedencia LC_ALL > LC_CTYPE > LANG, que es
# exactamente la que usa bash para contar caracteres en ${#cadena}. Mirando
# solo las variables se elegían bordes Unicode con LC_ALL=C y se descuadraba.
if [[ "$(locale charmap 2>/dev/null)" == "UTF-8" ]]; then
  UTF8_OK=1
  TL='╭'; TR='╮'; BL='╰'; BR='╯'; HZ='─'; VT='│'; LT='├'; RT='┤'
  SHZ='─'; ARROW='›'; BULLET='•'; DOT='●'; DOT_OFF='○'
  I_EST='◆'; I_CFG='◇'; I_TS='▲'; I_SYS='■'; I_SEC='▼'
else
  UTF8_OK=0
  TL='+'; TR='+'; BL='+'; BR='+'; HZ='-'; VT='|'; LT='+'; RT='+'
  SHZ='-'; ARROW='>'; BULLET='-'; DOT='o'; DOT_OFF='-'
  I_EST='*'; I_CFG='o'; I_TS='^'; I_SYS='#'; I_SEC='!'
fi

BOXW=64   # ancho interior del cuadro (se recalcula segun la ventana)

# ── Logotipos ──────────────────────────────────────────────────────────────
# Los logotipos de Pi-hole y Unbound en arte ASCII, al estilo de los que
# enseñan screenfetch y neofetch. 30 columnas cada uno.
#
# El caracter '@' es el FONDO del dibujo — el hueco del molinillo de Pi-hole,
# la separacion entre los dos brazos de Unbound— y no se pinta: se deja pasar
# el fondo del terminal, que es como lo hace neofetch. Para verlo dibujado,
# ponle un color a LOGO_BG mas abajo.
#
# El resto de caracteres llevan color por zonas. Las dos convenciones no son
# iguales, ojo al retocarlos:
#   Pi-hole  se colorea por FILA: arriba las hojas, abajo la baya
#   Unbound  por fila tambien, salvo la 13 —la del cambio— donde manda el
#            caracter: '%' es ya el galon azul y el resto sigue siendo cian
LOGO_BG=''          # color del fondo '@'; vacio = no se pinta

# shellcheck disable=SC2034  # por nameref desde render_logo
LOGO_PIH=(
  '@*+***#%@@@@@@@@@@@@@@@@@@@@@@'
  '@#+++++++*%@@@@@@@@@@@@@@@@@@@'
  '@@*++++++++*@@@@@@@%#**#@@@@@@'
  '@@%++++++++++%@@@*+====#@@@@@@'
  '@@@@*+++++**+*@%+=====*@@@@@@@'
  '@@@@@%#*+++*#+#+===+*%@@@@@@@@'
  '@@@@@@@@%##*%@***#%@@@@@@@@@@@'
  '@@@@@@@@@@@%#***##%@@@@@@@@@@@'
  '@@@@@@@@@#**********%@@@@@@@@@'
  '@@@@@@@#*************#%@@@@@@@'
  '@@@@@#***************###%@@@@@'
  '@@@#***************#######%@@@'
  '@%#######%%%######%%########%@'
  '%#########%@@@@@@@@##########%'
  '###########%@@@@@@%###########'
  '%##########@@@@@@@@%#########%'
  '@%########%@%#####%%%#######%@'
  '@@@%#######***************#@@@'
  '@@@@@%###***************#@@@@@'
  '@@@@@@@%#*************#@@@@@@@'
  '@@@@@@@@@%**********#@@@@@@@@@'
  '@@@@@@@@@@@##*****#@@@@@@@@@@@'
)
# Los mismos dos dibujos reducidos a la mitad, para ventanas pequeñas. Se
# sacaron del grande promediando la densidad de cada bloque de 2x2 y volviendo
# a mapearla a la misma rampa de caracteres, no redibujandolos: por eso se
# parecen.
# shellcheck disable=SC2034  # por nameref desde render_logo
LOGO_PIH_MIN=(
  '=++*=@@@@@@@@@@'
  '@*++++=@@++*@@@'
  '@@+*+**+==+@@@@'
  '@@@@+***#+@@@@@'
  '@@@@+******@@@@'
  '@@+*******##*@@'
  '*####*===*####*'
  '#####*@@@*#####'
  '@*###*#**##***@'
  '@@@********+@@@'
  '@@@@@+***+@@@@@'
)
# shellcheck disable=SC2034  # por nameref desde render_logo
LOGO_UNB_MIN=(
  '@@=++=+@+=++=@@'
  '=======@======='
  '=======@======='
  '=======@======='
  '=======@======='
  '====++@@@++===='
  '=+#%++@@@++%#+='
  '@*%%%%%%%%%%%*@'
  '@@+%%%%%%%%%+@@'
  '@@@@@+%%%+@@@@@'
)

# shellcheck disable=SC2034  # por nameref desde render_logo
LOGO_UNB=(
  '@@@@@@@%*+=+%@@@@%+=+*%@@@@@@@'
  '@@@@#*+=====#@@@@#=====+*#@@@@'
  '@#+=========#@@@@#=========+#@'
  '+===========#@@@@#===========+'
  '============#@@@@#============'
  '============#@@@@#============'
  '============#@@@@#============'
  '============#@@@@#============'
  '============#@@@@#============'
  '============#@@@@#============'
  '===========+@@@@@@+==========='
  '=======+*#%@@@@@@@@%#*+======='
  '====+*#%@@@@@@@@@@@@@@%#*+===='
  '=+*#%%%%%%%%@@@@@@%%%%%%%%#*+='
  '%@@%%%%%%%%%%%%%%%%%%%%%%%%@@%'
  '@@%%%%%%%%%%%%##%%%%%%%%%%%%@@'
  '@@@%%%%%%%%%%%%%%%%%%%%%%%%@@@'
  '@@@@@@%%%%%%%%%%%%%%%%%%@@@@@@'
  '@@@@@@@@@%%%%%%%%%%%%@@@@@@@@@'
  '@@@@@@@@@@@@%%%%%%@@@@@@@@@@@@'
)

# Devuelve el color de una celda del dibujo.
logo_color() {   # $1 PIH|UNB · $2 fila · $3 caracter · $4 nº de filas del dibujo
  [[ "$3" == '@' ]] && { printf '%s' "$LOGO_BG"; return; }
  # Las fronteras van en proporcion al alto para que valgan igual con el dibujo
  # grande de 22 filas y con el reducido de 11.
  local r=$(( $2 * 22 / $4 ))
  if [[ "$1" == PIH ]]; then
    if   (( r <= 6  )); then printf '%s' "$PHG"     # hojas
    elif (( r <= 13 )); then printf '%s' "$PH"      # baya, mitad de arriba
    else                     printf '%s' "$PHD"     # baya, mitad de abajo
    fi
  else
    if   (( r <= 12 )); then printf '%s' "$UB"      # brazos cian
    elif (( r <= 14 )); then [[ "$3" == '%' ]] && printf '%s' "$UBN" || printf '%s' "$UB"
    else                     printf '%s' "$UBN"     # galon azul
    fi
  fi
}

# Pinta un dibujo, agrupando las tiradas del mismo color en una sola secuencia
# en vez de emitir un escape por caracter.
ASCII_OUT=()
render_logo() {         # $1 nombre del array · $2 etiqueta PIH|UNB
  local -n _a="$1"
  local r i ch col prev line n=${#_a[@]}
  ASCII_OUT=()
  for r in "${!_a[@]}"; do
    line=''; prev='@@'
    for (( i=0; i<${#_a[r]}; i++ )); do
      ch="${_a[r]:i:1}"
      col=$(logo_color "$2" "$r" "$ch" "$n")
      if [[ "$col" != "$prev" ]]; then line+="${NC}${col}"; prev="$col"; fi
      # el fondo sin color se deja en blanco, que es lo que lo hace legible
      if [[ "$ch" == '@' && -z "$LOGO_BG" ]]; then line+=' '; else line+="$ch"; fi
    done
    ASCII_OUT+=( "$line$NC" )
  done
}

# Cabecera: los dos logotipos uno al lado del otro. Se compone al arrancar.
BANNER_ROWS=()
build_banner() {   # $1 = grande|mini
  local -a L R
  local hueco
  if [[ "${1:-grande}" == mini ]]; then
    render_logo LOGO_PIH_MIN PIH; L=( "${ASCII_OUT[@]}" )
    render_logo LOGO_UNB_MIN UNB; R=( "${ASCII_OUT[@]}" )
    hueco='               '                      # 15 espacios
    R=( "${R[@]}" "$hueco" )
  else
    render_logo LOGO_PIH PIH; L=( "${ASCII_OUT[@]}" )
    render_logo LOGO_UNB UNB; R=( "${ASCII_OUT[@]}" )
    # Unbound tiene dos filas menos: se centra para que no quede colgando.
    hueco='                              '        # 30 espacios
    R=( "$hueco" "${R[@]}" "$hueco" )
  fi
  BANNER_ROWS=()
  local i
  for i in "${!L[@]}"; do
    BANNER_ROWS+=( "${L[$i]}  ${R[$i]:-$hueco}" )
  done
}
# ── Disposición ────────────────────────────────────────────────────────────
# El panel se adapta a la ventana. Importa sobre todo el ANCHO: si el cuadro no
# cabe, el terminal parte cada fila por la mitad y el dibujo se deshace. El
# alto es menos grave — como mucho hay que subir para ver la cabecera.
#
# Tres tallas:
#   grande  logotipos de 30 columnas, menú a dos columnas
#   mini    los mismos logotipos reducidos a la mitad, 15 columnas
#   texto   sin dibujo, para ventanas pequeñas o teléfonos de pie
#
# Se puede forzar con NEXO_LOGO=grande|mini|no
term_dim() {          # $1 = lines|cols
  local v=''
  # `tput` es lo más fiable, pero necesita un TERM válido: por SSH o dentro de
  # cron no siempre lo hay y falla. Por eso hay dos suplentes detrás.
  v=$(tput "$1" 2>/dev/null) || v=''
  if [[ ! "$v" =~ ^[0-9]+$ ]]; then
    if [[ "$1" == lines ]]; then
      v=$(stty size 2>/dev/null | awk '{print $1}'); [[ "$v" =~ ^[0-9]+$ ]] || v="${LINES:-}"
    else
      v=$(stty size 2>/dev/null | awk '{print $2}'); [[ "$v" =~ ^[0-9]+$ ]] || v="${COLUMNS:-}"
    fi
  fi
  [[ "$v" =~ ^[0-9]+$ ]] && (( v > 0 )) || v=$( [[ "$1" == lines ]] && echo 24 || echo 80 )
  printf '%s' "$v"
}

LAYOUT=texto; MENU_COLS=2
elegir_layout() {
  local c l w
  c=$(term_dim cols); l=$(term_dim lines)
  # el cuadro necesita 6 columnas de margen: 2 de sangría, 2 bordes, 2 huecos
  w=$(( c - 6 )); (( w > 64 )) && w=64; (( w < 28 )) && w=28
  set_boxw "$w"
  MENU_COLS=2; (( BOXW < 50 )) && MENU_COLS=1
  case "${NEXO_LOGO:-auto}" in
    grande) LAYOUT=grande; return ;;
    mini)   LAYOUT=mini;   return ;;
    no|0)   LAYOUT=texto;  return ;;
  esac
  if   (( BOXW >= 62 && l >= 56 )); then LAYOUT=grande
  elif (( BOXW >= 34 && l >= 32 )); then LAYOUT=mini
  else                                   LAYOUT=texto
  fi
}

# Longitud visible de una cadena: sin los códigos de color, que ocupan bytes
# pero no se ven. Todo en bash puro — la versión anterior lanzaba sed+tr+wc+tr
# por cada llamada, y el panel hace unas 30 por redibujado: 120 procesos cada
# vez que se pinta el menú, que en una Raspberry se nota.
vislen() {
  local s="$1" out=''
  while [[ "$s" == *$'\033['* ]]; do
    out+="${s%%$'\033['*}"
    s="${s#*$'\033['}"
    s="${s#*m}"
  done
  out+="$s"
  # Sin locale UTF-8 bash cuenta BYTES, así que se quitan los de continuación
  # (10xxxxxx) y de cada carácter multibyte queda solo el primero.
  (( UTF8_OK )) || out="${out//[$'\x80'-$'\xbf']/}"
  printf '%s' "${#out}"
}
# La línea se construye repitiendo la cadena: `tr` trabaja por bytes y
# convertiría un '─' de 3 bytes en tres caracteres rotos.
HLINE=''
set_boxw() {
  BOXW=$1
  HLINE=''
  local _i
  for ((_i=0; _i<BOXW+2; _i++)); do HLINE+="$HZ"; done
}
set_boxw "$BOXW"
hline()  { printf '%s' "$HLINE"; }
btop()   { printf '  %s%s%s%s%s\n' "$LIN" "$TL" "$(hline)" "$TR" "$NC"; }
bsep()   { printf '  %s%s%s%s%s\n' "$LIN" "$LT" "$(hline)" "$RT" "$NC"; }
bbot()   { printf '  %s%s%s%s%s\n' "$LIN" "$BL" "$(hline)" "$BR" "$NC"; }
repeat_char() {  # $1 carácter · $2 cantidad
  local out='' i
  for (( i=0; i<$2; i++ )); do out+="$1"; done
  printf '%s' "$out"
}
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
    t+="…"; l=$(( l + 1 ))
  fi
  pad=$(( BOXW - l )); (( pad < 0 )) && pad=0
  # El ${NC} final va siempre: si el recorte se ha comido el reset de una
  # secuencia de color, el color se derramaría sobre el borde y las filas
  # siguientes. Como no ocupa ancho visible, no descuadra nada.
  printf '  %s%s%s %s%*s %s%s%s\n' "$LIN" "$VT" "$NC" "$t$NC" "$pad" '' "$LIN" "$VT" "$NC"
}
# Rellena hasta un ancho contando caracteres visibles. `printf %-*s` no sirve:
# cuenta BYTES, y una "é" ocupa dos, así que las columnas se descuadraban.
pad_to() {
  local t="$1" n="$2" l
  l=$(vislen "$t"); (( n -= l )); (( n < 0 )) && n=0
  printf '%s%*s' "$t" "$n" ''
}
# Una opción del menú: el número es lo que se teclea, así que va en blanco y
# destacado; la etiqueta en texto normal; el valor actual, si lo hay, apagado.
# Enseñar el valor ahí ahorra entrar solo para mirarlo.
mi() {   # $1 número · $2 etiqueta · $3 valor (opcional)
  local s
  printf -v s '%s[%2s]%s %s%s%s %s%s%s' \
    "$NUM" "$1" "$NC" "$LIN" "$ARROW" "$NC" "$TXT" "$2" "$NC"
  [[ -n "${3:-}" ]] && s+=" ${VAL}${3}${NC}"
  printf '%s' "$s"
}
# Cabecera de sección: título corto y una guía fina hasta el borde. La línea
# mantiene la estructura visible sin llenar el panel de cajas y colores.
sec() {  # $1 icono · $2 color · $3 título
  local label fill n
  label="${2}${1}${NC} ${BLD}${2}${3}${NC}"
  n=$(( BOXW - $(vislen "$label") - 2 )); (( n < 0 )) && n=0
  fill=$(repeat_char "$SHZ" "$n")
  brow "$label ${LIN}$fill${NC}"
}
# Pinta los elementos de un menú en una o dos columnas según quepa.
menu_items() {
  local -a it=("$@")
  local i w
  if (( MENU_COLS >= 2 )); then
    w=$(( (BOXW - 3) / 2 ))
    for (( i=0; i<${#it[@]}; i+=2 )); do
      if (( i+1 < ${#it[@]} )); then
        brow "  $(pad_to "${it[i]}" "$w")${it[i+1]}"
      else
        brow "  ${it[i]}"
      fi
    done
  else
    for i in "${!it[@]}"; do brow "  ${it[i]}"; done
  fi
}

# Fila centrada dentro del cuadro, para los banners.
bcenter() {
  local t="${1:-}" l pad
  l=$(vislen "$t"); pad=$(( (BOXW - l) / 2 )); (( pad < 0 )) && pad=0
  brow "$(printf '%*s%s' "$pad" '' "$t")"
}
banner_rows() { printf '%s\n' "${BANNER_ROWS[@]}"; }
# Cabecera compartida por el panel y la portada. Así el banner no es un adorno
# separado: logos, nombre, versión y lema forman una sola identidad visual.
draw_brand_header() {
  local r
  case "$LAYOUT" in
    grande|mini)
      build_banner "$LAYOUT"
      while IFS= read -r r; do bcenter "$r"; done < <(banner_rows) ;;
    *)
      brow ''
      bcenter "${PH}${BLD}Pi-hole${NC} ${LIN}${BULLET}${NC} ${UB}${BLD}Unbound${NC} ${LIN}${BULLET}${NC} ${TS}Tailscale${NC}" ;;
  esac
  bcenter "${BLD}${TXT}nexo-dns${NC} ${MUT}v$NEXO_VERSION${NC}"
  bcenter "${MUT}Privado ${LIN}${BULLET}${NC} ${MUT}filtrado ${LIN}${BULLET}${NC} ${MUT}recursivo${NC}"
  [[ "$LAYOUT" == texto ]] && brow ''
}

# Portada a pantalla completa: se usa al instalar y con `nexo-dns.sh banner`.
splash() {
  elegir_layout
  echo
  btop
  draw_brand_header
  bbot
  echo
}

# Una insignia compacta de servicio: semántica en el punto y marca en el nombre.
service_badge() {  # $1 estado on|off|na · $2 color · $3 nombre · $4 valor
  local mark state_col
  case "$1" in
    on)  mark="$DOT";     state_col="$GRN" ;;
    off) mark="$DOT";     state_col="$RED" ;;
    *)   mark="$DOT_OFF"; state_col="$MUT" ;;
  esac
  printf '%s%s%s %s%s%s%s' "$state_col" "$mark" "$NC" \
    "$2" "$3" "$NC" "${4:+ ${VAL}$4${NC}}"
}

info() { echo "${BLU}[i]${NC} $*"; }
ok()   { echo "${GRN}[✓]${NC} $*"; }
warn() { echo "${YEL}[!]${NC} $*"; }
err()  { echo "${RED}[✗]${NC} $*"; }
step() { echo; echo "${PH}══${NC} ${BLD}${TXT}$*${NC}"; }
pause(){ [[ -t 0 ]] || return 0; echo; read -rp "  ${DIM}Enter para continuar...${NC} " _ || true; }
ask()  { local p="$1" d="${2:-}" r; read -rp "  $p " r || true; echo "${r:-$d}"; }
yes_no(){ local r; r=$(ask "$1 [s/N]"); [[ "$r" =~ ^[sSyY]$ ]]; }

clear_screen() { clear 2>/dev/null || printf '\033[2J\033[H'; }

# ══════════════════════════════════════════════════════════ requisitos ═════════
need() { command -v "$1" >/dev/null 2>&1; }
require_root() {
  [[ $EUID -eq 0 ]] || {
    err "Hace falta root. Ejecuta: sudo bash $0 ${*:-}"
    exit 1
  }
}

# Evita dos instalaciones o dos paneles modificando los mismos ficheros a la
# vez. `status`, `health` y `security` siguen disponibles mientras tanto.
acquire_lock() {
  need flock || return 0
  exec 9>/run/lock/nexo-dns.lock || {
    err "No se pudo crear el bloqueo de ejecución"
    exit 1
  }
  if ! flock -n 9; then
    err "Ya hay otra instancia de nexo-dns realizando cambios"
    exit 1
  fi
}

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

# ══════════════════════════════════════════ ¿máquina en casa o VPS pública? ════
# No es un detalle cosmético: cambia cuál es el consejo correcto y cuál es el
# riesgo. En casa el DNS se reparte por el DHCP del router y el peor caso es
# quedarte sin internet. En una VPS no hay DHCP que tocar, y en cambio aparece
# un riesgo que en casa no existe: dejar un resolver recursivo abierto al
# mundo. Los resolvers abiertos se usan para amplificar ataques DDoS — una
# consulta de 60 bytes devuelve 4 KB — y acabas con la VPS suspendida por abuso.
IS_VPS=0; PLATFORM=""
detect_platform() {
  local virt vendor
  # Una Raspberry o un mini-PC en casa: hardware físico, no hay más que mirar.
  if [[ -r /proc/device-tree/model ]]; then
    PLATFORM="$MODEL"; IS_VPS=0; return
  fi
  vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
  case "$vendor" in
    *Amazon*)       PLATFORM="Amazon EC2"   ; IS_VPS=1 ;;
    *DigitalOcean*) PLATFORM="DigitalOcean" ; IS_VPS=1 ;;
    *Google*)       PLATFORM="Google Cloud" ; IS_VPS=1 ;;
    *Hetzner*)      PLATFORM="Hetzner"      ; IS_VPS=1 ;;
    *Vultr*)        PLATFORM="Vultr"        ; IS_VPS=1 ;;
    *Microsoft*)    PLATFORM="Azure"        ; IS_VPS=1 ;;
    *OVH*|*Oracle*) PLATFORM="$vendor"      ; IS_VPS=1 ;;
    *Scaleway*|*Linode*|*Akamai*) PLATFORM="$vendor"; IS_VPS=1 ;;
    *)
      virt=$(systemd-detect-virt 2>/dev/null) || virt=none
      if [[ "$virt" != none ]]; then PLATFORM="virtualizado ($virt)"; IS_VPS=1
      else PLATFORM="${MODEL:-hardware físico}"; IS_VPS=0; fi ;;
  esac
  # Una IP pública directa en la interfaz zanja la duda: esto da a internet.
  local a
  a=$(ip -4 -br addr show scope global 2>/dev/null | awk 'NR==1{sub(/\/.*/,"",$3); print $3}')
  if [[ -n "$a" ]] && ! is_private_ip "$a"; then IS_VPS=1; fi
}

is_private_ip() {
  case "$1" in
    10.*|192.168.*|127.*|169.254.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;  # CGNAT/tailnet
    *) return 1 ;;
  esac
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

# ═══════════════════════════════════════════════════════ AdGuard Home ══════════
AGH_PRESENT=0; AGH_VER=""; AGH_READY=0
detect_adguard() {
  AGH_PRESENT=0; AGH_VER=""; AGH_READY=0
  [[ -x "$AGH_BIN" ]] || return 0
  AGH_PRESENT=1
  AGH_VER=$("$AGH_BIN" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  # El asistente web es quien crea el usuario admin. Hasta pasar por él, el YAML
  # no tiene bloque `users:` y AdGuard sigue en modo instalación escuchando solo
  # en el 3000: está vivo pero no resuelve ni filtra nada.
  if [[ -f "$AGH_YAML" ]] && grep -qE '^users:' "$AGH_YAML" \
     && ! grep -qE '^users:[[:space:]]*\[\]' "$AGH_YAML"; then
    AGH_READY=1
  fi
  return 0
}

# Editor mínimo del YAML de AdGuard. No se usa `yq` a propósito: no está en
# Debian ni en Ubuntu, y meter una dependencia nueva para tocar ocho claves no
# compensa. El fichero es plano y de indentación fija (2 espacios por nivel),
# así que basta localizar el bloque de primer nivel y sustituir dentro.
#   $1 bloque · $2 clave · $3... líneas de reemplazo YA indentadas
agh_put() {
  local blk="$1" key="$2"; shift 2
  local repl; repl=$(printf '%s\n' "$@")
  [[ -f "$AGH_YAML" ]] || { err "No existe $AGH_YAML"; return 1; }
  local tmp; tmp=$(mktemp) || return 1
  awk -v blk="$blk" -v key="$key" -v repl="$repl" '
    BEGIN { inblk=0; done=0; skip=0 }
    {
      if ($0 ~ /^[A-Za-z_][A-Za-z0-9_]*:/) {
        if (inblk && !done) { print repl; done=1 }
        inblk = ($0 ~ "^" blk ":") ? 1 : 0
        skip=0; print; next
      }
      if (inblk && !done && $0 ~ "^  " key ":") {
        print repl; done=1; skip=1; next   # skip: tragar la lista o mapa viejo
      }
      if (skip) { if ($0 ~ /^    /) next; skip=0 }
      print
    }
    END { if (inblk && !done) print repl }
  ' "$AGH_YAML" > "$tmp" || { rm -f "$tmp"; return 1; }
  # Un fichero vacío significa que awk falló: no pisar la config buena.
  [[ -s "$tmp" ]] || { err "El editor de YAML devolvió un fichero vacío"; rm -f "$tmp"; return 1; }
  cat "$tmp" > "$AGH_YAML" && rm -f "$tmp"
}

agh_set() { agh_put "$1" "$2" "  $2: $3"; }
agh_set_list() {
  local blk="$1" key="$2"; shift 2
  local lines=("  $key:") i
  for i in "$@"; do lines+=("    - $i"); done
  agh_put "$blk" "$key" "${lines[@]}"
}
agh_get() {   # $1 bloque · $2 clave
  [[ -f "$AGH_YAML" ]] || return 1
  awk -v blk="$1" -v key="$2" '
    /^[A-Za-z_][A-Za-z0-9_]*:/ { inblk = ($0 ~ "^" blk ":") ? 1 : 0; next }
    inblk && $0 ~ "^  " key ":" { sub("^  " key ":[ ]*", ""); print; exit }
  ' "$AGH_YAML"
}
agh_block_list() {   # igual que agh_get pero para claves lista, una por línea
  [[ -f "$AGH_YAML" ]] || return 1
  awk -v blk="$1" -v key="$2" '
    /^[A-Za-z_][A-Za-z0-9_]*:/ { inblk = ($0 ~ "^" blk ":") ? 1 : 0; inkey=0; next }
    !inblk { next }
    $0 ~ "^  " key ":" { inkey=1; next }
    inkey {
      if ($0 ~ /^    - /) { sub(/^    - /, ""); print; next }
      if ($0 ~ /^  /) { inkey=0 }
    }
  ' "$AGH_YAML"
}

# ══════════════════════════════════════════════════════ motor de filtrado ══════
# ENGINE decide a quién se configura, se consulta y se muestra. Los dos motores
# pueden convivir instalados, pero solo uno puede quedarse el puerto 53.
ENGINE=""
valid_engine() { [[ "$1" == "pihole" || "$1" == "adguard" ]]; }

detect_engine() {
  detect_pihole; detect_adguard
  # Si hay elección guardada y ese motor sigue instalado, se respeta.
  case "$ENGINE" in
    pihole)  (( PH_MAJOR > 0 )) && return 0 ;;
    adguard) (( AGH_PRESENT ))  && return 0 ;;
  esac
  # Si no, manda la realidad: quien tenga cogido el 53.
  local holder
  holder=$(ss -tulpnH 2>/dev/null | awk '{n=split($5,a,":"); if(a[n]=="53") print}')
  if   grep -q 'AdGuardHome' <<<"$holder"; then ENGINE=adguard
  elif grep -q 'pihole-FTL'  <<<"$holder"; then ENGINE=pihole
  elif (( AGH_PRESENT ));                  then ENGINE=adguard
  else                                          ENGINE=pihole
  fi
  return 0
}

engine_name()  { [[ "$ENGINE" == adguard ]] && echo "AdGuard Home" || echo "Pi-hole"; }
engine_short() { [[ "$ENGINE" == adguard ]] && echo "AdGuard"      || echo "Pi-hole"; }
engine_color() { [[ "$ENGINE" == adguard ]] && echo "$AG"          || echo "$PH"; }
engine_svc()   { [[ "$ENGINE" == adguard ]] && echo "$AGH_SVC"     || echo "pihole-FTL"; }
other_engine() { [[ "$ENGINE" == adguard ]] && echo "pihole"       || echo "adguard"; }
engine_installed() {
  case "${1:-$ENGINE}" in
    adguard) (( AGH_PRESENT )) ;;
    *)       (( PH_MAJOR > 0 )) ;;
  esac
}
# ¿Está el motor listo para configurarse? Con AdGuard no basta el servicio: sin
# pasar el asistente está vivo pero sin hacer DNS.
engine_ready() {
  if [[ "$ENGINE" == adguard ]]; then (( AGH_PRESENT && AGH_READY )); else (( PH_MAJOR >= 6 )); fi
}

# ══════════════════════════════════════════════════ config persistente ═════════
LISTEN_IP=""; PIHOLE_PORT=53; UNBOUND_PORT=5335; WEB_PORT=80

load_conf() {
  # Solo se aceptan las cuatro claves que escribe save_conf. Antes se hacía
  # `source` del fichero completo: un contenido manipulado se ejecutaría como
  # root al abrir el panel.
  if [[ -f "$CONF" ]]; then
    local key value
    while IFS='=' read -r key value; do
      case "$key" in
        LISTEN_IP)    valid_ip "$value"     && LISTEN_IP="$value" ;;
        PIHOLE_PORT)  valid_port "$value"   && PIHOLE_PORT="$value" ;;
        UNBOUND_PORT) valid_port "$value"   && UNBOUND_PORT="$value" ;;
        WEB_PORT)     valid_port "$value"   && WEB_PORT="$value" ;;
        # ENGINE entra con validador propio, igual que el resto: solo dos
        # valores posibles. Un fichero manipulado no puede colar otra cosa.
        ENGINE)       valid_engine "$value" && ENGINE="$value" ;;
      esac
    done < "$CONF"
  fi
  [[ -z "$LISTEN_IP" ]] && LISTEN_IP=$(ip -4 -br addr show scope global 2>/dev/null | awk 'NR==1{sub(/\/.*/,"",$3); print $3}')
  if [[ -f "$UNBOUND_CONF" ]]; then
    local p; p=$(grep -oP '^\s*port:\s*\K[0-9]+' "$UNBOUND_CONF" 2>/dev/null | head -1)
    [[ -n "$p" ]] && UNBOUND_PORT="$p"
  fi
  detect_engine
  # PIHOLE_PORT conserva el nombre aunque el filtro sea AdGuard: es el puerto
  # DNS del motor activo, y renombrarlo obligaría a tocar el fichero de
  # configuración y las dos docenas de sitios que ya lo usan.
  if [[ "$ENGINE" == adguard ]] && (( AGH_PRESENT )); then
    local ap aw
    ap=$(agh_get dns port);  [[ "$ap" =~ ^[0-9]+$ ]] && PIHOLE_PORT="$ap"
    # http.address es "0.0.0.0:3000": el puerto va tras los dos puntos.
    aw=$(agh_get http address | grep -oE '[0-9]+$'); [[ "$aw" =~ ^[0-9]+$ ]] && WEB_PORT="$aw"
  elif [[ $PH_MAJOR -ge 6 ]]; then
    local q w
    q=$(ph_get dns.port);        [[ "$q" =~ ^[0-9]+$ ]] && PIHOLE_PORT="$q"
    w=$(ph_get webserver.port | grep -oE '^[0-9]+' | head -1); [[ "$w" =~ ^[0-9]+$ ]] && WEB_PORT="$w"
  fi
}

save_conf() {
  cat > "$CONF" <<EOF
# Generado por nexo-dns.sh v$NEXO_VERSION — $(date '+%Y-%m-%d %H:%M')
ENGINE=$ENGINE
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
  install -d -m 700 "$BACKUP_ROOT" "$d"
  [[ -f "$UNBOUND_CONF" ]] && cp -a "$UNBOUND_CONF" "$d/"
  [[ -f "$PIHOLE_TOML"  ]] && cp -a "$PIHOLE_TOML"  "$d/"
  [[ -f "$AGH_YAML"     ]] && cp -a "$AGH_YAML"     "$d/"
  [[ -f "$CONF"         ]] && cp -a "$CONF"         "$d/"
  chmod -R go-rwx "$d"
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
  if curl -fsSL --retry 3 --connect-timeout 10 --max-time 60 \
     -o /var/lib/unbound/root.hints.new https://www.internic.net/domain/named.root 2>/dev/null \
     && grep -q 'A.ROOT-SERVERS.NET' /var/lib/unbound/root.hints.new; then
    mv /var/lib/unbound/root.hints.new /var/lib/unbound/root.hints
    chown unbound:unbound /var/lib/unbound/root.hints 2>/dev/null || true
    echo /var/lib/unbound/root.hints
    return
  fi
  # Sin fichero y sin descarga, devolver la ruta igualmente dejaba en la config
  # un  root-hints: "/var/lib/unbound/root.hints"  que no existe. Unbound se
  # niega a arrancar y el instalador moría con un error que no señalaba a esto.
  # Unbound trae las direcciones de los servidores raíz compiladas dentro, así
  # que omitir la directiva es correcto: solo se pierde poder actualizarlas
  # sin actualizar el paquete.
  rm -f /var/lib/unbound/root.hints.new
  echo ""
}

write_unbound_conf() {
  detect_hw
  local hints hints_line
  hints=$(find_root_hints)
  if [[ -n "$hints" ]]; then
    hints_line="    root-hints: \"$hints\""
  else
    hints_line='    # sin root.hints: se usan los servidores raíz que Unbound trae dentro'
    warn "No hay fichero root.hints y no se ha podido descargar; se usan los internos"
  fi
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
$hints_line
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
  if [[ -f "$d/pi-hole.conf" ]]; then
    cp -a "$d/pi-hole.conf" "$UNBOUND_CONF"
  else
    # En una instalación nueva no había configuración anterior. Dejar el
    # fichero recién generado después de fallar no sería una reversión real.
    rm -f "$UNBOUND_CONF"
  fi
  systemctl restart unbound 2>/dev/null || true
  warn "Revertido desde $d"
}

restore_pihole() {
  local d="$1"
  [[ -f "$d/pihole.toml" ]] || return 0
  cp -a "$d/pihole.toml" "$PIHOLE_TOML"
  systemctl restart pihole-FTL 2>/dev/null || true
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
  ad=$(dig +dnssec cloudflare.com @127.0.0.1 -p "$UNBOUND_PORT" +time=5 +tries=2 2>/dev/null | grep -c ' ad;')
  bad=$(dig dnssec-failed.org @127.0.0.1 -p "$UNBOUND_PORT" +time=5 +tries=2 2>/dev/null | grep -c 'status: SERVFAIL')
  if [[ "$ad" == "1" && "$bad" == "1" ]]; then
    ok "DNSSEC valida (firma buena → ad, firma rota → SERVFAIL)"
  else
    err "DNSSEC no valida como debería (ad=$ad servfail=$bad)"
    err "Se revierte para no dejar activo un resolver sin validación comprobada"
    restore_unbound "$bkdir"
    return 1
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
  local failed=0
  ph_set dns.upstreams "[ \"127.0.0.1#$UNBOUND_PORT\" ]" || failed=1
  ph_set dns.dnssec false        || failed=1  # Unbound ya valida
  ph_set dns.domainNeeded true   || failed=1  # no mandar fuera nombres sin dominio
  ph_set dns.bogusPriv true      || failed=1  # ni PTR de rangos privados
  ph_set dns.EDNS0ECS false      || failed=1  # no filtrar la subred con ECS
  if (( failed )); then
    err "No se pudieron aplicar todos los ajustes de Pi-hole"
    return 1
  fi
  systemctl restart pihole-FTL 2>/dev/null || {
    err "Pi-hole no se pudo reiniciar"
    return 1
  }
  sleep 2
  systemctl is-active --quiet pihole-FTL || {
    err "Pi-hole no quedó activo después de configurarlo"
    return 1
  }
}

# Simétrico a restore_pihole: devuelve el YAML de una copia y reinicia. Se para
# el servicio antes de escribir porque AdGuard reescribe su fichero al salir y
# se llevaría por delante lo que acabamos de copiar.
restore_adguard() {
  local d="$1"
  [[ -f "$d/AdGuardHome.yaml" ]] || return 0
  systemctl stop "$AGH_SVC" 2>/dev/null || true
  cp -a "$d/AdGuardHome.yaml" "$AGH_YAML"
  systemctl start "$AGH_SVC" 2>/dev/null || true
}

# El mismo criterio que configure_pihole, traducido al YAML de AdGuard. Devuelve
# 1 si algo falla, para que quien llame pueda revertir igual que con Pi-hole.
configure_adguard() {
  detect_adguard; detect_hw
  (( AGH_PRESENT )) || { warn "AdGuard Home no está instalado"; return 1; }
  if (( ! AGH_READY )); then
    warn "AdGuard está instalado pero sin pasar el asistente web."
    warn "Abre http://$LISTEN_IP:3000 , crea tu usuario y vuelve aquí."
    return 1
  fi
  if (( RAM_MB <= 700 )); then
    warn "Solo ${RAM_MB} MB de RAM. AdGuard es un binario Go y gasta 100-150 MB;"
    warn "con Unbound al lado va justo. Pi-hole pesa bastante menos aquí."
  fi

  # Caché en bytes (AdGuard no acepta sufijos), con la misma escala que la de
  # Unbound. Ojo: medido en una Pi con 46 clientes, el conjunto de trabajo real
  # cabe en 2 MB, así que esto va sobrado a propósito y no hay que agrandarlo.
  local cache=4194304
  if   (( RAM_MB <= 600  )); then cache=2097152
  elif (( RAM_MB <= 2200 )); then cache=8388608
  elif (( RAM_MB <= 4400 )); then cache=16777216
  elif (( RAM_MB >  4400 )); then cache=33554432
  fi
  # El límite por cliente solo tiene sentido de cara a internet: en una LAN un
  # móvil sincronizando dispara ráfagas legítimas y 20 q/s las corta. En una VPS
  # es justo lo que impide que te usen de amplificador.
  local rl=0; (( IS_VPS )) && rl=20

  local was_active=0
  systemctl is-active --quiet "$AGH_SVC" 2>/dev/null && was_active=1
  (( was_active )) && systemctl stop "$AGH_SVC"

  local failed=0
  agh_set_list dns upstream_dns "127.0.0.1:$UNBOUND_PORT" || failed=1
  # Sin bootstrap ni fallback: el upstream es una IP local, no hay nada que
  # resolver para llegar a él. Un respaldo público sería una puerta trasera que
  # se saltaría a Unbound —y al filtrado— en cuanto Unbound tosiera.
  agh_put dns bootstrap_dns "  bootstrap_dns: []" || failed=1
  agh_put dns fallback_dns  "  fallback_dns: []"  || failed=1
  agh_set dns enable_dnssec false     || failed=1   # ya valida Unbound
  agh_set dns cache_size "$cache"     || failed=1
  agh_set dns cache_ttl_min 120       || failed=1   # mismo suelo que Unbound
  agh_set dns cache_ttl_max 86400     || failed=1
  agh_set dns cache_optimistic true   || failed=1   # equivale a serve-expired
  agh_set dns refuse_any true         || failed=1   # ANY amplifica x54
  agh_set dns ratelimit "$rl"         || failed=1
  agh_put dns edns_client_subnet \
      "  edns_client_subnet:" \
      "    custom_ip: \"\"" \
      "    enabled: false" \
      "    use_custom: false" || failed=1
  agh_set dns use_private_ptr_resolvers false || failed=1
  agh_put dns local_ptr_upstreams "  local_ptr_upstreams: []" || failed=1
  agh_set_list dns bind_hosts "0.0.0.0" || failed=1
  agh_set dns port "$PIHOLE_PORT"       || failed=1

  # AdGuard escribe CADA consulta al querylog y de fábrica guarda 90 días: en
  # una Raspberry con SD son cientos de miles de escrituras diarias sobre la
  # pieza más frágil. Se recorta el historial pero NO se desactiva el fichero,
  # porque de ahí leen el precalentado de caché y el panel web.
  # El formato del intervalo cambió entre versiones (antes días, ahora "2160h"),
  # así que se respeta el que ya tenga puesto.
  local qi si dias_q=3 dias_s=30
  (( RAM_MB <= 600 )) && dias_q=1
  qi=$(agh_get querylog interval)
  si=$(agh_get statistics interval)
  if   [[ "$qi" == *h* ]]; then agh_set querylog interval "$(( dias_q * 24 ))h" || failed=1
  elif [[ -n "$qi"    ]]; then agh_set querylog interval "$dias_q"              || failed=1; fi
  if   [[ "$si" == *h* ]]; then agh_set statistics interval "$(( dias_s * 24 ))h" || failed=1
  elif [[ -n "$si"    ]]; then agh_set statistics interval "$dias_s"              || failed=1; fi
  agh_set querylog file_enabled true || failed=1

  if (( failed )); then
    err "No se pudieron aplicar todos los ajustes de AdGuard Home"
    (( was_active )) && systemctl start "$AGH_SVC" 2>/dev/null
    return 1
  fi

  systemctl start "$AGH_SVC" 2>/dev/null || {
    err "AdGuard Home no se pudo arrancar tras configurarlo"
    return 1
  }
  sleep 3
  systemctl is-active --quiet "$AGH_SVC" || {
    err "AdGuard Home no quedó activo después de configurarlo"
    return 1
  }
  ok "AdGuard apuntando a Unbound 127.0.0.1:$UNBOUND_PORT"
  echo "     caché $((cache/1048576)) MB · TTL 120-86400 · optimista · DNSSEC delegado en Unbound"
  (( rl == 0 )) && echo "     sin límite por cliente (red doméstica)" \
                || echo "     límite de $rl consultas/s por cliente (máquina expuesta)"
  echo "     historial $dias_q día(s) y estadísticas $dias_s días, para no castigar la SD"
}

# Punto único: quien llame no necesita saber qué motor hay debajo.
configure_engine() {
  if [[ "$ENGINE" == adguard ]]; then configure_adguard; else configure_pihole; fi
}

# Devuelve la config del motor activo desde una copia de seguridad.
restore_engine() {
  if [[ "$ENGINE" == adguard ]]; then restore_adguard "$1"; else restore_pihole "$1"; fi
}

# Deja el 53 libre parando y DESHABILITANDO el servicio que lo tenga. Solo
# pararlo no basta: volvería en el siguiente arranque a pelearse por el puerto
# con el motor que acabas de poner.
stop_engine_svc() {
  local svc="$1"
  systemctl cat "$svc" >/dev/null 2>&1 || return 0
  systemctl disable --now "$svc" >/dev/null 2>&1 || systemctl stop "$svc" >/dev/null 2>&1 || true
  sleep 1
}

# Descarga e instala AdGuard Home con su instalador oficial. Mismo criterio que
# el de Pi-hole en v4.1: se baja a un temporal, se valida como Bash, se enseña
# el SHA-256 y solo entonces se ejecuta.
fetch_and_run_installer() {   # $1 URL · $2 palabra que debe aparecer dentro
  local url="$1" needle="$2" f hash
  f=$(mktemp) || { err "No se pudo crear un fichero temporal"; return 1; }
  if ! curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \
       --connect-timeout 10 --max-time 120 -o "$f" "$url"; then
    rm -f "$f"; err "No se pudo descargar $url"; return 1
  fi
  if ! bash -n "$f" || ! grep -qi "$needle" "$f"; then
    rm -f "$f"; err "El fichero descargado no parece un instalador válido"; return 1
  fi
  hash=$(sha256sum "$f" | awk '{print $1}')
  info "SHA-256 del instalador descargado: $hash"
  if ! sh "$f" -v; then rm -f "$f"; return 1; fi
  rm -f "$f"
}

install_adguard() {
  clear_screen; step "Instalar AdGuard Home"
  detect_adguard; detect_pihole
  if (( AGH_PRESENT )); then
    ok "AdGuard Home ya está instalado${AGH_VER:+ ($AGH_VER)}"
    (( AGH_READY )) || warn "Falta pasar el asistente web en http://$LISTEN_IP:3000"
    pause; return 0
  fi
  echo
  echo "  Se instala en ${BLD}$AGH_DIR${NC} con su propio servicio systemd."
  echo "  No hay paquete .deb: es un binario Go con instalador oficial."
  echo
  if (( PH_MAJOR > 0 )); then
    warn "Pi-hole está instalado y solo uno de los dos puede tener el puerto 53."
    warn "Pi-hole NO se desinstala: se para y se deshabilita, y puedes volver"
    warn "a él cuando quieras desde el panel."
    echo
  fi
  yes_no "¿Continuar?" || { info "Cancelado"; pause; return 0; }

  step "1/4 · Descarga e instalación"
  if ! fetch_and_run_installer \
       "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh" \
       "adguard"; then
    err "Falló la instalación de AdGuard Home"; pause; return 1
  fi
  detect_adguard
  (( AGH_PRESENT )) || { err "El binario no aparece en $AGH_BIN"; pause; return 1; }
  ok "AdGuard Home ${AGH_VER:-instalado}"

  step "2/4 · Liberar el puerto 53"
  # do_install ya trata systemd-resolved en su paso 2, pero aquí se entra
  # directo desde el panel: en Ubuntu, sin esto, AdGuard no puede atarse al 53.
  if resolved_conflicts; then
    warn "systemd-resolved está ocupando el puerto 53 (típico de Ubuntu)."
    if yes_no "¿Desactivo solo el stub de systemd-resolved?"; then
      fix_resolved || { err "No se pudo liberar el 53"; pause; return 1; }
    else
      err "Sin el puerto 53 libre AdGuard no podrá arrancar"; pause; return 1
    fi
  fi
  if (( PH_MAJOR > 0 )) && systemctl is-active --quiet pihole-FTL 2>/dev/null; then
    stop_engine_svc pihole-FTL
    ok "Pi-hole parado y deshabilitado (sigue instalado)"
  else
    ok "El 53 ya estaba libre"
  fi

  step "3/4 · Asistente web"
  echo
  warn "Este paso lo haces tú en el navegador: AdGuard pide crear usuario y"
  warn "contraseña, y este script no genera credenciales."
  echo
  echo "    1) Abre  ${BLD}http://$LISTEN_IP:3000${NC}"
  echo "    2) Escucha DNS en ${BLD}todas${NC} las interfaces, puerto ${BLD}$PIHOLE_PORT${NC}"
  echo "    3) Puerto del panel: ${BLD}$WEB_PORT${NC} (o el que prefieras)"
  echo "    4) Crea tu usuario y termina"
  echo
  info "Cuando acabes, vuelve aquí y pulsa Enter."
  pause

  step "4/4 · Enlazar con Unbound y optimizar"
  detect_adguard
  if (( ! AGH_READY )); then
    warn "El asistente aún no está terminado; no toco la configuración."
    warn "Cuando lo acabes: panel → Reoptimizar."
    pause; return 1
  fi
  ENGINE=adguard
  local bk; bk=$(backup_now); info "Copia en $bk"
  if configure_adguard; then
    load_conf; save_conf
    ok "AdGuard Home listo"
    echo "  Panel web : http://$LISTEN_IP:$WEB_PORT"
    echo "  DNS       : $LISTEN_IP:$PIHOLE_PORT → Unbound 127.0.0.1#$UNBOUND_PORT"
  else
    err "No se pudo configurar; se devuelve la copia previa"
    restore_adguard "$bk"
  fi
  pause
}

# ═════════════════════════════════════════════════════════ CAMBIO DE MOTOR ═════
switch_engine() {
  clear_screen; step "Cambiar motor de filtrado"
  detect_pihole; detect_adguard
  local target cur_n tgt_n prev="$ENGINE"
  target=$(other_engine); cur_n=$(engine_name)
  ENGINE="$target"; tgt_n=$(engine_name); ENGINE="$prev"

  echo "  Ahora mismo    : ${BLD}$cur_n${NC}"
  echo "  Se cambiaría a : ${BLD}$tgt_n${NC}"
  echo
  if ! engine_installed "$target"; then
    err "$tgt_n no está instalado."
    if [[ "$target" == adguard ]]; then
      echo "  Instálalo desde el panel → Instalar AdGuard Home."
    else
      echo "  Instálalo con:  ${BLD}sudo bash $0 install${NC}"
    fi
    pause; return 0
  fi
  if [[ "$target" == adguard ]] && (( ! AGH_READY )); then
    err "AdGuard no tiene el asistente terminado"; pause; return 0
  fi
  warn "Los dos comparten el puerto $PIHOLE_PORT, así que el actual se para y se"
  warn "deshabilita. No se desinstala nada y se puede volver cuando quieras."
  echo
  yes_no "¿Cambiar a $tgt_n?" || return 0

  local old_svc new_svc
  old_svc=$(engine_svc); ENGINE="$target"; new_svc=$(engine_svc)
  stop_engine_svc "$old_svc"
  systemctl enable --now "$new_svc" >/dev/null 2>&1 || systemctl start "$new_svc" >/dev/null 2>&1
  sleep 3

  # Verificación real: quedarse sin DNS deja la casa entera sin internet, así
  # que si el motor nuevo no resuelve se vuelve al anterior sin preguntar.
  if dig +short +time=5 +tries=2 google.com @127.0.0.1 -p "$PIHOLE_PORT" >/dev/null 2>&1; then
    load_conf; ENGINE="$target"; save_conf
    ok "Motor activo: $tgt_n"
    configure_engine || warn "Revisa la configuración: panel → Reoptimizar"
    if fw_active; then
      info "Regenerando el cortafuegos con los puertos de $tgt_n"
      install_firewall_quiet && ok "Cortafuegos al día" \
                             || warn "Revísalo: panel → Seguridad"
    fi
  else
    err "$tgt_n no resuelve en el puerto $PIHOLE_PORT; vuelvo a $cur_n"
    stop_engine_svc "$new_svc"
    ENGINE="$prev"
    systemctl enable --now "$old_svc" >/dev/null 2>&1 || systemctl start "$old_svc" >/dev/null 2>&1
    sleep 2
    if dig +short +time=5 google.com @127.0.0.1 -p "$PIHOLE_PORT" >/dev/null 2>&1; then
      ok "$cur_n restaurado y resolviendo"
    else
      err "Ninguno de los dos resuelve. Revisa: systemctl status $old_svc"
    fi
  fi
  pause
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
  clear_screen; splash
  step "Instalación del DNS privado"
  detect_os; detect_hw; detect_platform; detect_engine

  # El filtro se elige aquí, antes que nada: es lo que cambia todo lo demás.
  # Si ya hay uno instalado se propone ese, para no romper lo que hay.
  echo
  echo "  ${BLD}¿Qué filtro quieres?${NC} Unbound va detrás de los dos por igual."
  echo "    ${NUM}1${NC}) ${PH}Pi-hole${NC}       — más listas, panel clásico, gravity"
  echo "    ${NUM}2${NC}) ${AG}AdGuard Home${NC}  — DNS cifrado propio, reglas por cliente"
  echo
  local pick def=1
  [[ "$ENGINE" == adguard ]] && def=2
  pick=$(ask "Opción [1-2]:" "$def")
  case "$pick" in
    2) ENGINE=adguard ;;
    *) ENGINE=pihole  ;;
  esac
  local ENAME; ENAME=$(engine_name)

  echo
  echo "  Sistema : $OS_NAME"
  echo "  Equipo  : $MODEL · ${RAM_MB} MB · $CORES núcleos"
  echo "  Entorno : $PLATFORM"
  echo "  IP      : $LISTEN_IP"
  echo "  Filtro  : $(engine_color)${ENAME}${NC}"
  echo "  Puertos : DNS $PIHOLE_PORT · Unbound $UNBOUND_PORT · Web $WEB_PORT"
  if (( IS_VPS )); then
    echo
    warn "Esto es una máquina expuesta a internet, no una Raspberry en casa."
    warn "Al terminar hay que cerrar el DNS al mundo, o cualquiera podrá usarlo"
    warn "para amplificar ataques. Se ofrecerá al final."
  fi
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

  step "3/6 · $ENAME"
  if [[ "$ENGINE" == adguard ]]; then
    detect_adguard
    if (( AGH_PRESENT )); then
      ok "AdGuard Home ya está instalado${AGH_VER:+ ($AGH_VER)}, no lo toco"
    else
      warn "Se descargará el instalador oficial, se validará como shell y se"
      warn "mostrará su hash antes de ejecutarlo."
      pause
      fetch_and_run_installer \
        "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh" \
        "adguard" \
        || { err "Falló la instalación de AdGuard Home"; pause; return 1; }
      detect_adguard
    fi
    # Pi-hole y AdGuard no pueden compartir el 53.
    if (( PH_MAJOR > 0 )) && systemctl is-active --quiet pihole-FTL 2>/dev/null; then
      warn "Pi-hole tiene el puerto $PIHOLE_PORT: se para y se deshabilita (no se desinstala)"
      stop_engine_svc pihole-FTL
    fi
  else
    if need pihole; then
      ok "Pi-hole ya está instalado, no lo toco"
    else
      warn "El instalador de Pi-hole es interactivo y pide su propia configuración."
      warn "Se descargará primero, se validará como Bash y se mostrará su hash."
      pause
      local installer installer_hash
      installer=$(mktemp) || { err "No se pudo crear un fichero temporal"; pause; return 1; }
      if ! curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \
           --connect-timeout 10 --max-time 120 \
           -o "$installer" https://install.pi-hole.net; then
        rm -f "$installer"
        err "No se pudo descargar el instalador de Pi-hole"; pause; return 1
      fi
      if ! bash -n "$installer" || ! grep -qi 'pi-hole' "$installer"; then
        rm -f "$installer"
        err "El fichero descargado no parece un instalador válido de Pi-hole"
        pause; return 1
      fi
      installer_hash=$(sha256sum "$installer" | awk '{print $1}')
      info "SHA-256 del instalador descargado: $installer_hash"
      if ! bash "$installer"; then
        rm -f "$installer"
        err "Falló la instalación de Pi-hole"; pause; return 1
      fi
      rm -f "$installer"
    fi
    detect_pihole
    if (( AGH_PRESENT )) && systemctl is-active --quiet "$AGH_SVC" 2>/dev/null; then
      warn "AdGuard tiene el puerto $PIHOLE_PORT: se para y se deshabilita (no se desinstala)"
      stop_engine_svc "$AGH_SVC"
    fi
  fi

  step "4/6 · Ajustes del kernel"
  apply_sysctl_dns; ok "Buffers UDP ampliados"

  step "5/6 · Unbound"
  local bk; bk=$(backup_now)
  write_unbound_conf
  apply_unbound "$bk" || { pause; return 1; }

  step "6/6 · Enlazar $ENAME con Unbound"
  # AdGuard no puede configurarse hasta que su asistente web crea el usuario, y
  # ese paso lo da la persona: el script no inventa credenciales.
  if [[ "$ENGINE" == adguard ]]; then
    detect_adguard
    if (( ! AGH_READY )); then
      echo
      warn "Falta el asistente web de AdGuard, y ese paso lo das tú:"
      warn "pide crear usuario y contraseña, y el script no las genera."
      echo
      echo "    1) Abre  ${BLD}http://$LISTEN_IP:3000${NC}"
      echo "    2) Escucha DNS en ${BLD}todas${NC} las interfaces, puerto ${BLD}$PIHOLE_PORT${NC}"
      echo "    3) Crea tu usuario y termina"
      echo
      info "Cuando acabes, pulsa Enter y sigo con la optimización."
      pause
      detect_adguard
    fi
  fi
  if ! configure_engine; then
    err "La configuración no quedó completa; restaurando la copia anterior"
    restore_engine "$bk"
    restore_unbound "$bk"
    pause
    return 1
  fi
  load_conf; save_conf
  echo
  ok "Instalación terminada"
  if [[ "$ENGINE" == adguard ]]; then
    echo "  Panel web : http://$LISTEN_IP:$WEB_PORT"
  else
    echo "  Panel web : http://$LISTEN_IP:$WEB_PORT/admin"
  fi
  echo "  DNS       : $LISTEN_IP:$PIHOLE_PORT → Unbound 127.0.0.1#$UNBOUND_PORT"
  echo "  Copia     : $bk"
  echo

  if (( IS_VPS )); then
    step "Cerrar el DNS a internet"
    warn "En una VPS no hay router al que apuntar: se llega por Tailscale."
    warn "Y hay que cerrar el 53 al mundo antes de que lo encuentre un escáner."
    echo
    if ! fw_active; then
      yes_no "¿Pongo el cortafuegos ahora? (recomendado)" && install_firewall
    else
      ok "El cortafuegos de nexo-dns ya está puesto"
    fi
    echo
    info "Para usarlo desde tus equipos:"
    echo "    1) ${BLD}sudo bash $0${NC} → Tailscale → Instalar, y luego ${BLD}sudo tailscale up${NC}"
    echo "    2) En login.tailscale.com/admin/dns pon esta máquina como"
    echo "       nameserver global y marca «Override local DNS»"
  else
    warn "Falta lo más importante: que tus equipos lo usen. En el DHCP de tu"
    warn "router pon $LISTEN_IP como ÚNICO servidor DNS. Si dejas uno público"
    warn "de secundario, el filtrado se salta de forma intermitente."
  fi
  pause
}

# ═══════════════════════════════════════════════════════ CAMBIO DE PUERTOS ═════
change_unbound_port() {
  clear_screen; step "Puerto de Unbound"
  echo "  Actual: ${BLD}$UNBOUND_PORT${NC}   ·   Pi-hole usa el $PIHOLE_PORT"
  local np; np=$(ask "Nuevo puerto para Unbound:")
  valid_port "$np" || { err "Puerto inválido"; pause; return; }
  [[ "$np" == "$PIHOLE_PORT" ]] && { err "Chocaría con $(engine_name) (puerto $PIHOLE_PORT)"; pause; return; }
  if port_taken_by_other "$np" unbound; then
    err "El puerto $np ya lo usa otro proceso:"; ss -tulpn 2>/dev/null | grep ":$np " | sed 's/^/    /'
    pause; return
  fi
  local bk; bk=$(backup_now); info "Copia en $bk"
  sed -i "s/^\(\s*\)port:.*/\1port: $np/" "$UNBOUND_CONF"
  local old="$UNBOUND_PORT"; UNBOUND_PORT="$np"
  if apply_unbound "$bk"; then
    local ENAME; ENAME=$(engine_name)
    if ! engine_ready; then
      # Sin motor listo no hay nada que reapuntar, y sobre todo: no se puede
      # condicionar el cambio a que resuelva. Antes se revertía un cambio
      # correcto solo porque el filtro no estaba instalado.
      save_conf; ok "Unbound movido del $old al $np"
      warn "$ENAME no está listo: cuando lo esté, apunta su upstream a 127.0.0.1#$np"
    else
      # configure_engine reapunta el upstream del motor que toque y reinicia
      # su servicio; devuelve 1 si algo falla.
      if configure_engine >/dev/null; then
        sleep 2
      else
        err "No se pudo reapuntar $ENAME; revirtiendo"
        UNBOUND_PORT="$old"; restore_engine "$bk"; restore_unbound "$bk"
        pause; return
      fi
      if dig +short +time=5 google.com @127.0.0.1 -p "$PIHOLE_PORT" >/dev/null 2>&1; then
        save_conf; ok "Unbound movido del $old al $np y $ENAME apuntando ahí"
      else
        err "$ENAME dejó de resolver; revirtiendo"
        UNBOUND_PORT="$old"; restore_engine "$bk"; restore_unbound "$bk"
      fi
    fi
  else
    UNBOUND_PORT="$old"
  fi
  pause
}

# Fija el puerto DNS en el motor activo y lo reinicia. AdGuard reescribe su
# YAML al salir, así que hay que pararlo antes de tocarlo; Pi-hole lo acepta en
# caliente.
engine_set_dns_port() {
  local p="$1"
  if [[ "$ENGINE" == adguard ]]; then
    systemctl stop "$AGH_SVC" 2>/dev/null || true
    agh_set dns port "$p" || return 1
    systemctl start "$AGH_SVC" 2>/dev/null || return 1
  else
    ph_set dns.port "$p" || return 1
    systemctl restart pihole-FTL 2>/dev/null || return 1
  fi
}

change_pihole_port() {
  local ENAME; ENAME=$(engine_name)
  clear_screen; step "Puerto DNS de $ENAME"
  engine_ready || { err "$ENAME no está listo"; pause; return; }
  echo "  Actual: ${BLD}$PIHOLE_PORT${NC}   ·   Unbound usa el $UNBOUND_PORT"
  echo
  warn "Fuera del 53, los clientes NO lo encontrarán solos: casi ningún router"
  warn "ni sistema operativo deja indicar un puerto DNS distinto del 53."
  local np; np=$(ask "Nuevo puerto DNS para $ENAME:")
  valid_port "$np" || { err "Puerto inválido"; pause; return; }
  [[ "$np" == "$UNBOUND_PORT" ]] && { err "Chocaría con Unbound (puerto $UNBOUND_PORT)"; pause; return; }
  if port_taken_by_other "$np" "$(engine_svc)"; then
    err "El puerto $np ya está ocupado:"; ss -tulpn 2>/dev/null | grep ":$np " | sed 's/^/    /'
    pause; return
  fi
  local old="$PIHOLE_PORT"; backup_now >/dev/null
  engine_set_dns_port "$np" || { err "No se pudo aplicar el cambio"; pause; return; }
  sleep 3
  if dig +short +time=5 google.com @127.0.0.1 -p "$np" >/dev/null 2>&1; then
    PIHOLE_PORT="$np"; save_conf; ok "$ENAME escuchando en el $np"
  else
    err "No responde en el $np; volviendo al $old"
    engine_set_dns_port "$old"
  fi
  pause
}

change_web_port() {
  clear_screen; step "Puerto del panel web"
  engine_ready || { err "$(engine_name) no está listo"; pause; return; }

  # AdGuard guarda el panel como dirección completa (http.address =
  # "0.0.0.0:3000"), no como la lista con sufijos de Pi-hole. Se resuelve aquí
  # y se sale; el enredo de abajo es exclusivo del formato de Pi-hole.
  if [[ "$ENGINE" == adguard ]]; then
    local acur anp aold
    acur=$(agh_get http address)
    echo "  Actual: ${BLD}${acur:-$WEB_PORT}${NC}"
    anp=$(ask "Nuevo puerto web:")
    valid_port "$anp" || { err "Puerto inválido"; pause; return; }
    [[ "$anp" == "$PIHOLE_PORT" || "$anp" == "$UNBOUND_PORT" ]] && {
      err "Ese puerto ya lo usa el DNS"; pause; return; }
    if port_taken_by_other "$anp" "$AGH_SVC"; then
      err "El puerto $anp ya está ocupado:"; ss -tulpn 2>/dev/null | grep ":$anp " | sed 's/^/    /'
      pause; return
    fi
    aold="$WEB_PORT"
    backup_now >/dev/null
    systemctl stop "$AGH_SVC" 2>/dev/null || true
    agh_set http address "0.0.0.0:$anp"
    systemctl start "$AGH_SVC" 2>/dev/null || true
    sleep 3
    if ss -tulnH 2>/dev/null | awk -v p="$anp" '{n=split($5,a,":"); if(a[n]==p) f=1} END{exit !f}'; then
      WEB_PORT="$anp"; save_conf; ok "Panel de AdGuard en http://$LISTEN_IP:$anp"
    else
      err "No escucha en el $anp; vuelvo al $aold"
      systemctl stop "$AGH_SVC" 2>/dev/null || true
      agh_set http address "0.0.0.0:$aold"
      systemctl start "$AGH_SVC" 2>/dev/null || true
    fi
    pause; return
  fi

  local cur; cur=$(ph_get webserver.port)
  echo "  Actual: ${BLD}${cur:-$WEB_PORT}${NC}"
  local np; np=$(ask "Nuevo puerto web:")
  valid_port "$np" || { err "Puerto inválido"; pause; return; }
  [[ "$np" == "$PIHOLE_PORT" || "$np" == "$UNBOUND_PORT" ]] && {
    err "Ese puerto ya lo usa el DNS"; pause; return; }
  if port_taken_by_other "$np" pihole-FTL; then
    err "El puerto $np ya está ocupado:"; ss -tulpn 2>/dev/null | grep ":$np " | sed 's/^/    /'
    pause; return
  fi

  # El valor de webserver.port no es un número: es una lista con sufijos.
  # Por defecto Pi-hole v6 trae  80o,443os,[::]:80o,[::]:443os
  #   o = opcional (si no puede atarlo, no aborta)   s = TLS
  # Escribir "$np,[::]:$np" a secas —como se hacía antes— borraba el 443 y
  # dejaba el panel sin HTTPS. Aquí solo se sustituye el número del puerto
  # HTTP y se respeta todo lo demás tal y como estuviera.
  local new
  new=$(awk -v old="$WEB_PORT" -v new="$np" 'BEGIN{
      n = split(ARGV[1], parts, ",")
      out = ""
      for (i = 1; i <= n; i++) {
        p = parts[i]
        # separa un posible prefijo "[::]:" del número y sus sufijos
        pre = ""; rest = p
        if (sub(/^\[::\]:/, "", rest)) pre = "[::]:"
        num = rest; sub(/[^0-9].*$/, "", num)
        suf = substr(rest, length(num) + 1)
        # solo se toca el puerto HTTP (sin sufijo "s"); el de TLS se respeta
        if (num == old && suf !~ /s/) num = new
        out = out (out == "" ? "" : ",") pre num suf
      }
      print out
    }' "${cur:-$WEB_PORT}")
  [[ -z "$new" ]] && new="$np,[::]:$np"

  local bk; bk=$(backup_now); info "Copia en $bk"
  echo "  ${DIM}$cur${NC}  →  ${BLD}$new${NC}"
  ph_set webserver.port "$new" || { pause; return; }
  systemctl restart pihole-FTL; sleep 3

  # Verificación real: que algo esté escuchando de verdad en el puerto nuevo.
  # Antes esto no se comprobaba y, si el puerto no se podía atar, te quedabas
  # sin panel web y sin aviso.
  if ss -tlnH 2>/dev/null | awk -v p="$np" '{n=split($4,a,":"); if(a[n]==p) f=1} END{exit !f}'; then
    WEB_PORT="$np"; save_conf
    ok "Panel en http://$LISTEN_IP:$np/admin"
  else
    err "Nadie escucha en el puerto $np; volviendo a la configuración anterior"
    ph_set webserver.port "$cur"
    systemctl restart pihole-FTL; sleep 2
    warn "Panel de nuevo en el puerto $WEB_PORT"
  fi
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
    # ALL significa "respondo a quien sea". En casa, detrás del router, da
    # igual. En una VPS con IP pública eso es un resolver abierto: se usa para
    # amplificar DDoS y termina con la máquina suspendida por abuso.
    if (( IS_VPS )) && ! fw_active; then
      echo
      err "Pero esto es una máquina pública ($PLATFORM) y no hay cortafuegos."
      warn "Con listeningMode=ALL y el 53 abierto eres un resolver DNS abierto."
      yes_no "¿Cierro el DNS a internet dejando pasar solo el tailnet?" \
        && install_firewall
    fi
  elif [[ -n "$lm" ]]; then
    warn "Pi-hole en listeningMode=$lm: los equipos del tailnet NO podrán usarlo"
    if (( IS_VPS )) && ! fw_active; then
      warn "Ojo: esta máquina es pública ($PLATFORM). Poner ALL sin cortafuegos"
      warn "la convierte en un resolver abierto. Primero pon el cortafuegos"
      warn "(panel → Seguridad) y luego vuelve aquí."
      yes_no "¿Poner ALL de todas formas?" \
        && { ph_set dns.listeningMode ALL; systemctl restart pihole-FTL; }
    else
      yes_no "¿Lo pongo en ALL?" && { ph_set dns.listeningMode ALL; systemctl restart pihole-FTL; }
    fi
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
  echo "  Esto coge los dominios que TÚ más usas (del historial del filtro) y"
  echo "  los resuelve cada media hora, y 3 min después de cada arranque — que"
  echo "  es cuando la caché está vacía y más duele."
  echo
  engine_ready || { warn "Necesita $(engine_name) funcionando"; pause; return; }
  yes_no "¿Instalar?" || return

  cat > /usr/local/bin/dns-prewarm.sh <<'SCRIPT'
#!/usr/bin/env bash
# Precalienta la caché de Unbound con los dominios más usados de esta red.
# Consulta al puerto de Unbound para no ensuciar las estadísticas de Pi-hole.
set -uo pipefail
DB=/etc/pihole/pihole-FTL.db
AGH_LOG=/opt/AdGuardHome/data/querylog.json
TOP=${1:-250}; DIAS=${2:-7}
PORT=$(grep -oP '^\s*port:\s*\K[0-9]+' /etc/unbound/unbound.conf.d/pi-hole.conf 2>/dev/null | head -1)
PORT=${PORT:-5335}
# Sirve para los dos motores: se mira cuál tiene historial, así el precalentado
# sobrevive a un cambio de filtro sin reinstalarlo.
DOMS=()
if [[ -r "$DB" ]] && command -v pihole-FTL >/dev/null 2>&1; then
  # status 2 = reenviada, 3 = de caché. Los bloqueados no interesa resolverlos.
  mapfile -t DOMS < <(pihole-FTL sqlite3 "$DB" "
    SELECT d.domain FROM query_storage q JOIN domain_by_id d ON q.domain = d.id
    WHERE q.timestamp > strftime('%s','now','-$DIAS days') AND q.status IN (2,3)
    GROUP BY d.domain ORDER BY COUNT(*) DESC LIMIT $TOP;" 2>/dev/null)
fi
if [[ ${#DOMS[@]} -eq 0 && -r "$AGH_LOG" ]]; then
  # AdGuard: JSON por línea. QH es el dominio; se descartan las bloqueadas,
  # que no tiene sentido resolver.
  mapfile -t DOMS < <(tail -n 50000 "$AGH_LOG" 2>/dev/null \
    | grep -v '"IsFiltered":true' \
    | grep -oE '"QH":"[^"]+"' | sed 's/"QH":"//; s/"$//' \
    | sort | uniq -c | sort -rn | head -"$TOP" | awk '{print $2}')
fi
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
After=unbound.service pihole-FTL.service AdGuardHome.service
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
# Las mismas listas para los dos motores: el formato hosts/adblock lo entienden
# por igual gravity (Pi-hole) y filters (AdGuard).
LISTAS_RECOMENDADAS=(
  "https://big.oisd.nl/|OISD Big - equilibrada, pocos falsos positivos"
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt|HaGeZi Multi - muy buena calidad"
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt|HaGeZi Threat Intelligence - malware y phishing"
  "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt|AdGuard DNS filter"
)

# Añade una lista al bloque `filters:` del YAML de AdGuard. El id solo tiene
# que ser único; AdGuard usa el epoch para lo mismo.
agh_add_filter() {   # $1 url · $2 nombre
  local url="$1" name="$2" id tmp
  grep -qF "url: $url" "$AGH_YAML" 2>/dev/null && return 2
  id=$(( $(date +%s) + RANDOM % 1000 ))
  tmp=$(mktemp) || return 1
  awk -v url="$url" -v name="$name" -v id="$id" '
    function emit() {
      print "  - enabled: true"; print "    url: " url
      print "    name: " name;   print "    id: " id
    }
    BEGIN { inblk=0; done=0 }
    {
      if ($0 ~ /^[A-Za-z_][A-Za-z0-9_]*:/) {
        if (inblk && !done) { emit(); done=1 }
        if ($0 ~ /^filters:/) {
          inblk=1
          # "filters: []" con una entrada colgando debajo sería YAML inválido.
          if ($0 ~ /^filters:[ ]*\[\][ ]*$/) { print "filters:"; next }
        } else inblk=0
        print; next
      }
      print
    }
    END { if (inblk && !done) emit() }
  ' "$AGH_YAML" > "$tmp"
  [[ -s "$tmp" ]] || { rm -f "$tmp"; return 1; }
  cat "$tmp" > "$AGH_YAML"; rm -f "$tmp"
}

manage_lists_adguard() {
  echo "  Listas activas en AdGuard:"
  awk '/^filters:/{f=1;next} /^[A-Za-z_]/{f=0} f && /^    name:/{sub(/^    name: /,"");print "    · " $0}' \
    "$AGH_YAML" 2>/dev/null || true
  echo
  echo "    1) Añadir listas recomendadas"
  echo "    2) Recargar listas (reinicia AdGuard)"
  echo "    0) Volver"
  local o; o=$(ask "Opción:")
  case "$o" in
    1)
      local e a c added=0 r
      systemctl stop "$AGH_SVC" 2>/dev/null || true
      for e in "${LISTAS_RECOMENDADAS[@]}"; do
        a="${e%%|*}"; c="${e##*|}"
        agh_add_filter "$a" "$c"; r=$?
        if   (( r == 0 )); then ok "$c"; added=$((added+1))
        elif (( r == 2 )); then info "${DIM}ya estaba:${NC} $c"
        else err "no se pudo añadir: $c"; fi
      done
      systemctl start "$AGH_SVC" 2>/dev/null || true
      echo
      (( added == 0 )) && info "No había ninguna nueva que añadir" \
                       || ok "$added lista(s) añadidas; AdGuard las descarga al arrancar"
      ;;
    2) systemctl restart "$AGH_SVC" 2>/dev/null && ok "AdGuard reiniciado" || err "No se pudo reiniciar" ;;
    *) : ;;
  esac
}

manage_lists() {
  clear_screen; step "Listas de bloqueo · $(engine_name)"
  if [[ "$ENGINE" == adguard ]]; then
    (( AGH_READY )) || { err "AdGuard no está listo (falta el asistente web)"; pause; return; }
    manage_lists_adguard
    pause; return
  fi
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
      local e a c added=0 n
      for e in "${LISTAS_RECOMENDADAS[@]}"; do
        a="${e%%|*}"; c="${e##*|}"
        # changes() distingue entre insertada e ignorada por duplicada. Antes
        # se anunciaba "añadida" siempre, aunque la lista ya estuviera puesta.
        n=$(pihole-FTL sqlite3 /etc/pihole/gravity.db \
              "INSERT OR IGNORE INTO adlist (address, comment) VALUES ('$a','$c'); SELECT changes();" 2>/dev/null)
        if [[ "$n" == "1" ]]; then ok "$c"; added=$((added+1))
        else info "${DIM}ya estaba:${NC} $c"; fi
      done
      echo
      (( added == 0 )) && { info "No había ninguna nueva que añadir"; pause; return; }
      yes_no "¿Actualizar gravity ahora? (tarda unos minutos)" && pihole updateGravity
      ;;
    2) pihole updateGravity ;;
  esac
  pause
}

# ══════════════════════════════════════════════════════════════ ESTADO ═════════
show_status() {
  clear_screen; step "Estado"
  detect_os; detect_hw; detect_platform
  echo "  Sistema  : $OS_NAME"
  echo "  Equipo   : $MODEL · ${RAM_MB} MB · $CORES núcleos"
  echo "  Entorno  : $PLATFORM$( (( IS_VPS )) && printf ' %s' "${YEL}· expuesto a internet${NC}" )"
  local EC EN EVER; EC=$(engine_color); EN=$(engine_name)
  [[ "$ENGINE" == adguard ]] && EVER="${AGH_VER:-?}" || EVER="v${PH_MAJOR}"
  echo "  IP       : $LISTEN_IP     ${EC}${EN}${NC} ${EVER}"
  echo "  Puertos  : ${EC}${EN}${NC} $PIHOLE_PORT · ${UB}Unbound${NC} $UNBOUND_PORT · Web $WEB_PORT"
  if [[ "$ENGINE" == adguard ]] && (( ! AGH_READY )); then
    echo "  ${YEL}!${NC} AdGuard sin terminar el asistente: http://$LISTEN_IP:3000"
  fi
  echo
  local s col
  for s in unbound pihole-FTL "$AGH_SVC" tailscaled; do
    case "$s" in
      unbound)     col="$UB"  ;;
      pihole-FTL)  col="$PH"  ;;
      "$AGH_SVC")  col="$AG"  ;;
      *)           col="$TS"  ;;
    esac
    if systemctl is-active --quiet "$s" 2>/dev/null; then echo "  ${GRN}${DOT}${NC} ${col}${s}${NC}"
    elif systemctl cat "$s" >/dev/null 2>&1;        then echo "  ${RED}${DOT}${NC} ${col}${s}${NC} (parado)"
    else echo "  ${DIM}${DOT} $s (no instalado)${NC}"; fi
  done
  echo
  echo "  ${BLD}Resolución${NC}"
  local r1 r2 bl
  r2=$(dig_short +time=3 google.com @127.0.0.1 -p "$UNBOUND_PORT")
  r1=$(dig_short +time=3 google.com @127.0.0.1 -p "$PIHOLE_PORT")
  bl=$(dig_short doubleclick.net @127.0.0.1 -p "$PIHOLE_PORT")
  echo "    ${UB}Unbound${NC} :$UNBOUND_PORT → ${r2:-${RED}sin respuesta${NC}}"
  echo "    ${EC}${EN}${NC} :$PIHOLE_PORT → ${r1:-${RED}sin respuesta${NC}}"
  echo "    ${PHD}Bloqueo${NC}       → ${bl:-(vacío)}"
  if need unbound-control; then
    local st q h
    st=$(unbound-control stats_noreset 2>/dev/null)
    q=$(awk -F= '/^total.num.queries=/{print $2}' <<<"$st")
    h=$(awk -F= '/^total.num.cachehits=/{print $2}' <<<"$st")
    if [[ -n "${q:-}" && "${q:-0}" -gt 0 ]]; then
      echo
      echo "  ${BLD}${UBC}Caché de Unbound${NC}"
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
  if [[ -r "$FTL_DB" ]] || [[ "$ENGINE" == adguard && -r "$AGH_LOG" ]]; then
    echo; echo "  ${BLD}¿Lo usa alguien?${NC}"
    local qn cl
    if [[ "$ENGINE" == adguard && -r "$AGH_LOG" ]]; then
      # AdGuard no usa SQLite: el registro es JSON, una consulta por línea. Se
      # mira solo la cola; recorrerlo entero en una Pi 3 se nota y no aporta.
      local tail_log; tail_log=$(tail -n 20000 "$AGH_LOG" 2>/dev/null)
      qn=$(wc -l <<<"$tail_log" | tr -d ' ')
      cl=$(grep -oE '"IP":"[^"]+"' <<<"$tail_log" 2>/dev/null | sort -u | wc -l | tr -d ' ')
      echo "    ${qn:-0} consultas recientes de ${cl:-0} cliente(s)"
    else
      qn=$(pihole-FTL sqlite3 "$FTL_DB" "SELECT COUNT(*) FROM query_storage WHERE timestamp > strftime('%s','now','-1 day');" 2>/dev/null)
      cl=$(pihole-FTL sqlite3 "$FTL_DB" "SELECT COUNT(DISTINCT client) FROM query_storage WHERE timestamp > strftime('%s','now','-1 day');" 2>/dev/null)
      echo "    ${qn:-0} consultas de ${cl:-0} cliente(s) en 24 h"
    fi
    if [[ "${cl:-0}" -le 2 ]]; then
      echo "    ${YEL}!${NC} Muy pocos clientes."
      if (( IS_VPS )); then
        echo "      ${DIM}En una VPS los equipos entran por Tailscale: revisa que${NC}"
        echo "      ${DIM}esté marcado «Override local DNS» en el panel del tailnet.${NC}"
      else
        echo "      ${DIM}Una casa normal tiene 5-20 aparatos. Revisa el DHCP del${NC}"
        echo "      ${DIM}router: debe repartir $LISTEN_IP como ÚNICO DNS. Un${NC}"
        echo "      ${DIM}secundario público salta el filtrado.${NC}"
      fi
    else
      echo "    ${GRN}✓${NC} La red lo está usando"
    fi
  fi

  # ── Exposición ──
  # En una máquina pública esto importa más que cualquier prueba de resolución:
  # un resolver abierto no se nota hasta que llega el aviso de abuso.
  if (( IS_VPS )); then
    echo; echo "  ${BLD}Exposición${NC}"
    # El equivalente de listeningMode en AdGuard es bind_hosts: si incluye
    # 0.0.0.0 está escuchando en todo, igual que ALL en Pi-hole.
    local lm abierto=0
    if [[ "$ENGINE" == adguard ]]; then
      if agh_block_list dns bind_hosts 2>/dev/null | grep -q '0\.0\.0\.0'; then
        lm="bind_hosts=0.0.0.0"; abierto=1
      else
        lm="bind_hosts acotado"
      fi
    else
      lm="listeningMode=$(ph_get dns.listeningMode)"
      [[ "$lm" == "listeningMode=ALL" ]] && abierto=1
    fi
    if fw_active; then
      echo "    ${GRN}✓${NC} cortafuegos de nexo-dns activo"
    elif (( abierto )); then
      echo "    ${RED}✗${NC} $lm sin cortafuegos: resolver DNS ABIERTO"
      echo "      ${DIM}panel → Seguridad → cortafuegos${NC}"
      fails=$((fails+1))
    else
      echo "    ${YEL}!${NC} sin cortafuegos, pero $lm limita el alcance"
      echo "      ${DIM}aun así conviene cerrarlo: panel → Seguridad${NC}"
    fi
  fi

  echo
  (( fails == 0 )) && ok "Todo correcto" || err "$fails prueba(s) fallidas"
  pause
}

do_optimize() {
  local ENAME; ENAME=$(engine_name)
  clear_screen; step "Reoptimizar Unbound + $ENAME"
  detect_os; detect_hw; detect_engine
  ENAME=$(engine_name)
  echo "  Se dimensiona para: $MODEL · ${RAM_MB} MB · $CORES núcleos"
  echo "  → Unbound: num-threads=$THREADS · msg-cache=$MSG · rrset-cache=$RRSET"
  echo "  → Filtro : $(engine_color)${ENAME}${NC} apuntando a 127.0.0.1#$UNBOUND_PORT"
  echo
  yes_no "¿Continuar?" || return
  local bk; bk=$(backup_now); info "Copia en $bk"
  apply_sysctl_dns
  write_unbound_conf
  if apply_unbound "$bk"; then
    if configure_engine; then
      save_conf; ok "Optimización aplicada"
    else
      err "No se pudo configurar $ENAME; restaurando la copia anterior"
      restore_engine "$bk"
      restore_unbound "$bk"
    fi
  fi
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

# ═══════════════════════════════════════════════════════════ SEGURIDAD ═════════
FW_NFT=/etc/nexo-dns-firewall.nft
FW_UNIT=/etc/systemd/system/nexo-dns-firewall.service

fw_active() { nft list table inet nexo_dns >/dev/null 2>&1; }

# Qué puertos hay que cerrar al mundo. Con Pi-hole son siempre los mismos tres.
# AdGuard puede levantar además DNS cifrado, y ahí está la trampa: cerrar solo
# el 53 deja el MISMO resolver contestando por 853 o 443, con el panel diciendo
# que está cerrado a internet.
#
# El 3000 solo se cierra si el asistente está a medias. Terminado, AdGuard mueve
# el panel al puerto elegido —que ya es WEB_PORT— y el 3000 deja de escuchar:
# cerrarlo siempre sería cerrar un puerto que no usa nadie.
FW_TCP=""; FW_UDP=""; FW_EXTRA=""
engine_fw_ports() {
  FW_TCP="$PIHOLE_PORT, $UNBOUND_PORT, $WEB_PORT"
  FW_UDP="$PIHOLE_PORT, $UNBOUND_PORT"
  FW_EXTRA=""
  [[ "$ENGINE" == adguard && -f "$AGH_YAML" ]] || return 0

  local tcp="" udp="" v
  (( AGH_READY )) || tcp="3000"
  if [[ "$(agh_get tls enabled)" == "true" ]]; then
    for v in port_https port_dns_over_tls; do
      local p; p=$(agh_get tls "$v")
      [[ "$p" =~ ^[0-9]+$ ]] && (( p > 0 )) && tcp="${tcp:+$tcp, }$p"
    done
    local q; q=$(agh_get tls port_dns_over_quic)
    [[ "$q" =~ ^[0-9]+$ ]] && (( q > 0 )) && udp="${udp:+$udp, }$q"
    local dc; dc=$(agh_get tls port_dnscrypt)
    if [[ "$dc" =~ ^[0-9]+$ ]] && (( dc > 0 )); then
      tcp="${tcp:+$tcp, }$dc"; udp="${udp:+$udp, }$dc"
    fi
  fi
  [[ -n "$tcp" ]] && { FW_TCP="$FW_TCP, $tcp"; FW_EXTRA="TCP $tcp"; }
  [[ -n "$udp" ]] && { FW_UDP="$FW_UDP, $udp"; FW_EXTRA="${FW_EXTRA:+$FW_EXTRA · }UDP $udp"; }
  return 0
}

# La IP pública se pregunta por DNS, no por HTTP: es una consulta normal a
# OpenDNS, sin cabeceras ni cookies, y encaja con lo que ya hace esta máquina.
public_ip() { dig +short +time=3 +tries=1 myip.opendns.com @resolver1.opendns.com 2>/dev/null | grep -v '^;;' | head -1; }

show_exposure() {
  clear_screen; step "Exposición a internet"
  detect_platform
  local pub lm
  echo "  Plataforma : ${BLD}$PLATFORM${NC}"
  echo "  IP local   : ${BLD}$LISTEN_IP${NC}"
  pub=$(public_ip)
  echo "  IP pública : ${BLD}${pub:-no se ha podido averiguar}${NC}"
  echo

  echo "  ${BLD}Quién está escuchando${NC}"
  ss -tulpnH 2>/dev/null \
    | awk '{ n=split($5,a,":"); p=a[n];
             if (p==53 || p==5335 || p==80 || p==443 || p==8080 ||
                 p==3000 || p==853 || p==784 || p==8853 || p==5443)
               print "    " $1 "  " $5 "  " $NF }' \
    | sort -u | sed 's/users:((//;s/))$//'
  echo

  # ── Lo que de verdad decide si eres un resolver abierto ──
  if [[ "$ENGINE" == adguard ]]; then
    echo "  ${BLD}Modo de escucha de AdGuard Home${NC}"
    local binds; binds=$(agh_block_list dns bind_hosts 2>/dev/null)
    if grep -q '0\.0\.0\.0' <<<"$binds"; then
      err "bind_hosts = 0.0.0.0 · responde a CUALQUIERA que pregunte"
      (( IS_VPS )) && {
        echo "      ${RED}Esto es un resolver DNS abierto en una máquina pública.${NC}"
        echo "      ${DIM}Se usa para amplificar ataques DDoS y acaba en suspensión${NC}"
        echo "      ${DIM}de la VPS por abuso. Ponle un cortafuegos (opción 2).${NC}"; }
    elif [[ -z "$binds" ]]; then
      warn "no he podido leer bind_hosts de $AGH_YAML"
    else
      ok "bind_hosts = $(tr '\n' ' ' <<<"$binds")· atado a direcciones concretas"
    fi
    # El 3000 del asistente y el DNS cifrado son la misma puerta por otro lado:
    # cerrar solo el 53 no basta con AdGuard.
    if [[ "$(agh_get tls enabled)" == "true" ]]; then
      warn "DNS cifrado activo: revisa también 853 (DoT), 443 (DoH), 784 (DoQ)"
      warn "y 5443 (DNSCrypt) además del $PIHOLE_PORT."
    fi
  else
    echo "  ${BLD}Modo de escucha de Pi-hole${NC}"
    lm=$(ph_get dns.listeningMode)
    case "$lm" in
      LOCAL)  ok "listeningMode=LOCAL · solo responde a tu propia subred" ;;
      ALL)    err "listeningMode=ALL · responde a CUALQUIERA que pregunte"
              (( IS_VPS )) && {
                echo "      ${RED}Esto es un resolver DNS abierto en una máquina pública.${NC}"
                echo "      ${DIM}Se usa para amplificar ataques DDoS y acaba en suspensión${NC}"
                echo "      ${DIM}de la VPS por abuso. Ponle un cortafuegos (opción 2).${NC}"; } ;;
      BIND|SINGLE) ok "listeningMode=$lm · atado a una interfaz concreta" ;;
      *)      warn "listeningMode=${lm:-desconocido}" ;;
    esac
  fi
  echo

  echo "  ${BLD}Cortafuegos${NC}"
  if ! need nft; then
    warn "nftables no está instalado"
  elif fw_active; then
    ok "Reglas de nexo-dns activas"
    nft list table inet nexo_dns 2>/dev/null | grep -E 'dport|saddr' | sed 's/^/      /'
  else
    if (( IS_VPS )); then
      warn "Sin reglas propias. En una VPS pública conviene poner el DNS"
      warn "a resguardo (opción 2)."
    else
      info "Sin reglas propias (en una red doméstica no suele hacer falta)"
    fi
  fi
  pause
}

install_firewall() {
  clear_screen; step "Cortafuegos del DNS"
  need nft || {
    warn "Hace falta nftables."
    yes_no "¿Lo instalo?" || { pause; return; }
    apt-get install -y nftables || { err "No se pudo instalar"; pause; return; }
  }
  engine_fw_ports
  echo
  echo "  Se cierra el DNS ($PIHOLE_PORT) y el panel web ($WEB_PORT) a internet,"
  if [[ -n "$FW_EXTRA" ]]; then
    echo "  y además los puertos propios de AdGuard: ${BLD}${FW_EXTRA}${NC}"
    echo "  ${DIM}Cerrar solo el 53 dejaría el mismo resolver accesible por ahí.${NC}"
  fi
  echo "  dejándolos abiertos solo para:"
  echo "    · la propia máquina (loopback)"
  echo "    · redes privadas: 10/8, 172.16/12, 192.168/16"
  echo "    · el tailnet de Tailscale: 100.64/10"
  echo
  echo "  ${BLD}El SSH no se toca.${NC} La política de la cadena es ${BLD}accept${NC} y solo"
  echo "  se descartan esos puertos concretos, así que esto ${BLD}no puede${NC}"
  echo "  dejarte fuera de la máquina."
  echo
  yes_no "¿Aplicar?" || { pause; return; }
  install_firewall_quiet
  echo
  warn "Esto es el cortafuegos DEL SISTEMA. Si tu proveedor tiene además"
  warn "grupos de seguridad (AWS, Azure, GCP...), revísalos también: son"
  warn "una segunda puerta, por delante de esta."
  pause
}

# La generación de reglas, sin preguntas ni pausas. La usa el menú y también el
# cambio de motor, que tiene que rehacerlas con los puertos del filtro nuevo:
# el fichero .nft lleva los números escritos dentro, así que si no se regenera
# se queda cerrando los del motor anterior.
install_firewall_quiet() {
  need nft || return 1
  engine_fw_ports

  # `table` antes de `delete` crea la tabla si no existe: así el delete nunca
  # falla en la primera ejecución y el fichero es idempotente.
  cat > "$FW_NFT" <<EOF
#!/usr/sbin/nft -f
# Generado por nexo-dns.sh v$NEXO_VERSION el $(date '+%Y-%m-%d %H:%M')
# Cierra el DNS y el panel web a internet. No toca el SSH ni nada más.
table inet nexo_dns
delete table inet nexo_dns

table inet nexo_dns {
    set confiables {
        type ipv4_addr
        flags interval
        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }
    }
    chain input {
        type filter hook input priority -10; policy accept;
        iif lo accept
        ip saddr @confiables accept
        ip6 saddr { fd00::/8, fe80::/10 } accept
        udp dport { $FW_UDP } drop
        tcp dport { $FW_TCP } drop
    }
}
EOF
  chmod 644 "$FW_NFT"

  if ! nft -c -f "$FW_NFT" 2>/dev/null; then
    err "Las reglas no son válidas:"; nft -c -f "$FW_NFT" 2>&1 | sed 's/^/    /'
    rm -f "$FW_NFT"; return 1
  fi
  nft -f "$FW_NFT" || { err "No se pudieron cargar"; return 1; }
  ok "Reglas cargadas · TCP {$FW_TCP} · UDP {$FW_UDP}"

  local nftbin; nftbin=$(command -v nft)
  cat > "$FW_UNIT" <<EOF
[Unit]
Description=Cortafuegos del DNS de nexo-dns
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$nftbin -f $FW_NFT
ExecStop=$nftbin delete table inet nexo_dns

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable nexo-dns-firewall.service >/dev/null 2>&1 && ok "Se reaplica en cada arranque"

  # Comprobación real: desde la propia máquina se tiene que seguir resolviendo.
  sleep 1
  if dig +short +time=5 google.com @127.0.0.1 -p "$PIHOLE_PORT" >/dev/null 2>&1; then
    ok "El DNS sigue funcionando desde la máquina"
    return 0
  else
    err "El DNS ha dejado de responder — quitando las reglas"
    nft delete table inet nexo_dns 2>/dev/null || true
    systemctl disable nexo-dns-firewall.service >/dev/null 2>&1 || true
    rm -f "$FW_NFT" "$FW_UNIT"; systemctl daemon-reload
    return 1
  fi
}

remove_firewall() {
  clear_screen; step "Quitar el cortafuegos"
  fw_active || [[ -f "$FW_UNIT" ]] || { info "No hay nada que quitar"; pause; return; }
  yes_no "¿Seguro? El DNS volverá a estar abierto a internet" || { pause; return; }
  nft delete table inet nexo_dns 2>/dev/null || true
  systemctl disable --now nexo-dns-firewall.service >/dev/null 2>&1 || true
  rm -f "$FW_NFT" "$FW_UNIT"
  systemctl daemon-reload
  ok "Reglas retiradas"
  pause
}

security_menu() {
  while true; do
    clear_screen; step "Seguridad"
    echo
    echo "    1) Ver exposición a internet"
    echo "    2) Cerrar el DNS y el panel a internet (cortafuegos)"
    echo "    3) Quitar el cortafuegos"
    echo "    0) Volver"
    echo
    local o; o=$(ask "Opción:")
    case "$o" in
      1) show_exposure ;;
      2) install_firewall ;;
      3) remove_firewall ;;
      0|"") return ;;
    esac
  done
}

# ══════════════════════════════════════════════════════════════ PANEL ══════════
panel() {
  # Sin terminal, `read` devuelve vacío al instante y el menú giraría en un
  # bucle infinito quemando CPU. Pasa de verdad con `curl ... | sudo bash`.
  if [[ ! -t 0 ]]; then
    err "El panel necesita un terminal interactivo."
    echo "  Descarga el script y ejecútalo, en vez de pasarlo por una tubería:"
    echo "    ${BLD}curl -fsSLO https://raw.githubusercontent.com/Dark-admin/pihole-unbound-manager/main/nexo-dns.sh${NC}"
    echo "    ${BLD}sudo bash nexo-dns.sh${NC}"
    echo "  O usa una orden directa:  ${BLD}status${NC} · ${BLD}health${NC} · ${BLD}install${NC} · ${BLD}optimize${NC}"
    exit 1
  fi
  while true; do
    load_conf; detect_os; detect_platform
    elegir_layout
    clear_screen
    local up_state ph_state ts_state ESHORT ECOL ESVC EOTHER
    ESHORT=$(engine_short); ECOL=$(engine_color); ESVC=$(engine_svc)
    EOTHER=$([[ "$ENGINE" == adguard ]] && echo "Pi-hole" || echo "AdGuard")
    systemctl is-active --quiet unbound 2>/dev/null && up_state=on || up_state=off
    systemctl is-active --quiet "$ESVC" 2>/dev/null && ph_state=on || ph_state=off
    if   systemctl is-active --quiet tailscaled 2>/dev/null; then ts_state=on
    elif need tailscale;                                     then ts_state=off
    else                                                          ts_state=na; fi

    echo
    btop
    draw_brand_header
    bsep
    if (( BOXW >= 50 )); then
      brow "$(service_badge "$ph_state" "$ECOL" "$ESHORT" ":$PIHOLE_PORT")   $(service_badge "$up_state" "$UB" Unbound ":$UNBOUND_PORT")   $(service_badge "$ts_state" "$TS" Tailscale '')"
    else
      brow "$(service_badge "$ph_state" "$ECOL" "$ESHORT" ":$PIHOLE_PORT")  $(service_badge "$up_state" "$UB" Unbound ":$UNBOUND_PORT")"
      brow "$(service_badge "$ts_state" "$TS" Tailscale '')"
    fi
    brow "${MUT}HOST${NC}  ${TXT}$(hostname)${NC} ${LIN}${BULLET}${NC} ${VAL}$LISTEN_IP${NC} ${LIN}${BULLET}${NC} ${MUT}$PLATFORM${NC}"
    if (( IS_VPS )); then
      if fw_active; then
        brow "${MUT}SEGURIDAD${NC}  ${GRN}${DOT} PROTEGIDO${NC} ${LIN}${BULLET}${NC} ${MUT}DNS cerrado a internet${NC}"
      else
        brow "${MUT}SEGURIDAD${NC}  ${YEL}${I_SEC} ATENCIÓN${NC} ${LIN}${BULLET}${NC} ${YEL}DNS abierto a internet${NC}"
      fi
    fi
    bsep
    sec "$I_EST" "$GRN" "ESTADO"
    menu_items "$(mi 1 'Ver estado')" "$(mi 2 'Chequeo real')"
    bsep
    sec "$I_CFG" "$(engine_color)" "DNS"
    menu_items "$(mi 3 'Puerto Unbound' "$UNBOUND_PORT")" \
               "$(mi 4 "Puerto $ESHORT" "$PIHOLE_PORT")" \
               "$(mi 5 'Puerto web' "$WEB_PORT")" \
               "$(mi 6 'IP del servidor')" \
               "$(mi 7 "Reoptimizar $ESHORT")" \
               "$(mi 8 "Listas de $ESHORT")" \
               "$(mi 9 'Precalentar caché')"
    bsep
    sec "$I_SEC" "$YEL" "SEGURIDAD"
    menu_items "$(mi 10 'Exposición y cortafuegos')"
    bsep
    sec "$I_TS" "$TS" "TAILSCALE"
    menu_items "$(mi 11 'Instalar')" "$(mi 12 'Optimizar')"
    bsep
    sec "$I_SYS" "$UB" "SISTEMA"
    menu_items "$(mi 13 'Red / BBR')" "$(mi 14 'Reiniciar servicios')" \
               "$(mi 15 'Copias / restaurar')" "$(mi 16 'Instalar todo')"
    bsep
    # Las opciones del motor van al final a propósito: así los números 1..16 no
    # se mueven de donde ya estaban documentados. La sección va en índigo porque
    # ESTADO ya usa verde y el de AdGuard no se distinguiría de él.
    sec "$I_CFG" "$UBN" "MOTOR"
    menu_items "$(mi 17 "Cambiar a $EOTHER")" "$(mi 18 'Instalar AdGuard Home')"
    bsep
    menu_items "$(mi 0 'Salir')"
    brow "${MUT}Selecciona una opción y pulsa Enter${NC}"
    bbot
    echo
    local c; c=$(ask "$(engine_color)${ARROW}${NC} ${TXT}Opción${NC} ${UB}[0-18]${NC}")
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
      10) security_menu ;;
      11) install_tailscale ;;
      12) optimize_tailscale ;;
      13) network_tuning ;;
      14) clear_screen; step "Reiniciando"
          systemctl restart unbound && ok "Unbound" || err "Unbound"
          sleep 1
          systemctl restart "$ESVC" && ok "$ESHORT" || err "$ESHORT"
          pause ;;
      15) backups_menu ;;
      16) do_install ;;
      17) switch_engine ;;
      18) install_adguard ;;
      0)  echo; ok "Hasta luego"; exit 0 ;;
      *)  ;;
    esac
  done
}

# ═══════════════════════════════════════════════════════════════ MAIN ═════════
COMMAND="${1:-panel}"
case "$COMMAND" in
  -v|--version) echo "nexo-dns $NEXO_VERSION"; exit 0 ;;
  -h|--help)    sed -n '2,28p' "$0"; exit 0 ;;
  banner)       splash; exit 0 ;;
  install|status|health|optimize|security|firewall|engine|panel) ;;
  *) err "Orden desconocida: $COMMAND"; sed -n '2,28p' "$0"; exit 1 ;;
esac

require_root "$COMMAND"
case "$COMMAND" in
  # `engine` para y arranca servicios y reescribe la config: toma el bloqueo
  # igual que los demás, para que no se cruce con una instalación en curso.
  install|optimize|firewall|engine|panel) acquire_lock ;;
esac
detect_os
detect_platform
load_conf

case "$COMMAND" in
  install)  do_install ;;
  status)   show_status ;;
  health)   health_check ;;
  optimize) do_optimize ;;
  security) show_exposure ;;
  firewall) install_firewall ;;
  engine)   switch_engine ;;
  panel)    panel ;;
esac
