#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Integración Snort -> Wazuh (portable para laboratorios)
# - Idempotente en la práctica (reaplica configuración sin duplicados)
# - Soporta sudo remoto con/sin NOPASSWD
# - Soporta modos: completo / only-rules / only-agent
# - Soporta dry-run (planifica y valida SSH, no modifica nada)
# =========================================================

SCRIPT_START=$(date +%s)
format_time() { local total="$1"; echo "$((total/60)) minutos y $((total%60)) segundos"; }

# -------------------------
# Flags / modo
# -------------------------
DRY_RUN=0
MODE="full"   # full | only-rules | only-agent
MAKE_BACKUPS="${MAKE_BACKUPS:-no}"   # no | yes
STRICT_SNORT_TEST="${STRICT_SNORT_TEST:-yes}" # yes | no

usage() {
  cat <<'USAGE'
Uso: bash snort-wazuh.sh [opciones]

Opciones:
  --dry-run        Muestra el plan y valida SSH. No modifica nada remoto.
  --only-rules     Solo instala/actualiza reglas (Snort + Wazuh Manager).
  --only-agent     Solo instala/configura wazuh-agent (sin tocar reglas).
  -h, --help       Muestra esta ayuda.

Variables opcionales (env):
  MAKE_BACKUPS=yes         Crea backup .bak de ficheros antes de reescribirlos.
  STRICT_SNORT_TEST=no     No aborta si 'snort -T' falla al validar reglas.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --only-rules)
      [[ "$MODE" == "full" ]] || { echo "[-] No puedes combinar --only-rules con --only-agent" >&2; exit 1; }
      MODE="only-rules"
      ;;
    --only-agent)
      [[ "$MODE" == "full" ]] || { echo "[-] No puedes combinar --only-agent con --only-rules" >&2; exit 1; }
      MODE="only-agent"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[-] Opción no reconocida: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

# -------------------------
# Config por defecto
# -------------------------
DEFAULT_KEY_BASENAME="mykey"
DEFAULT_KEY_PATH="$(pwd)/${DEFAULT_KEY_BASENAME}"
DEFAULT_KNOWN_HOSTS_PATH="$(pwd)/known_hosts_${DEFAULT_KEY_BASENAME}"

DEFAULT_SSH_USER="debian"
DEFAULT_SSH_PORT="22"

DEFAULT_WAZUH_MANAGER_HOST=""
DEFAULT_WAZUH_MANAGER_AGENT_ADDR=""  # vacío => usa host SSH del manager
DEFAULT_SNORT_HOST=""
DEFAULT_AGENT_NAME="snort-server"

DEFAULT_SNORT_IFACE="auto"
DEFAULT_SNORT_LOG_FILE="/var/log/snort/alert_fast.txt"
DEFAULT_WAZUH_LOG_FORMAT="snort-fast"
DEFAULT_SNORT_RULES_FILE="/etc/snort/rules/local.rules"
DEFAULT_SNORT_LUA_PATH="/etc/snort/snort.lua"

DEFAULT_SNORT_RULE_ICMP_SID="1001001"
DEFAULT_SNORT_RULE_SYN_SID="1001010"
DEFAULT_SNORT_RULE_SYN_COUNT="20"
DEFAULT_SNORT_RULE_SYN_SECONDS="3"

WAZUH_PORT_DATA="1514"
WAZUH_PORT_ENROLL="1515"
SSH_WAIT_TIMEOUT=300

# -------------------------
# Helpers
# -------------------------
die()  { echo "[-] $*" >&2; exit 1; }
ok()   { echo "[+] $*"; }
inf()  { echo "[*] $*"; }
warn() { echo "[!] $*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Falta el comando '$1'."
}

ssh_supports_accept_new() {
  local ver
  ver="$(ssh -V 2>&1 || true)"
  [[ "$ver" =~ OpenSSH_([0-9]+)\.([0-9]+) ]] || return 1
  local maj="${BASH_REMATCH[1]}"
  local min="${BASH_REMATCH[2]}"
  (( maj > 7 )) && return 0
  (( maj == 7 && min >= 6 )) && return 0
  return 1
}

wait_for_ssh() {
  local host="$1"
  local start now

  inf "Comprobando SSH en ${SSH_USER}@${host}:${SSH_PORT} (timeout ${SSH_WAIT_TIMEOUT}s)..."

  ssh-keygen -f "$KNOWN_HOSTS_PATH" -R "$host" >/dev/null 2>&1 || true
  ssh-keygen -f "$KNOWN_HOSTS_PATH" -R "[$host]:$SSH_PORT" >/dev/null 2>&1 || true

  start=$(date +%s)
  until ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" -o BatchMode=yes \
      "${SSH_USER}@${host}" "echo ok" >/dev/null 2>&1; do
    sleep 5
    echo -n "."
    now=$(date +%s)
    if (( now - start > SSH_WAIT_TIMEOUT )); then
      echo
      return 1
    fi
  done
  echo
  return 0
}

# Ejecuta script remoto subiéndolo temporalmente y lanzándolo con TTY para sudo interactivo.
run_remote_script_tty() {
  local host="$1"; shift
  local local_script="$1"; shift

  if (( DRY_RUN )); then
    inf "[dry-run] Ejecutaría en ${host}: $(basename "$local_script") $*"
    return 0
  fi

  local remote_tmp="/tmp/remote_job_${RANDOM}_$$.sh"
  local remote_tmp_q
  printf -v remote_tmp_q '%q' "$remote_tmp"

  if ! ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
      "${SSH_USER}@${host}" \
      "umask 077; cat > ${remote_tmp_q} && chmod 700 ${remote_tmp_q}" < "$local_script"; then
    return 1
  fi

  local cmd a aq
  printf -v cmd 'bash %q' "$remote_tmp"
  for a in "$@"; do
    printf -v aq '%q' "$a"
    cmd+=" $aq"
  done
  printf -v aq '%q' "$remote_tmp"
  cmd+="; rc=\$?; rm -f ${aq}; exit \$rc"

  ssh -tt -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
      "${SSH_USER}@${host}" "$cmd"
}

TMP_FILES=()
register_tmp() { TMP_FILES+=("$1"); }
cleanup_tmps() {
  local f
  for f in "${TMP_FILES[@]:-}"; do
    [[ -n "$f" ]] && rm -f "$f" >/dev/null 2>&1 || true
  done
}
trap cleanup_tmps EXIT

# -------------------------
# Dependencias locales
# -------------------------
require_cmd bash
require_cmd ssh
require_cmd ssh-keygen
require_cmd awk
require_cmd base64
require_cmd tr
require_cmd sed
require_cmd mktemp
require_cmd tee

# -------------------------
# Banner
# -------------------------
echo "===================================================="
echo " Integración Snort ➜ Wazuh (entorno local virtualizado)"
echo "===================================================="

(( DRY_RUN )) && warn "MODO DRY-RUN activo: no se modificarán las VMs."
[[ "$MODE" == "only-rules" ]] && inf "Modo: solo reglas (Snort + Wazuh Manager)"
[[ "$MODE" == "only-agent" ]] && inf "Modo: solo agente Wazuh (sin reglas)"

# -------------------------
# Inputs SSH
# -------------------------
echo

echo "=== Configuración SSH ==="
read -r -p "Usuario SSH remoto [${DEFAULT_SSH_USER}]: " SSH_USER
SSH_USER="${SSH_USER:-$DEFAULT_SSH_USER}"
[[ -n "$SSH_USER" ]] || die "Usuario SSH remoto vacío."

read -r -p "Puerto SSH [${DEFAULT_SSH_PORT}]: " SSH_PORT
SSH_PORT="${SSH_PORT:-$DEFAULT_SSH_PORT}"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "Puerto inválido: '$SSH_PORT'"

read -r -p "Ruta a la clave privada SSH [${DEFAULT_KEY_PATH}]: " SSH_KEY_PATH
SSH_KEY_PATH="${SSH_KEY_PATH:-$DEFAULT_KEY_PATH}"
[[ -f "$SSH_KEY_PATH" ]] || die "No se encuentra la clave privada: $SSH_KEY_PATH"

DEFAULT_KH_FROM_KEY="$(pwd)/known_hosts_$(basename "$SSH_KEY_PATH")"
read -r -p "Ruta de known_hosts dedicado [${DEFAULT_KH_FROM_KEY}]: " KNOWN_HOSTS_PATH
KNOWN_HOSTS_PATH="${KNOWN_HOSTS_PATH:-$DEFAULT_KH_FROM_KEY}"

mkdir -p "$(dirname "$KNOWN_HOSTS_PATH")"
touch "$KNOWN_HOSTS_PATH"
chmod 600 "$KNOWN_HOSTS_PATH" || true
chmod 600 "$SSH_KEY_PATH" || true

ok "Clave privada: $SSH_KEY_PATH"
ok "Known hosts:   $KNOWN_HOSTS_PATH"

# -------------------------
# Inputs entorno
# -------------------------
echo

echo "=== Configuración del entorno (Wazuh + Snort) ==="
read -r -p "IP/hostname de la VM Wazuh Manager (SSH): " WAZUH_MANAGER_HOST
WAZUH_MANAGER_HOST="${WAZUH_MANAGER_HOST:-$DEFAULT_WAZUH_MANAGER_HOST}"
[[ -n "$WAZUH_MANAGER_HOST" ]] || die "La IP/hostname del Wazuh Manager no puede estar vacía."

read -r -p "IP/hostname del Manager que usará el agente [${WAZUH_MANAGER_HOST}]: " WAZUH_MANAGER_AGENT_ADDR
WAZUH_MANAGER_AGENT_ADDR="${WAZUH_MANAGER_AGENT_ADDR:-$WAZUH_MANAGER_HOST}"
[[ -n "$WAZUH_MANAGER_AGENT_ADDR" ]] || die "La IP/hostname del manager para el agente no puede estar vacía."

read -r -p "IP/hostname de la VM Snort (SSH): " SNORT_HOST
SNORT_HOST="${SNORT_HOST:-$DEFAULT_SNORT_HOST}"
[[ -n "$SNORT_HOST" ]] || die "La IP/hostname de la VM Snort no puede estar vacía."

read -r -p "Nombre del agente en Wazuh [${DEFAULT_AGENT_NAME}]: " AGENT_NAME
AGENT_NAME="${AGENT_NAME:-$DEFAULT_AGENT_NAME}"
[[ -n "$AGENT_NAME" ]] || die "El nombre del agente no puede estar vacío."

read -r -p "Interfaz de Snort (auto para detectar) [${DEFAULT_SNORT_IFACE}]: " SNORT_IFACE_INPUT
SNORT_IFACE_INPUT="${SNORT_IFACE_INPUT:-$DEFAULT_SNORT_IFACE}"

read -r -p "Ruta del log de Snort [${DEFAULT_SNORT_LOG_FILE}]: " SNORT_LOG_FILE
SNORT_LOG_FILE="${SNORT_LOG_FILE:-$DEFAULT_SNORT_LOG_FILE}"

read -r -p "Formato Wazuh para ese log [${DEFAULT_WAZUH_LOG_FORMAT}]: " WAZUH_LOG_FORMAT
WAZUH_LOG_FORMAT="${WAZUH_LOG_FORMAT:-$DEFAULT_WAZUH_LOG_FORMAT}"

read -r -p "Ruta de reglas locales de Snort [${DEFAULT_SNORT_RULES_FILE}]: " SNORT_RULES_FILE
SNORT_RULES_FILE="${SNORT_RULES_FILE:-$DEFAULT_SNORT_RULES_FILE}"

read -r -p "Ruta de snort.lua (comprobación) [${DEFAULT_SNORT_LUA_PATH}]: " SNORT_LUA_PATH
SNORT_LUA_PATH="${SNORT_LUA_PATH:-$DEFAULT_SNORT_LUA_PATH}"

read -r -p "SID regla ICMP Snort [${DEFAULT_SNORT_RULE_ICMP_SID}]: " SNORT_RULE_ICMP_SID
SNORT_RULE_ICMP_SID="${SNORT_RULE_ICMP_SID:-$DEFAULT_SNORT_RULE_ICMP_SID}"

read -r -p "SID regla SYN scan Snort [${DEFAULT_SNORT_RULE_SYN_SID}]: " SNORT_RULE_SYN_SID
SNORT_RULE_SYN_SID="${SNORT_RULE_SYN_SID:-$DEFAULT_SNORT_RULE_SYN_SID}"

read -r -p "Umbral SYN scan (count) [${DEFAULT_SNORT_RULE_SYN_COUNT}]: " SNORT_RULE_SYN_COUNT
SNORT_RULE_SYN_COUNT="${SNORT_RULE_SYN_COUNT:-$DEFAULT_SNORT_RULE_SYN_COUNT}"

read -r -p "Ventana SYN scan (seconds) [${DEFAULT_SNORT_RULE_SYN_SECONDS}]: " SNORT_RULE_SYN_SECONDS
SNORT_RULE_SYN_SECONDS="${SNORT_RULE_SYN_SECONDS:-$DEFAULT_SNORT_RULE_SYN_SECONDS}"

[[ "$SNORT_RULE_ICMP_SID" =~ ^[0-9]+$ ]] || die "SID ICMP inválido"
[[ "$SNORT_RULE_SYN_SID" =~ ^[0-9]+$ ]] || die "SID SYN inválido"
[[ "$SNORT_RULE_SYN_COUNT" =~ ^[0-9]+$ ]] || die "count SYN inválido"
[[ "$SNORT_RULE_SYN_SECONDS" =~ ^[0-9]+$ ]] || die "seconds SYN inválido"
[[ "$SNORT_RULE_ICMP_SID" != "$SNORT_RULE_SYN_SID" ]] || die "Los SIDs de Snort deben ser distintos."

# Flags derivados del modo
DO_MANAGER_PREP=1
DO_SNORT_RULES=1
DO_SNORT_AGENT=1
DO_WAIT_AGENT=1
DO_MANAGER_RULES=1
case "$MODE" in
  only-rules)
    DO_MANAGER_PREP=0
    DO_SNORT_AGENT=0
    DO_WAIT_AGENT=0
    ;;
  only-agent)
    DO_SNORT_RULES=0
    DO_MANAGER_RULES=0
    ;;
esac

# Variables que se rellenan después
TARGET_AGENT_VERSION=""
AGENT_ID=""
AGENT_KEY_B64=""
DETECTED_SNORT_IFACE=""

# -------------------------
# Resumen
# -------------------------
echo

echo "=== Resumen de configuración ==="
echo "Modo:                       ${MODE}"
(( DRY_RUN )) && echo "Dry-run:                    sí"
echo "Wazuh Manager (SSH):        ${WAZUH_MANAGER_HOST}"
echo "Manager para el agente:     ${WAZUH_MANAGER_AGENT_ADDR}"
echo "VM Snort (SSH):             ${SNORT_HOST}"
echo "Nombre agente Wazuh:        ${AGENT_NAME}"
echo "Interfaz Snort solicitada:  ${SNORT_IFACE_INPUT}"
echo "Log Snort:                  ${SNORT_LOG_FILE}"
echo "Formato Wazuh (localfile):  ${WAZUH_LOG_FORMAT}"
echo "Reglas Snort (local):       ${SNORT_RULES_FILE}"
echo "snort.lua (check):          ${SNORT_LUA_PATH}"
echo "SID Snort ICMP / SYN:       ${SNORT_RULE_ICMP_SID} / ${SNORT_RULE_SYN_SID}"
echo "Puertos Wazuh (referencia): ${WAZUH_PORT_DATA}/tcp-udp, ${WAZUH_PORT_ENROLL}/tcp"
echo "Backups remotos:            ${MAKE_BACKUPS}"
echo "snort -T estricto:          ${STRICT_SNORT_TEST}"
echo
read -r -p "¿Continuar? (y/N): " CONFIRM
CONFIRM="${CONFIRM:-N}"
[[ "$CONFIRM" =~ ^[Yy]$ ]] || die "Cancelado por el usuario."

# -------------------------
# SSH opts
# -------------------------
STRICT_OPT="accept-new"
if ! ssh_supports_accept_new; then
  inf "Tu OpenSSH no parece soportar accept-new. Usaré StrictHostKeyChecking=no."
  STRICT_OPT="no"
fi
SSH_OPTS=(
  -o "ConnectTimeout=5"
  -o "StrictHostKeyChecking=${STRICT_OPT}"
  -o "UserKnownHostsFile=${KNOWN_HOSTS_PATH}"
)

# -------------------------
# Comprobar SSH
# -------------------------
echo
inf "Comprobando acceso SSH a las VMs..."
wait_for_ssh "$WAZUH_MANAGER_HOST" || die "No hay SSH en Wazuh Manager: $WAZUH_MANAGER_HOST"
ok "SSH disponible en Wazuh Manager ($WAZUH_MANAGER_HOST)"
wait_for_ssh "$SNORT_HOST" || die "No hay SSH en Snort: $SNORT_HOST"
ok "SSH disponible en Snort ($SNORT_HOST)"

if (( DRY_RUN )); then
  echo
  inf "DRY-RUN completado. Se validó conectividad SSH y parámetros."
  echo "Acciones previstas:"
  (( DO_MANAGER_PREP )) && echo "  - Preparar agente en Wazuh Manager y extraer key/version"
  (( DO_SNORT_RULES ))  && echo "  - Instalar/actualizar reglas Snort en ${SNORT_RULES_FILE}"
  (( DO_SNORT_AGENT ))  && echo "  - Instalar/configurar wazuh-agent en Snort + localfile"
  (( DO_WAIT_AGENT ))   && echo "  - Esperar conexión del agente en manager"
  (( DO_MANAGER_RULES ))&& echo "  - Instalar reglas Wazuh en manager"
  exit 0
fi

# =========================
# Paso 1: Preparar agente Wazuh (si aplica)
# =========================
if (( DO_MANAGER_PREP )); then
  echo
  inf "Paso 1/5: Preparando agente '${AGENT_NAME}' en Wazuh Manager y obteniendo clave..."

  MANAGER_PREP_SCRIPT="$(mktemp)"; register_tmp "$MANAGER_PREP_SCRIPT"
  MANAGER_PREP_TMP="$(mktemp)"; register_tmp "$MANAGER_PREP_TMP"

  cat > "$MANAGER_PREP_SCRIPT" <<'REMOTE_MANAGER_PREP'
#!/usr/bin/env bash
set -euo pipefail
AGENT_NAME="$1"
log(){ echo "$*" >&2; }
SUDO=""; SUDO_KEEPALIVE_PID=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
  if sudo -n true >/dev/null 2>&1; then
    log "[remote-manager] sudo sin contraseña disponible"
  else
    log "[remote-manager] sudo requiere contraseña. Se pedirá ahora..."
    sudo -v || { log "[remote-manager][ERROR] sudo -v falló"; exit 1; }
    (
      while true; do sudo -n true >/dev/null 2>&1 || exit; sleep 60; kill -0 "$$" >/dev/null 2>&1 || exit; done
    ) &
    SUDO_KEEPALIVE_PID="$!"
    trap '[[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "${SUDO_KEEPALIVE_PID}" >/dev/null 2>&1 || true' EXIT
  fi
fi

MANAGER_WAZUH_VERSION="$(dpkg-query -W -f='${Version}\n' wazuh-manager 2>/dev/null || true)"
MANAGER_WAZUH_VERSION="$(echo "$MANAGER_WAZUH_VERSION" | tr -d '\r')"
[[ -n "$MANAGER_WAZUH_VERSION" ]] || { log "[remote-manager][ERROR] wazuh-manager no detectado"; exit 1; }
log "[remote-manager] Version detectada: $MANAGER_WAZUH_VERSION"

get_agent_line(){ $SUDO awk -v name="$AGENT_NAME" '$2==name {print; exit}' /var/ossec/etc/client.keys 2>/dev/null || true; }
AGENT_KEY_LINE="$(get_agent_line)"
if [[ -z "$AGENT_KEY_LINE" ]]; then
  log "[remote-manager] El agente '$AGENT_NAME' no existe. Creando..."
  $SUDO /var/ossec/bin/manage_agents -a "$AGENT_NAME" -i any >/dev/null 2>&1 || \
    printf 'A\n%s\nany\ny\nQ\n' "$AGENT_NAME" | $SUDO /var/ossec/bin/manage_agents >/dev/null
  AGENT_KEY_LINE="$(get_agent_line)"
fi
[[ -n "$AGENT_KEY_LINE" ]] || { log "[remote-manager][ERROR] No se pudo leer client.keys"; exit 1; }
AGENT_ID="$(echo "$AGENT_KEY_LINE" | awk '{print $1}')"
AGENT_KEY_B64="$(printf '%s' "$AGENT_KEY_LINE" | base64 | tr -d '\n')"
log "[remote-manager] Agente listo: ID=$AGENT_ID Name=$AGENT_NAME"
printf '__MANAGER_VER__=%s\n' "$MANAGER_WAZUH_VERSION"
printf '__AGENT_ID__=%s\n' "$AGENT_ID"
printf '__AGENT_KEY_B64__=%s\n' "$AGENT_KEY_B64"
REMOTE_MANAGER_PREP
  chmod 700 "$MANAGER_PREP_SCRIPT"

  if ! run_remote_script_tty "$WAZUH_MANAGER_HOST" "$MANAGER_PREP_SCRIPT" "$AGENT_NAME" | tee "$MANAGER_PREP_TMP"; then
    die "Falló la preparación del agente en el manager."
  fi

  MANAGER_PREP_OUT="$(tr -d '\r' < "$MANAGER_PREP_TMP")"
  TARGET_AGENT_VERSION="$(printf '%s\n' "$MANAGER_PREP_OUT" | awk -F= '/^__MANAGER_VER__=/{print substr($0,index($0,"=")+1); exit}')"
  AGENT_ID="$(printf '%s\n' "$MANAGER_PREP_OUT" | awk -F= '/^__AGENT_ID__=/{print substr($0,index($0,"=")+1); exit}')"
  AGENT_KEY_B64="$(printf '%s\n' "$MANAGER_PREP_OUT" | awk -F= '/^__AGENT_KEY_B64__=/{print substr($0,index($0,"=")+1); exit}')"

  [[ -n "$TARGET_AGENT_VERSION" ]] || die "No se pudo extraer versión de wazuh-manager"
  [[ -n "$AGENT_ID" ]] || die "No se pudo extraer ID de agente"
  [[ -n "$AGENT_KEY_B64" ]] || die "No se pudo extraer key de agente"

  ok "Wazuh Manager version: $TARGET_AGENT_VERSION"
  ok "Agente preparado: ID=$AGENT_ID Name=$AGENT_NAME"
fi

# =========================
# Paso 2: Reglas Snort (si aplica)
# =========================
if (( DO_SNORT_RULES )); then
  echo
  inf "Paso 2/5: Instalando reglas locales de Snort y detectando interfaz..."

  SNORT_RULES_SCRIPT="$(mktemp)"; register_tmp "$SNORT_RULES_SCRIPT"
  SNORT_RULES_OUT="$(mktemp)"; register_tmp "$SNORT_RULES_OUT"

  cat > "$SNORT_RULES_SCRIPT" <<'REMOTE_SNORT_RULES'
#!/usr/bin/env bash
set -euo pipefail
SNORT_RULES_FILE="$1"
SNORT_LUA_PATH="$2"
SNORT_IFACE_INPUT="$3"
ICMP_SID="$4"
SYN_SID="$5"
SYN_COUNT="$6"
SYN_SECONDS="$7"
MAKE_BACKUPS="$8"
STRICT_SNORT_TEST="$9"

log(){ echo "$*"; }
SUDO=""; SUDO_KEEPALIVE_PID=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
  if sudo -n true >/dev/null 2>&1; then
    log "[remote-snort-rules] sudo sin contraseña disponible"
  else
    log "[remote-snort-rules] sudo requiere contraseña. Se pedirá ahora..."
    sudo -v || { log "[remote-snort-rules][ERROR] sudo -v falló"; exit 1; }
    (
      while true; do sudo -n true >/dev/null 2>&1 || exit; sleep 60; kill -0 "$$" >/dev/null 2>&1 || exit; done
    ) &
    SUDO_KEEPALIVE_PID="$!"
    trap '[[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "${SUDO_KEEPALIVE_PID}" >/dev/null 2>&1 || true' EXIT
  fi
fi

# Autodetección de interfaz
DETECTED_IFACE=""
if [[ -n "$SNORT_IFACE_INPUT" && "$SNORT_IFACE_INPUT" != "auto" ]]; then
  DETECTED_IFACE="$SNORT_IFACE_INPUT"
else
  DETECTED_IFACE="$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')"
  if [[ -z "$DETECTED_IFACE" ]]; then
    DETECTED_IFACE="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -Ev '^(lo)$' | head -n1)"
  fi
fi
[[ -n "$DETECTED_IFACE" ]] || { log "[remote-snort-rules][ERROR] No pude detectar interfaz"; exit 1; }
log "[remote-snort-rules] Interfaz detectada/seleccionada: $DETECTED_IFACE"
printf '__DETECTED_SNORT_IFACE__=%s\n' "$DETECTED_IFACE"

RULE_DIR="$(dirname "$SNORT_RULES_FILE")"
$SUDO mkdir -p "$RULE_DIR"
$SUDO touch "$SNORT_RULES_FILE"

TMP_NEW="/tmp/snort_local_rules_new_$$.txt"
cat > "$TMP_NEW" <<EOF
# Reglas locales Snort (laboratorio Snort -> Wazuh)
# Mensajes alineados con las reglas locales de Wazuh

# BEGIN NICS_LAB SNORT RULES
alert icmp any any -> any any (
    msg:"Intento ICMPv4 detectado";
    sid:${ICMP_SID};
    rev:1;
)

alert tcp any any -> any any (
    flags:S;
    flow:stateless;
    msg:"Nmap TCP SYN scan";
    detection_filter:track by_src, count ${SYN_COUNT}, seconds ${SYN_SECONDS};
    sid:${SYN_SID};
    rev:1;
)
# END NICS_LAB SNORT RULES
EOF

# Conserva reglas externas al bloque y reemplaza SOLO nuestro bloque.
TMP_CUR="/tmp/snort_local_rules_cur_$$.txt"
$SUDO cat "$SNORT_RULES_FILE" > "$TMP_CUR" || true
$SUDO perl -0777 -i -pe 's/\n?# BEGIN NICS_LAB SNORT RULES.*?# END NICS_LAB SNORT RULES\n?//sg' "$TMP_CUR"

# Si aún hay SIDs duplicados fuera de nuestro bloque, avisar
if grep -Eq "sid:${ICMP_SID};|sid:${SYN_SID};" "$TMP_CUR"; then
  log "[remote-snort-rules][WARN] Se encontraron SIDs ${ICMP_SID}/${SYN_SID} fuera del bloque gestionado."
  log "[remote-snort-rules][WARN] Se sobrescribirá el fichero completo para evitar duplicados."
  if [[ "$MAKE_BACKUPS" == "yes" ]]; then
    $SUDO cp -p "$SNORT_RULES_FILE" "${SNORT_RULES_FILE}.bak" || true
  fi
  $SUDO install -m 644 "$TMP_NEW" "$SNORT_RULES_FILE"
else
  # Si el contenido final coincide, no tocar
  cat "$TMP_CUR" > /tmp/snort_local_rules_final_$$.txt
  if [[ -s /tmp/snort_local_rules_final_$$.txt ]]; then
    printf '\n' >> /tmp/snort_local_rules_final_$$.txt
  fi
  cat "$TMP_NEW" >> /tmp/snort_local_rules_final_$$.txt

  if $SUDO cmp -s "/tmp/snort_local_rules_final_$$.txt" "$SNORT_RULES_FILE"; then
    log "[remote-snort-rules] local.rules ya estaba en el estado deseado."
  else
    [[ "$MAKE_BACKUPS" == "yes" ]] && $SUDO cp -p "$SNORT_RULES_FILE" "${SNORT_RULES_FILE}.bak" || true
    $SUDO install -m 644 "/tmp/snort_local_rules_final_$$.txt" "$SNORT_RULES_FILE"
    log "[remote-snort-rules] local.rules actualizado."
  fi
fi

$SUDO rm -f "$TMP_NEW" "$TMP_CUR" "/tmp/snort_local_rules_final_$$.txt" >/dev/null 2>&1 || true

if [[ -f "$SNORT_LUA_PATH" ]]; then
  if $SUDO grep -q "local.rules" "$SNORT_LUA_PATH"; then
    log "[remote-snort-rules] OK: snort.lua referencia local.rules"
  else
    log "[remote-snort-rules][WARN] snort.lua no parece referenciar local.rules"
  fi
else
  log "[remote-snort-rules][WARN] No existe $SNORT_LUA_PATH"
fi

if command -v snort >/dev/null 2>&1 && [[ -f "$SNORT_LUA_PATH" ]]; then
  log "[remote-snort-rules] Validando con snort -T ..."
  if $SUDO snort -T -c "$SNORT_LUA_PATH" >/tmp/snort_test_$$.log 2>&1; then
    log "[remote-snort-rules] snort -T OK"
  else
    log "[remote-snort-rules][WARN] snort -T falló. Últimas líneas:"
    $SUDO tail -n 40 /tmp/snort_test_$$.log || true
    if [[ "$STRICT_SNORT_TEST" == "yes" ]]; then
      $SUDO rm -f /tmp/snort_test_$$.log >/dev/null 2>&1 || true
      exit 23
    fi
  fi
  $SUDO rm -f /tmp/snort_test_$$.log >/dev/null 2>&1 || true
fi

if $SUDO systemctl list-unit-files 2>/dev/null | grep -qE '^snort(\.service)?'; then
  log "[remote-snort-rules] Servicio snort detectado (reinicio opcional)..."
  $SUDO systemctl restart snort >/dev/null 2>&1 || log "[remote-snort-rules][WARN] No se pudo reiniciar snort"
else
  log "[remote-snort-rules] No hay servicio systemd 'snort' (normal si lo lanzas manualmente)."
fi

log "[remote-snort-rules] Reglas Snort listas."
REMOTE_SNORT_RULES
  chmod 700 "$SNORT_RULES_SCRIPT"

  if ! run_remote_script_tty "$SNORT_HOST" "$SNORT_RULES_SCRIPT" \
      "$SNORT_RULES_FILE" "$SNORT_LUA_PATH" "$SNORT_IFACE_INPUT" \
      "$SNORT_RULE_ICMP_SID" "$SNORT_RULE_SYN_SID" "$SNORT_RULE_SYN_COUNT" "$SNORT_RULE_SYN_SECONDS" \
      "$MAKE_BACKUPS" "$STRICT_SNORT_TEST" | tee "$SNORT_RULES_OUT"; then
    die "Falló la instalación/validación de reglas Snort."
  fi

  DETECTED_SNORT_IFACE="$(tr -d '\r' < "$SNORT_RULES_OUT" | awk -F= '/^__DETECTED_SNORT_IFACE__=/{print substr($0,index($0,"=")+1); exit}')"
  [[ -n "$DETECTED_SNORT_IFACE" ]] || warn "No se pudo extraer la interfaz detectada; revisa salida remota."
  [[ -n "$DETECTED_SNORT_IFACE" ]] && ok "Interfaz Snort detectada: $DETECTED_SNORT_IFACE"
  ok "Reglas Snort aplicadas."
fi

# =========================
# Paso 3: wazuh-agent en Snort (si aplica)
# =========================
if (( DO_SNORT_AGENT )); then
  echo
  inf "Paso 3/5: Instalando/configurando wazuh-agent en Snort..."

  [[ -n "${TARGET_AGENT_VERSION:-}" ]] || die "Falta TARGET_AGENT_VERSION (Paso 1 no ejecutado)"
  [[ -n "${AGENT_KEY_B64:-}" ]] || die "Falta AGENT_KEY_B64 (Paso 1 no ejecutado)"

  SNORT_AGENT_SCRIPT="$(mktemp)"; register_tmp "$SNORT_AGENT_SCRIPT"

  cat > "$SNORT_AGENT_SCRIPT" <<'REMOTE_SNORT_AGENT'
#!/usr/bin/env bash
set -euo pipefail
MANAGER_IP="$1"
KEY_B64="$2"
SNORT_LOG_FILE="$3"
WAZUH_LOG_FORMAT="$4"
TARGET_VER="$5"
MAKE_BACKUPS="$6"
log(){ echo "$*"; }
SUDO=""; SUDO_KEEPALIVE_PID=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
  if sudo -n true >/dev/null 2>&1; then
    log "[remote-snort] sudo sin contraseña disponible"
  else
    log "[remote-snort] sudo requiere contraseña. Se pedirá ahora..."
    sudo -v || { log "[remote-snort][ERROR] sudo -v falló"; exit 1; }
    (
      while true; do sudo -n true >/dev/null 2>&1 || exit; sleep 60; kill -0 "$$" >/dev/null 2>&1 || exit; done
    ) &
    SUDO_KEEPALIVE_PID="$!"
    trap '[[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "${SUDO_KEEPALIVE_PID}" >/dev/null 2>&1 || true' EXIT
  fi
fi

$SUDO mkdir -p "$(dirname "$SNORT_LOG_FILE")"
$SUDO touch "$SNORT_LOG_FILE"
$SUDO chmod 644 "$SNORT_LOG_FILE" || true

log "[remote-snort] Configurando repo Wazuh..."
$SUDO apt-get update -o Acquire::Retries=3
$SUDO apt-get install -y curl gnupg ca-certificates apt-transport-https
if [[ ! -f /usr/share/keyrings/wazuh.gpg ]]; then
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | $SUDO gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  $SUDO chmod 644 /usr/share/keyrings/wazuh.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  $SUDO tee /etc/apt/sources.list.d/wazuh.list >/dev/null
$SUDO apt-get update -o Acquire::Retries=3

log "[remote-snort] Instalando wazuh-agent=$TARGET_VER ..."
$SUDO apt-mark unhold wazuh-agent 2>/dev/null || true
$SUDO apt-get install -y --allow-downgrades -o Dpkg::Options::="--force-confnew" -o Dpkg::Options::="--force-confdef" "wazuh-agent=$TARGET_VER"
$SUDO apt-mark hold wazuh-agent >/dev/null || true
$SUDO systemctl stop wazuh-agent >/dev/null 2>&1 || true

KEY_LINE="$(echo "$KEY_B64" | base64 -d)"
printf '%s\n' "$KEY_LINE" | $SUDO tee /var/ossec/etc/client.keys >/dev/null
if getent group wazuh >/dev/null; then $SUDO chown root:wazuh /var/ossec/etc/client.keys; else $SUDO chown root:root /var/ossec/etc/client.keys; fi
$SUDO chmod 640 /var/ossec/etc/client.keys

OSSEC_CONF="/var/ossec/etc/ossec.conf"
TMP_OSSEC="/tmp/ossec_conf_new_$$.xml"
$SUDO cat "$OSSEC_CONF" > "$TMP_OSSEC"

# Limpia enrollment existentes y localfiles previos del mismo log
$SUDO perl -0777 -i -pe 's/<enrollment>.*?<\/enrollment>\s*//sg' "$TMP_OSSEC"
$SUDO perl -0777 -i -pe "s#\\s*<localfile>\\s*.*?<location>\\Q${SNORT_LOG_FILE}\\E</location>\\s*</localfile>\\s*##sg" "$TMP_OSSEC"

# Reemplaza primer bloque client (si no existe, inserta antes de cierre)
if $SUDO grep -q '<client>' "$TMP_OSSEC"; then
  $SUDO perl -0777 -i -pe "s#<client>.*?</client>#<client>\n  <server>\n    <address>${MANAGER_IP}</address>\n    <port>1514</port>\n    <protocol>tcp</protocol>\n  </server>\n  <enrollment>\n    <enabled>no</enabled>\n  </enrollment>\n</client>#s" "$TMP_OSSEC"
else
  $SUDO perl -0777 -i -pe "s#</ossec_config>#<client>\n  <server>\n    <address>${MANAGER_IP}</address>\n    <port>1514</port>\n    <protocol>tcp</protocol>\n  </server>\n  <enrollment>\n    <enabled>no</enabled>\n  </enrollment>\n</client>\n</ossec_config>#s" "$TMP_OSSEC"
fi

LOCALFILE_BLOCK="  <localfile>\n    <log_format>${WAZUH_LOG_FORMAT}</log_format>\n    <location>${SNORT_LOG_FILE}</location>\n  </localfile>\n"
if $SUDO grep -q "<!--[[:space:]]*Log analysis[[:space:]]*-->" "$TMP_OSSEC"; then
  $SUDO perl -0777 -i -pe "s#(<!--[[:space:]]*Log analysis[[:space:]]*-->\s*)#\$1${LOCALFILE_BLOCK}#s" "$TMP_OSSEC"
else
  $SUDO perl -0777 -i -pe "s#</ossec_config>#${LOCALFILE_BLOCK}</ossec_config>#s" "$TMP_OSSEC"
fi

if ! $SUDO cmp -s "$TMP_OSSEC" "$OSSEC_CONF"; then
  [[ "$MAKE_BACKUPS" == "yes" ]] && $SUDO cp -p "$OSSEC_CONF" "${OSSEC_CONF}.bak" || true
  $SUDO install -m 640 "$TMP_OSSEC" "$OSSEC_CONF"
  if getent group wazuh >/dev/null; then $SUDO chown root:wazuh "$OSSEC_CONF"; else $SUDO chown root:root "$OSSEC_CONF"; fi
  log "[remote-snort] ossec.conf actualizado."
else
  log "[remote-snort] ossec.conf ya estaba en el estado deseado."
fi
$SUDO rm -f "$TMP_OSSEC" >/dev/null 2>&1 || true

log "[remote-snort] Reiniciando wazuh-agent..."
$SUDO systemctl daemon-reload
$SUDO systemctl enable wazuh-agent >/dev/null 2>&1 || true
$SUDO systemctl restart wazuh-agent
$SUDO tail -n 40 /var/ossec/logs/ossec.log || true
if $SUDO tail -n 200 /var/ossec/logs/ossec.log | grep -q "Requesting a key from server"; then
  log "[remote-snort][ERROR] Sigue intentando enrollment (1515)."
  exit 31
fi
log "[remote-snort] wazuh-agent configurado correctamente."
REMOTE_SNORT_AGENT
  chmod 700 "$SNORT_AGENT_SCRIPT"

  if ! run_remote_script_tty "$SNORT_HOST" "$SNORT_AGENT_SCRIPT" \
      "$WAZUH_MANAGER_AGENT_ADDR" "$AGENT_KEY_B64" "$SNORT_LOG_FILE" "$WAZUH_LOG_FORMAT" "$TARGET_AGENT_VERSION" "$MAKE_BACKUPS"; then
    die "Falló la instalación/configuración de wazuh-agent en Snort."
  fi

  ok "wazuh-agent configurado en Snort."
fi

# =========================
# Paso 4: Esperar agente (si aplica)
# =========================
if (( DO_WAIT_AGENT )); then
  echo
  inf "Paso 4/5: Esperando conexión del agente en Wazuh Manager..."

  MANAGER_WAIT_SCRIPT="$(mktemp)"; register_tmp "$MANAGER_WAIT_SCRIPT"
  cat > "$MANAGER_WAIT_SCRIPT" <<'REMOTE_MANAGER_WAIT'
#!/usr/bin/env bash
set -euo pipefail
AGENT_NAME="$1"
log(){ echo "$*"; }
SUDO=""; SUDO_KEEPALIVE_PID=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
  if sudo -n true >/dev/null 2>&1; then
    :
  else
    log "[remote-manager] sudo requiere contraseña. Se pedirá ahora..."
    sudo -v || { log "[remote-manager][ERROR] sudo -v falló"; exit 1; }
    (
      while true; do sudo -n true >/dev/null 2>&1 || exit; sleep 60; kill -0 "$$" >/dev/null 2>&1 || exit; done
    ) &
    SUDO_KEEPALIVE_PID="$!"
    trap '[[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "${SUDO_KEEPALIVE_PID}" >/dev/null 2>&1 || true' EXIT
  fi
fi
CONNECTED=0
for _ in $(seq 1 40); do
  if $SUDO /var/ossec/bin/agent_control -lc 2>/dev/null | grep -q "Name: ${AGENT_NAME}"; then
    CONNECTED=1; break
  fi
  sleep 3
done
if [[ "$CONNECTED" -ne 1 ]]; then
  log "[remote-manager][WARN] El agente aún no aparece."
  $SUDO /var/ossec/bin/agent_control -l || true
  $SUDO tail -n 120 /var/ossec/logs/ossec.log | egrep -i "authd|remoted|error|reject|${AGENT_NAME}" || true
  exit 1
fi
log "[remote-manager] Agente conectado detectado."
REMOTE_MANAGER_WAIT
  chmod 700 "$MANAGER_WAIT_SCRIPT"

  if ! run_remote_script_tty "$WAZUH_MANAGER_HOST" "$MANAGER_WAIT_SCRIPT" "$AGENT_NAME"; then
    die "El agente no llegó a conectar al Wazuh Manager."
  fi

  ok "Agente conectado en manager."
fi

# =========================
# Paso 5: Reglas Wazuh Manager (si aplica)
# =========================
if (( DO_MANAGER_RULES )); then
  echo
  inf "Paso 5/5: Instalando reglas locales de Wazuh para eventos Snort..."

  MANAGER_RULES_SCRIPT="$(mktemp)"; register_tmp "$MANAGER_RULES_SCRIPT"
  cat > "$MANAGER_RULES_SCRIPT" <<'REMOTE_MANAGER_RULES'
#!/usr/bin/env bash
set -euo pipefail
MAKE_BACKUPS="$1"
log(){ echo "$*"; }
SUDO=""; SUDO_KEEPALIVE_PID=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
  if sudo -n true >/dev/null 2>&1; then
    :
  else
    log "[remote-manager] sudo requiere contraseña. Se pedirá ahora..."
    sudo -v || { log "[remote-manager][ERROR] sudo -v falló"; exit 1; }
    (
      while true; do sudo -n true >/dev/null 2>&1 || exit; sleep 60; kill -0 "$$" >/dev/null 2>&1 || exit; done
    ) &
    SUDO_KEEPALIVE_PID="$!"
    trap '[[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "${SUDO_KEEPALIVE_PID}" >/dev/null 2>&1 || true' EXIT
  fi
fi

RULE_FILE="/var/ossec/etc/rules/snort_local_rules.xml"
TMP_RULES="/tmp/snort_local_rules_wazuh_$$.xml"
cat > "$TMP_RULES" <<'EOF'
<group name="local,snort,network,scan,">
  <rule id="600001" level="7">
    <match>Intento ICMPv4 detectado</match>
    <description>Snort ICMP detection</description>
  </rule>

  <rule id="600010" level="8">
    <match>Nmap TCP SYN scan</match>
    <description>Snort scan activity detected</description>
  </rule>
</group>
EOF

if ! $SUDO cmp -s "$TMP_RULES" "$RULE_FILE" 2>/dev/null; then
  [[ "$MAKE_BACKUPS" == "yes" && -f "$RULE_FILE" ]] && $SUDO cp -p "$RULE_FILE" "${RULE_FILE}.bak" || true
  $SUDO install -m 640 "$TMP_RULES" "$RULE_FILE"
  $SUDO chown root:wazuh "$RULE_FILE" 2>/dev/null || $SUDO chown root:root "$RULE_FILE"
  log "[remote-manager] Reglas Wazuh actualizadas."
  log "[remote-manager] Reiniciando wazuh-manager..."
  $SUDO systemctl restart wazuh-manager
else
  log "[remote-manager] Reglas Wazuh ya estaban en el estado deseado."
fi

$SUDO rm -f "$TMP_RULES" >/dev/null 2>&1 || true
$SUDO tail -n 80 /var/ossec/logs/ossec.log | egrep -i 'rule|decoder|error|failed|xml|syntax' || true
log "[remote-manager] Reglas locales Wazuh listas."
REMOTE_MANAGER_RULES
  chmod 700 "$MANAGER_RULES_SCRIPT"

  if ! run_remote_script_tty "$WAZUH_MANAGER_HOST" "$MANAGER_RULES_SCRIPT" "$MAKE_BACKUPS"; then
    die "Falló la instalación de reglas Wazuh en el manager."
  fi

  ok "Reglas Wazuh instaladas en manager."
fi

# -------------------------
# Resumen final
# -------------------------
SCRIPT_END=$(date +%s)

echo
echo "===================================================="
echo " Integración Snort -> Wazuh (resultado)"
echo "===================================================="
echo "Modo ejecutado:              ${MODE}"
echo "Wazuh Manager (SSH):         ${WAZUH_MANAGER_HOST}"
echo "Manager para agente:         ${WAZUH_MANAGER_AGENT_ADDR}"
echo "VM Snort (SSH):              ${SNORT_HOST}"
echo "Agente Wazuh:                ${AGENT_NAME}"
[[ -n "$AGENT_ID" ]] && echo "ID agente Wazuh:             ${AGENT_ID}"
[[ -n "$TARGET_AGENT_VERSION" ]] && echo "Versión Wazuh (manager):     ${TARGET_AGENT_VERSION}"
echo "Log Snort integrado:         ${SNORT_LOG_FILE}"
echo "Formato Wazuh:               ${WAZUH_LOG_FORMAT}"
echo "Reglas Snort:                ${SNORT_RULES_FILE}"
echo "snort.lua:                   ${SNORT_LUA_PATH}"
echo "Interfaz Snort (detectada):  ${DETECTED_SNORT_IFACE:-no detectada}"
echo "SIDs Snort ICMP / SYN:       ${SNORT_RULE_ICMP_SID} / ${SNORT_RULE_SYN_SID}"
echo "Backups remotos:             ${MAKE_BACKUPS}"
echo "[⏱] Tiempo TOTAL: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo

echo "Comprobaciones útiles:"
echo "  [Snort] Interfaz por defecto:"
echo "    ip route | awk '/default/ {print \$5; exit}'"
echo
if [[ -n "${DETECTED_SNORT_IFACE:-}" ]]; then
  echo "  [Snort] Arrancar captura (interfaz detectada):"
  echo "    sudo snort -i ${DETECTED_SNORT_IFACE} -c ${SNORT_LUA_PATH} -A alert_fast -k none -l /var/log/snort"
else
  echo "  [Snort] Arrancar captura (ajusta interfaz real):"
  echo "    sudo snort -i <iface> -c ${SNORT_LUA_PATH} -A alert_fast -k none -l /var/log/snort"
fi

echo
echo "  [Snort] Ver log de alertas:"
echo "    sudo tail -f ${SNORT_LOG_FILE}"
echo
echo "  [Snort] Ver reglas locales:"
echo "    sudo grep -nE 'Intento ICMPv4 detectado|Nmap TCP SYN scan' ${SNORT_RULES_FILE}"
echo
echo "  [Snort] Estado wazuh-agent:"
echo "    sudo systemctl status wazuh-agent"
echo "    sudo tail -f /var/ossec/logs/ossec.log"
echo
echo "  [Manager] Ver agentes:"
echo "    sudo /var/ossec/bin/agent_control -l"
echo
echo "  [Manager] Ver reglas Wazuh:"
echo "    sudo cat /var/ossec/etc/rules/snort_local_rules.xml"
echo