#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Despliegue idempotente del agente Caldera (Sandcat)
# en una o varias VMs Linux vía SSH.
#
# Mejoras:
# - Idempotencia (no reinicia ni reescribe si no hay cambios)
# - Compatible con varias distros Linux (apt/dnf/yum/zypper/apk)
# - systemd o fallback nohup
# - Modo interactivo y no interactivo
# =========================================================

# =========================
# Timer global
# =========================
SCRIPT_START=$(date +%s)
format_time() {
  local total="${1:-0}"
  echo "$((total/60)) min $((total%60)) s"
}

# =========================
# Config por defecto
# =========================
DEFAULT_KEY_BASENAME="mykey"
DEFAULT_KEY_PATH="$(pwd)/${DEFAULT_KEY_BASENAME}"
DEFAULT_KNOWN_HOSTS_PATH="$(pwd)/known_hosts_${DEFAULT_KEY_BASENAME}"

DEFAULT_SSH_USER="debian"
DEFAULT_SSH_PORT="22"

DEFAULT_CALDERA_PROTO="http"
DEFAULT_CALDERA_PORT="8888"
DEFAULT_CALDERA_GROUP="red"

DEFAULT_SERVICE_NAME="caldera-agent"
DEFAULT_SERVICE_MODE="auto"      # auto | systemd | nohup

AGENT_DIR_DEFAULT="/opt/caldera"
AGENT_NAME_DEFAULT="caldera-agent"

SSH_CONNECT_TIMEOUT=5
SSH_WAIT_TIMEOUT=300

AUTO_CONFIRM=0
PICK_MODE=""
HOSTS_INLINE=""
HOSTS_FILE=""
REFRESH_HOSTKEYS=0
CALDERA_INSECURE=0

SSH_USER=""
SSH_PORT=""
SSH_KEY_PATH=""
KNOWN_HOSTS_PATH=""

CALDERA_HOST=""
CALDERA_PROTO="$DEFAULT_CALDERA_PROTO"
CALDERA_PORT="$DEFAULT_CALDERA_PORT"
CALDERA_GROUP="$DEFAULT_CALDERA_GROUP"
CALDERA_URL=""

AGENT_DIR="$AGENT_DIR_DEFAULT"
AGENT_NAME="$AGENT_NAME_DEFAULT"
SERVICE_NAME="$DEFAULT_SERVICE_NAME"
SERVICE_MODE="$DEFAULT_SERVICE_MODE"

# =========================
# Helpers
# =========================
die()  { echo "[-] $*" >&2; exit 1; }
ok()   { echo "[+] $*"; }
inf()  { echo "[*] $*"; }
warn() { echo "[!] $*"; }

usage() {
  cat <<'EOF'
Uso:
  ./caldera-agent-deploy-idempotente.sh [opciones]

SSH / acceso:
  -u, --ssh-user USER           Usuario SSH remoto (default: debian)
  -p, --ssh-port PORT           Puerto SSH (default: 22)
  -k, --ssh-key PATH            Ruta clave privada SSH (default: ./mykey)
      --known-hosts PATH        Ruta known_hosts dedicado (default: ./known_hosts_<basename_clave>)
      --ssh-timeout SEC         ConnectTimeout SSH (default: 5)
      --wait-timeout SEC        Timeout espera SSH antes de desplegar (default: 300)
      --refresh-hostkeys        Limpia huellas previas del host en known_hosts (opcional)

Caldera:
      --caldera-url URL         URL completa de Caldera (ej: http://192.168.56.10:8888)
      --caldera-host HOST       Host/IP de Caldera (si no se usa --caldera-url)
      --caldera-proto P         http|https (default: http)
      --caldera-port PORT       Puerto Caldera (default: 8888)
      --caldera-group GROUP     Grupo del agente (default: red)
      --caldera-insecure        Permite TLS autofirmado (curl -k / wget --no-check-certificate)

Agente / servicio:
      --agent-dir DIR           Directorio remoto del agente (default: /opt/caldera)
      --agent-name NAME         Nombre binario remoto (default: caldera-agent)
      --service-name NAME       Nombre del servicio (default: caldera-agent)
      --service-mode MODE       auto|systemd|nohup (default: auto)

Hosts destino:
  -H, --hosts "h1,h2 h3"        Hosts inline (espacios/comas)
  -f, --hosts-file FILE         Fichero de hosts (uno por línea, soporta comas)
      --all                     Seleccionar todos sin preguntar
      --pick "1 3 5"            Seleccionar índices concretos
  -y, --yes                     Confirmar sin preguntar

Otros:
  -h, --help                    Mostrar ayuda

Ejemplos:
  ./caldera-agent-deploy-idempotente.sh -u ubuntu -k ./mykey \
    --caldera-host 192.168.56.10 --hosts "192.168.56.20,192.168.56.30" --all -y

  ./caldera-agent-deploy-idempotente.sh -u root -k ./mykey \
    --caldera-url https://caldera.lab.local:8443 --caldera-insecure \
    -f hosts.txt --all -y --service-mode systemd
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Falta el comando '$1'."
}
has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

trim_cr() { printf '%s' "$1" | tr -d '\r'; }

ssh_supports_accept_new() {
  local ver
  ver="$(ssh -V 2>&1 || true)"
  [[ "$ver" =~ OpenSSH_([0-9]+)\.([0-9]+) ]] || return 1
  local maj="${BASH_REMATCH[1]}"
  local min="${BASH_REMATCH[2]}"
  if (( maj > 7 )); then return 0; fi
  if (( maj == 7 && min >= 6 )); then return 0; fi
  return 1
}

add_target() {
  local h
  h="$(trim_cr "$1")"
  [[ -n "$h" ]] || return 0
  TARGETS_RAW+=("$h")
}

parse_hosts_line() {
  local line="$1"
  line="$(trim_cr "$line")"
  line="${line//,/ }"
  # shellcheck disable=SC2086
  for h in $line; do
    [[ -n "$h" ]] && add_target "$h"
  done
}

wait_for_ssh() {
  local host="$1"
  local start now

  inf "Comprobando SSH en ${SSH_USER}@${host}:${SSH_PORT} (timeout ${SSH_WAIT_TIMEOUT}s)..."

  if [[ "$REFRESH_HOSTKEYS" == "1" ]]; then
    inf "Limpieza de huellas previas en known_hosts dedicado para ${host}"
    ssh-keygen -f "$KNOWN_HOSTS_PATH" -R "$host" >/dev/null 2>&1 || true
    ssh-keygen -f "$KNOWN_HOSTS_PATH" -R "[$host]:$SSH_PORT" >/dev/null 2>&1 || true
  fi

  start=$(date +%s)
  until ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" -o "BatchMode=yes" \
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

# =========================
# Parseo de argumentos
# =========================
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--ssh-user)       [[ $# -ge 2 ]] || die "Falta valor para $1"; SSH_USER="$2"; shift 2 ;;
    -p|--ssh-port)       [[ $# -ge 2 ]] || die "Falta valor para $1"; SSH_PORT="$2"; shift 2 ;;
    -k|--ssh-key)        [[ $# -ge 2 ]] || die "Falta valor para $1"; SSH_KEY_PATH="$2"; shift 2 ;;
    --known-hosts)       [[ $# -ge 2 ]] || die "Falta valor para $1"; KNOWN_HOSTS_PATH="$2"; shift 2 ;;
    --ssh-timeout)       [[ $# -ge 2 ]] || die "Falta valor para $1"; SSH_CONNECT_TIMEOUT="$2"; shift 2 ;;
    --wait-timeout)      [[ $# -ge 2 ]] || die "Falta valor para $1"; SSH_WAIT_TIMEOUT="$2"; shift 2 ;;
    --refresh-hostkeys)  REFRESH_HOSTKEYS=1; shift ;;

    --caldera-url)       [[ $# -ge 2 ]] || die "Falta valor para $1"; CALDERA_URL="$2"; shift 2 ;;
    --caldera-host)      [[ $# -ge 2 ]] || die "Falta valor para $1"; CALDERA_HOST="$2"; shift 2 ;;
    --caldera-proto)     [[ $# -ge 2 ]] || die "Falta valor para $1"; CALDERA_PROTO="$2"; shift 2 ;;
    --caldera-port)      [[ $# -ge 2 ]] || die "Falta valor para $1"; CALDERA_PORT="$2"; shift 2 ;;
    --caldera-group)     [[ $# -ge 2 ]] || die "Falta valor para $1"; CALDERA_GROUP="$2"; shift 2 ;;
    --caldera-insecure)  CALDERA_INSECURE=1; shift ;;

    --agent-dir)         [[ $# -ge 2 ]] || die "Falta valor para $1"; AGENT_DIR="$2"; shift 2 ;;
    --agent-name)        [[ $# -ge 2 ]] || die "Falta valor para $1"; AGENT_NAME="$2"; shift 2 ;;
    --service-name)      [[ $# -ge 2 ]] || die "Falta valor para $1"; SERVICE_NAME="$2"; shift 2 ;;
    --service-mode)      [[ $# -ge 2 ]] || die "Falta valor para $1"; SERVICE_MODE="$2"; shift 2 ;;

    -H|--hosts)          [[ $# -ge 2 ]] || die "Falta valor para $1"; HOSTS_INLINE="$2"; shift 2 ;;
    -f|--hosts-file)     [[ $# -ge 2 ]] || die "Falta valor para $1"; HOSTS_FILE="$2"; shift 2 ;;
    --all)               PICK_MODE="all"; shift ;;
    --pick)              [[ $# -ge 2 ]] || die "Falta valor para $1"; PICK_MODE="$2"; shift 2 ;;
    -y|--yes)            AUTO_CONFIRM=1; shift ;;

    -h|--help)           usage; exit 0 ;;
    *)                   die "Opción no reconocida: $1 (usa --help)" ;;
  esac
done

# =========================
# Dependencias locales
# =========================
require_cmd bash
require_cmd ssh
require_cmd ssh-keygen
require_cmd chmod
require_cmd mkdir
require_cmd tr

# =========================
# Banner
# =========================
echo "===================================================="
echo " Integración Caldera -> VMs (agente Sandcat)"
echo "  (idempotente + portable)"
echo "===================================================="

# =========================
# Inputs SSH / clave (CORREGIDO: vuelve el modo interactivo)
# =========================
echo
echo "=== Configuración SSH ==="

# Usuario SSH: si no se pasó por CLI, preguntar (manteniendo default)
if [[ -z "${SSH_USER:-}" ]]; then
  read -r -p "Usuario SSH remoto [${DEFAULT_SSH_USER}]: " SSH_USER
  SSH_USER="${SSH_USER:-$DEFAULT_SSH_USER}"
fi

# Puerto SSH: si no se pasó por CLI, preguntar (manteniendo default)
if [[ -z "${SSH_PORT:-}" ]]; then
  read -r -p "Puerto SSH [${DEFAULT_SSH_PORT}]: " SSH_PORT
  SSH_PORT="${SSH_PORT:-$DEFAULT_SSH_PORT}"
fi

# Clave SSH: si no se pasó por CLI, preguntar (manteniendo default)
if [[ -z "${SSH_KEY_PATH:-}" ]]; then
  read -r -p "Ruta a la clave privada SSH [${DEFAULT_KEY_PATH}]: " SSH_KEY_PATH
  SSH_KEY_PATH="${SSH_KEY_PATH:-$DEFAULT_KEY_PATH}"
fi

# known_hosts dedicado: si no se pasó por CLI, preguntar con default derivado de la clave
if [[ -z "${KNOWN_HOSTS_PATH:-}" ]]; then
  DEFAULT_KH_FROM_KEY="$(pwd)/known_hosts_$(basename "$SSH_KEY_PATH")"
  read -r -p "Ruta de known_hosts dedicado [${DEFAULT_KH_FROM_KEY}]: " KNOWN_HOSTS_PATH
  KNOWN_HOSTS_PATH="${KNOWN_HOSTS_PATH:-$DEFAULT_KH_FROM_KEY}"
fi

[[ -n "$SSH_USER" ]] || die "Usuario SSH remoto vacío."
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "Puerto SSH inválido: '$SSH_PORT'"
[[ "$SSH_CONNECT_TIMEOUT" =~ ^[0-9]+$ ]] || die "SSH timeout inválido: '$SSH_CONNECT_TIMEOUT'"
[[ "$SSH_WAIT_TIMEOUT" =~ ^[0-9]+$ ]] || die "Wait timeout inválido: '$SSH_WAIT_TIMEOUT'"

[[ -f "$SSH_KEY_PATH" ]] || die "No se encuentra la clave privada: $SSH_KEY_PATH"

mkdir -p "$(dirname "$KNOWN_HOSTS_PATH")"
touch "$KNOWN_HOSTS_PATH"
chmod 600 "$KNOWN_HOSTS_PATH" || true
chmod 600 "$SSH_KEY_PATH" || true

ok "Usuario SSH:    $SSH_USER"
ok "Puerto SSH:     $SSH_PORT"
ok "Clave privada:  $SSH_KEY_PATH"
ok "Known hosts:    $KNOWN_HOSTS_PATH"

# =========================
# Inputs Caldera
# =========================
echo
echo "=== Configuración Caldera ==="

if [[ -z "$CALDERA_URL" ]]; then
  if [[ -z "$CALDERA_HOST" ]]; then
    read -r -p "IP/hostname de la VM Caldera (manual): " CALDERA_HOST
  fi
  [[ -n "$CALDERA_HOST" ]] || die "La IP/hostname de Caldera no puede estar vacía."

  [[ "$CALDERA_PROTO" == "http" || "$CALDERA_PROTO" == "https" ]] || die "Protocolo inválido: '$CALDERA_PROTO'"
  [[ "$CALDERA_PORT" =~ ^[0-9]+$ ]] || die "Puerto Caldera inválido: '$CALDERA_PORT'"

  CALDERA_URL="${CALDERA_PROTO}://${CALDERA_HOST}:${CALDERA_PORT}"
else
  [[ "$CALDERA_URL" =~ ^https?:// ]] || die "--caldera-url debe empezar por http:// o https://"
fi

if [[ -z "${CALDERA_GROUP:-}" ]]; then
  read -r -p "Grupo del agente en Caldera [${DEFAULT_CALDERA_GROUP}]: " CALDERA_GROUP
  CALDERA_GROUP="${CALDERA_GROUP:-$DEFAULT_CALDERA_GROUP}"
fi

[[ "$SERVICE_MODE" == "auto" || "$SERVICE_MODE" == "systemd" || "$SERVICE_MODE" == "nohup" ]] || die "service-mode inválido: $SERVICE_MODE"
[[ -n "$CALDERA_GROUP" ]] || die "Grupo Caldera vacío"
[[ -n "$AGENT_DIR" ]] || die "Agent dir vacío"
[[ -n "$AGENT_NAME" ]] || die "Agent name vacío"
[[ -n "$SERVICE_NAME" ]] || die "Service name vacío"

AGENT_PATH="${AGENT_DIR%/}/${AGENT_NAME}"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

ok "URL Caldera:       $CALDERA_URL"
ok "Grupo agente:      $CALDERA_GROUP"
ok "Service mode:      $SERVICE_MODE"
ok "Agent path remoto: $AGENT_PATH"

# =========================
# Hosts destino (inline/file/interactivo)
# =========================
TARGETS_RAW=()

if [[ -n "$HOSTS_INLINE" ]]; then
  parse_hosts_line "$HOSTS_INLINE"
fi

if [[ -n "$HOSTS_FILE" ]]; then
  [[ -f "$HOSTS_FILE" ]] || die "No existe el fichero de hosts: $HOSTS_FILE"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim_cr "$line")"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    parse_hosts_line "$line"
  done < "$HOSTS_FILE"
fi

if ((${#TARGETS_RAW[@]} == 0)); then
  echo
  echo "=== Hosts destino (VMs cliente) ==="
  echo "Introduce IPs/hostnames (manual). ENTER vacío para terminar."
  echo "Ejemplo: 192.168.56.20, 192.168.56.30"
  echo
  while true; do
    read -r -p "Host(s): " line
    [[ -z "$line" ]] && break
    parse_hosts_line "$line"
  done
fi

((${#TARGETS_RAW[@]} > 0)) || die "No se introdujo ningún host destino."

# Deduplicar preservando orden
declare -A seen=()
TARGETS=()
for h in "${TARGETS_RAW[@]}"; do
  if [[ -z "${seen[$h]+x}" ]]; then
    TARGETS+=("$h")
    seen["$h"]=1
  fi
done

# =========================
# Informe + selección
# =========================
echo
echo "=== Hosts detectados ==="
i=1
for h in "${TARGETS[@]}"; do
  printf "  %2d) %s\n" "$i" "$h"
  ((i++))
done
echo "Total: ${#TARGETS[@]} host(s)"
echo

if [[ -z "$PICK_MODE" ]]; then
  read -r -p "¿Actuar sobre todos (all) o elegir índices (ej: 1 3)? [all]: " PICK_MODE
  PICK_MODE="${PICK_MODE:-all}"
fi

SELECTED=()
if [[ "$PICK_MODE" == "all" || "$PICK_MODE" == "ALL" ]]; then
  SELECTED=("${TARGETS[@]}")
else
  for idx in $PICK_MODE; do
    [[ "$idx" =~ ^[0-9]+$ ]] || die "Índice inválido: '$idx'"
    (( idx >= 1 && idx <= ${#TARGETS[@]} )) || die "Índice fuera de rango: '$idx'"
    SELECTED+=("${TARGETS[$((idx-1))]}")
  done
  declare -A sseen=()
  tmp=()
  for h in "${SELECTED[@]}"; do
    if [[ -z "${sseen[$h]+x}" ]]; then
      tmp+=("$h")
      sseen["$h"]=1
    fi
  done
  SELECTED=("${tmp[@]}")
fi

echo
echo "=== Selección final ==="
echo "Caldera:  $CALDERA_URL"
echo "Clientes:"
for h in "${SELECTED[@]}"; do echo "  - $h"; done
echo "Total: ${#SELECTED[@]} host(s)"
echo

if [[ "$AUTO_CONFIRM" != "1" ]]; then
  read -r -p "¿Continuar e instalar/actualizar el agente en estos hosts? (y/N): " CONFIRM
  CONFIRM="${CONFIRM:-N}"
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || die "Cancelado por el usuario."
fi

# =========================
# Opciones SSH
# =========================
STRICT_OPT="accept-new"
if ! ssh_supports_accept_new; then
  inf "Tu OpenSSH no soporta 'accept-new'. Usaré 'StrictHostKeyChecking=no'."
  STRICT_OPT="no"
fi

SSH_OPTS=(
  -o "ConnectTimeout=${SSH_CONNECT_TIMEOUT}"
  -o "StrictHostKeyChecking=${STRICT_OPT}"
  -o "UserKnownHostsFile=${KNOWN_HOSTS_PATH}"
)

# =========================
# Despliegue remoto (idempotente)
# =========================
SUCCESS=()
FAILED=()

echo
inf "Desplegando agente Sandcat en hosts seleccionados..."

for h in "${SELECTED[@]}"; do
  echo
  inf "=========================================="
  inf "Host destino: ${SSH_USER}@${h}:${SSH_PORT}"
  inf "=========================================="

  if ! wait_for_ssh "$h"; then
    echo "[-] Timeout al conectar por SSH con ${h}"
    echo "    Prueba manualmente:"
    echo "    ssh -i \"$SSH_KEY_PATH\" -p \"$SSH_PORT\" ${SSH_USER}@${h}"
    FAILED+=("$h")
    continue
  fi

  ok "SSH disponible en ${h}"

  REMOTE_TMP_SCRIPT="/tmp/caldera_deploy_agent_${RANDOM}_$$.sh"
  printf -v REMOTE_TMP_SCRIPT_Q '%q' "$REMOTE_TMP_SCRIPT"

  if ! ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
      "${SSH_USER}@${h}" \
      "umask 077; cat > ${REMOTE_TMP_SCRIPT_Q} && chmod 700 ${REMOTE_TMP_SCRIPT_Q}"; then
    echo "[-] No se pudo crear el script temporal remoto en ${h}"
    FAILED+=("$h")
    continue
  fi <<'REMOTE_EOF'
#!/usr/bin/env bash
set -euo pipefail

CALDERA_URL="$1"
AGENT_DIR="$2"
AGENT_PATH="$3"
SERVICE_PATH="$4"
CALDERA_GROUP="$5"
HOST_LABEL="$6"
SERVICE_MODE="$7"
SERVICE_NAME="$8"
CALDERA_INSECURE="$9"

PIDFILE="${AGENT_DIR}/caldera-agent.pid"
LOGFILE="${AGENT_DIR}/caldera-agent.log"

echo "[+] Host remoto: $(hostname) (${HOST_LABEL})"

have_cmd() { command -v "$1" >/dev/null 2>&1; }
msg() { echo "[*] $*"; }
okm() { echo "[+] $*"; }
wrn() { echo "[!] $*"; }
err() { echo "[-] $*" >&2; }

# --------------------------------------------
# Privilegios (sudo/doas) + keepalive
# --------------------------------------------
SUDO=""
SUDO_KEEPALIVE_PID=""

if [[ "$(id -u)" -ne 0 ]]; then
  if have_cmd sudo; then
    SUDO="sudo"
  elif have_cmd doas; then
    SUDO="doas"
  else
    err "No eres root y no existe sudo/doas en este host."
    exit 1
  fi

  if [[ "$SUDO" == "sudo" ]]; then
    if sudo -n true >/dev/null 2>&1; then
      okm "sudo sin contraseña disponible"
    else
      wrn "sudo requiere contraseña. Se pedirá ahora..."
      sudo -v || { err "No se pudo validar sudo"; exit 1; }
      (
        while true; do
          sudo -n true >/dev/null 2>&1 || exit
          sleep 60
          kill -0 "$$" >/dev/null 2>&1 || exit
        done
      ) &
      SUDO_KEEPALIVE_PID="$!"
      trap '[[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill "${SUDO_KEEPALIVE_PID}" >/dev/null 2>&1 || true' EXIT
    fi
  else
    okm "Usando doas"
  fi
fi

# --------------------------------------------
# Detección de gestor de paquetes e instalación deps
# --------------------------------------------
install_deps_if_needed() {
  local need_curl=0 need_ca=1
  have_cmd curl || have_cmd wget || need_curl=1

  if [[ "$CALDERA_URL" =~ ^http:// ]]; then
    need_ca=0
  fi

  if (( need_curl == 0 && need_ca == 0 )); then
    okm "Dependencias suficientes (curl/wget ya disponible y HTTP sin CA)"
    return 0
  fi

  if have_cmd apt-get; then
    msg "Instalando dependencias con apt-get..."
    $SUDO apt-get update -y
    $SUDO apt-get install -y curl ca-certificates || $SUDO apt-get install -y wget ca-certificates
  elif have_cmd dnf; then
    msg "Instalando dependencias con dnf..."
    $SUDO dnf install -y curl ca-certificates || $SUDO dnf install -y wget ca-certificates
  elif have_cmd yum; then
    msg "Instalando dependencias con yum..."
    $SUDO yum install -y curl ca-certificates || $SUDO yum install -y wget ca-certificates
  elif have_cmd zypper; then
    msg "Instalando dependencias con zypper..."
    $SUDO zypper --non-interactive install curl ca-certificates || \
      $SUDO zypper --non-interactive install wget ca-certificates
  elif have_cmd apk; then
    msg "Instalando dependencias con apk..."
    $SUDO apk add --no-cache curl ca-certificates || $SUDO apk add --no-cache wget ca-certificates
    $SUDO update-ca-certificates >/dev/null 2>&1 || true
  else
    if have_cmd curl || have_cmd wget; then
      wrn "No se detectó gestor de paquetes soportado, pero hay curl/wget. Continuando..."
    else
      err "No se detectó gestor de paquetes soportado ni curl/wget."
      exit 1
    fi
  fi
}

# --------------------------------------------
# Descarga Sandcat (curl o wget)
# --------------------------------------------
download_sandcat() {
  local out_file="$1"
  local url="${CALDERA_URL}/file/download"

  if have_cmd curl; then
    local curl_opts=(-fsS -X POST -H "file:sandcat.go" -H "platform:linux" -o "$out_file")
    [[ "$CALDERA_INSECURE" == "1" ]] && curl_opts=(-k "${curl_opts[@]}")
    curl "${curl_opts[@]}" "$url"
    return 0
  elif have_cmd wget; then
    local wget_opts=(--method=POST --header="file:sandcat.go" --header="platform:linux" -O "$out_file")
    [[ "$CALDERA_INSECURE" == "1" ]] && wget_opts=(--no-check-certificate "${wget_opts[@]}")
    wget "${wget_opts[@]}" "$url"
    return 0
  else
    err "No existe curl ni wget en el host remoto."
    return 1
  fi
}

probe_caldera() {
  if have_cmd curl; then
    local opts=(-fsS --connect-timeout 5)
    [[ "$CALDERA_INSECURE" == "1" ]] && opts=(-k "${opts[@]}")
    if curl "${opts[@]}" "${CALDERA_URL}" >/dev/null 2>&1; then
      okm "Caldera responde: ${CALDERA_URL}"
      return 0
    fi
  elif have_cmd wget; then
    local opts=(--spider -q --timeout=5)
    [[ "$CALDERA_INSECURE" == "1" ]] && opts=(--no-check-certificate "${opts[@]}")
    if wget "${opts[@]}" "${CALDERA_URL}" >/dev/null 2>&1; then
      okm "Caldera responde: ${CALDERA_URL}"
      return 0
    fi
  fi
  wrn "No se pudo verificar conectividad con Caldera ahora mismo. Se desplegará igualmente."
  return 0
}

# --------------------------------------------
# Preparación dirs
# --------------------------------------------
msg "Creando directorio del agente: ${AGENT_DIR}"
$SUDO mkdir -p "${AGENT_DIR}"
$SUDO chmod 755 "${AGENT_DIR}" || true

# --------------------------------------------
# Dependencias + conectividad
# --------------------------------------------
install_deps_if_needed
probe_caldera

# --------------------------------------------
# Descarga/actualización idempotente del binario
# --------------------------------------------
TMPBIN="$(mktemp /tmp/sandcat.XXXXXX)"
trap 'rm -f "$TMPBIN" "${TMP_SVC:-}" >/dev/null 2>&1 || true' EXIT

msg "Descargando/actualizando agente Sandcat..."
download_sandcat "$TMPBIN"

chmod +x "$TMPBIN"

BINARY_CHANGED=1
if $SUDO test -f "${AGENT_PATH}"; then
  if $SUDO cmp -s "$TMPBIN" "${AGENT_PATH}"; then
    BINARY_CHANGED=0
    okm "El binario del agente ya estaba actualizado (sin cambios)"
  fi
fi

if (( BINARY_CHANGED == 1 )); then
  msg "Instalando binario actualizado en ${AGENT_PATH}"
  $SUDO cp "$TMPBIN" "${AGENT_PATH}"
  $SUDO chmod +x "${AGENT_PATH}"
  okm "Agente actualizado"
fi

# --------------------------------------------
# Selección de modo de servicio
# --------------------------------------------
resolve_service_mode() {
  local mode="$1"
  if [[ "$mode" == "auto" ]]; then
    if have_cmd systemctl && [[ -d /run/systemd/system ]]; then
      echo "systemd"
    else
      echo "nohup"
    fi
  else
    echo "$mode"
  fi
}

SERVICE_MODE_RESOLVED="$(resolve_service_mode "$SERVICE_MODE")"
okm "Modo de ejecución resuelto: ${SERVICE_MODE_RESOLVED}"

# --------------------------------------------
# Modo systemd (idempotente)
# --------------------------------------------
deploy_systemd() {
  local svc_changed=1
  TMP_SVC="$(mktemp /tmp/${SERVICE_NAME}.service.XXXXXX)"

  cat > "$TMP_SVC" <<EOSVC
[Unit]
Description=Caldera Sandcat Agent (${HOST_LABEL})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${AGENT_PATH} -server ${CALDERA_URL} -group ${CALDERA_GROUP} -v
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOSVC

  if $SUDO test -f "${SERVICE_PATH}" && $SUDO cmp -s "$TMP_SVC" "${SERVICE_PATH}"; then
    svc_changed=0
    okm "Servicio systemd ya estaba actualizado (sin cambios)"
  else
    msg "Creando/actualizando unidad systemd: ${SERVICE_PATH}"
    $SUDO cp "$TMP_SVC" "${SERVICE_PATH}"
    $SUDO chmod 644 "${SERVICE_PATH}" || true
    $SUDO systemctl daemon-reload
    svc_changed=1
    okm "Unidad systemd actualizada"
  fi

  $SUDO systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true

  if (( BINARY_CHANGED == 1 || svc_changed == 1 )); then
    msg "Reiniciando ${SERVICE_NAME}.service (cambios detectados)"
    $SUDO systemctl restart "${SERVICE_NAME}.service"
  else
    if ! $SUDO systemctl is-active --quiet "${SERVICE_NAME}.service"; then
      msg "Servicio inactivo; iniciando ${SERVICE_NAME}.service"
      $SUDO systemctl restart "${SERVICE_NAME}.service"
    else
      okm "Servicio ya activo y sin cambios; no se reinicia"
    fi
  fi

  echo "[+] Estado del servicio (primeras líneas):"
  $SUDO systemctl status "${SERVICE_NAME}.service" --no-pager | head -n 15 || true

  if $SUDO systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    okm "${SERVICE_NAME}.service activo"
  else
    wrn "${SERVICE_NAME}.service no está activo (revisar logs)"
    return 1
  fi
}

# --------------------------------------------
# Fallback nohup (idempotente sin systemd)
# --------------------------------------------
deploy_nohup() {
  local need_restart=0

  if [[ ! -f "${PIDFILE}" ]]; then
    need_restart=1
  else
    local pid
    pid="$(cat "${PIDFILE}" 2>/dev/null || true)"
    if [[ -z "$pid" ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
      need_restart=1
    fi
  fi

  if (( BINARY_CHANGED == 1 )); then
    need_restart=1
  fi

  if (( need_restart == 0 )); then
    okm "Agente ya ejecutándose (nohup) y sin cambios; no se relanza"
    return 0
  fi

  if [[ -f "${PIDFILE}" ]]; then
    local oldpid
    oldpid="$(cat "${PIDFILE}" 2>/dev/null || true)"
    if [[ -n "${oldpid}" ]] && kill -0 "${oldpid}" >/dev/null 2>&1; then
      msg "Deteniendo proceso previo (${oldpid})..."
      kill "${oldpid}" >/dev/null 2>&1 || true
      sleep 1
      kill -9 "${oldpid}" >/dev/null 2>&1 || true
    fi
  fi

  msg "Lanzando agente en background (nohup)..."
  (
    cd "${AGENT_DIR}" || exit 1
    nohup "${AGENT_PATH}" -server "${CALDERA_URL}" -group "${CALDERA_GROUP}" -v >> "${LOGFILE}" 2>&1 &
    echo $! > "${PIDFILE}"
  )

  local npid
  npid="$(cat "${PIDFILE}" 2>/dev/null || true)"
  if [[ -n "$npid" ]] && kill -0 "$npid" >/dev/null 2>&1; then
    okm "Agente levantado (nohup), PID=${npid}"
    echo "[+] Log: ${LOGFILE}"
    return 0
  fi

  err "No se pudo arrancar el agente en modo nohup"
  return 1
}

case "${SERVICE_MODE_RESOLVED}" in
  systemd)
    if ! have_cmd systemctl || [[ ! -d /run/systemd/system ]]; then
      err "Se pidió modo systemd pero systemd no está disponible en este host."
      exit 1
    fi
    deploy_systemd
    ;;
  nohup)
    deploy_nohup
    ;;
  *)
    err "Modo de servicio no soportado: ${SERVICE_MODE_RESOLVED}"
    exit 1
    ;;
esac

okm "Despliegue remoto completado"
REMOTE_EOF

  printf -v REMOTE_RUN_CMD \
    'bash %q %q %q %q %q %q %q %q %q %q; rc=$?; rm -f %q; exit $rc' \
    "$REMOTE_TMP_SCRIPT" \
    "$CALDERA_URL" \
    "$AGENT_DIR" \
    "$AGENT_PATH" \
    "$SERVICE_PATH" \
    "$CALDERA_GROUP" \
    "$h" \
    "$SERVICE_MODE" \
    "$SERVICE_NAME" \
    "$CALDERA_INSECURE" \
    "$REMOTE_TMP_SCRIPT"

  if ssh -tt -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
      "${SSH_USER}@${h}" "$REMOTE_RUN_CMD"; then
    ok "Agente desplegado/actualizado correctamente en ${h}"
    SUCCESS+=("$h")
  else
    echo "[-] Falló el despliegue del agente en ${h}"
    ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
      "${SSH_USER}@${h}" "rm -f ${REMOTE_TMP_SCRIPT_Q}" >/dev/null 2>&1 || true
    FAILED+=("$h")
    continue
  fi
done

# =========================
# Resumen final
# =========================
SCRIPT_END=$(date +%s)

echo
echo "===================================================="
echo " Resumen final"
echo "===================================================="
echo "Caldera URL:     ${CALDERA_URL}"
echo "Grupo Caldera:   ${CALDERA_GROUP}"
echo "Usuario SSH:     ${SSH_USER}"
echo "Puerto SSH:      ${SSH_PORT}"
echo "Clave privada:   ${SSH_KEY_PATH}"
echo "Known hosts:     ${KNOWN_HOSTS_PATH}"
echo "Service mode:    ${SERVICE_MODE}"
echo "Insecure TLS:    ${CALDERA_INSECURE}"
echo

echo "Éxitos: ${#SUCCESS[@]}"
for h in "${SUCCESS[@]}"; do echo "  - ${h}"; done
echo

echo "Fallos: ${#FAILED[@]}"
for h in "${FAILED[@]}"; do echo "  - ${h}"; done
echo

echo "[⏱] Tiempo TOTAL: $(format_time "$((SCRIPT_END-SCRIPT_START))")"
echo "===================================================="
echo
echo "Comprobaciones manuales recomendadas (VM cliente):"
echo "  ssh -i \"$SSH_KEY_PATH\" -p \"$SSH_PORT\" ${SSH_USER}@<IP_VM>"
if [[ "$SERVICE_MODE" == "nohup" ]]; then
  echo "  ps aux | grep '[c]aldera-agent'"
  echo "  tail -f ${AGENT_DIR}/caldera-agent.log"
else
  echo "  sudo systemctl status ${SERVICE_NAME}.service"
  echo "  sudo journalctl -u ${SERVICE_NAME}.service -f"
fi
echo
echo "En la GUI de Caldera deberías ver el/los agentes conectados (grupo '${CALDERA_GROUP}')."
