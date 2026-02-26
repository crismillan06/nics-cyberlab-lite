#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# prep-lab.sh
# Preparación de entorno educativo (concienciación)
#
# - VM Caldera: instala nmap + hydra + SecLists (wordlists)
# - VM Snort: crea usuario local de test con contraseña débil
# - Espera opcional con contador para Caldera (HTTP)
#
# Uso previsto: laboratorio autorizado / formación interna
# =========================================================

# -------------------------
# Config por defecto
# -------------------------
DEFAULT_SSH_USER="debian"
DEFAULT_SSH_PORT="22"
DEFAULT_SSH_KEY="$(pwd)/mykey"
AUTO_CONFIRM=0

CALDERA_HOST=""
SNORT_HOST=""
CALDERA_USER=""
SNORT_USER=""
SSH_USER=""
SSH_PORT=""
SSH_KEY_PATH=""
KNOWN_HOSTS_PATH=""

CALDERA_URL=""            # si vacío => http://<CALDERA_HOST>:8888
CALDERA_WAIT_TIMEOUT=300  # segundos
SKIP_CALDERA_WAIT=0

TEST_USER="nicslab"
# Hash SHA-512 (crypt) de la contraseña del ejercicio (no guardar la contraseña en texto plano)
# Contraseña real del ejercicio: "pandora"
TEST_PASS_HASH='$6$ON5XNZn5mNrmoZDc$CZmskRdths0SK0oTam7YcJSfzuVcpdRx1DPR7H25gze0H6jOuomfqKLtItLaS9cJevwDZdaoXar6kkUuzFZPf1'

SSH_WAIT_TIMEOUT=300
SSH_CONNECT_TIMEOUT=5

# -------------------------
# Helpers
# -------------------------
die()  { echo "[-] $*" >&2; exit 1; }
ok()   { echo "[+] $*"; }
inf()  { echo "[*] $*"; }
warn() { echo "[!] $*"; }

usage() {
  cat <<'EOF'
Uso:
  ./prep-lab.sh [opciones]

Opciones SSH:
  -u, --ssh-user USER         Usuario SSH por defecto para ambas VMs (default: debian)
      --caldera-user USER     Usuario SSH específico para Caldera
      --snort-user USER       Usuario SSH específico para Snort
  -p, --ssh-port PORT         Puerto SSH (default: 22)
  -k, --ssh-key PATH          Ruta clave privada SSH (default: ./mykey)
      --known-hosts PATH      Ruta known_hosts dedicado (default: ./known_hosts_<basename_clave>)

Hosts:
      --caldera-host HOST     Host/IP de la VM Caldera
      --snort-host HOST       Host/IP de la VM Snort

Caldera readiness:
      --caldera-url URL       URL a comprobar (default: http://<caldera-host>:8888)
      --wait-timeout SEC      Timeout de espera de Caldera HTTP (default: 300)
      --skip-caldera-wait     No esperar HTTP de Caldera

Usuario de prueba (Snort):
      --test-user USER        Usuario local de prueba (default: nicslab)
      --test-pass-hash HASH   Hash de contraseña (crypt SHA-512) para chpasswd -e

Otros:
  -y, --yes                  Confirmar sin preguntar
  -h, --help                 Ayuda

Ejemplo:
  ./prep-lab.sh \
    --caldera-host 10.0.1.13 \
    --snort-host 10.0.1.16 \
    -u nics -k ./mykey -y
EOF
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Falta el comando '$1'."; }

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

format_mmss() {
  local s="${1:-0}"
  printf "%02d:%02d" "$((s/60))" "$((s%60))"
}

# Limpia la línea al salir (éxito, error, Ctrl+C)
cleanup_wait_line() { printf "\r\033[K"; }

wait_http_ready_counter() {
  local url="$1"
  local timeout="${2:-300}"
  local start_wait now elapsed

  require_cmd curl

  start_wait=$(date +%s)
  trap cleanup_wait_line EXIT

  while true; do
    if curl -fs --max-time 2 -o /dev/null "$url" >/dev/null 2>&1; then
      break
    fi

    now=$(date +%s)
    elapsed=$((now - start_wait))

    if (( elapsed > timeout )); then
      printf "\r\033[K"
      trap - EXIT
      die "Timeout esperando Caldera en ${url}"
    fi

    printf "\r⏱︎ Esperando Caldera: %s\033[K" "$(format_mmss "$elapsed")"
    sleep 3
  done

  trap - EXIT
  printf "\r\033[K"
}

wait_for_ssh() {
  local host="$1" user="$2"
  local start now

  inf "Comprobando SSH en ${user}@${host}:${SSH_PORT} (timeout ${SSH_WAIT_TIMEOUT}s)..."

  start=$(date +%s)
  until ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" -o BatchMode=yes \
      "${user}@${host}" "echo ok" >/dev/null 2>&1; do
    sleep 5
    echo -n "."
    now=$(date +%s)
    if (( now - start > SSH_WAIT_TIMEOUT )); then
      echo
      die "Timeout SSH con ${user}@${host}:${SSH_PORT}"
    fi
  done
  echo
  ok "SSH disponible en ${user}@${host}"
}

run_remote_script_tty() {
  local host="$1"; shift
  local user="$1"; shift
  local local_script="$1"; shift

  local remote_tmp="/tmp/remote_job_${RANDOM}_$$.sh"
  local remote_tmp_q
  printf -v remote_tmp_q '%q' "$remote_tmp"

  if ! ssh -i "$SSH_KEY_PATH" -p "$SSH_PORT" "${SSH_OPTS[@]}" \
      "${user}@${host}" \
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
      "${user}@${host}" "$cmd"
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
# Parseo argumentos
# -------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--ssh-user)       [[ $# -ge 2 ]] || die "Falta valor para $1"; SSH_USER="$2"; shift 2 ;;
    --caldera-user)      [[ $# -ge 2 ]] || die "Falta valor para $1"; CALDERA_USER="$2"; shift 2 ;;
    --snort-user)        [[ $# -ge 2 ]] || die "Falta valor para $1"; SNORT_USER="$2"; shift 2 ;;
    -p|--ssh-port)       [[ $# -ge 2 ]] || die "Falta valor para $1"; SSH_PORT="$2"; shift 2 ;;
    -k|--ssh-key)        [[ $# -ge 2 ]] || die "Falta valor para $1"; SSH_KEY_PATH="$2"; shift 2 ;;
    --known-hosts)       [[ $# -ge 2 ]] || die "Falta valor para $1"; KNOWN_HOSTS_PATH="$2"; shift 2 ;;

    --caldera-host)      [[ $# -ge 2 ]] || die "Falta valor para $1"; CALDERA_HOST="$2"; shift 2 ;;
    --snort-host)        [[ $# -ge 2 ]] || die "Falta valor para $1"; SNORT_HOST="$2"; shift 2 ;;

    --caldera-url)       [[ $# -ge 2 ]] || die "Falta valor para $1"; CALDERA_URL="$2"; shift 2 ;;
    --wait-timeout)      [[ $# -ge 2 ]] || die "Falta valor para $1"; CALDERA_WAIT_TIMEOUT="$2"; shift 2 ;;
    --skip-caldera-wait) SKIP_CALDERA_WAIT=1; shift ;;

    --test-user)         [[ $# -ge 2 ]] || die "Falta valor para $1"; TEST_USER="$2"; shift 2 ;;
    --test-pass-hash)    [[ $# -ge 2 ]] || die "Falta valor para $1"; TEST_PASS_HASH="$2"; shift 2 ;;

    -y|--yes)            AUTO_CONFIRM=1; shift ;;
    -h|--help)           usage; exit 0 ;;
    *)                   die "Opción no reconocida: $1 (usa --help)" ;;
  esac
done

# -------------------------
# Dependencias locales
# -------------------------
require_cmd bash
require_cmd ssh
require_cmd ssh-keygen
require_cmd mktemp
require_cmd chmod
require_cmd mkdir

# -------------------------
# Inputs interactivos
# -------------------------
echo "===================================================="
echo " Preparación entorno educativo (Caldera + Snort)"
echo "===================================================="

echo
echo "=== Configuración SSH ==="

# Primero: usuario por defecto (como pediste)
if [[ -z "${SSH_USER:-}" ]]; then
  read -r -p "Usuario SSH por defecto [${DEFAULT_SSH_USER}]: " SSH_USER
  SSH_USER="${SSH_USER:-$DEFAULT_SSH_USER}"
fi

# Luego: usuarios por VM (opcionalmente distintos)
if [[ -z "${CALDERA_USER:-}" ]]; then
  read -r -p "Usuario SSH para Caldera [${SSH_USER}]: " CALDERA_USER
  CALDERA_USER="${CALDERA_USER:-$SSH_USER}"
fi
if [[ -z "${SNORT_USER:-}" ]]; then
  read -r -p "Usuario SSH para Snort [${SSH_USER}]: " SNORT_USER
  SNORT_USER="${SNORT_USER:-$SSH_USER}"
fi

if [[ -z "${SSH_PORT:-}" ]]; then
  read -r -p "Puerto SSH [${DEFAULT_SSH_PORT}]: " SSH_PORT
  SSH_PORT="${SSH_PORT:-$DEFAULT_SSH_PORT}"
fi

if [[ -z "${SSH_KEY_PATH:-}" ]]; then
  read -r -p "Ruta clave SSH [${DEFAULT_SSH_KEY}]: " SSH_KEY_PATH
  SSH_KEY_PATH="${SSH_KEY_PATH:-$DEFAULT_SSH_KEY}"
fi

echo
echo "=== Hosts de las VMs ==="
if [[ -z "${CALDERA_HOST:-}" ]]; then
  read -r -p "Host/IP VM Caldera: " CALDERA_HOST
fi
[[ -n "$CALDERA_HOST" ]] || die "Caldera host vacío"

if [[ -z "${SNORT_HOST:-}" ]]; then
  read -r -p "Host/IP VM Snort: " SNORT_HOST
fi
[[ -n "$SNORT_HOST" ]] || die "Snort host vacío"

if [[ -z "${KNOWN_HOSTS_PATH:-}" ]]; then
  DEFAULT_KH_FROM_KEY="$(pwd)/known_hosts_$(basename "$SSH_KEY_PATH")"
  read -r -p "known_hosts dedicado [${DEFAULT_KH_FROM_KEY}]: " KNOWN_HOSTS_PATH
  KNOWN_HOSTS_PATH="${KNOWN_HOSTS_PATH:-$DEFAULT_KH_FROM_KEY}"
fi

if [[ -z "${CALDERA_URL:-}" ]]; then
  CALDERA_URL="http://${CALDERA_HOST}:8888"
fi

[[ -f "$SSH_KEY_PATH" ]] || die "No existe la clave SSH: $SSH_KEY_PATH"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "Puerto SSH inválido"
[[ "$CALDERA_WAIT_TIMEOUT" =~ ^[0-9]+$ ]] || die "wait-timeout inválido"
[[ -n "$TEST_USER" ]] || die "test-user vacío"
[[ -n "$TEST_PASS_HASH" ]] || die "test-pass-hash vacío"

mkdir -p "$(dirname "$KNOWN_HOSTS_PATH")"
touch "$KNOWN_HOSTS_PATH"
chmod 600 "$KNOWN_HOSTS_PATH" || true
chmod 600 "$SSH_KEY_PATH" || true

STRICT_OPT="accept-new"
if ! ssh_supports_accept_new; then
  STRICT_OPT="no"
fi
SSH_OPTS=(
  -o "ConnectTimeout=${SSH_CONNECT_TIMEOUT}"
  -o "StrictHostKeyChecking=${STRICT_OPT}"
  -o "UserKnownHostsFile=${KNOWN_HOSTS_PATH}"
)

echo
echo "=== Resumen ==="
echo "Caldera SSH: ${CALDERA_USER}@${CALDERA_HOST}:${SSH_PORT}"
echo "Snort SSH:   ${SNORT_USER}@${SNORT_HOST}:${SSH_PORT}"
echo "Caldera URL: ${CALDERA_URL}"
echo "Usuario test local (Snort): ${TEST_USER}"
echo "Contraseña test local: [oculta]"
echo

if [[ "$AUTO_CONFIRM" != "1" ]]; then
  read -r -p "¿Preparar entorno ahora? (y/N): " CONFIRM
  CONFIRM="${CONFIRM:-N}"
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || die "Cancelado."
fi

# -------------------------
# Paso 1: SSH readiness
# -------------------------
inf "Comprobando conectividad SSH..."
wait_for_ssh "$CALDERA_HOST" "$CALDERA_USER"
wait_for_ssh "$SNORT_HOST" "$SNORT_USER"

# -------------------------
# Paso 2: Caldera (nmap + hydra + wordlists)
# -------------------------
inf "Preparando VM Caldera (herramientas + wordlists)..."

CALDERA_SETUP_SCRIPT="$(mktemp)"
register_tmp "$CALDERA_SETUP_SCRIPT"

cat > "$CALDERA_SETUP_SCRIPT" <<'REMOTE_CALDERA_SETUP'
#!/usr/bin/env bash
set -euo pipefail

# Importante para comandos en /usr/sbin cuando el usuario no es root
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

WORDLIST_OFFICIAL="/snap/seclists/current/Passwords/Common-Credentials/Pwdb_top-10000000.txt"
OUTDIR="${HOME}/wordlists"

have_cmd() { command -v "$1" >/dev/null 2>&1; }
err() { echo "[-] $*" >&2; }
log() { echo "[remote-caldera] $*"; }

# Privilegios
SUDO=""
SUDO_KEEPALIVE_PID=""
if [[ "$(id -u)" -ne 0 ]]; then
  if have_cmd sudo; then
    SUDO="sudo"
  elif have_cmd doas; then
    SUDO="doas"
  else
    err "No eres root y no existe sudo/doas."
    exit 1
  fi

  if [[ "$SUDO" == "sudo" ]]; then
    if sudo -n true >/dev/null 2>&1; then
      log "sudo sin contraseña disponible"
    else
      log "sudo requiere contraseña. Se pedirá ahora..."
      sudo -v || { err "sudo -v falló"; exit 1; }
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
    log "Usando doas"
  fi
fi

if ! have_cmd apt-get; then
  err "Este bloque está pensado para Debian/Ubuntu (apt-get)."
  exit 1
fi

log "Actualizando índices APT..."
$SUDO apt-get update -y >/dev/null

# Ubuntu: asegurar universe para hydra
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" == "ubuntu" ]]; then
    if ! grep -RhsE '^[[:space:]]*deb .* universe' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | grep -q universe; then
      log "Habilitando repositorio 'universe'..."
      $SUDO apt-get install -y software-properties-common >/dev/null
      $SUDO add-apt-repository -y universe >/dev/null
      $SUDO apt-get update -y >/dev/null
    else
      log "'universe' ya está habilitado."
    fi
  fi
fi

log "Instalando nmap, hydra, snapd, curl y ca-certificates..."
$SUDO apt-get install -y nmap hydra snapd curl ca-certificates >/dev/null

if have_cmd systemctl; then
  log "Asegurando servicio snapd..."
  $SUDO systemctl enable --now snapd >/dev/null 2>&1 || true
  $SUDO systemctl enable --now snapd.socket >/dev/null 2>&1 || true
fi

have_cmd snap || { err "snap no está disponible tras instalar snapd"; exit 1; }

if ! snap list 2>/dev/null | awk '{print $1}' | grep -qx seclists; then
  log "Instalando SecLists vía snap..."
  $SUDO snap install seclists >/dev/null
else
  log "SecLists ya está instalado."
fi

if [[ ! -f "${WORDLIST_OFFICIAL}" ]]; then
  log "Buscando wordlist oficial en /snap/seclists..."
  ALT="$($SUDO find /snap/seclists -type f -name 'Pwdb_top-10000000.txt' 2>/dev/null | head -n1 || true)"
  [[ -n "$ALT" && -f "$ALT" ]] || { err "No se localizó Pwdb_top-10000000.txt"; exit 1; }
  WORDLIST_OFFICIAL="$ALT"
fi

log "Preparando directorio de wordlists en ${OUTDIR}..."
mkdir -p "${OUTDIR}"

TARGET_LINK="${OUTDIR}/Pwdb_top-10000000.txt"
if [[ ! -e "${TARGET_LINK}" ]]; then
  ln -s "${WORDLIST_OFFICIAL}" "${TARGET_LINK}" 2>/dev/null || cp "${WORDLIST_OFFICIAL}" "${TARGET_LINK}"
fi

log "Generando subsets (1k/10k/100k)..."
head -n 1000   "${TARGET_LINK}" > "${OUTDIR}/pwdb_top_1k.txt"
head -n 10000  "${TARGET_LINK}" > "${OUTDIR}/pwdb_top_10k.txt"
head -n 100000 "${TARGET_LINK}" > "${OUTDIR}/pwdb_top_100k.txt"

log "Herramientas y wordlists listas."
exit 0
REMOTE_CALDERA_SETUP
chmod 700 "$CALDERA_SETUP_SCRIPT"

if ! run_remote_script_tty "$CALDERA_HOST" "$CALDERA_USER" "$CALDERA_SETUP_SCRIPT"; then
  die "Falló la preparación de herramientas/wordlists en Caldera."
fi

# -------------------------
# Paso 3: Snort (usuario local test)
# -------------------------
inf "Preparando VM Snort (usuario local de prueba)..."

SNORT_USER_SCRIPT="$(mktemp)"
register_tmp "$SNORT_USER_SCRIPT"

cat > "$SNORT_USER_SCRIPT" <<'REMOTE_SNORT_USER'
#!/usr/bin/env bash
set -euo pipefail

TEST_USER="$1"
TEST_PASS_HASH="$2"

# Importante para comandos en /usr/sbin cuando el usuario no es root
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

have_cmd() { command -v "$1" >/dev/null 2>&1; }
err() { echo "[-] $*" >&2; }
log() { echo "[remote-snort] $*"; }

# Privilegios
SUDO=""
SUDO_KEEPALIVE_PID=""
if [[ "$(id -u)" -ne 0 ]]; then
  if have_cmd sudo; then
    SUDO="sudo"
  elif have_cmd doas; then
    SUDO="doas"
  else
    err "No eres root y no existe sudo/doas."
    exit 1
  fi

  if [[ "$SUDO" == "sudo" ]]; then
    if sudo -n true >/dev/null 2>&1; then
      log "sudo sin contraseña disponible"
    else
      log "sudo requiere contraseña. Se pedirá ahora..."
      sudo -v || { err "sudo -v falló"; exit 1; }
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
    log "Usando doas"
  fi
fi

log "Comprobando usuario local de prueba: ${TEST_USER}"

# Resolver binarios (con PATH ampliado)
USERADD_BIN="$(command -v useradd || true)"
ADDUSER_BIN="$(command -v adduser || true)"
CHPASSWD_BIN="$(command -v chpasswd || true)"
USERMOD_BIN="$(command -v usermod || true)"
PASSWD_BIN="$(command -v passwd || true)"

if ! id -u "$TEST_USER" >/dev/null 2>&1; then
  log "Creando usuario '${TEST_USER}'..."
  if [[ -n "$USERADD_BIN" ]]; then
    $SUDO "$USERADD_BIN" -m -s /bin/bash "$TEST_USER"
  elif [[ -n "$ADDUSER_BIN" ]]; then
    $SUDO "$ADDUSER_BIN" --disabled-password --gecos "" "$TEST_USER"
  elif have_cmd busybox; then
    $SUDO busybox adduser -D "$TEST_USER"
  else
    err "No existe useradd/adduser (ni fallback busybox) en el sistema."
    exit 1
  fi
else
  log "El usuario '${TEST_USER}' ya existe. Se actualizará la contraseña."
fi

log "Aplicando hash de contraseña al usuario '${TEST_USER}'..."
if [[ -n "$CHPASSWD_BIN" ]]; then
  printf '%s:%s\n' "$TEST_USER" "$TEST_PASS_HASH" | $SUDO "$CHPASSWD_BIN" -e
elif [[ -n "$USERMOD_BIN" ]]; then
  $SUDO "$USERMOD_BIN" -p "$TEST_PASS_HASH" "$TEST_USER"
else
  err "No existe chpasswd ni usermod para aplicar el hash."
  exit 1
fi

if [[ -n "$PASSWD_BIN" ]]; then
  $SUDO "$PASSWD_BIN" -u "$TEST_USER" >/dev/null 2>&1 || true
fi

log "Usuario local de prueba listo."
exit 0
REMOTE_SNORT_USER
chmod 700 "$SNORT_USER_SCRIPT"

if ! run_remote_script_tty "$SNORT_HOST" "$SNORT_USER" "$SNORT_USER_SCRIPT" "$TEST_USER" "$TEST_PASS_HASH"; then
  die "Falló la creación/actualización del usuario de prueba en Snort."
fi

# -------------------------
# Paso 4: Espera Caldera (contador)
# -------------------------
if [[ "$SKIP_CALDERA_WAIT" != "1" ]]; then
  inf "Esperando disponibilidad HTTP de Caldera..."
  wait_http_ready_counter "$CALDERA_URL" "$CALDERA_WAIT_TIMEOUT"
fi

# -------------------------
# Resultado final (mínimo)
# -------------------------
echo "[✔] Entorno listo para realizar los ejercicios de capacitación y concienciación."
