#!/usr/bin/env bash
set -euo pipefail

# ============================================
# Script: Preparación SSH idempotente para labs
# - Reutiliza clave existente (por defecto)
# - Instala clave pública en hosts (sin duplicados)
# - Compatible con entornos de prácticas (VMware/VirtualBox/KVM/WSL/Linux/macOS)
# ============================================

# =========================
# Config por defecto
# =========================
KEY_BASENAME="mykey"
KEY_DIR="$(pwd)"
DEFAULT_PORT="22"
CONNECT_TIMEOUT="5"
KEY_TYPE="ed25519"              # ed25519 | rsa4096
REGENERATE_KEY="ask"            # ask | yes | no
AUTO_CONFIRM="0"
COPY_METHOD="auto"              # auto | ssh-copy-id | manual
PICK_MODE=""                    # "" | all | "1 3 5"
HOSTS_INLINE=""
HOSTS_FILE=""

REMOTE_USER=""
SSH_PORT=""
KEY_PATH=""
KNOWN_HOSTS_PATH=""

# =========================
# Helpers
# =========================
die() { echo "[-] $*" >&2; exit 1; }
ok()  { echo "[+] $*"; }
inf() { echo "[*] $*"; }
wrn() { echo "[!] $*"; }

usage() {
  cat <<'EOF'
Uso:
  ./prep_ssh_lab_idempotente.sh [opciones]

Opciones:
  -u, --user USER           Usuario SSH remoto (ej: ubuntu, kali, root)
  -p, --port PORT           Puerto SSH (por defecto: 22)
  -k, --key-basename NAME   Nombre base de la clave (por defecto: mykey)
  -d, --key-dir DIR         Directorio donde guardar claves (por defecto: cwd)
  -t, --key-type TYPE       Tipo de clave: ed25519 | rsa4096 (por defecto: ed25519)

      --regen-key           Fuerza regeneración de clave (idempotencia controlada)
      --reuse-key           Fuerza reutilización de clave existente si la hay
      --copy-method M       auto | ssh-copy-id | manual (por defecto: auto)

  -H, --hosts "h1,h2 h3"    Hosts inline (separados por espacios/comas)
  -f, --hosts-file FILE     Fichero con hosts (uno por línea; admite comas/espacios)
      --all                 Selecciona todos los hosts sin preguntar
      --pick "1 3 5"        Selecciona índices concretos (según listado)
  -y, --yes                 Confirmar sin preguntar
      --timeout SEC         ConnectTimeout SSH (por defecto: 5)
  -h, --help                Mostrar ayuda

Ejemplos:
  ./prep_ssh_lab_idempotente.sh -u ubuntu -H "192.168.56.10,192.168.56.11" --all -y
  ./prep_ssh_lab_idempotente.sh -u kali -f hosts.txt --pick "1 3" --copy-method manual
  ./prep_ssh_lab_idempotente.sh -u root -H "10.0.0.5" --regen-key -y
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Falta el comando '$1'. Instálalo e inténtalo de nuevo."
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

portable_ts() {
  # Evita dependencia de 'date -Iseconds' (no siempre disponible en macOS/BSD)
  date +"%Y-%m-%dT%H:%M:%S%z"
}

ssh_supports_accept_new() {
  local ver
  ver="$(ssh -V 2>&1 || true)"  # "OpenSSH_9.6p1, ..."
  [[ "$ver" =~ OpenSSH_([0-9]+)\.([0-9]+) ]] || return 1
  local maj="${BASH_REMATCH[1]}"
  local min="${BASH_REMATCH[2]}"
  if (( maj > 7 )); then return 0; fi
  if (( maj == 7 && min >= 6 )); then return 0; fi
  return 1
}

trim_cr() {
  # Elimina \r (Windows CRLF)
  printf '%s' "$1" | tr -d '\r'
}

add_target() {
  local h
  h="$(trim_cr "$1")"
  [[ -n "$h" ]] || return 0
  TARGETS_RAW+=("$h")
}

parse_hosts_line() {
  local line="$1"
  line="${line//,/ }"
  # shellcheck disable=SC2086
  for h in $line; do
    add_target "$h"
  done
}

# =========================
# Parseo de argumentos
# =========================
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--user)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      REMOTE_USER="$2"; shift 2;;
    -p|--port)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      SSH_PORT="$2"; shift 2;;
    -k|--key-basename)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      KEY_BASENAME="$2"; shift 2;;
    -d|--key-dir)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      KEY_DIR="$2"; shift 2;;
    -t|--key-type)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      KEY_TYPE="$2"; shift 2;;
    --regen-key)
      REGENERATE_KEY="yes"; shift;;
    --reuse-key)
      REGENERATE_KEY="no"; shift;;
    --copy-method)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      COPY_METHOD="$2"; shift 2;;
    -H|--hosts)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      HOSTS_INLINE="$2"; shift 2;;
    -f|--hosts-file)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      HOSTS_FILE="$2"; shift 2;;
    --all)
      PICK_MODE="all"; shift;;
    --pick)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      PICK_MODE="$2"; shift 2;;
    -y|--yes)
      AUTO_CONFIRM="1"; shift;;
    --timeout)
      [[ $# -ge 2 ]] || die "Falta valor para $1"
      CONNECT_TIMEOUT="$2"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      die "Opción no reconocida: $1 (usa --help)"
      ;;
  esac
done

# =========================
# Dependencias mínimas
# =========================
require_cmd bash
require_cmd ssh
require_cmd ssh-keygen
require_cmd grep
require_cmd chmod
require_cmd mkdir
require_cmd awk
require_cmd sed
require_cmd tr

# ssh-copy-id es opcional (hay fallback manual)
if [[ "$COPY_METHOD" == "ssh-copy-id" ]]; then
  has_cmd ssh-copy-id || die "Has pedido --copy-method ssh-copy-id pero no existe 'ssh-copy-id' en este sistema."
fi

# =========================
# Validaciones básicas
# =========================
[[ "$KEY_TYPE" == "ed25519" || "$KEY_TYPE" == "rsa4096" ]] || die "Tipo de clave no válido: $KEY_TYPE (usa ed25519 o rsa4096)"
[[ "$COPY_METHOD" == "auto" || "$COPY_METHOD" == "ssh-copy-id" || "$COPY_METHOD" == "manual" ]] || die "copy-method inválido: $COPY_METHOD"
[[ "$CONNECT_TIMEOUT" =~ ^[0-9]+$ ]] || die "Timeout inválido: '$CONNECT_TIMEOUT'"

SSH_PORT="${SSH_PORT:-$DEFAULT_PORT}"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "Puerto inválido: '$SSH_PORT'"

mkdir -p "$KEY_DIR"
KEY_PATH="${KEY_DIR%/}/${KEY_BASENAME}"
KNOWN_HOSTS_PATH="${KEY_DIR%/}/known_hosts_${KEY_BASENAME}"

# =========================
# Inputs interactivos (si faltan)
# =========================
echo "=== Preparación SSH idempotente (clave + distribución) ==="

if [[ -z "$REMOTE_USER" ]]; then
  read -r -p "Usuario SSH remoto (ej: kali / ubuntu / root): " REMOTE_USER
fi
[[ -n "${REMOTE_USER}" ]] || die "Usuario remoto vacío"

# =========================
# Gestión de clave (IDEMPOTENTE)
# =========================
generate_key() {
  inf "Generando par de claves en: ${KEY_PATH}"
  rm -f "${KEY_PATH}" "${KEY_PATH}.pub"

  case "$KEY_TYPE" in
    ed25519)
      ssh-keygen -t ed25519 -a 64 -f "${KEY_PATH}" -N "" -C "lab-${KEY_BASENAME}-$(portable_ts)" >/dev/null
      ;;
    rsa4096)
      ssh-keygen -t rsa -b 4096 -o -a 64 -f "${KEY_PATH}" -N "" -C "lab-${KEY_BASENAME}-$(portable_ts)" >/dev/null
      ;;
  esac

  chmod 700 "$KEY_DIR" 2>/dev/null || true
  chmod 600 "${KEY_PATH}"
  chmod 644 "${KEY_PATH}.pub"
  ok "Claves creadas: ${KEY_PATH} y ${KEY_PATH}.pub"
}

ensure_keypair() {
  local priv_exists=0 pub_exists=0
  [[ -f "${KEY_PATH}" ]] && priv_exists=1
  [[ -f "${KEY_PATH}.pub" ]] && pub_exists=1

  if (( priv_exists == 1 && pub_exists == 1 )); then
    if ssh-keygen -y -f "${KEY_PATH}" >/dev/null 2>&1; then
      case "$REGENERATE_KEY" in
        yes)
          wrn "Se solicitó regeneración de clave (--regen-key)."
          generate_key
          ;;
        no)
          ok "Reutilizando clave existente (idempotente): ${KEY_PATH}"
          ;;
        ask)
          read -r -p "Ya existe una clave en ${KEY_PATH}. ¿Reutilizarla? (Y/n): " ans
          ans="${ans:-Y}"
          if [[ "$ans" =~ ^[Nn]$ ]]; then
            generate_key
          else
            ok "Reutilizando clave existente (idempotente): ${KEY_PATH}"
          fi
          ;;
      esac
    else
      wrn "La clave privada existente parece inválida/corrupta. Se regenerará."
      generate_key
    fi
    return
  fi

  if (( priv_exists == 1 && pub_exists == 0 )); then
    inf "Existe clave privada pero falta la pública. Intentando reconstruir ${KEY_PATH}.pub ..."
    ssh-keygen -y -f "${KEY_PATH}" > "${KEY_PATH}.pub"
    chmod 644 "${KEY_PATH}.pub"
    ok "Clave pública reconstruida: ${KEY_PATH}.pub"
    return
  fi

  if (( priv_exists == 0 && pub_exists == 1 )); then
    die "Existe ${KEY_PATH}.pub pero falta la clave privada ${KEY_PATH}. No se puede continuar de forma segura."
  fi

  generate_key
}

ensure_keypair

# =========================
# Entrada de hosts (inline/file/interactiva)
# =========================
TARGETS_RAW=()

if [[ -n "$HOSTS_INLINE" ]]; then
  parse_hosts_line "$HOSTS_INLINE"
fi

if [[ -n "$HOSTS_FILE" ]]; then
  [[ -f "$HOSTS_FILE" ]] || die "No existe el fichero de hosts: $HOSTS_FILE"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim_cr "$line")"
    # Saltar comentarios y líneas vacías
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    parse_hosts_line "$line"
  done < "$HOSTS_FILE"
fi

if ((${#TARGETS_RAW[@]} == 0)); then
  echo
  echo "Introduce las IPs/hostnames destino (manual)."
  echo " - Puedes meter varios separados por espacios o comas en una misma línea."
  echo " - Pulsa ENTER en una línea vacía para terminar."
  echo
  while true; do
    read -r -p "Host(s): " line
    [[ -z "$line" ]] && break
    parse_hosts_line "$line"
  done
fi

((${#TARGETS_RAW[@]} > 0)) || die "No se introdujo ningún host."

# Quitar duplicados manteniendo orden
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
  read -r -p "¿Quieres actuar sobre todos (all) o elegir índices (ej: 1 3 5)? [all]: " PICK_MODE
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

  # Deduplicar selección
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
for h in "${SELECTED[@]}"; do echo "  - $h"; done
echo "Total: ${#SELECTED[@]} host(s)"
echo

if [[ "$AUTO_CONFIRM" != "1" ]]; then
  read -r -p "¿Continuar e instalar la clave pública en estos hosts? (y/N): " CONFIRM
  CONFIRM="${CONFIRM:-N}"
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || die "Cancelado por el usuario."
fi

# =========================
# Opciones SSH (known_hosts separado)
# =========================
STRICT_OPT="accept-new"
if ! ssh_supports_accept_new; then
  inf "Tu OpenSSH no parece soportar 'StrictHostKeyChecking=accept-new'. Usaré 'StrictHostKeyChecking=no'."
  STRICT_OPT="no"
fi

SSH_OPTS=(
  -o "ConnectTimeout=${CONNECT_TIMEOUT}"
  -o "StrictHostKeyChecking=${STRICT_OPT}"
  -o "UserKnownHostsFile=${KNOWN_HOSTS_PATH}"
)

# =========================
# Método de instalación (ssh-copy-id o manual)
# =========================
choose_copy_method() {
  local chosen="$COPY_METHOD"
  if [[ "$chosen" == "auto" ]]; then
    if has_cmd ssh-copy-id; then
      chosen="ssh-copy-id"
    else
      chosen="manual"
    fi
  fi
  printf '%s' "$chosen"
}

install_key_ssh_copy_id() {
  local host="$1"
  ssh-copy-id -i "${KEY_PATH}.pub" -p "${SSH_PORT}" "${SSH_OPTS[@]}" "${REMOTE_USER}@${host}"
}

install_key_manual_idempotent() {
  local host="$1"
  # Enviamos la clave pública por STDIN y en remoto añadimos solo si no existe ya (idempotente)
  ssh -p "${SSH_PORT}" "${SSH_OPTS[@]}" "${REMOTE_USER}@${host}" '
    set -eu
    umask 077
    SSH_DIR="$HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"
    mkdir -p "$SSH_DIR"
    touch "$AUTH_KEYS"
    chmod 700 "$SSH_DIR" || true
    chmod 600 "$AUTH_KEYS" || true

    added=0
    while IFS= read -r keyline; do
      [ -z "$keyline" ] && continue
      if grep -Fqx -- "$keyline" "$AUTH_KEYS"; then
        :
      else
        printf "%s\n" "$keyline" >> "$AUTH_KEYS"
        added=1
      fi
    done

    exit 0
  ' < "${KEY_PATH}.pub"
}

verify_key_login() {
  local host="$1"
  ssh -i "${KEY_PATH}" -p "${SSH_PORT}" "${SSH_OPTS[@]}" -o "BatchMode=yes" "${REMOTE_USER}@${host}" "echo OK" >/dev/null 2>&1
}

CHOSEN_METHOD="$(choose_copy_method)"
ok "Método de instalación seleccionado: ${CHOSEN_METHOD}"

# =========================
# Distribución
# =========================
SUCCESS=()
FAILED=()

inf "Instalando clave pública..."
for h in "${SELECTED[@]}"; do
  echo
  inf ">> ${REMOTE_USER}@${h}:${SSH_PORT}"

  if [[ "$CHOSEN_METHOD" == "ssh-copy-id" ]]; then
    if install_key_ssh_copy_id "$h"; then
      ok "Clave instalada/verificada con ssh-copy-id en ${h}"
    else
      echo "[-] Falló ssh-copy-id en ${h}"
      FAILED+=("$h")
      continue
    fi
  else
    if install_key_manual_idempotent "$h"; then
      ok "Clave instalada/verificada manualmente (idempotente) en ${h}"
    else
      echo "[-] Falló instalación manual en ${h}"
      FAILED+=("$h")
      continue
    fi
  fi

  if verify_key_login "$h"; then
    ok "Verificación OK (login por clave) en ${h}"
  else
    inf "No se pudo verificar login por clave en ${h} (puede ser normal si el SSH restringe BatchMode/TTY o hay políticas PAM)."
  fi

  SUCCESS+=("$h")
done

# =========================
# Resumen
# =========================
echo
echo "=== Resumen ==="
echo "Clave privada: ${KEY_PATH}"
echo "Clave pública: ${KEY_PATH}.pub"
echo "Known hosts:   ${KNOWN_HOSTS_PATH}"
echo "Método usado:  ${CHOSEN_METHOD}"
echo
echo "Éxitos: ${#SUCCESS[@]}"
for h in "${SUCCESS[@]}"; do echo "  - $h"; done
echo
echo "Fallos: ${#FAILED[@]}"
for h in "${FAILED[@]}"; do echo "  - $h"; done
echo

ok "Listo. Ya puedes reutilizar ${KEY_PATH} en los siguientes scripts del lab."
