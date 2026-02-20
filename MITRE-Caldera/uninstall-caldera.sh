#!/bin/bash
# =========================================================
#  Desinstalación completa de MITRE Caldera (local) - Mejorada
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash uninstall-caldera.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash uninstall-caldera.sh"
    exit 1
fi

LOCAL_USER="$SUDO_USER"
LOCAL_USER_HOME=$(eval echo "~$LOCAL_USER")

echo "[i] Usuario real: $LOCAL_USER"
echo "[i] HOME real: $LOCAL_USER_HOME"

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

# ===== Carpeta de logs =====
LOG_DIR="$LOCAL_USER_HOME/caldera-logs"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/caldera-uninstall.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Desinstalación automática de MITRE Caldera (Mejorada)"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

# ===============================
# FUNCIONES
# ===============================
is_caldera_pid() {
  local pid="$1"
  # Validación simple: cmdline contiene server.py y la ruta de caldera del usuario
  ps -p "$pid" -o cmd= 2>/dev/null | grep -qE "server\.py" && \
  ps -p "$pid" -o cmd= 2>/dev/null | grep -q "$LOCAL_USER_HOME/caldera"
}

stop_pid_gracefully() {
  local pid="$1"

  echo "[+] Deteniendo PID $pid (TERM)..."
  kill "$pid" 2>/dev/null || true

  # Espera corta (hasta ~5s)
  for _ in 1 2 3 4 5; do
    if ! ps -p "$pid" >/dev/null 2>&1; then
      echo "[✔] PID $pid detenido."
      return 0
    fi
    sleep 1
  done

  echo "[!] PID $pid sigue activo, forzando (KILL)..."
  kill -9 "$pid" 2>/dev/null || true
  sleep 1

  if ps -p "$pid" >/dev/null 2>&1; then
    echo "[✖] No se pudo detener el PID $pid (sigue vivo)."
    return 1
  fi

  echo "[✔] PID $pid detenido (KILL)."
  return 0
}

# ===============================
# DETENER PROCESO DE CALDERA
# ===============================
PID_FILE="$LOG_DIR/caldera.pid"
STOPPED_ANY=0

if [[ -f "$PID_FILE" ]]; then
  CALDERA_PID="$(cat "$PID_FILE" 2>/dev/null || true)"

  if [[ -n "$CALDERA_PID" ]] && ps -p "$CALDERA_PID" >/dev/null 2>&1; then
    if is_caldera_pid "$CALDERA_PID"; then
      echo "[i] PID file encontrado: $CALDERA_PID (validado como Caldera)"
      stop_pid_gracefully "$CALDERA_PID" || true
      STOPPED_ANY=1
    else
      echo "[!] El PID del fichero ($CALDERA_PID) NO parece ser Caldera."
      echo "    Por seguridad no lo mato con el PID file."
    fi
  else
    echo "[i] PID file existe pero el PID no está activo."
  fi
else
  echo "[i] No existe archivo PID, se buscará el proceso por patrón."
fi

# Si no se detuvo nada por PID file, intentar localizar procesos de Caldera
if [[ "$STOPPED_ANY" -eq 0 ]]; then
  echo "[+] Buscando procesos Caldera por patrón (server.py en $LOCAL_USER_HOME/caldera)..."

  # Obtenemos PIDs candidatos (si hay)
  mapfile -t PIDS < <(ps -eo pid=,cmd= | grep -F "$LOCAL_USER_HOME/caldera" | grep -E "server\.py" | grep -v grep | awk '{print $1}' || true)

  if [[ "${#PIDS[@]}" -eq 0 ]]; then
    echo "[i] No se encontraron procesos Caldera activos."
  else
    echo "[i] Procesos candidatos: ${PIDS[*]}"
    for pid in "${PIDS[@]}"; do
      if ps -p "$pid" >/dev/null 2>&1; then
        stop_pid_gracefully "$pid" || true
      fi
    done
  fi
fi

# ===============================
# ELIMINAR DIRECTORIOS DE CALDERA
# ===============================
echo "[+] Eliminando directorios de Caldera..."
rm -rf "$LOCAL_USER_HOME/caldera" || true
rm -rf "$LOCAL_USER_HOME/caldera_venv" || true
echo "[✔] Directorios eliminados."

# ===============================
# ELIMINAR LOGS DE SERVIDOR / RESIDUALES
# ===============================
echo "[+] Eliminando logs del servidor y residuales..."
rm -f "$LOG_DIR/caldera.pid" || true
rm -f "$LOG_DIR/caldera-server.log" || true
rm -f "$LOG_DIR/.built" || true
echo "[✔] Logs del servidor eliminados."

# ===============================
# AJUSTAR PERMISOS
# ===============================
echo "[+] Ajustando permisos del directorio de logs..."
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOG_DIR" 2>/dev/null || true

# ===============================
# TIEMPO TOTAL
# ===============================
SCRIPT_END=$(date +%s)

echo "-----------------------------------------------"
echo "[✔] Caldera ha sido desinstalado COMPLETAMENTE."
echo "[⏱] Tiempo TOTAL de desinstalación: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "-----------------------------------------------"
echo "Log completo disponible en:"
echo "  $LOG_FILE"
echo "===================================================="
