#!/bin/bash
# =========================================================
#  Desinstalación completa de MITRE Caldera (local)
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

# Redirigir salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Desinstalación automática de MITRE Caldera"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

# ===============================
# DETENER PROCESO DE CALDERA
# ===============================
PID_FILE="$LOG_DIR/caldera.pid"

if [[ -f "$PID_FILE" ]]; then
    CALDERA_PID=$(cat "$PID_FILE")
    if ps -p "$CALDERA_PID" > /dev/null 2>&1; then
        echo "[+] Deteniendo proceso Caldera (PID: $CALDERA_PID)..."
        kill "$CALDERA_PID" || true
        sleep 2
        if ps -p "$CALDERA_PID" > /dev/null 2>&1; then
            echo "[!] Proceso no terminó, forzando..."
            kill -9 "$CALDERA_PID" || true
        fi
        echo "[✔] Proceso Caldera detenido."
    else
        echo "[i] No hay proceso Caldera activo."
    fi
else
    echo "[i] No existe archivo PID, se asume que Caldera no está en ejecución."
fi

# ===============================
# ELIMINAR DIRECTORIOS DE CALDERA
# ===============================
echo "[+] Eliminando directorios de Caldera..."

rm -rf "$LOCAL_USER_HOME/caldera"
rm -rf "$LOCAL_USER_HOME/caldera_venv"

echo "[✔] Directorios eliminados."

# ===============================
# ELIMINAR LOGS Y ARCHIVOS RESIDUALES
# ===============================
echo "[+] Eliminando logs y archivos residuales..."

rm -f "$LOG_DIR/caldera.pid"
rm -f "$LOG_DIR/caldera-server.log"

echo "[✔] Logs eliminados."

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
