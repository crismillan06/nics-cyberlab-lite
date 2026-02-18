#!/bin/bash
# =========================================================
#  Desinstalación completa de Snort 3 (compilado desde código)
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash uninstall-snort3.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash uninstall-snort3.sh"
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
LOG_DIR="$LOCAL_USER_HOME/snort-logs"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/snort-uninstall.log"

# Redirigir salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Desinstalación automática de Snort 3 (compilado desde código)"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

# ===============================
# DETENER SNORT SI ESTÁ EJECUTÁNDOSE
# ===============================
echo "[+] Comprobando si Snort está en ejecución..."

if pgrep -x "snort" >/dev/null 2>&1; then
    echo "[!] Snort está en ejecución. Deteniéndolo..."
    pkill -9 snort || true
    echo "[✔] Snort detenido."
else
    echo "[i] Snort no está en ejecución."
fi

# ===============================
# ELIMINAR BINARIOS Y LIBRERÍAS
# ===============================
echo "[+] Eliminando binarios y librerías de Snort 3..."

rm -f /usr/local/bin/snort
rm -rf /usr/local/snort3
rm -rf /usr/local/lib/snort
rm -rf /usr/local/lib64/snort
rm -rf /usr/local/include/snort*

echo "[✔] Binarios eliminados."

# ===============================
# ELIMINAR libdaq
# ===============================
echo "[+] Eliminando libdaq..."

rm -rf /usr/local/lib/libdaq*
rm -rf /usr/local/include/daq
rm -rf /usr/local/lib/pkgconfig/daq.pc

echo "[✔] libdaq eliminado."

# ===============================
# ELIMINAR CONFIGURACIÓN Y REGLAS
# ===============================
echo "[+] Eliminando configuración de Snort..."

rm -rf /etc/snort
rm -rf /var/log/snort

echo "[✔] Configuración eliminada."

# ===============================
# LIMPIEZA DE ARCHIVOS TEMPORALES
# ===============================
echo "[+] Eliminando directorios temporales..."

rm -rf /tmp/snort3
rm -rf /tmp/libdaq

echo "[✔] Directorios temporales eliminados."

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
echo "[✔] Snort 3 ha sido desinstalado COMPLETAMENTE."
echo "[⏱] Tiempo TOTAL de desinstalación: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "-----------------------------------------------"
echo "Log completo disponible en:"
echo "  $LOG_FILE"
echo "===================================================="
