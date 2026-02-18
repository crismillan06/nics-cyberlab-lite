#!/bin/bash
# =========================================================
#  Desinstalación completa de Wazuh (Manager + Indexer + Dashboard)
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash uninstall-wazuh.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash uninstall-wazuh.sh"
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
LOG_DIR="$LOCAL_USER_HOME/wazuh-logs"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/wazuh-uninstall.log"

# Redirigir salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Desinstalación automática de Wazuh"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

echo "[+] Deteniendo servicios..."
systemctl stop wazuh-manager 2>/dev/null || true
systemctl stop wazuh-indexer 2>/dev/null || true
systemctl stop wazuh-dashboard 2>/dev/null || true
systemctl stop filebeat 2>/dev/null || true

echo "[+] Deshabilitando servicios..."
systemctl disable wazuh-manager 2>/dev/null || true
systemctl disable wazuh-indexer 2>/dev/null || true
systemctl disable wazuh-dashboard 2>/dev/null || true
systemctl disable filebeat 2>/dev/null || true

echo "[+] Eliminando paquetes..."
apt-get remove --purge -y wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null || true
apt-get autoremove -y
apt-get autoclean -y

echo "[+] Eliminando repositorios y claves..."
rm -f /etc/apt/sources.list.d/wazuh.list
rm -f /etc/apt/sources.list.d/beats.list
rm -f /etc/apt/trusted.gpg.d/wazuh.gpg
rm -f /etc/apt/trusted.gpg.d/beats.gpg

echo "[+] Eliminando directorios residuales..."
rm -rf /var/ossec
rm -rf /etc/wazuh*
rm -rf /etc/filebeat
rm -rf /usr/share/wazuh*
rm -rf /usr/share/filebeat
rm -rf /var/lib/wazuh*
rm -rf /var/lib/filebeat
rm -rf /var/log/wazuh*
rm -rf /var/log/filebeat
rm -rf /opt/wazuh*
rm -rf /opt/wazuh-indexer
rm -rf /opt/wazuh-dashboard

echo "[+] Eliminando archivos generados por el instalador..."
rm -f "$LOCAL_USER_HOME/wazuh-install.sh"
rm -f "$LOCAL_USER_HOME/wazuh-install-files.tar"
rm -rf "$LOCAL_USER_HOME/wazuh-install-files"
rm -f /tmp/wazuh-admin-password

echo "[+] Actualizando índices de paquetes..."
apt-get update -y

# ===== Ajustar permisos =====
echo "[+] Ajustando permisos para el usuario local..."
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOG_DIR" 2>/dev/null || true

echo "-----------------------------------------------"
echo "[✔] Wazuh ha sido desinstalado COMPLETAMENTE."
echo "-----------------------------------------------"

# ===== Tiempo total =====
SCRIPT_END=$(date +%s)
echo "[⏱] Tiempo TOTAL de desinstalación: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo "Log completo disponible en: $LOG_FILE"
echo "===================================================="
