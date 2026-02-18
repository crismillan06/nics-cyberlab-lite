#!/bin/bash
# =========================================================
#  Instalación completa de Wazuh (Manager + Indexer + Dashboard)
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash install-wazuh.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash install-wazuh.sh"
    exit 1
fi

LOCAL_USER="$SUDO_USER"
LOCAL_USER_HOME=$(eval echo "~$LOCAL_USER")

echo "INCIANDO DEPLIEGUE DE WAZUH - NICS-CYBERLAB "
echo "----------------------------------------------------"
echo "[i] Usuario real: $LOCAL_USER"
echo "[i] HOME real: $LOCAL_USER_HOME"

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }

# ===== Carpeta de logs =====
LOG_DIR="$LOCAL_USER_HOME/wazuh-logs"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/wazuh-install.log"

# Redirigir toda la salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Instalación automática de Wazuh"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

echo "[+] Actualizando sistema..."
apt-get update -o Acquire::Retries=3
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

echo "[+] Instalando dependencias..."
apt-get install -y curl net-tools gnupg lsb-release apt-transport-https

echo "[+] Descargando instalador oficial de Wazuh..."
cd "$LOCAL_USER_HOME"
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
chmod +x wazuh-install.sh

echo "[+] Ejecutando instalación automática..."
bash ./wazuh-install.sh -a

echo "[+] Esperando a que Wazuh Manager arranque..."
sleep 15

echo "[+] Comprobando estado del servicio wazuh-manager..."
if systemctl is-active --quiet wazuh-manager; then
    echo "[✔] wazuh-manager activo"
else
    echo "[✖] wazuh-manager NO está activo"
    systemctl status wazuh-manager --no-pager
fi

echo "[+] Comprobando puerto 1515..."
netstat -tuln | grep 1515 || echo "[!] puerto 1515 no encontrado."

# =========================
# MOSTRAR DATOS DEL DASHBOARD
# =========================

echo "-----------------------------------------------"
echo "Acceso al Wazuh Dashboard:"

IP_LOCAL=$(hostname -I | awk '{print $1}')
echo "  URL      : https://$IP_LOCAL"
echo "  Usuario  : admin"

if [[ -f "$LOCAL_USER_HOME/wazuh-install-files.tar" ]]; then
    PASS=$(tar -axf "$LOCAL_USER_HOME/wazuh-install-files.tar" wazuh-install-files/wazuh-passwords.txt -O \
        | grep -A1 "'admin'" | tail -n1 | awk -F"'" '{print $2}')
    echo "  Password : $PASS"
else
    echo "  Password : (No encontrada automáticamente)"
fi

echo "-----------------------------------------------"
echo "[✔] Instalación de Wazuh completada."

# ===== Ajustar permisos =====
echo "[+] Ajustando permisos para el usuario local..."
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOCAL_USER_HOME/wazuh-logs" 2>/dev/null || true
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOCAL_USER_HOME/wazuh-install.sh" 2>/dev/null || true
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOCAL_USER_HOME/wazuh-install-files"* 2>/dev/null || true

# ===== Tiempo total =====
SCRIPT_END=$(date +%s)
echo "[⏱] Tiempo TOTAL de instalación: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "===================================================="
echo "Log completo disponible en: $LOG_FILE"
echo "===================================================="
