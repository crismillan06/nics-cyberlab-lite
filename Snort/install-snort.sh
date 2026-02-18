#!/bin/bash
# =========================================================
#  Instalación completa de Snort 3 (local, compilado desde código)
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash install-snort3.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash install-snort3.sh"
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

LOG_FILE="$LOG_DIR/snort-install.log"

# Redirigir salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Instalación automática de Snort 3 (compilado desde código)"
echo " Carpeta de logs: $LOG_DIR"
echo " Log: $LOG_FILE"
echo "===================================================="

set -e

# ===============================
# ACTUALIZACIÓN Y DEPENDENCIAS
# ===============================
echo "[+] Actualizando sistema..."
apt-get update -y
apt-get upgrade -y
apt-get autoremove --purge -y
apt-get autoclean -y

echo "[+] Instalando dependencias de compilación..."
apt-get install -y \
    build-essential cmake pkg-config autoconf automake libtool bison flex git \
    libpcap-dev libpcre3 libpcre3-dev libpcre2-dev libdumbnet-dev zlib1g-dev \
    liblzma-dev openssl libssl-dev libluajit-5.1-dev luajit libtirpc-dev \
    libnghttp2-dev libhwloc-dev

# ===============================
# COMPILAR E INSTALAR libdaq
# ===============================
echo "[+] Compilando libdaq..."
cd /tmp
rm -rf libdaq
git clone https://github.com/snort3/libdaq.git
cd libdaq

./bootstrap
./configure
make -j"$(nproc)"
make install
ldconfig

# ===============================
# COMPILAR E INSTALAR SNORT 3
# ===============================
echo "[+] Compilando Snort 3..."
cd /tmp
rm -rf snort3
git clone https://github.com/snort3/snort3.git
cd snort3

./configure_cmake.sh --prefix=/usr/local/snort3
cd build
make -j"$(nproc)"
make install
ldconfig

ln -sf /usr/local/snort3/bin/snort /usr/local/bin/snort

# ===============================
# CONFIGURACIÓN DE SNORT 3
# ===============================
echo "[+] Configurando Snort 3..."

mkdir -p /etc/snort/rules
cp -r /usr/local/snort3/etc/snort/* /etc/snort/

# snort.lua
tee /etc/snort/snort.lua > /dev/null <<'EOL'
RULE_PATH = "/etc/snort/rules"
LOCAL_RULES = RULE_PATH .. "/local.rules"
daq = { modules = { { name = "afpacket" } } }
ips = { enable_builtin_rules = false, include = { LOCAL_RULES } }
alert_fast = { file = true }
outputs = { alert_fast }
EOL

# Reglas locales
tee /etc/snort/rules/local.rules > /dev/null <<'EOL'
alert icmp any any -> any any (msg:"Intento ICMPv4 detectado"; sid:1000010; rev:1;)
#alert tcp any any -> any any (msg:"Nmap TCP SYN scan"; flow:stateless; flags:S; detection_filter:track by_src, count 5, seconds 20; sid:1000011; rev:2;)
EOL

mkdir -p /var/log/snort
touch /var/log/snort/alert_fast.txt
chmod -R 755 /var/log/snort
chown -R "$LOCAL_USER:$LOCAL_USER" /var/log/snort

# Activar modo promiscuo
ip link set "$(ip route get 8.8.8.8 | awk '/dev/ {print $5}')" promisc on

# ===============================
# AJUSTAR PERMISOS
# ===============================
echo "[+] Ajustando permisos..."
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOG_DIR" 2>/dev/null || true

# ===============================
# TIEMPO TOTAL
# ===============================
SCRIPT_END=$(date +%s)

echo "-----------------------------------------------"
echo "[✔] Instalación de Snort 3 completada."
echo "[⏱] Tiempo TOTAL: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "-----------------------------------------------"
echo "Comandos útiles:"
echo
echo "Terminal 1 – Snort capturando tráfico:"
echo "  sudo snort -i <INTERFAZ> -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort"
echo
echo "Terminal 2 – Ver alertas en tiempo real:"
echo "  tail -f /var/log/snort/alert_fast.txt"
echo
echo "Log completo disponible en:"
echo "  $LOG_FILE"
echo "===================================================="
