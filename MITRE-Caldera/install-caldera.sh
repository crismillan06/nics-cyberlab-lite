#!/bin/bash
# =========================================================
#  Instalación completa de MITRE Caldera (local)
# =========================================================

# ===== Comprobación de root =====
if [[ $EUID -ne 0 ]]; then
   echo "[✖] Este script debe ejecutarse como root."
   echo "    Usa: sudo bash install-caldera.sh"
   exit 1
fi

# ===== Detectar usuario real =====
if [[ -z "$SUDO_USER" ]]; then
    echo "[✖] Este script debe ejecutarse con sudo, no como root directo."
    echo "    Usa: sudo bash install-caldera.sh"
    exit 1
fi

LOCAL_USER="$SUDO_USER"
LOCAL_USER_HOME=$(eval echo "~$LOCAL_USER")

echo "[i] Usuario real: $LOCAL_USER"
echo "[i] HOME real: $LOCAL_USER_HOME"

# ===== Timer global =====
SCRIPT_START=$(date +%s)
format_time() { local total=$1; echo "$((total/60)) minutos y $((total%60)) segundos"; }
format_mmss() { printf "%02d:%02d" $(( $1/60 )) $(( $1%60 )); }

# ===== Carpeta de logs =====
LOG_DIR="$LOCAL_USER_HOME/caldera-logs"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/caldera-install.log"

# Redirigir salida al log + pantalla
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo " Instalación automática de MITRE Caldera"
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

echo "[+] Instalando dependencias..."
apt-get install -y python3 python3-venv python3-pip curl git build-essential

# ===============================
# NODE.JS 20
# ===============================
echo "[+] Instalando Node.js 20..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# ===============================
# INSTALACIÓN DE CALDERA
# ===============================
echo "[+] Descargando MITRE Caldera..."
cd "$LOCAL_USER_HOME"

if [[ ! -d "caldera" ]]; then
    git clone https://github.com/mitre/caldera.git --recursive
fi

echo "[+] Creando entorno virtual..."
if [[ ! -d "caldera_venv" ]]; then
    python3 -m venv "$LOCAL_USER_HOME/caldera_venv"
fi

echo "[+] Activando entorno virtual..."
source "$LOCAL_USER_HOME/caldera_venv/bin/activate"

echo "[+] Actualizando pip..."
pip install --upgrade pip

echo "[+] Instalando dependencias Python..."
pip install --break-system-packages -r "$LOCAL_USER_HOME/caldera/requirements.txt"

# ===============================
# PLUGIN MAGMA
# ===============================
echo "[+] Instalando dependencias del plugin Magma..."
cd "$LOCAL_USER_HOME/caldera/plugins/magma"
rm -rf node_modules package-lock.json
npm install vite@2.9.15 @vitejs/plugin-vue@2.3.4 vue@3.2.45 --legacy-peer-deps

# ===============================
# INICIAR CALDERA EN SEGUNDO PLANO
# ===============================
echo "[+] Iniciando Caldera en segundo plano..."

cd "$LOCAL_USER_HOME/caldera"
nohup "$LOCAL_USER_HOME/caldera_venv/bin/python3" server.py --insecure --build > "$LOG_DIR/caldera-server.log" 2>&1 &

CALDERA_PID=$!
echo "$CALDERA_PID" > "$LOG_DIR/caldera.pid"

echo "[✔] Caldera iniciado en segundo plano."
echo "[i] PID del proceso: $CALDERA_PID"
echo "[i] Log del servidor: $LOG_DIR/caldera-server.log"

# ===============================
# ESPERAR A QUE CALDERA ESTÉ LISTO (CONTADOR SIN TIMEOUT)
# ===============================
echo "[+] Esperando a que Caldera esté disponible..."

CALDERA_URL="http://$(hostname -I | awk '{print $1}'):8888/login"
START_WAIT=$(date +%s)

# Limpia la línea al salir (éxito, error, Ctrl+C)
cleanup_wait_line() { printf "\r\033[K"; }
trap cleanup_wait_line EXIT

while true; do
    # -f: falla si HTTP no es 2xx/3xx
    # --max-time: evita cuelgues
    if curl -fs --max-time 2 -o /dev/null "$CALDERA_URL" >/dev/null 2>&1; then
        break
    fi

    NOW=$(date +%s)
    ELAPSED=$((NOW - START_WAIT))

    # Contador en la misma línea (solo transcurrido)
    printf "\r⏱︎:: %s\033[K" "$(format_mmss "$ELAPSED")"

    sleep 3
done

# Quita el trap y deja la salida limpia
trap - EXIT
printf "\r\033[K"
echo "[✔] Caldera está listo y accesible."

# ===============================
# AJUSTAR PERMISOS
# ===============================
echo "[+] Ajustando permisos..."
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOCAL_USER_HOME/caldera" 2>/dev/null || true
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOCAL_USER_HOME/caldera_venv" 2>/dev/null || true
chown -R "$LOCAL_USER:$LOCAL_USER" "$LOG_DIR" 2>/dev/null || true

# ===============================
# TIEMPO TOTAL + RESUMEN FINAL
# ===============================
SCRIPT_END=$(date +%s)

# IP "bonita" (informativa)
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"

echo "-----------------------------------------------"
echo "[✔] Instalación de Caldera completada."
echo "[⏱] Tiempo TOTAL: $(format_time $((SCRIPT_END-SCRIPT_START)))"
echo "-----------------------------------------------"
echo "Acceso Caldera:"
echo "  Local    : http://127.0.0.1:8888"
if [[ -n "${HOST_IP:-}" ]]; then
  echo "  Red      : http://$HOST_IP:8888"
fi
echo "  Usuario  : admin"
echo "  Password : admin"
echo
echo "Para detener Caldera:"
echo "  kill \$(cat $LOG_DIR/caldera.pid)"
echo
echo "Para levantar Caldera de forma manual, tras reiniciar el equipo o matar el proceso:"
echo "  cd ~/caldera"
echo "  ~/caldera_venv/bin/python3 server.py --insecure"
echo
echo "Log completo disponible en:"
echo "  $LOG_FILE"
echo "===================================================="
