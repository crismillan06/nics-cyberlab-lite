# 🧪 Laboratorio Práctico con Diferentes Niveles — NICS | CyberLab

> **Aviso de uso responsable:** todo lo descrito está orientado a un **entorno de laboratorio autorizado y controlado**. No reutilice procedimientos fuera de un contexto permitido.

## Índice
- [Introducción](#introducción)
- [Visión general de los escenarios](#visión-general-de-los-escenarios)
  - [Level-01 – Mini SOC: detección y monitorización](#level-01--mini-soc-detección-y-monitorización)
- [Normas generales del laboratorio](#normas-generales-del-laboratorio)
- [Metodología de trabajo y evidencias](#metodología-de-trabajo-y-evidencias)
- [Logs y verificaciones](#logs-y-verificaciones)
---
- [Ejercicio 1 — Snort: detección de tráfico ICMP](#ejercicio-1--snort-detección-de-tráfico-icmp)
- [Ejercicio 2 — Wazuh: agentes, integración de logs y dashboard](#ejercicio-2--wazuh-agentes-integración-de-logs-y-dashboard)
- [Ejercicio 3 — MITRE Caldera: ataque básico y detección en Wazuh](#ejercicio-3--mitre-caldera-ataque-básico-y-detección-en-wazuh)
- [Ejercicio 4 — Simulación Mini SOC: escaneo de reconocimiento con Nmap](#ejercicio-4--simulación-mini-soc-escaneo-de-reconocimiento-con-nmap)
- [Ejercicio 5 — Reglas personalizadas en Snort y Wazuh](#ejercicio-5--reglas-personalizadas-en-snort-y-wazuh)
- [Ejercicio 6 — Ataque de fuerza bruta contra servicio SSH](#ejercicio-6--ataque-de-fuerza-bruta-contra-servicio-ssh)
- [Ejercicio 7 — Diseño e implementación de estrategia defensiva ante ataques a SSH](#ejercicio-7--diseño-e-implementación-de-estrategia-defensiva-ante-ataques-a-ssh)
- [Ejercicio 8 — Creación de un KPI operativo basado en un ataque real](#ejercicio-8--creación-de-un-kpi-operativo-basado-en-un-ataque-real)
- [Investigación Opcional — MITRE Caldera (profundización teórico-práctica)](#investigación-opcional--mitre-caldera-profundización-teórico-práctica)

---

## Introducción

Este documento recoge los **escenarios prácticos y ejercicios** asociados a los distintos niveles del laboratorio **NICS | CyberLab**. El objetivo es guiar prácticas **realistas, progresivas y alineadas con el trabajo de un SOC**, combinando simulación ofensiva controlada y capacidades defensivas (detección, correlación y mejora).

Cada nivel parte de un despliegue automatizado y refuerza el ciclo operativo:

**detección → investigación → mejora → reporte**

## Visión general de los escenarios

El laboratorio se estructura en **niveles progresivos**, donde cada nivel amplía o profundiza en los conceptos del anterior.

### Level-01 – Mini SOC: detección y monitorización

Nivel orientado a la **aclimatación y familiarización** con herramientas y tareas básicas de un **SOC**, mediante un entorno **controlado** desplegado en OpenStack. El foco del Level-01 no es “hacer de pentester”, sino **aprender el flujo operacional**: generar actividad → observar telemetría → investigar → documentar.

#### **Nodos principales**

* **Nodo víctima (IDS):** Snort _v.3.10.2.0_
  * S.O: Debian 12
  * Configuración de recursos _(mínimo requerido)_:
    * 1CPU
    * 2GB de RAM
    * 20GB de Disco

* **Nodo monitor (SIEM/XDR):** Wazuh _v.4.9.2_ (Manager + Dashboard)
  * S.O: Debian 12 
  * Configuración de recursos _(mínimo requerido)_:
    * 2CPU
    * 4GB de RAM
    * 40GB de Disco

* **Nodo atacante (Adversary Emulation):** MITRE Caldera _v.5.3.0-52_
  * S.O: Debian 12 
  * Configuración de recursos _(mínimo requerido)_:
    * 1CPU
    * 2GB de RAM
    * 20GB de Disco

**Flujo operativo (qué se entrena)**

1. **Generación de actividad** (tráfico y acciones controladas).
2. **Detección primaria** (alertas IDS / logs).
3. **Ingesta y correlación** en SIEM/XDR (eventos centralizados).
4. **Investigación rápida** (búsqueda, filtros, timeline).
5. **Evidencias + conclusión** (qué pasó, por qué importa, cómo se mejora).

**Qué aprende el alumnado (competencias)**

* Detectar tráfico y actividad sospechosa en un entorno realista.
* Localizar y analizar **logs**, eventos y alertas.
* Correlacionar eventos (relación **origen → acción → evidencia → alerta**).
* Documentar evidencias con criterio (capturas, timestamps, agente, regla, severidad).

#### Expliación del escenario

Este Level-01 se apoya en un “mini SOC” con ruta simple, pero suficiente para entender el ciclo completo.

**Nodos / componentes**

* **Atacante (emulación controlada):** genera acciones representativas (p. ej. comandos remotos, reconocimiento, pruebas de conectividad).
* **Víctima (telemetría + IDS):** inspecciona tráfico y genera alertas (IDS) + eventos de sistema.
* **Monitor (SIEM/XDR):** centraliza, normaliza y permite investigar (dashboards, hunting, eventos).

**Flujo didáctico**

1. **Provoca actividad** desde el nodo atacante (tráfico y/o ejecución controlada).
2. **Comprueba** si Snort genera alertas (visibilidad inmediata en logs).
3. **Integra y valida** que Wazuh recibe esa telemetría (agente activo + eventos).
4. **Investiga** en Wazuh (Threat Hunting / Events) filtrando por agente y rango temporal.
5. **Entrega evidencias** (capturas de alertas/eventos + detalle de regla y severidad) y redacta **conclusión técnica**.

#### Nota importante (alcance y recursos)

El Level-01 está diseñado para ser **simple y consistente**: prioriza que el alumnado domine el flujo end-to-end antes de añadir complejidad. Aun así, el mismo esquema permite crecer en dificultad según recursos disponibles (más fuentes de logs, más reglas, más escenarios, más volumen de eventos), sin cambiar la base del laboratorio.

---

## Normas generales del laboratorio

Estas normas aplican a **todos los niveles** del laboratorio **NICS | CyberLab** y se han redactado para que tengan sentido directo en los ejercicios (simulación ofensiva controlada + defensa/SOC), alineando prácticas con **ENS (España)**, **NIS2 (UE)** y **RGPD (UE)**.

### 1) Alcance, autorización y uso aceptable (NICS | CyberLab)

* **Uso exclusivamente educativo** y **solo dentro del entorno autorizado** (proyecto OpenStack/laboratorio asignado).
* Queda **prohibido** ejecutar técnicas, herramientas o tráfico ofensivo **fuera del laboratorio** (infraestructura externa, redes corporativas, terceros, etc.).
* La actividad “red” (Caldera/Nmap/Hydra/…) se considera **simulación controlada**: se limita a lo necesario para generar telemetría y evidencias SOC (sin objetivos “de impacto”).
* **Reglas de Engagement (RoE) de laboratorio**:

  * sin DoS/estrés deliberado,
  * sin persistencia innecesaria,
  * sin exfiltración de datos,
  * sin escaneo masivo fuera del rango/objetivo indicado,
  * sin reutilizar credenciales fuera del entorno.

### 2) Principios operativos tipo ENS (seguridad por diseño en el LAB)

En los ejercicios se trabaja bajo un enfoque de **gestión de riesgos** y ciclo **prevención → detección → respuesta → recuperación**, con trazabilidad y control del cambio. ([Boletín Oficial del Estado](https://www.boe.es/buscar/act.php?id=BOE-A-2022-7191))

Aplicación práctica en el LAB:

* **Mínimo privilegio**: usar cuentas/roles justos para cada tarea (y documentar cuándo/por qué se eleva).
* **Trazabilidad**: todo cambio relevante (reglas Snort/Wazuh, parsers, configuración) debe quedar reflejado en evidencias.
* **Reversibilidad**: si se activa una regla o ajuste, se registra el *antes/después* y cómo se revierte.

### 3) Gestión de incidentes y notificación (NIS2)

[NIS2](https://www.nis-2-directive.com/) introduce disciplina de **notificación por fases**. En el laboratorio **no se notifica a autoridades**, pero **se entrena el formato** como entregable:

* **Aviso temprano (early warning)**,
* **Notificación de incidente**,
* **Informe final** (y, si procede, **intermedios/progreso**).

Regla didáctica (para que encaje con los ejercicios):

* Si un ejercicio genera una “ruta coherente” (p. ej. Recon → Acceso → Post-Access), el alumnado redacta:

  1. **Early warning** (qué ha pasado + impacto potencial + si parece malicioso),
  2. **Notificación** (IOCs, severidad, alcance, medidas iniciales),
  3. **Informe final** (timeline, causa probable, contención/mitigación, lecciones aprendidas).

### 4) Protección de datos y tratamiento de evidencias (RGPD)

En el LAB, por defecto:

* **No se usan datos personales reales**. Si por diseño del ejercicio aparece información potencialmente personal (usuarios, IPs asociables, logs con identificadores), se aplica **minimización** en el entregable (capturas, informes).
* Las evidencias se almacenan en ubicación controlada (repositorio/carpeta del curso) y con acceso restringido a quienes “necesitan saber” (principio de **confidencialidad**).

**Brechas de datos (en modo formación):** si un escenario simula exposición/compromiso de datos, el alumnado debe elaborar un **borrador de notificación** (qué datos, alcance, medidas), entrenando la lógica de RGPD (notificación “sin dilación indebida” y, cuando aplique, en el marco temporal establecido).

---

## Metodología de trabajo y evidencias

Para **cada ejercicio**, se entrega obligatoriamente:

### Evidencias técnicas

* **Capturas de terminal** (comandos + salida).
* **Logs relevantes** (Snort, Wazuh, sistema, Caldera tasks/output).
* **Capturas de dashboard** cuando aplique (filtros visibles).

Cada evidencia debe permitir reconstruir:

* **Nodo implicado** (hostname/agent.name).
* **Herramienta/acción** (comando, ability, rule.id).
* **Momento del ejercicio** (timestamp o rango temporal del dashboard).

### Conclusión técnica

Al final de cada ejercicio, incluir:

* **Acción realizada** (qué se ejecutó y dónde).
* **Eventos generados/detectados** (qué reglas saltaron, severidad, correlación).
* **Valor operativo SOC** (triage, hipótesis, respuesta, hardening/mejora propuesta).

---

## Logs y verificaciones

### Consultas recomendadas

Observe siempre los **logs personalizados** generados por los scripts de instalación en cada una de las **VMs**, además de los **logs de ejecución** de cada herramienta.

> ℹ️ **Importante:** los scripts usan `SUDO_USER`, por lo que los logs de instalación se guardan en el **HOME del usuario que lanzó el script con `sudo`** (por ejemplo: `/home/usuario/...`), no en `/root`.


### 1) Wazuh (`wazuh-manager`)

#### Log personalizado de instalación (generado por el script)

```bash
cat ~/wazuh-logs/wazuh-install.log
```

#### Ver log en tiempo real (recomendado durante instalación)

```bash
tail -f ~/wazuh-logs/wazuh-install.log
```

#### Log operativo de Wazuh Manager (servicio)

```bash
sudo tail -f /var/ossec/logs/ossec.log
```

#### Comprobaciones útiles (servicio/puertos)

```bash
sudo systemctl status wazuh-manager --no-pager
sudo ss -tulpn | grep -E '1514|1515|55000|443'
```

### 2) Snort (`snort-server`)

#### Log personalizado de instalación (generado por el script)

```bash
cat ~/snort-logs/snort-install.log
```

#### Ver log en tiempo real (recomendado durante instalación/compilación)

```bash
tail -f ~/snort-logs/snort-install.log
```

#### Log de alertas de Snort (runtime)

```bash
tail -f /var/log/snort/alert_fast.txt
```

#### Consultar alertas ya registradas

```bash
cat /var/log/snort/alert_fast.txt
```

#### Comprobaciones útiles

```bash
snort -V
ip link show
ls -l /var/log/snort/
```

> ℹ️ **Nota:** recuerde que `alert_fast.txt` se rellena cuando Snort está ejecutándose y capturando tráfico con una regla que dispare alertas.

### 3) MITRE Caldera (`caldera-server`)

#### Log personalizado de instalación (generado por el script)

```bash
cat ~/caldera-logs/caldera-install.log
```

#### Ver log en tiempo real (recomendado durante instalación)

```bash
tail -f ~/caldera-logs/caldera-install.log
```

#### Log del servidor Caldera (ejecución en segundo plano)

```bash
tail -f ~/caldera-logs/caldera-server.log
```

#### Consultar PID guardado por el script

```bash
cat ~/caldera-logs/caldera.pid
```

#### Comprobaciones útiles (proceso/puerto)

```bash
ps -ef | grep -i caldera | grep -v grep
ss -tulpn | grep 8888
curl -I http://127.0.0.1:8888
```

### 4) Consulta rápida de errores (todas las VMs)

Para revisar rápidamente errores comunes en los logs de instalación:

```bash
grep -Ei "error|fail|failed|exception|traceback" ~/wazuh-logs/wazuh-install.log
grep -Ei "error|fail|failed|exception|traceback" ~/snort-logs/snort-install.log
grep -Ei "error|fail|failed|exception|traceback" ~/caldera-logs/caldera-install.log
```

> ℹ️ **Nota:** Ejecute solo el comando correspondiente a la VM en la que se encuentre.

### 5) Recomendación de uso durante el despliegue

Mientras ejecuta cada instalador, mantenga otra terminal abierta con:

```bash
tail -f ~/nombre-carpeta-logs/*.log
```

Ejemplos:

```bash
tail -f ~/wazuh-logs/wazuh-install.log
tail -f ~/snort-logs/snort-install.log
tail -f ~/caldera-logs/caldera-install.log
```

---

## Ejercicio 1 — Snort: detección de tráfico ICMP 

### Objetivo

Verificar detección de tráfico **ICMP (ping)** y generación de alertas en formato rápido (`alert_fast`) en tiempo real.

### Prerrequisitos

* Acceso SSH al **nodo víctima (Snort)**.
* IP de la interfaz de red del nodo Snort (receptora del ping).
* Host con conectividad para ejecutar el ping (nodo atacante o cliente externo).

### Preparación e identificación (Nodo Snort)

Identificación de interfaz e IP 

En el **nodo Snort**, ejecute:

```bash
ip a
```

* Identifique la interfaz conectada a la red del laboratorio (por ejemplo, `ens3`).
* Anote la IP asignada (por ejemplo, `10.0.0.X`).

> A partir de aquí se asume `ens3`. Sustituya la interfaz si corresponde.

---

### Ejecución

> Este ejercicio se realiza con **tres terminales** (dos en Snort y una en el atacante/cliente).

#### Terminal 1 (Nodo Snort) — Arranque de Snort capturando tráfico

Inicie Snort en modo captura usando:

* interfaz `ens3`
* configuración `/etc/snort/snort.lua`
* salida rápida `alert_fast`
* logs en `/var/log/snort`

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

**Observación esperada**

* Arranque sin errores.
* Proceso en ejecución (no devuelve prompt).

**Si falla**

* Verifique interfaz, permisos y ruta de configuración.

#### Terminal 2 (Nodo Snort) — Monitorización de alertas en tiempo real

En otra sesión SSH al mismo nodo, monitorice:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

**Observación esperada**

* Espera de nuevas líneas.
* Aparición de entradas cuando exista coincidencia de reglas.

> Si el fichero no existe, valide el arranque de Snort y la ruta de logs (`-l /var/log/snort`).

#### Terminal 3 (Cliente externo o Nodo atacante) — Generación de ICMP (ping)

Ejecute:

```bash
ping -c 4 <IP_tarjeta_snort>
```

Ejemplo:

```bash
ping -c 4 10.0.0.25
```

**Resultado esperado**

* Aparición de alertas ICMP en `alert_fast.txt`.

**Criterio de éxito**

* Snort capturando en Terminal 1.
* Alertas visibles en Terminal 2 al ejecutar ping en Terminal 3.

---

### Validación / Troubleshooting (si no aparece alerta)

1. Confirmar llegada de ICMP a la interfaz:

```bash
sudo tcpdump -ni ens3 icmp
```

2. Confirmar escritura de logs:

```bash
ls -lah /var/log/snort/
```

3. Confirmar reglas ICMP habilitadas según set de reglas instalado.

### Evidencias a entregar

Capture pantalla o copie salida de:

* Snort en ejecución (Terminal 1)
* alertas en `alert_fast.txt` (Terminal 2)
* salida del ping (Terminal 3)

### Conclusión final

Incluya:

* Acción realizada (ping + captura IDS)
* Evidencia generada (alerta en `alert_fast`)
* Valor SOC (detección inicial + base de integración con SIEM)

---

## Ejercicio 2 — Wazuh: agentes, integración de logs y dashboard

### Objetivo

1. Ubicar y utilizar módulos clave del **Dashboard de Wazuh** (agentes, hunting, eventos).
2. Desplegar un **agente** desde la GUI del Manager.
3. Configurar el **Wazuh Agent** (nodo Snort) para ingerir logs de Snort (`alert_fast.txt`).
4. Verificar en el Dashboard la llegada de eventos y documentar evidencias.

### Prerrequisitos

> La IP/URL y credenciales del Dashboard se obtienen del despliegue (por ejemplo, `log/level.log`).

* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Acceso SSH al **nodo Snort**.
* IP/hostname del **Wazuh Manager** alcanzable desde el nodo Snort.
* IP del nodo Snort para generar ICMP en la validación.

---

### 2.1. Preparación e identificación (Dashboard)

#### Identificación de Endpoints Summary

1. Acceda al Dashboard e inicie sesión.
2. Navegue a: **☰ → Server management → Endpoints Summary**
3. Observe el listado de agentes.

**Evidencie**

* Capture la vista **Endpoints Summary**.

#### Identificación de Threat Hunting

Ubique: **☰ → Threat Intelligence → Threat Hunting**

No ejecute búsquedas todavía; únicamente localice el módulo.

**Evidencie**

* Capture la pantalla de **Threat Hunting**.

### 2.2. Ejecución

#### Inicio del asistente de despliegue (Dashboard / Wazuh Manager)

1. Acceda a **☰ → Server management → Endpoints Summary**
2. Pulse **+ Deploy new agent**

**Evidencie**

* Capture el inicio del **asistente guiado** de despliegue (“Deploy new agent”).

#### Completar el asistente y obtener comandos (Dashboard / especificación)

Complete el asistente. Habitualmente se solicitará:

1. **Sistema operativo del endpoint**

   * Seleccione Linux (si el nodo Snort es Linux).

2. **Dirección del Manager**

   * Indique IP/hostname del Wazuh Manager **alcanzable desde el nodo Snort**.

3. **Nombre del agente**

   * Defina un nombre consistente (por ejemplo, `snort-server`).

4. **Grupo (opcional)**

   * Asigne un grupo (por ejemplo, `soc-lab` o `snort-endpoints`).

5. **Bloque de comandos**

   * Obtenga los comandos generados para:

     * instalar `wazuh-agent` (repositorio + paquete)
     * configurar variables básicas (Manager/Nombre)
     * registrar/enrolar el agente
     * iniciar y habilitar el servicio

> **Nota operativa:** la forma exacta del comando varía por versión (instalación por repositorio, script, o enrolamiento). Ejecute exactamente lo generado por el Dashboard.

**Evidencie**

* Capture la pantalla donde se visualicen los **comandos generados**.

#### Ejecución de comandos del asistente (Nodo Snort)

Conéctese por SSH al **nodo Snort** y ejecute el bloque de comandos generado por el Dashboard.

**Evidencie**

* Capture la salida que muestre instalación/registro sin errores.

#### Verificación del estado del servicio (Nodo Snort)

```bash
sudo systemctl status wazuh-agent
```

Si no está activo:

```bash
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent
```

**Evidencie**

* Capture `status` mostrando **active (running)**.

#### Verificación del agente en el Dashboard

Regrese al Dashboard:

* **☰ → Server management → Endpoints Summary**
* Localice el agente por nombre y valide:

  * estado **Active/Connected**
  * “last keep alive” reciente

**Evidencie**

* Capture el agente en estado **Active**.

### 2.3. Integración de Snort (Nodo Snort)

#### Configuración de ingesta en el agente: lectura de `alert_fast.txt`

> Este apartado puede estar **ya realizado** en el entorno. Proceda así:
>
> * Si ya existe el bloque `localfile`, **visualice y evidencie** la configuración.
> * Si no existe, **genere uno nuevo** para el agente creado.

Edite la configuración:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Localice la sección:

```xml
<!-- Log analysis -->
```

Añada o verifique:

```xml
<!-- Log analysis -->
  <localfile>
    <log_format>snort-fast</log_format>
    <location>/var/log/snort/alert_fast.txt</location>
  </localfile>
```

**Evidencie**

* Capture el fragmento de `ossec.conf` donde se visualice `<localfile>`.


#### Reinicio del agente (Nodo Snort)

```bash
sudo systemctl restart wazuh-agent && sudo systemctl status wazuh-agent
```

**Evidencie**

* Capture el `status` tras el reinicio (servicio activo).

### 2.4. Validación end-to-end (Snort → Wazuh)

#### Generación de eventos en Snort (Nodo Snort)

Arranque Snort:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

#### Visualización de logs de Snort en vivo (Nodo Snort)

En otra terminal:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

**Evidencie**

* Capture el `tail -f` mostrando entradas nuevas.

#### Generación de ICMP desde un cliente (externo o nodo atacante)

```bash
ping -c 4 <IP_tarjeta_snort>
```

**Evidencie**

* Capture la salida del `ping`.

### 2.5. Visualización en Wazuh (Eventos y Threat Hunting)

#### Acceso a Threat Hunting y selección del agente

En el Dashboard:

1. Acceda a **☰ → Threat Intelligence → Threat Hunting**
2. Seleccione el agente `snort-server` (o el nombre definido)
3. Ajuste el rango temporal a **Last 15 minutes** (amplíe si hubo pausas)

**Evidencie**

* Capture **Threat Hunting** con agente seleccionado y rango temporal visible.

#### Ruta de “Events” y validación alternativa

Según versión, los eventos también se consultan desde:

* **☰ → Threat Intelligence → Threat Hunting → Events**

**Evidencie**

* Capture la vista **Events/Discover** con eventos listados y rango temporal visible.

#### Filtrado de eventos relacionados con Snort

En Threat Hunting o Events/Discover, aplique filtros típicos:

* palabra clave: `snort`
* fragmentos del mensaje del log
* filtro por agente/host (cuando exista selector)

**Evidencie**

* Capture la lista de eventos evidenciando que corresponden a Snort.

#### Revisión del detalle de un evento

Abra un evento y revise:

* timestamp
* agente/host
* mensaje/payload
* campos relevantes (si se muestran)

**Evidencie**

* Capture el detalle del evento.

---

### Limpieza (recomendable)

#### Eliminación del agente

> Realice esta limpieza especialmente si se repetirán despliegues o si se requiere dejar el entorno estable.

En el nodo Wazuh a través del terminal:

```bash
sudo /var/ossec/bin/manage_agents
```

Acciones típicas:

* listar agentes
* seleccionar agente a eliminar
* confirmar eliminación

**Evidencie**

* Capture la pantalla donde se observe la eliminación.

### Conclusión final

Redacte una conclusión técnica:

* Integración realizada (agente registrado y activo).
* Log integrado (`/var/log/snort/alert_fast.txt`) y mecanismo de ingesta (`localfile` con `snort-fast`).
* Validación end-to-end (alerta Snort generada por ping y evento visible en Wazuh).
* Utilidad SOC (detección, trazabilidad, triage y base para casos de uso/reglas).

---

## Ejercicio 3 — MITRE Caldera: ataque básico y detección en Wazuh

### Objetivo

Ejecutar una **operación básica de ataque** desde **MITRE Caldera** contra el nodo víctima y verificar si la actividad generada es **detectada y registrada en Wazuh**.

El ejercicio permite comprender el flujo:

> **ataque (Caldera) → ejecución en víctima → telemetría → detección (Wazuh)**

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Acceso al **Dashboard de MITRE Caldera** (nodo atacante).
* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Agente de Caldera **activo** en el nodo víctima (Snort).
* Agente de Wazuh **instalado y operativo** en el nodo Snort.

---

### 3.1. Preparación e identificación (Caldera + Wazuh)

#### Acceso al Dashboard de MITRE Caldera

Desde un navegador, acceda a:

```
http://IP_CALDERA:8888
```

Autentíquese con las credenciales del laboratorio.

**Observación esperada**

* Acceso correcto al Dashboard.
* Visualización del menú lateral (Agents, Operations, Adversaries, etc.).

#### Verificación del agente en Caldera

En el Dashboard de Caldera:

1. Acceda a **Agents**.
2. Identifique el agente correspondiente al **nodo víctima (Snort)**.

**Observación esperada**

* Agente visible.
* Estado **Alive** (activo).

> Si el agente no está activo, **no continúe** con el ejercicio.

**Evidencie**

* Capture el listado de **Agents** donde se vea el agente del nodo Snort en estado **Alive**.

### 3.2. Ejecución (Caldera)

#### Creación de la operación básica

Acceda a **Operations** y seleccione **New Operation**.

Configure la operación con los siguientes parámetros:

* **Name:** `XXxx-ataque-basico`
* **Group:** `red`
* **Adversary:** `Worm`
* **Planner:** `atomic`
* **Run State:** `Run`

Inicie la operación.

**Observación esperada**

* Operación creada correctamente.
* Estado: en ejecución.

**Evidencie**

* Capture la operación creada (pantalla de **Operations** mostrando el nombre y el estado).

#### Ejecución de comandos desde la operación

Ejecute las siguientes acciones desde la operación creada:

1. **Comando básico de ejecución (MITRE T1059):**

```bash
whoami
```

2. **Comando con impacto en logs (simulación de escalada):**

```bash
sudo su
```

**Resultado esperado**

* Ambos comandos se ejecutan con estado `SUCCESS`.
* La salida es visible desde Caldera.

> El segundo comando está diseñado para **generar telemetría clara**.

**Evidencie**

* Capture la vista de **tasks/abilities** donde se vean los comandos ejecutados con estado **SUCCESS** y su salida.

### 3.3. Validación end-to-end (Caldera → Wazuh)

#### Búsqueda de eventos en Wazuh (Threat Hunting / Events)

Acceda al **Dashboard de Wazuh**:

```
https://IP_WAZUH_DASHBOARD
```

Vaya a:

* **☰ → Threat Intelligence → Threat Hunting → Events** (según versión)

Filtre los eventos por:

* `agent.name` → nodo Snort (por ejemplo, `snort-server`)
* Rango temporal → últimos **10–15 minutos** (amplíe si hubo pausas)

**Observación esperada**

* Eventos relacionados con:

  * uso de `sudo`
  * ejecución de comandos / elevación de privilegios
  * cambios de usuario / contexto (según telemetría disponible)

**Evidencie**

* Capture la lista de eventos filtrada por el agente Snort y el rango temporal visible.

#### Correlación ataque → detección (validación mínima)

Identifique al menos una alerta/evento y documente:

* **Regla** que ha generado la alerta (`rule.id` y `rule.description`).
* **Nivel de severidad** (`rule.level`).
* **Timestamp** (`timestamp`) del evento/alerta.
* Asociación correcta al host:

  * `agent.name = snort-server` (o el nombre definido)

**Criterio de éxito**

* La actividad ejecutada desde Caldera es visible en Wazuh.
* Los eventos están correctamente asociados al nodo Snort.

**Evidencie**

* Capture el detalle del evento donde se vean `rule.id`, `rule.level`, `timestamp` y `agent.name`.

---

### Validación / Troubleshooting (si no aparece evento en Wazuh)

En el nodo Snort:

```bash
sudo systemctl status wazuh-agent
sudo tail -f /var/ossec/logs/ossec.log
```

Revise también:

* que el agente seleccionado en Wazuh es el correcto (`agent.name`)
* que el rango temporal en el Dashboard incluye el momento del ataque

### Evidencias a entregar

Documente o capture:

* Agente activo en Caldera (Alive).
* Operación creada y en ejecución.
* Comandos ejecutados (tasks en `SUCCESS` con salida visible).
* Eventos correspondientes en Wazuh (misma ventana temporal), mostrando:

  * `rule.id`, `rule.level`, `timestamp`, `agent.name`.

### Conclusión final

Incluya:

* Qué se ejecutó desde Caldera y sobre qué nodo.
* Qué telemetría se generó y cómo se observó en Wazuh.
* Qué regla(s) se activaron (`rule.id`, `rule.level`) y por qué.
* Valor SOC: trazabilidad ataque→evento, base para detecciones y casos de uso.

---

## Ejercicio 4 — Simulación Mini SOC: escaneo de reconocimiento con Nmap

### Objetivo

Simular un **ataque de reconocimiento** mediante **Nmap (SYN scan)** ejecutado desde **MITRE Caldera** contra el nodo víctima (Snort) y analizar:

1. La **ausencia de detección** cuando las reglas están desactivadas.
2. La **detección correcta** tras activar reglas en **Snort y Wazuh**.

El ejercicio ilustra el flujo completo de un **Mini-SOC**:

> **reconocimiento (Caldera) → ejecución → logs → correlación → alerta (Wazuh)**

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Acceso al **nodo atacante** (Caldera).
* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Agente de Wazuh **operativo** en el nodo Snort.
* IP del nodo Snort (objetivo del escaneo).

**¡IMPORTANTE!**
Lance en el nodo Snort siempre:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```
> ⚠️ Recuerde que siempre que quiera capturar tráfico tendrá que arrancar Snort con el comando previo.

---

### 4.1. Preparación e identificación (estado inicial)

#### Verificación de Snort en ejecución (Nodo Snort)

Antes de iniciar el ejercicio, asegúrese de que Snort está capturando tráfico:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

**Observación esperada**

* Snort arranca sin errores y queda en ejecución.

> Si Snort no está corriendo, el ejercicio podría dar un “falso negativo” (no detección por falta de captura).

### 4.2. Ejecución (reconocimiento SIN detección)

#### Ejecución del escaneo Nmap (desde Caldera)

Desde el terminal del nodo Caldera, ejecute una habilidad de **Command Execution (T1059)** mediante el comando:

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

### 4.3. Análisis en Wazuh (sin reglas activas)

Acceda al **Dashboard de Wazuh**.

1. Vaya a **Threat Intelligence → Threat Hunting → Events**.
2. Filtre por:

   * `agent.name` → nodo Snort
   * Rango temporal → últimos 10 minutos

**Resultado esperado**

* [✖] No aparecen alertas de escaneo
* [✖] No existe correlación de Nmap

El SOC **no detecta el reconocimiento**.

> ⚠️ Asegúrese de que el fallo de la detección no haya sido causado por no tener Snort arrancado.

Si es necesario, vuelva a lanzarlo:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

### 4.4. Activación de reglas de detección (Snort + Wazuh)

#### Activar regla en Snort (Nodo Snort)

Primeramente pare Snort si está arrancado monitoreando ya sea, y posteriormente realice los siguientes pasos.

En el nodo Snort:

```bash
sudo nano /etc/snort/rules/local.rules
```

Descomente:

```bash
alert tcp any any -> any any (
    msg:"Posible TCP SYN scan detectado";
    flags:S;
    flow:stateless;
    detection_filter:track by_src, count 5, seconds 20;
    sid:1000011;
    rev:3;
)
```

> Esta regla se descomenta para habilitar explícitamente la detección de escaneos SYN en Snort.

Compruebe su funcionamiento mediante un test:

```bash
# El fichero de configuración de Snort ha cambiado en la versión 3 a snort.lua
sudo snort -T -c /etc/snort/snort.lua
```

Lance de nuevo Snort:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

#### Activar regla en Wazuh (Nodo Wazuh Manager)

En el nodo Wazuh Manager:

```bash
sudo nano /var/ossec/etc/rules/snort_local_rules.xml
```

Descomente el grupo y la regla:

```xml
#<group name="local,snort,network,scan">

  <!-- ICMP Echo Request -->
  <rule id="600001" level="5">
    <match>ICMP Echo Request detectado</match>
    <description>Snort - ICMP Echo Request detected</description>
  </rule>

  #<!-- TCP SYN Scan -->
  #<rule id="600010" level="8">
    #<match>Posible TCP SYN scan detectado</match>
    #<description>Snort - TCP SYN scan activity detected</description>
  #</rule>

  </rule>
#</group>
```

Reinicie Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

### 4.5. Reejecución del reconocimiento (CON detección)

Desde Caldera, ejecute **el mismo comando**:

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

### 4.6. Análisis de detección en Wazuh (detección esperada)

En el Dashboard de Wazuh:

* Filtre por el agente Snort.
* Observe eventos relacionados con:

  * **Nmap TCP SYN scan**
  * Severidad elevada (level 8)

**Resultado esperado**

* [✔] Alerta visible
* [✔] Regla aplicada correctamente
* [✔] Reconocimiento detectado

---

### Validación / Troubleshooting (si no aparece detección)

1. Verifique que Snort está corriendo y escribiendo alertas:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

2. Verifique que la regla de Snort se cargó correctamente:

```bash
sudo snort -T -c /etc/snort/snort.lua
```

3. Verifique reinicio y estado del manager:

```bash
sudo systemctl status wazuh-manager
```

4. Amplíe el rango temporal en Wazuh (**Last 1 hour**) si hubo pausas.

### Evidencias a entregar

Documente o capture:

* Snort arrancado en el nodo Snort (comando y ejecución).
* Ejecución del primer `nmap -sS -Pn` desde Caldera.
* Vista en Wazuh mostrando **ausencia de detección** (sin reglas activas).
* Fragmento de `/etc/snort/rules/local.rules` con la regla descomentada.
* Ejecución de `sudo snort -T -c /etc/snort/snort.lua` (test correcto).
* Fragmento de `/var/ossec/etc/rules/snort_local_rules.xml` con la regla activada.
* Reinicio de `wazuh-manager`.
* Ejecución del segundo `nmap -sS -Pn` desde Caldera.
* Vista en Wazuh mostrando la **detección** (regla/level asociado).

### Conclusión final

Incluya:

* Qué se ejecutó (reconocimiento con Nmap) y desde dónde.
* Diferencia observada **antes vs después** de activar reglas.
* Qué regla(s) permitieron la detección (Snort + Wazuh) y severidad asociada.
* Valor SOC: importancia de casos de uso/reglas, tuning y validación continua.

---

## Ejercicio 5 — Reglas personalizadas en Snort y Wazuh

### Objetivo

Diseñar y probar **reglas personalizadas** en Snort y Wazuh para mejorar la detección de tráfico sospechoso y reducir falsos positivos.

El ejercicio permite comprender el flujo completo de un Mini-SOC:

**tráfico sospechoso controlado (Caldera) → ejecución en víctima (Snort) → telemetría → detección y correlación (Wazuh)**

Se busca que el alumnado:

* Ajuste firmas en Snort (ICMP, TCP SYN, Port Knocking).
* Cree reglas personalizadas en Wazuh para correlación de eventos.
* Evalúe la efectividad de la detección y el impacto en falsos positivos.

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Acceso al nodo atacante (Caldera / terminal).
* Acceso al Dashboard de Wazuh (nodo monitor).
* Agente de Wazuh operativo en el nodo Snort.
* IP del nodo Snort (objetivo del tráfico).
* Snort corriendo para capturar tráfico:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

---

### 5.1. Preparación e identificación (estado inicial)

#### Captura activa en Snort (Nodo Snort)

Asegúrese de que Snort está capturando tráfico antes de ejecutar las pruebas:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

> ⚠️ Si Snort no está corriendo, habrá “falsos negativos” (no detección por falta de captura).

#### Preparación del atacante para Port Knocking (`hping3`)

En el nodo atacante, instale `hping3` si no está disponible:

```bash
sudo apt update
sudo apt install -y hping3
```

> ℹ️ Recomendable: crear un script con los 3 envíos (por ejemplo `h3ping.sh`) y darle permisos `+x`.

### 5.2. Ejecución (tráfico CON/SIN detección con reglas actuales)

> En esta fase se busca observar el comportamiento con el set actual de reglas.

#### Prueba ICMP (ping)

```bash
ping -c 4 <IP_NODO_SNORT>
```

#### Prueba TCP SYN (Nmap)

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

#### Prueba Port Knocking (hping3)

Ejecute de forma consecutiva:

```bash
sudo hping3 -S -p 1001 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1002 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1003 <IP_NODO_SNORT> -c 1
```

**Observación esperada en Wazuh**

* [✔] Aparecen alertas de ICMP, TCP SYN.
* [✖] No aparecen alertas de Port Knocking.
* [⚠] Asegúrese de que Snort esté corriendo para capturar tráfico.

### 5.3. Activación de reglas de detección (Snort + Wazuh)

#### Activar reglas en Snort (Nodo Snort)

En el nodo Snort, edite:

```bash
sudo nano /etc/snort/rules/local.rules
```

Configure (o verifique) las reglas existentes y añada la nueva regla para Port Knocking:

```bash
alert icmp any any -> any any (
    msg:"ICMP Echo Request detectado";
    itype:8;
    detection_filter:track by_src, count 3, seconds 20;
    sid:1000010;
    rev:2;
)

alert tcp any any -> any any (
    msg:"Posible TCP SYN scan detectado";
    flags:S;
    flow:stateless;
    detection_filter:track by_src, count 5, seconds 20;
    sid:1000011;
    rev:3;
)

# Inserte aquí bloque con la nueva regla para Port-Knocking
```

> <details>
> <summary><b>ℹ️ Solución:</b></summary>
> alert tcp any any -> any [1001,1002,1003] ( 
> <br>msg:"Posible port knocking detectado";
> <br>flags:S;
> <br>flow:stateless;
> <br>sid:1000022;
> <br>rev:3;
> <br>)
> </details>

Comprobar configuración:

```bash
sudo snort -T -c /etc/snort/snort.lua
```

Lanzar Snort:

```bash
sudo snort -i ens3 -c /etc/snort/snort.lua -A alert_fast -k none -l /var/log/snort
```

#### Activar reglas en Wazuh (Nodo Wazuh Manager)

En el nodo Wazuh Manager, edite:

```bash
sudo nano /var/ossec/etc/rules/snort_local_rules.xml
```

Añada la regla nueva de Port Knocking manteniendo las existentes:

```xml
<group name="local,snort,network,scan">

  <rule id="600001" level="5">
    <match>ICMP Echo Request detectado</match>
    <description>Snort - ICMP Echo Request detected</description>
  </rule>

  <rule id="600010" level="8">
    <match>Posible TCP SYN scan detectado</match>
    <description>Snort - TCP SYN scan activity detected</description>
  </rule>

  <!-- Inserte aquí bloque con la nueva regla para Port-Knocking -->

</group>
```

> <details>
> <summary><b>ℹ️ Solución:</b></summary>
>
> ```xml
> <rule id="600020" level="9">
> <br><match>Posible port knocking detectado</match>
> <br><description>Snort - Port knocking attempt detected</description>
> <br></rule>
> ```
>
> </details>

Reiniciar Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

### 5.4. Reejecución del tráfico (CON detección)

Desde Caldera/atacante, ejecute de nuevo:

**ICMP**

```bash
ping -c 4 <IP_NODO_SNORT>
```

**TCP SYN (Nmap)**

```bash
nmap -sS -Pn <IP_NODO_SNORT>
```

**Port Knocking**

```bash
sudo hping3 -S -p 1001 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1002 <IP_NODO_SNORT> -c 1
sudo hping3 -S -p 1003 <IP_NODO_SNORT> -c 1
```

Visualice los logs de Snort:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

### Resultado esperado en Snort

```
[**] [1:1000010:2] "ICMP Echo Request detectado"
[**] [1:1000011:3] "Posible TCP SYN scan detectado"
[**] [1:1000022:3] "Posible port knocking detectado"
```

### 5.5. Análisis de detección en Wazuh

En el Dashboard de Wazuh:

* Filtre por **agent.name → nodo Snort**
* Observe eventos relacionados con:

| Evento                    | Severidad Wazuh | Observación                  |
| ------------------------- | --------------- | ---------------------------- |
| ICMP Echo Request         | 5               | Ping detectado               |
| TCP SYN scan              | 8               | Escaneo tipo Nmap detectado  |
| Port Knocking (secuencia) | 9               | Secuencia completa detectada |

**Resultado esperado**

* [✔] Alertas visibles.
* [✔] Reglas aplicadas correctamente.
* [✔] Correlación de port knocking generada correctamente.

#### Interpretación de la severidad en Wazuh (rule.level) + relación con fases tipo INCIBE

En Wazuh, la criticidad que aparece en el Dashboard (campo **`rule.level`**, escala **0–15**) representa una **prioridad operativa** asignada por la regla que coincide con el evento.  
No es una “verdad absoluta”: es una forma de decir **qué mirar primero** en un flujo SOC.

Para que el alumnado no se quede solo con el número, en este LAB se interpreta la severidad junto con una lógica **por fases** (modelo tipo INCIBE): un ataque real rara vez es un único evento; suele ser una **secuencia** (ruta) donde cada fase aumenta el riesgo.

##### 1) Guía por rangos (qué significa en triage)

- **0–2 (Muy bajo / Informativo):**  
  Telemetría útil para contexto. Normalmente no dispara acción, pero sirve para reconstruir líneas temporales.

- **3–4 (Bajo):**  
  Actividad relevante pero frecuente. Suele vigilarse por repetición o por correlación con otros eventos.

- **5–6 (Medio):**  
  Señal potencial de actividad sospechosa. Requiere contexto: origen, frecuencia, ventana temporal y si hay continuidad.

- **7–9 (Alto):**  
  Indicadores claros de actividad anómala asociable a ataque (reconocimiento agresivo, patrones intencionados). Debe investigarse con prioridad.

- **10–12 (Muy alto):**  
  Acciones con impacto o fuerte sospecha de compromiso (persistencia, abuso de credenciales, cambios sensibles). Suele requerir escalado.

- **13–15 (Crítico):**  
  Evidencia fuerte de compromiso/impacto grave. En un entorno real suele activar respuesta inmediata.

> ℹ️ **Importante:** el número guía la prioridad, pero el “peligro real” se determina por **contexto** y por **cadena de eventos**. Un level 5 puede ser grave si encaja en una ruta completa.

##### 2) Cómo se conecta con fases tipo INCIBE (ruta completa del ataque)

En el LAB, el alumnado debe pensar en fases (simplificado):

- **Fase A — Reconocimiento:** el atacante identifica puertos/servicios/superficie.
- **Fase B — Acceso / Credenciales:** intenta conseguir credenciales o acceso inicial.
- **Fase C — Acceso remoto / Entrada:** inicia sesión o establece un punto de apoyo.
- **Fase D — Exploración interna (Discovery/Ejecución):** confirma usuario, permisos, red, sistema.
- **Fase E — Escalada / Acciones posteriores:** intenta elevar permisos o preparar persistencia.

La severidad ayuda a ubicar “dónde estamos”:
- Niveles **medios (5–6)** suelen aparecer en **señales tempranas** (inicio o pruebas).
- Niveles **altos (7–9)** suelen encajar con **fase activa** (recon agresivo, patrones claros).
- Niveles **muy altos/críticos (10+)** suelen acercarse a **compromiso o impacto**.

##### 3) Aplicación al ejercicio (por qué 5, 8 y 9 encajan con fases)

En este ejercicio se observan eventos típicos de fase temprana:

- **ICMP Echo Request (level 5) — Señal temprana / Reconocimiento ligero**  
  Puede ser legítimo (diagnóstico) o parte de reconocimiento.  
  Por eso se queda en un nivel medio: **es señal**, pero no confirma ataque por sí sola.

- **TCP SYN scan (level 8) — Reconocimiento activo (Fase A)**  
  El escaneo SYN es un patrón clásico de enumeración de servicios.  
  Aquí el riesgo sube porque suele ser el paso previo a “elegir objetivo”.

- **Port Knocking (level 9) — Acceso intencionado / Preparación de acceso (Fase B–C según contexto)**  
  Una secuencia de puertos específica es poco frecuente en uso normal.  
  Puede interpretarse como una técnica para habilitar un acceso oculto o preparar entrada, por eso se eleva.

> En este punto del LAB todavía no hay “impacto”, pero ya hay **intencionalidad** clara (sobre todo en SYN scan y knocking).

##### 4) Cómo decidir peligrosidad (mini-guía guiada por fases)

Cuando el alumnado vea una alerta debe completar este guion (rápido):

1. **¿En qué fase encaja este evento?**  
   (reconocimiento / acceso / acceso remoto / discovery / escalada)

2. **¿Qué evidencia lo respalda?**  
   (origen IP, repetición, patrón, secuencia, timestamps)

3. **¿Está aislado o forma parte de una ruta?**  
   - Aislado: puede ser ruido o prueba.
   - Ruta: aumenta criticidad (ej.: ICMP → SYN scan → knocking).

4. **¿Qué haría un atacante después? (hipótesis guiada)**  
   Si estamos en Fase A: buscar credenciales o explotar un servicio.  
   Si estamos en Fase B: intentar login/abuso de credenciales.  
   Si estamos en Fase C: ejecutar comandos de discovery, etc.

##### 5) Regla práctica del LAB (cómo “sube” el riesgo)

- **1 evento medio (5–6)**: vigilar y contextualizar.  
- **2 eventos relacionados en <15 min**: tratar como ruta inicial, investigar con prioridad.  
- **3 eventos encadenados (ICMP + SYN + knocking)**: considerar “ruta coherente de ataque” y documentarla por fases (INCIBE) aunque aún no haya compromiso.

---

### Validación / Troubleshooting

1. Verifique que Snort está corriendo y escribiendo alertas:

```bash
sudo tail -f /var/log/snort/alert_fast.txt
```

2. Verifique que las reglas se cargan correctamente:

```bash
sudo snort -T -c /etc/snort/snort.lua
```

3. Verifique reinicio y estado del manager:

```bash
sudo systemctl status wazuh-manager
```

4. En Wazuh, amplíe el rango temporal (**Last 1 hour**) y revise que filtra por el agente correcto.

### Evidencias a entregar

Documente o capture:

* Snort arrancado en el nodo Snort (comando y ejecución).
* Pruebas iniciales (ICMP, Nmap, hping3) y resultados.
* Fragmento de `/etc/snort/rules/local.rules` con las reglas (incluida Port Knocking).
* Ejecución de `sudo snort -T -c /etc/snort/snort.lua` (test correcto).
* Fragmento de `/var/ossec/etc/rules/snort_local_rules.xml` con la regla añadida.
* Reinicio de `wazuh-manager`.
* `tail -f /var/log/snort/alert_fast.txt` mostrando las alertas esperadas.
* Vista en Wazuh mostrando eventos de ICMP, SYN scan y Port Knocking (con severidad).

### Conclusión final

Incluya:

* Qué tráfico se generó (ICMP, SYN scan, Port Knocking) y desde dónde.
* Diferencia observada antes vs después de activar reglas.
* Qué reglas se añadieron/modificaron (Snort + Wazuh) y qué detectan.
* Valor SOC: tuning de firmas, reducción de ruido, priorización y casos de uso reutilizables.

---

## Ejercicio 6 — Ataque de fuerza bruta contra servicio SSH

### Objetivo general

Realizar un ataque de fuerza bruta contra un servicio **SSH** utilizando **Hydra**, con el fin de:

* Comprender el funcionamiento del ataque.
* Identificar evidencias generadas en el sistema.
* Comprobar el nivel de detección inicial del entorno.
* Mapear el ataque con **MITRE ATT&CK**.
* Preparar el escenario para ejercicios defensivos posteriores.

### Contexto

El servicio SSH es uno de los servicios más atacados en entornos reales.
Los ataques de fuerza bruta buscan probar múltiples combinaciones de credenciales hasta encontrar una válida.

Este ejercicio simula este escenario desde el punto de vista ofensivo.

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Acceso al **nodo atacante (Caldera / terminal)**.
* Acceso SSH o conectividad hacia el **nodo objetivo** con SSH expuesto.
* Conocer el **usuario objetivo** (o el usuario configurado en el laboratorio).
* Disponer de Hydra en el nodo atacante (si aplica, instalarlo).
* Acceso al **Dashboard de Wazuh** (nodo monitor) para observar si hay detección.

---

### 6.1. Preparación e identificación (reconocimiento + entorno)

#### Reconocimiento inicial

Antes de lanzar el ataque, el alumnado debe verificar:

* Que el servicio SSH está activo.
* Que el sistema es accesible desde la máquina atacante.
* Qué usuario será el objetivo.

Ejemplos de acciones habituales:

* Comprobación de conectividad.
* Verificación de puertos abiertos.

#### Intro a Hydra

Hydra es una herramienta de fuerza bruta y ataque por diccionario capaz de atacar múltiples protocolos.

Características principales:

* Ataques paralelos.
* Soporte para usuario único o listas.
* Uso de diccionarios personalizados.
* Soporte para SSH, FTP, HTTP, RDP, etc.

#### Diccionarios disponibles en el entorno (nodo Caldera)

En este laboratorio, el alumnado utilizará el **nodo con terminal de CALDERA**, el cual dispone de un conjunto limitado de diccionarios preinstalados como parte del despliegue del entorno.

Visualice los diccionarios disponibles en el nodo Caldera:

```bash
ls -lh wordlists/
```

Características:

* No incluye las librerías completas de Kali Linux.
* Incluye varias wordlists funcionales.
* Una de ellas contiene la contraseña correcta del usuario objetivo.

El alumnado deberá:

* Localizar los diccionarios disponibles.
* Seleccionar cuál utilizar.
* Probar hasta encontrar el que contiene la credencial válida.

Este proceso forma parte del aprendizaje.

### 6.2. Ejecución (ataque con Hydra)

#### Sintaxis básica de Hydra

Estructura general:

```bash
hydra -l <usuario> -P <wordlists/DICCIONARIO> ssh://IP_OBJETIVO
```

Parámetros:

* `-l` → Usuario perteneciente a la máquina objetivo del ataque.
* `-P` → Diccionario de contraseñas utilizado.
* `ssh://` → Servicio objetivo.

Hydra probará cada contraseña hasta encontrar una válida.
Cuando la encuentre, la mostrará en pantalla.

#### Observación del comportamiento

Durante el ataque, el alumnado debe observar:

* Número de intentos.
* Velocidad del ataque.
* Mensajes mostrados por Hydra.
* Tiempo hasta encontrar credencial.

### 6.3. Validación end-to-end (credencial → acceso → detección)

#### Verificación de acceso

Una vez obtenida la contraseña:

```bash
ssh usuario@IP_OBJETIVO
```

Confirmar acceso exitoso.

#### Análisis del impacto

Redacte una reflexión sobre:

* Facilidad del compromiso.
* Qué controles faltan.
* Qué consecuencias tendría en producción.

#### Detección inicial (estado actual)

Compruebe si el entorno:

* Genera alertas.
* Registra eventos visibles.
* Bloquea el ataque.

Lo esperado es que **no exista detección específica**.

> ℹ️ **Nota:** Este resultado será la base para el Ejercicio 7.

### 6.4. Mapeo MITRE ATT&CK y creación del *layout* entregable (ruta completa del ataque)

En este ejercicio el alumnado **no debe mapear solo la fuerza bruta**, sino **la ruta completa** de un ataque coherente con lo visto en el LAB (p. ej. reconocimiento con Nmap → ataque a credenciales → acceso SSH → ejecución/descubrimiento/escalada con comandos).
El resultado final **es un layer entregable** en **ATT&CK Navigator**.

#### Qué se entrega 

1. **Layer de ATT&CK Navigator** (exportada en JSON desde el Navigator).
2. **Capturas** del Navigator con las técnicas marcadas y las notas visibles.
3. **Breve justificación por fases** (modelo tipo INCIBE): describe por fases, enlazando *acción observada → técnica ATT&CK*.

#### 1) Acceso a la matriz y apertura en ATT&CK Navigator

1. Abra la **[Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)**
2. Active **show sub-techniques** (para ver subtécnicas).
3. En la parte superior/derecha, pulse **“View on the ATT&CK® Navigator”**.

   * Esto te lleva al **Navigator**, donde construirás la *layer* entregable.

> **ℹ️ Recomendación:** si en la matriz aparece “Version Permalink”, verifique que se está usando la **misma versión**.

#### 2) Crear la layer en el Navigator

Dentro del Navigator:

1. **Create New Layer** (o “New Layer”).
2. Rellene:
   * **Name**: `LAB-SSH-ataque-completo-<equipo/alumnado>`
   * **Description**: Del escenario (Nmap → Hydra → SSH → comandos).

3. Use el buscador del Navigator para ir añadiendo técnicas:
   * Busque por **ID** (ej. `T1110`) o por **nombre** (ej. “Brute Force”).

4. Para cada técnica marcada:
   * Añade una **nota/comentario** con: *qué hizo*, *con qué herramienta*, *qué evidencia lo prueba* (captura/log).

Al terminar:
* Exporte: **Export / Download layer (JSON)**.

##### Tips de navegación (para técnicas/subtécnicas)

* En la matriz, las **tácticas** son columnas (Reconnaissance, Credential Access, Discovery, Privilege Escalation…).
* Las **técnicas** son tarjetas dentro de cada columna.
* Las **subtécnicas** aparecen al activar **show sub-techniques** y suelen llevar formato `Txxxx.xxx`.
* En el Navigator, lo más rápido es buscar por **ID** cuando ya lo tengas identificado.

#### 3) Construir la “ruta del atacante” por fases (modelo tipo INCIBE)

Aquí no hay que “adivinar”; hay que **formular una hipótesis guiada** y mapear **lo que se ha ejecutado/observado** en el LAB.

Puede usar este guion (rellenable) como una plantilla guía. El alumnado debe completar **todas** las fases con lo que corresponda:

**Fase A — Reconocimiento (qué busca y por qué)**

* Qué propósito tiene el atacante (descubrir exposición, puertos/servicios, superficie).
* Qué hizo en el LAB (ej.: Nmap SYN scan).
* Qué evidencia tienes (comando + salida/captura).
* Qué técnica(s) ATT&CK encajan (ID + nombre, y si aplica subtécnica).

**Fase B — Acceso / Credenciales (qué intenta y cómo)**

* Qué propósito tiene (obtener credenciales válidas).
* Qué hizo (Hydra contra SSH con diccionarios del nodo Caldera).
* Evidencia (comando Hydra + “login found” / resultado).
* Técnica(s) ATT&CK (ID + nombre + subtécnica si aplica).

**Fase C — Acceso remoto (cómo obtiene acceso)**

* Qué propósito tiene (sesión remota interactiva).
* Qué hizo (SSH con credencial válida).
* Evidencia (comando `ssh usuario@IP` + prompt/éxito).
* Técnica(s) ATT&CK.

**Fase D — Ejecución / Descubrimiento (qué información consigue)**

* Qué propósito tiene (confirmar usuario, permisos, sistema, red).
* Qué hizo (ej.: `whoami`, `id`, `uname -a`, `ip a`…).
* Evidencia (salidas en terminal o tareas Caldera si aplica).
* Técnica(s) ATT&CK.

**Fase E — Escalada de privilegios (si aplica en tu ruta)**

* Qué propósito tiene (elevar permisos, root/admin).
* Qué hizo (ej.: `sudo su` si se ejecutó).
* Evidencia (salida del comando / evento Wazuh asociado).
* Técnica(s) ATT&CK.

> ℹ️ **Importante**: si una fase no se ejecutó realmente, el alumnado debe marcarla como **hipótesis** (“qué haría después”) y justificarlo como continuación lógica, pero separando claramente **observado** vs **hipotético** en la nota del Navigator.

#### 4) Plantilla mínima para rellenar

El alumnado debe completar una tabla como esta (y esas mismas notas deben ir en el Navigator por técnica):

* **Fase (INCIBE):**
* **Acción en el LAB:**
* **Herramienta / comando:**
* **Evidencia (captura/log):**
* **Táctica ATT&CK (columna):**
* **Técnica/Subtécnica (ID + nombre):**
* **Justificación:**

---

### Validación / Troubleshooting

* Verifique conectividad hacia el objetivo y que SSH responde.
* Revise que el **usuario** y la **IP** sean correctos.
* Confirme que el diccionario seleccionado existe y tiene permisos de lectura:

```bash
ls -lah wordlists/
```

* Si hay errores de servicio o acceso, valide el estado del objetivo y el puerto 22.

### Evidencias a entregar

* Comando ejecutado (Hydra).
* Resultado de Hydra (credencial encontrada / output).
* Acceso SSH exitoso.
* Logs del sistema (si se revisan).
* Estado del SIEM (si hubo eventos/alertas o no).

### Conclusión final

Explique:

* Qué ocurrió.
* Qué debilidades se evidencian.
* Por qué este escenario es realista.

Resultado esperado:

✔ Obtención de credenciales
✔ Acceso al sistema
✔ Ausencia de detección específica
✔ Ataque correctamente mapeado (MITRE ATT&CK)

---

## Ejercicio 7 — Diseño e implementación de estrategia defensiva ante ataques a SSH

### Objetivo general

Diseñar e implementar una estrategia defensiva que permita:

* Detectar ataques de fuerza bruta contra SSH.
* Generar alertas en el SIEM.
* Mitigar automáticamente el ataque.
* Endurecer el servicio para reducir superficie de exposición.
* Relacionar las defensas con el marco **MITRE D3FEND**.

El alumnado debe transformar el entorno del ejercicio anterior en un sistema capaz de **detectar, responder y resistir** este tipo de ataques.

### Contexto

En el ejercicio previo se comprobó que un ataque de fuerza bruta puede ejecutarse sin generar alertas específicas.

En este ejercicio se busca **cerrar esa brecha**, aplicando controles defensivos a distintos niveles:

* Monitorización
* Respuesta automática
* Endurecimiento del servicio

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Haber completado el **Ejercicio 6** (ataque con Hydra).
* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Acceso SSH al **nodo objetivo** (donde corre SSH) para aplicar hardening si aplica.
* Acceso al **nodo Wazuh Manager** para modificar reglas / respuesta activa si aplica.
* Capacidad de relanzar el ataque (Hydra) desde el nodo atacante para validar.

---

### 7.1. Preparación e identificación (análisis inicial)

#### Análisis inicial del problema

El alumnado debe analizar:

* Qué comportamiento tiene un ataque de fuerza bruta.
* Qué evidencias genera en el sistema.
* Por qué inicialmente no es detectado.

Debe identificar:

* Fuentes de logs relevantes.
* Eventos repetitivos.
* Indicadores de intento de compromiso.

#### Diseño de la estrategia defensiva

Definir una estrategia que combine varios enfoques:

* Detección.
* Mitigación.
* Prevención.

Se espera una breve justificación de por qué se elige cada control.

### 7.2. Ejecución (implementación de controles)

#### Métodos defensivos sugeridos (visión general)

> No obligatorios. Son líneas de trabajo posibles.

**A. Reglas personalizadas en Wazuh**
Consiste en crear reglas que identifiquen patrones asociados a:

* Múltiples intentos fallidos.
* Accesos desde una misma IP.
* Mensajes concretos de autenticación fallida.

Objetivo:

* Elevar eventos a nivel de alerta.
* Clasificarlos como intento de ataque.

**B. Mecanismos de bloqueo automático**
Uso de herramientas que:

* Analizan logs.
* Detectan patrones de abuso.
* Bloquean la IP origen temporal o permanentemente.

Ejemplo conceptual:

* Sistemas tipo fail2ban.

Objetivo:

* Cortar el ataque sin intervención manual.

**C. Hardening del servicio SSH**
Endurecimiento del servicio para reducir probabilidad de compromiso:

Algunas líneas habituales:

* Deshabilitar autenticación por contraseña.
* Usar únicamente autenticación por clave.
* Limitar usuarios permitidos.
* Reducir intentos máximos.
* Cambiar puerto por defecto (medida secundaria).

Objetivo:

* Hacer que el ataque sea inefectivo incluso antes de ser bloqueado.

**D. Correlación y visibilidad**
Asegurar que:

* Los eventos relevantes llegan al SIEM.
* Son visibles.
* Están correctamente clasificados.

#### Implementación

El alumnado implementará los controles seleccionados.

Debe quedar claro:

* Qué se ha modificado.
* Por qué.
* En qué sistema.

No se exige un conjunto concreto de herramientas, solo que se cumpla el objetivo.

### 7.3. Validación (repetición del ataque)

Se debe repetir el ataque del ejercicio anterior y comprobar:

* Aparición de alertas.
* Bloqueo del origen.
* Reducción de intentos exitosos.
* Diferencia de comportamiento respecto al ejercicio previo.

### 7.4. Mapeo MITRE D3FEND (controles defensivos aplicados)

En este ejercicio el alumnado debe **traducir los controles defensivos que ha aplicado** (Wazuh rules/correlación, bloqueos, hardening SSH, etc.) a **técnicas D3FEND**, de forma que quede una **ruta defensiva completa** y justificable.

A diferencia de ATT&CK, en **D3FEND no se entrega una “layer”** como tal. El entregable aquí es un **mapeo documentado** (tabla + evidencias + justificación).

---

#### Qué se entrega

1. **Tabla de mapeo Control → D3FEND** (como mínimo, todos los controles que el alumnado haya aplicado en el Ej. 7).
2. **Capturas** del sitio de D3FEND mostrando las técnicas seleccionadas (o sus fichas) y/o la matriz (Harden / Detect / Isolate).
3. **Evidencia técnica del control aplicado** (snippet de config, captura de Wazuh/SSH/firewall/active response) y justifique el control.

#### 1) Acceso a D3FEND y cómo navegar

1. Abra **[MITRE D3FEND](https://d3fend.mitre.org/)**.

2. Elementos clave de navegación (como en tu captura):

   * **CAD (matriz)** con columnas grandes: **Harden / Detect / Isolate**.
   * Buscador **D3FEND Lookup** (para buscar técnicas por nombre).
   * Buscador **ATT&CK Lookup** (muy útil si quieres partir de técnicas del ataque del Ej. 6).
   * Al hacer clic en una “tarjeta” (técnica), se abre su **ficha** con descripción y relaciones.

**Dos formas válidas de encontrar técnicas:**

* **A) Desde el control defensivo (lo que implementaste):** buscar por palabras clave en **D3FEND Lookup** (ej.: “threshold”, “locking”, “traffic filtering”, “certificate”, “mfa”…).
* **B) Desde el ataque (ATT&CK → D3FEND):** en **ATT&CK Lookup** escribir un ID del ataque (ej.: `T1110`) y usar las contramedidas/relaciones sugeridas para llegar a técnicas D3FEND que lo mitiguen/detecten.

#### 2) Construir el mapeo “defensa por fases” (Harden / Detect / Isolate)

El alumnado debe organizar sus controles en estas **tres fases D3FEND**, explicando qué hace cada una:

* **Harden (Prevención/Reducción de superficie):** endurecer para que el ataque sea más difícil o inútil.
* **Detect (Detección/Visibilidad):** generar señal útil en SIEM (Wazuh), umbrales, correlación, análisis.
* **Isolate (Contención):** cortar el ataque (bloqueo IP, account lock, SG/firewall, active response).

> ℹ️ **Importante**: aquí el alumnado no “elige al azar”. Debe mapear **lo que realmente configuró** en el Ejercicio 7 (y si propone algo extra, debe marcarlo como “hipótesis/mejora”, separado de lo implementado).

#### 3) Plantilla guiada por control (lo que deben rellenar)

Para **cada control** aplicado, completar este bloque (y acompañarlo de capturas):

* **Control aplicado (qué hice):**
* **Dónde lo apliqué (Wazuh / SSH / firewall / SG / etc.):**
* **Evidencia técnica:** (snippet config / captura dashboard / log)
* **Ubicación en D3FEND:** (Harden / Detect / Isolate)
* **Técnica D3FEND seleccionada (ID + nombre):**
* **Justificación:** por qué esa técnica representa tu control y cómo frena/detecta el ataque de fuerza bruta.

#### 4) Tabla base (ejemplo orientativo)

> El alumnado debe completar una tabla así con **sus** controles. Esta es la referencia que ya tenías (se mantiene):

| Control aplicado                                                      | Propósito  | Técnica D3FEND                                                                                              |
| --------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------- |
| Umbral/correlación “N fallos SSH en X” en Wazuh                       | Detección  | **D3-ANET — Authentication Event Thresholding**                                                             |
| Detección por intentos fallidos repetidos                             | Detección  | **D3-CAA — Connection Attempt Analysis**                                                                    |
| Bloqueo por IP (firewall/active response/SG)                          | Contención | **D3-ITF — Inbound Traffic Filtering** *(y/o **D3-NAM — Network Access Mediation** si lo haces con SG/NAC)* |
| Bloqueo por cuenta (si aplica)                                        | Contención | **D3-AL — Account Locking**                                                                                 |
| Endurecer credenciales / política contraseñas (si mantienes password) | Prevención | **D3-CH — Credential Hardening** *(y/o **D3-SPP — Strong Password Policy**)*                                |
| Pasar a claves/certificados / MFA (si aplica)                         | Prevención | **D3-CBAN — Certificate-based Authentication** *(y/o **D3-MFA — Multi-factor Authentication**)*             |

#### 5) Cómo justificarlo “como SOC” (enlace con el ataque del Ej. 6)

La justificación debe conectar **ataque → defensa**:

* Qué parte del ataque frenas (p. ej. “Credential Access / Brute Force”).
* Qué señal produces (Wazuh: umbrales, correlación, alertas).
* Qué acción de contención aplicas (bloqueo IP/cuenta, SG, firewall).
* Qué endurecimiento reduce el riesgo residual (MFA/keys/política contraseñas).

Formato recomendado:

* “Este control reduce/detecta **fuerza bruta SSH** porque…”
* “La evidencia es… (captura/log/config)”
* “Se alinea con D3FEND porque describe exactamente… (nombre técnica)”

---

### Validación / Troubleshooting

* Verifique que los logs relevantes llegan a Wazuh (autenticación SSH).
* Revise que las reglas están cargadas y no hay errores en el manager.
* Si hay bloqueo automático, confirme que la IP se bloquea realmente (firewall/active response).
* Si aplicó hardening (p.ej. deshabilitar password), valide que SSH sigue siendo accesible para administración (evitar auto-bloqueo operativo).

### Evidencias a entregar

* Fragmentos de configuración modificados (reglas, hardening, bloqueo).
* Capturas de eventos/alertas en Wazuh.
* Evidencia del bloqueo (si aplica).
* Comparativa antes vs después (resultado del ataque).

### Conclusión final 

Reflexión final:

* Qué controles fueron más efectivos.
* Qué capa aportó mayor valor.
* Cómo se podría mejorar en un entorno real.

---

## Ejercicio 8 — Creación de un KPI operativo basado en un ataque real

### Objetivo

Diseñar un **KPI operativo propio** a partir de un ataque observado durante el laboratorio (MITRE Caldera → Snort → Wazuh), de forma que:

* Permita **detectar rápidamente la recurrencia del ataque**.
* Facilite el **triage y la reacción de otro analista SOC**.
* Sirva como **indicador continuo** de riesgo operativo.

Este ejercicio simula una tarea real de un SOC **Level 1 / Level 2**: transformar una detección puntual en un **indicador reutilizable**.

### Contexto del ejercicio

Durante los ejercicios anteriores se ha observado un patrón de ataque realista, por ejemplo:

* Ejecución remota de comandos desde Caldera.
* Uso de `sudo` / cambio de privilegios.
* Actividad anómala detectada por reglas de Wazuh.

Este patrón **no se trata como un evento aislado**, sino como un **caso recurrente** que debe ser monitorizado.

### Prerrequisitos

> Las IPs y credenciales pueden consultarse en: `cat log/level.log`

* Haber completado los ejercicios previos (especialmente aquellos que generen eventos claros en Wazuh).
* Acceso al **Dashboard de Wazuh** (nodo monitor).
* Tener al menos un conjunto de eventos reales generados durante el laboratorio (para usar como base del KPI).

---

### 8.1. Preparación e identificación (selección del ataque base)

#### Identificación del ataque observado

Seleccione **un ataque concreto** ejecutado en el laboratorio.

Ejemplos válidos:

* Uso no habitual de `sudo` desde una sesión remota.
* Ejecución de comandos sospechosos (`whoami`, `id`, `uname`).
* Acceso inicial seguido de escalada de privilegios.

Documente brevemente:

* Nodo afectado.
* Técnica MITRE asociada (ej. T1059, T1548).
* Regla(s) de Wazuh que lo detectaron.

> **Este ataque será la base del KPI.**

### 8.2. Definición del KPI operativo

#### Diseño del KPI

El KPI debe responder a una pregunta **accionable**, por ejemplo:

> “¿Con qué frecuencia se detectan intentos de escalada de privilegios desde accesos remotos?”

Defina el KPI con la siguiente estructura:

* **Nombre del KPI**
* **Descripción**
* **Evento o patrón que mide**
* **Fuente de datos**
* **Umbral operativo**
* **Acción recomendada**

#### Ejemplo de definición

**KPI:** `Intentos de escalada de privilegios no esperados`

**Descripción:**
Mide el número de eventos donde se detecta uso de `sudo` o cambio de privilegios en nodos que no deberían realizar tareas administrativas.

**Fuente:**
Wazuh – reglas relacionadas con `sudo` (`rule.id` correspondiente).

**Frecuencia de medida:**
Tiempo real / revisión diaria.

### 8.3. Implementación del KPI en Wazuh

#### Identificación del patrón en Wazuh

Acceda al Dashboard:

**☰ → Threat Hunting → Events**

Filtre por:

* `agent.name`: nodo Snort
* `rule.description` o `full_log` conteniendo `sudo`
* Rango temporal: últimos ejercicios

Verifique que el patrón es **repetible y reconocible**.

#### Definición de umbrales

Defina un umbral simple y claro:

Ejemplo:

* **0–1 eventos / día:** comportamiento esperado.
* **2–3 eventos / día:** revisión manual.
* **>3 eventos / día:** posible incidente → escalar.

Este umbral es parte del KPI y lo convierte en **operativo**, no solo informativo.

---

## Investigación Opcional — MITRE Caldera (profundización teórico-práctica)

Actividad opcional para explorar **capacidades avanzadas de MITRE Caldera** que normalmente no se dominan en la primera toma de contacto. El objetivo no es “tocar botones”, sino entender **cómo funciona por dentro** (modelo de datos + ejecución) y validarlo con **pruebas cortas, repetibles y bien documentadas**.

> Idea: elegir **3–4 bloques** y documentar cada uno con *concepto → prueba → evidencia → conclusión*.  
> Recomendación: usar siempre una convención de nombres (por ejemplo `INV-<bloque>-<grupo>`) para que luego sea fácil localizar operaciones y resultados.

### Qué se entrega

1. **Documento breve** (2–3 páginas) con apartados por bloque.
2. **Capturas** del Dashboard (antes/durante/después) y, si procede, salida de tasks.
3. **Checklist** final de lo probado (probado / pendiente).

### Bloques de investigación (elige 3–4)

#### 1) Modelo mental de Caldera: ¿qué es cada cosa?

**Teoría (qué entender)**

* **Agent:** el “implant” que vive en la máquina víctima y ejecuta lo que Caldera ordena.
* **Ability:** una acción/técnica concreta (equivale a “una pieza” del comportamiento del atacante).
* **Adversary:** un conjunto de abilities ordenadas que representan una ruta o estilo de ataque.
* **Planner:** la lógica que decide cómo se ejecuta esa ruta (orden, selección, reintentos).
* **Operation:** la ejecución real: “esta ruta” sobre “estos agentes” en “este momento”.

**Práctica (qué probar)**

* Identificar en la UI: 1 agent, 3 abilities, 1 adversary y 1 planner.
* Explicar en 3–5 líneas cómo viaja una orden:
  *Operation → Planner → Abilities → Agent → Output*.
* Ejecutar una operación mínima (2–3 abilities) para ver el flujo completo.

**Evidencia**

* Captura del agent + captura de la operación mostrando tasks y output (al menos 2 tasks).

---

#### 2) Agents: estabilidad, permisos y “supervivencia”

**Teoría (qué entender)**

* Un agente no solo “está vivo”: importa **si ejecuta con permisos suficientes**, si mantiene conexión estable y cómo se recupera ante fallos.
* Muchos “fallos de Caldera” en realidad son:
  * permisos insuficientes,
  * binarios/comandos no disponibles,
  * o pérdida de conectividad.

**Práctica (qué probar)**

* Diseñar una mini-prueba de estabilidad:
  * ejecutar 3 tasks seguidas,
  * forzar un fallo controlado (p. ej. cortar conexión/reiniciar host si se permite),
  * observar si vuelve y qué tareas fallan o quedan pendientes.
* Ejecutar 1 ability “simple” y 1 ability que normalmente requiera más privilegios, para ver la diferencia.

**Evidencia**

* Captura de Agents (Alive/Last seen) + captura de tasks con éxito/fallo y su mensaje de error.

---

#### 3) Abilities: qué hacen “de verdad” y qué requieren

**Teoría (qué entender)**

* Una ability no es solo un comando: tiene **plataforma**, **ejecutor**, **condiciones** y devuelve un **output**.
* Dos abilities con “misma intención” pueden generar evidencias muy distintas según:
  * el host,
  * permisos,
  * o el método de ejecución.

**Práctica (qué probar)**

* Seleccionar 5 abilities de categorías distintas (p. ej. discovery / execution / privilege).
* Para cada una, completar:
  * qué intenta conseguir,
  * qué ejecuta exactamente (comando/acción),
  * qué devuelve (output),
  * qué requisito tiene (permisos, binarios, sistema).
* Marcar cuáles son “ruidosas” (generan mucha evidencia) y cuáles más “discretas”.

**Evidencia**

* Captura de cada task con output (o error) + 1 línea de nota por ability.

---

#### 4) Adversaries: construir una ruta coherente

**Teoría (qué entender)**

* Un adversary es el “guion” del atacante: lo importante es la **coherencia** (qué tiene sentido ejecutar y en qué orden).
* La calidad se mide por:
  * secuencia lógica por fases,
  * dependencias claras,
  * y reproducibilidad (que sea repetible con resultados similares).

**Práctica (qué probar)**

* Crear un adversary propio con 4–6 abilities ordenadas por fases:
  * Recon → Discovery → Credential/Access → Post-access.
* Ejecutarlo y comprobar:
  * si se cumple la secuencia,
  * dónde falla,
  * qué dependencia faltaba (permiso, comando, contexto).
* Ajustar 1 vez el adversary para mejorar la tasa de éxito (cambio de orden o sustitución de 1 ability).

**Evidencia**

* Captura del adversary (lista de abilities) + captura de la operación ejecutada (tasks y resultados).

---

#### 5) Planners: misma ruta, resultados distintos

**Teoría (qué entender)**

* El planner define el “cómo”: puede ejecutar de forma simple o más adaptativa (según versión/plugins).
* Cambiar de planner puede afectar:
  * orden real de ejecución,
  * reintentos,
  * y tasa final de éxito.

**Práctica (qué probar)**

* Ejecutar **el mismo adversary** con planners distintos (si el entorno los ofrece) y comparar:
  * orden de tasks,
  * tasa de éxito,
  * tiempos,
  * comportamiento ante fallos.

**Evidencia**

* Tabla comparativa (2 ejecuciones) + capturas de ambas operaciones.

---

#### 6) Facts y encadenamiento: cuando Caldera “usa lo aprendido”

**Teoría (qué entender)**

* Los **facts** permiten automatizar: Caldera guarda datos descubiertos y los reutiliza.
* Esto convierte una operación de “comandos sueltos” en una ruta más realista.

**Práctica (qué probar)**

* Ejecutar una ability que descubra un dato (usuario/host/IP/ruta).
* Ver si aparece como fact.
* Usar ese fact como input en otra ability (encadenamiento simple).
* Si no aparecen facts automáticamente, documentar por qué (parser ausente, output no estructurado, etc.).

**Evidencia**

* Captura del fact + captura de la segunda task usando ese dato.

---

#### 7) Parsers: evitar que todo sea “texto”

**Teoría (qué entender)**

* Sin parsing, el output queda “plano” y no se puede reutilizar.
* Con parsers, el output se convierte en facts (datos) y permite encadenar operaciones.

**Práctica (qué probar)**

* Elegir una ability con output rico (varios campos).
* Identificar 1 dato que debería extraerse siempre (usuario, IP, hostname, ruta…).
* Proponer cómo se extraería (regex conceptual) y dónde encajaría (parser asociado a esa ability).

**Evidencia**

* Captura del output + párrafo proponiendo el dato a extraer, regex conceptual y utilidad.

---

#### 8) Plugins: ampliar capacidades (sin entrar en instalación)

**Teoría (qué entender)**

* Caldera es modular: los plugins pueden añadir planners, abilities, pantallas o funcionalidades.
* Entender plugins sirve para saber qué capacidades “no se ven” si no están instaladas.

**Práctica (qué probar)**

* Listar plugins visibles en el entorno.
* Elegir 1 plugin y explicar:
  * qué añade,
  * qué casos de uso habilita,
  * qué complejidad introduce (operación, mantenimiento, aprendizaje).

**Evidencia**

* Captura del listado + mini ficha del plugin.

### Plantilla de ejemplo

Para cada bloque seleccionado, redactar:

* **Concepto:** qué es y por qué importa en Caldera.
* **Prueba realizada:** qué tocaste / ejecutaste.
* **Resultado observado:** qué pasó (éxito/fallo) y por qué crees que ocurrió.
* **Evidencias:** capturas y/o output.
* **Conclusión:** qué aprendiste y qué mejorarías en una siguiente iteración.

---

###### © NICS LAB — NICS | CyberLab

_Proyecto experimental para entornos de laboratorio y formación en ciberseguridad._
