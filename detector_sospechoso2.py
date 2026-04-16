import psutil
import time
import os
import json
from datetime import datetime

# ==============================
# CARGAR CONFIGURACIÓN EXTERNA
# ==============================
# Se carga un archivo JSON externo que permite modificar parámetros
# del sistema sin necesidad de cambiar el código fuente
with open("config.json", "r") as f:
    config = json.load(f)

# Parámetros configurables desde el archivo externo
CPU_UMBRAL = config["cpu_umbral"]          # Umbral de CPU para considerar un proceso sospechoso
INTERVALO = config["intervalo_escaneo"]    # Tiempo entre cada escaneo del sistema
COOLDOWN = config["cooldown"]              # Tiempo de espera para evitar alertas repetidas
PALABRAS_SOSPECHOSAS = config["palabras_sospechosas"]  # Lista negra configurable de palabras clave

RUTA_REPORTE = "reporte_seguridad.txt"
procesos_vistos = set()
procesos_reportados = {}

MI_PROCESO_PID = os.getpid()
MI_RUTA = os.path.abspath(__file__).lower()

def analizar_procesos():
    sospechosos = []
    ahora = time.time()

    for p in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
        try:
            pid = p.info['pid']
            nombre = (p.info['name'] or "").lower()
            cmdline_list = p.info['cmdline'] or []
            cmdline = " ".join(cmdline_list).lower()
            ruta = (p.info['exe'] or "").lower()

            if pid == MI_PROCESO_PID:
                continue

            if MI_RUTA in cmdline:
                continue

            es_nuevo = pid not in procesos_vistos
            procesos_vistos.add(pid)

            score = 0
            motivos = []

            # ==============================
            # DETECCIÓN DE CPU
            # ==============================
            # Se obtiene el porcentaje de uso de CPU del proceso
            # Este valor permite identificar procesos que consumen demasiados recursos
            cpu = p.cpu_percent(interval=0.1)

            if cpu > CPU_UMBRAL:
                score += 5
                motivos.append(f"Alto consumo de CPU: {cpu}%")


            if es_nuevo:
                score += 1
                motivos.append("Proceso nuevo")

            if nombre in ["cmd.exe", "powershell.exe", "py.exe"]:

                if any(pal in cmdline for pal in PALABRAS_SOSPECHOSAS):
                    score += 5
                    motivos.append("Shell con comando sospechoso")

                elif len(cmdline) > 120:
                    score += 3
                    motivos.append("Shell con comando largo")

                elif any(r in ruta for r in ["appdata", "temp"]):
                    score += 4
                    motivos.append("Shell ejecutado desde ruta sospechosa")

            if any(r in ruta for r in ["appdata", "temp", "roaming"]):
                score += 3
                motivos.append("Ejecución en ruta sospechosa")

            script_detectado = False

            for arg in cmdline_list:
                if arg.endswith(".py"):
                    script_detectado = True

                    if any(pal in arg.lower() for pal in PALABRAS_SOSPECHOSAS):
                        score += 6
                        motivos.append(f"Script sospechoso: {arg}")
                    else:
                        score += 2
                        motivos.append(f"Script ejecutándose: {arg}")

            if "python" in nombre and script_detectado:
                score += 2
                motivos.append("Python ejecutando script")

            if score >= 6:
                ultima = procesos_reportados.get(pid, 0)

                # Uso del cooldown configurable desde JSON para evitar múltiples reportes
                if ahora - ultima > COOLDOWN:
                    procesos_reportados[pid] = ahora

                    sospechosos.append({
                        "pid": pid,
                        "nombre": nombre,
                        "cmd": cmdline,
                        "ruta": ruta,
                        "score": score,
                        "cpu": cpu,  # Se agrega el consumo de CPU al reporte para evidencia
                        "motivos": motivos
                    })

        except:
            continue

    return sospechosos


def generar_reporte(sospechosos):
    with open(RUTA_REPORTE, "a", encoding="utf-8") as f:

        f.write("\n==============================\n")
        f.write(f"Fecha: {datetime.now()}\n")

        if sospechosos:
            for p in sospechosos:
                riesgo = "ALTO" if p["score"] >= 8 else "MEDIO"

                f.write(f"""
ALERTA DETECTADA
PID: {p['pid']}
Proceso: {p['nombre']}
Riesgo: {riesgo}
Score: {p['score']}
CPU: {p['cpu']}%     # Se incluye el uso de CPU como parte de la evidencia

Ruta:
{p['ruta']}

Comando:
{p['cmd']}

Motivos:
 - {"\n - ".join(p['motivos'])}
--------------------------
""")
        else:
            f.write("Sin nuevos eventos\n")

    print(f"[✔] Escaneo | Detectados: {len(sospechosos)}")


def monitoreo():
    print("[INFO] Monitoreo iniciado...")

    while True:
        sospechosos = analizar_procesos()
        generar_reporte(sospechosos)

        # Intervalo configurable desde JSON
        time.sleep(INTERVALO)


monitoreo()