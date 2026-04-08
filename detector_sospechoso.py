import psutil   # Permite obtener información de procesos y recursos del sistema
import time     # Se usa para controlar tiempos y pausas
import os       # Se usa para obtener rutas y datos del sistema
from datetime import datetime  # Permite registrar fecha y hora en el reporte


# ==============================
# CONFIGURACIÓN GENERAL
# ==============================

# Nombre del archivo donde se guardarán los reportes de seguridad
RUTA_REPORTE = "reporte_seguridad.txt"

# Conjunto para guardar los PID (ID de procesos) que ya se han visto
# y así detectar procesos nuevos
procesos_vistos = set()

# Diccionario para recordar cuándo fue la última vez que se reportó
# un proceso sospechoso, evitando repetir alertas constantemente
procesos_reportados = {}

# Tiempo de espera en segundos antes de volver a reportar
# el mismo proceso sospechoso
COOLDOWN = 10

# PID del programa actual (este mismo script)
# Se usa para evitar que el sistema se detecte a sí mismo
MI_PROCESO_PID = os.getpid()

# Ruta absoluta del archivo actual en minúsculas
# También se usa para evitar auto-detección
MI_RUTA = os.path.abspath(__file__).lower()

# Lista de palabras clave que podrían indicar comportamiento sospechoso
PALABRAS_SOSPECHOSAS = [
    "virus", "malware", "miner", "hack",
    "test", "temp", "payload"
]


# ==============================
# FUNCIÓN: analizar_procesos()
# ==============================
# Esta función revisa todos los procesos activos del sistema
# y evalúa si alguno parece sospechoso según ciertas reglas.
# Devuelve una lista de procesos marcados como sospechosos.
def analizar_procesos():
    sospechosos = []  # Lista donde se guardarán procesos detectados
    ahora = time.time()  # Hora actual en segundos, usada para cooldown

    # Recorre todos los procesos activos y obtiene algunos datos clave
    for p in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
        try:
            # Extraer información del proceso
            pid = p.info['pid']  # ID del proceso
            nombre = (p.info['name'] or "").lower()  # Nombre del proceso
            cmdline_list = p.info['cmdline'] or []  # Lista de argumentos usados al ejecutar
            cmdline = " ".join(cmdline_list).lower()  # Convierte la lista en texto
            ruta = (p.info['exe'] or "").lower()  # Ruta del ejecutable

            # Evita analizar este mismo programa
            if pid == MI_PROCESO_PID:
                continue

            # Evita analizar cualquier proceso que esté ejecutando este archivo
            if MI_RUTA in cmdline:
                continue

            # Detecta si el proceso es nuevo
            es_nuevo = pid not in procesos_vistos
            procesos_vistos.add(pid)

            # Variables para calcular nivel de sospecha
            score = 0      # Puntaje de riesgo
            motivos = []   # Lista de razones por las que fue marcado

            # Si el proceso es nuevo, suma un poco de riesgo
            if es_nuevo:
                score += 1
                motivos.append("Proceso nuevo")

            # Detecta shells comunes que suelen usarse para ejecutar scripts o comandos
            if nombre in ["cmd.exe", "powershell.exe", "py.exe"]:

                # Si en el comando hay palabras sospechosas, suma bastante riesgo
                if any(pal in cmdline for pal in PALABRAS_SOSPECHOSAS):
                    score += 5
                    motivos.append("Shell con comando sospechoso")

                # Si el comando es demasiado largo, puede ser comportamiento raro
                elif len(cmdline) > 120:
                    score += 3
                    motivos.append("Shell con comando largo")

                # Si el shell se ejecuta desde AppData o Temp, también es sospechoso
                elif any(r in ruta for r in ["appdata", "temp"]):
                    score += 4
                    motivos.append("Shell ejecutado desde ruta sospechosa")

            # Detecta procesos ejecutados desde rutas comúnmente usadas por malware
            if any(r in ruta for r in ["appdata", "temp", "roaming"]):
                score += 3
                motivos.append("Ejecución en ruta sospechosa")

            # Variable para saber si se detectó un script Python
            script_detectado = False

            # Revisa cada argumento del comando del proceso
            for arg in cmdline_list:
                # Si el argumento termina en .py, se considera un script Python
                if arg.endswith(".py"):
                    script_detectado = True

                    # Si el nombre del script contiene palabras sospechosas
                    if any(pal in arg.lower() for pal in PALABRAS_SOSPECHOSAS):
                        score += 6
                        motivos.append(f"Script sospechoso: {arg}")
                    else:
                        # Si es un script Python normal, suma un poco de riesgo
                        score += 2
                        motivos.append(f"Script ejecutándose: {arg}")

            # Si el proceso es Python y además ejecuta un script
            if "python" in nombre and script_detectado:
                score += 2
                motivos.append("Python ejecutando script")

            # Si el puntaje de riesgo es suficientemente alto, se marca como sospechoso
            if score >= 6:
                # Revisa cuándo fue la última vez que se reportó este PID
                ultima = procesos_reportados.get(pid, 0)

                # Solo se vuelve a reportar si ya pasó el tiempo de cooldown
                if ahora - ultima > COOLDOWN:
                    procesos_reportados[pid] = ahora

                    # Guarda toda la información del proceso sospechoso
                    sospechosos.append({
                        "pid": pid,
                        "nombre": nombre,
                        "cmd": cmdline,
                        "ruta": ruta,
                        "score": score,
                        "motivos": motivos
                    })

        except:
            # Si ocurre un error con un proceso (por permisos o porque ya cerró),
            # simplemente se ignora y continúa con el siguiente
            continue

    # Devuelve la lista de procesos sospechosos encontrados
    return sospechosos


# ==============================
# FUNCIÓN: generar_reporte()
# ==============================
# Esta función recibe la lista de procesos sospechosos y los guarda
# en un archivo de texto como evidencia del monitoreo.
def generar_reporte(sospechosos):
    # Abre el archivo en modo "append" para no borrar reportes anteriores
    with open(RUTA_REPORTE, "a", encoding="utf-8") as f:

        # Escribe un separador para organizar cada escaneo
        f.write("\n==============================\n")
        f.write(f"Fecha: {datetime.now()}\n")

        # Si se detectaron procesos sospechosos
        if sospechosos:
            for p in sospechosos:
                # Define el nivel de riesgo según el score
                riesgo = "ALTO" if p["score"] >= 8 else "MEDIO"

                # Escribe la información completa del proceso detectado
                f.write(f"""
ALERTA DETECTADA
PID: {p['pid']}
Proceso: {p['nombre']}
Riesgo: {riesgo}
Score: {p['score']}

Ruta:
{p['ruta']}

Comando:
{p['cmd']}

Motivos:
 - {"\n - ".join(p['motivos'])}
--------------------------
""")
        else:
            # Si no hubo procesos sospechosos en este escaneo
            f.write("Sin nuevos eventos\n")

    # Muestra en consola un resumen del escaneo
    print(f"[✔] Escaneo | Detectados: {len(sospechosos)}")


# ==============================
# FUNCIÓN: monitoreo()
# ==============================
# Esta función ejecuta el monitoreo en tiempo real.
# Llama continuamente al análisis de procesos y genera reportes.
def monitoreo():
    print("[INFO] Monitoreo iniciado...")

    # Bucle infinito para mantener el monitoreo activo
    while True:
        sospechosos = analizar_procesos()   # Analiza procesos activos
        generar_reporte(sospechosos)        # Guarda resultados en el reporte
        time.sleep(2)  # Espera 2 segundos antes del siguiente escaneo


# ==============================
# EJECUCIÓN PRINCIPAL
# ==============================
# Inicia el sistema de monitoreo
monitoreo()