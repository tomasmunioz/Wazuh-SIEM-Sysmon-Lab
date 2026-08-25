# Wazuh-SIEM-Sysmon-Lab

Laboratorio práctico de **Blue Team** orientado al monitoreo de endpoints Windows, análisis de eventos y detección de actividad sospechosa utilizando **Wazuh** y **Sysmon**.
El objetivo del proyecto fue implementar un entorno de monitoreo capaz de recolectar telemetría de un sistema Windows, detectar modificaciones de archivos, analizar intentos de autenticación y observar la ejecución de procesos mediante Sysmon.
Como parte final del laboratorio, se creó una **regla personalizada de Wazuh** para detectar la ejecución de `cmd.exe` iniciada desde PowerShell.

Objetivos:

- Implementar un SIEM utilizando Wazuh.
- Conectar un endpoint Windows mediante Wazuh Agent.
- Implementar File Integrity Monitoring (FIM).
- Detectar creación, modificación y eliminación de archivos.
- Analizar eventos de autenticación de Windows.
- Detectar múltiples intentos fallidos de inicio de sesión.
- Integrar Sysmon con Wazuh.
- Monitorear creación y ejecución de procesos.
- Analizar relaciones Parent Process → Child Process.
- Relacionar detecciones con MITRE ATT&CK.
- Crear una regla personalizada de detección.

Tecnologías utilizadas:

- Wazuh
- Wazuh Agent
- Sysmon
- Windows 11
- PowerShell
- VirtualBox
- MITRE ATT&CK

File Integrity Monitoring:

Se configuró **File Integrity Monitoring** para supervisar un directorio específico del endpoint Windows.
Directorio monitoreado: C:\wazuhlab
Para comprobar el funcionamiento se realizaron tres acciones sobre un archivo: Creación → Modificación → Eliminación
Wazuh detectó correctamente los cambios y generó eventos correspondientes a: File added to the system, Integrity checksum changed, File deleted
Esto permite detectar modificaciones inesperadas sobre archivos importantes del sistema.

Monitoreo de autenticación:

Se provocaron múltiples intentos fallidos de autenticación para generar: Windows Event ID 4625
Este evento representa: An account failed to log on
Wazuh recibió los eventos y permitió analizarlos desde Threat Hunting.
Posteriormente se detectó la repetición de múltiples fallos de autenticación mediante: Rule ID: 60204
La detección fue relacionada por Wazuh con comportamiento compatible con Brute Force.
Esto demuestra la capacidad del SIEM para pasar de eventos individuales a una alerta de mayor relevancia mediante correlación.

Integración de Sysmon:

Para aumentar la visibilidad del endpoint se instaló **Microsoft Sysmon**.
Sysmon permite registrar información más detallada sobre la actividad del sistema, incluyendo:
- creación de procesos
- procesos padre e hijo
- línea de comandos
- usuario que ejecutó el proceso
- hashes
- identificadores de procesos
- nivel de integridad
Los eventos son registrados en: Microsoft-Windows-Sysmon/Operational
Wazuh fue configurado para recolectar estos eventos.

Monitoreo de procesos:

Para generar telemetría se ejecutaron comandos desde PowerShell y CMD.
Entre las pruebas realizadas: whoami, hostname, ipconfig
También se ejecutó una cadena mediante cmd.exe: cmd.exe /c "whoami && hostname && ipconfig"
Sysmon registró la creación del proceso mediante: Event ID: 1, Event: Process Create

Análisis Parent → Child Process:

Uno de los puntos más importantes del laboratorio fue analizar la relación entre procesos.
En la prueba realizada se observó: Powershell.exe ---> cmd.exe
El evento de Sysmon permitió identificar: Image:C:\Windows\System32\cmd.exe  ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
También fue posible observar la línea de comandos ejecutada: cmd.exe /c "whoami && hostname && ipconfig"
Este tipo de telemetría es especialmente útil para investigaciones de seguridad, ya que no solamente muestra qué programa se ejecutó sino qué proceso originó su ejecución.

Detecciones de Wazuh:

Tras integrar Sysmon, Wazuh comenzó a generar diferentes alertas relacionadas con la ejecución de procesos, entre ellas:
-Powershell process spawned powershell instance
-Powershell process spawned Windows command shell instance
-Discovery activity executed
-Suspicious Windows cmd shell execution
Esto demuestra que los eventos de Sysmon estaban siendo correctamente recolectados y procesados por el motor de reglas de Wazuh.

Regla personalizada de Wazuh:

Finalmente se creó una regla personalizada para elevar la prioridad cuando PowerShell inicia una instancia de CMD.
xml
<rule id="100100" level="10">
    <if_sid>92004</if_sid>
    <description>LAB PowerShell ejecuto CMD</description>
    <mitre>
        <id>T1059.003</id>
    </mitre>
</rule>
La regla fue almacenada dentro de: /var/ossec/etc/rules/local_rules.xml
Antes de aplicarla se verificó la configuración mediante: /var/ossec/bin/wazuh-analysisd -t
Después se reinició el manager para cargar la nueva regla.

Resultado de la regla personalizada:

Se volvió a ejecutar desde PowerShell: cmd.exe /c "whoami && hostname && ipconfig"
Sysmon generó el evento correspondiente y Wazuh activó la regla personalizada.
Resultado:
Rule ID:      100100
Rule Level:   10
Description:
LAB PowerShell ejecuto CMD
MITRE ID:
T1059.003
Tactic:
Execution
Technique:
Windows Command Shell
La detección confirmó que la regla personalizada estaba funcionando correctamente.

MITRE ATT&CK:

La detección fue asociada con: T1059.003 – Windows Command Shell
Táctica: Execution
Técnica: Command and Scripting Interpreter: Windows Command Shell
El uso de MITRE ATT&CK permite contextualizar las alertas dentro de técnicas conocidas utilizadas durante ataques reales.

Evidencias:

Las capturas del laboratorio se encuentran dentro del directorio: /screenshots
Incluyen evidencia de:
- File Integrity Monitoring.
- Eventos de autenticación.
- Multiple Windows Logon Failures.
- Integración Sysmon + Wazuh.
- Process Creation.
- PowerShell → CMD.
- Regla personalizada `100100`.
- Clasificación MITRE ATT&CK.



