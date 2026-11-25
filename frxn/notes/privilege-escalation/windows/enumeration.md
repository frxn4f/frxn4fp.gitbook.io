# Enumeration

## Manual

> **Usuario actual y hostname**

```bat
whoami
hostname
```

`whoami` devuelve el dominio y usuario actual (`DOMAIN\USERNAME`), o el nombre del equipo y usuario si se trata de una cuenta local.

`hostname` devuelve el nombre del equipo.

***

> **Grupos a los que pertenece el usuario actual**

```bat
whoami /groups
```

***

> **Enumerar privilegios del usuario actual**

```bat
whoami /priv
```

***

> **Enumerar usuarios locales**

```powershell
Get-LocalUser
```

***

> **Enumerar grupos locales**

```powershell
Get-LocalGroup
```

Alternativa:

```bat
net localgroup
```

***

> **Enumerar miembros de un grupo local específico**

```powershell
Get-LocalGroupMember groupname
```

Ejemplo:

```powershell
Get-LocalGroupMember "Remote Management Users"
```

En el ejemplo se enumeran los usuarios pertenecientes al grupo Remote Management Users, que suele estar relacionado con el acceso remoto mediante WinRM. Pertenecer al grupo no garantiza por sí solo que WinRM esté habilitado o accesible.

***

> **Obtener información del sistema**

```bat
systeminfo
```

Permite obtener información del sistema operativo, versión, arquitectura, hotfixes instalados y otros datos relevantes.

***

> **Enumerar interfaces de red**

```bat
ipconfig /all
```

Muestra información detallada de las interfaces de red, direcciones IP, DNS, gateway, máscara de subred y configuración DHCP.

***

> **Tabla de enrutamiento**

```bat
route print
```

{yellow}Útil para determinar posibles vectores de ataque hacia otros sistemas o redes a las que el equipo tenga acceso.

***

> **Enumerar conexiones de red activas**

```bat
netstat -ano
```

* \[`-a`] Para mostrar todas las conexiones TCP activas y los puertos TCP/UDP en escucha.
* \[`-n`] Para deshabilitar la resolución de nombres y mostrar las direcciones IP y puertos numéricamente.
* \[`-o`] Para mostrar el ID del proceso (PID) asociado a cada conexión.

Podemos relacionar el PID con el proceso correspondiente mediante:

```bat
tasklist /FI "PID eq <PID>"
```

***

> **Enumerar aplicaciones instaladas**

Aplicaciones de 64 bits:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher
```

Aplicaciones de 32 bits:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher
```

Se consultan las claves del registro donde Windows almacena información de las aplicaciones instaladas. No todas las aplicaciones tienen por qué aparecer, especialmente las portables o algunas instaladas únicamente para el usuario actual.

***

> **Enumerar procesos**

```powershell
Get-Process
```

Alternativa para obtener información más detallada:

```powershell
Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine
```

Útil para identificar procesos interesantes, sus rutas de ejecución, procesos padre y posibles argumentos de línea de comandos.

***

> **Obtener historial de comandos**

```powershell
Get-History
```

Muestra los comandos ejecutados en la sesión actual de PowerShell.

> **ConsoleHost\_history**

```powershell
type (Get-PSReadLineOption).HistorySavePath
```

Permite consultar el historial persistente de PowerShell almacenado por PSReadLine, incluyendo comandos ejecutados en sesiones anteriores.

***

> **Event Viewer**

```bat
eventvwr.msc
```

Permite consultar los registros de eventos de Windows. Puede contener información interesante sobre inicios de sesión, errores, ejecución de servicios y actividad del sistema.

## Automatizada

### WinPEAS

> **Enumeración por defecto**

```powershell
.\winPEASany.exe
```

### Seatbelt

> **Enumeración para todos los usuarios y grupos de comprobaciones**

```powershell
.\Seatbelt.exe -group=all
```

Para obtener los resultados completos, evitando los filtros aplicados por defecto:

```powershell
.\Seatbelt.exe -group=all -full
```
